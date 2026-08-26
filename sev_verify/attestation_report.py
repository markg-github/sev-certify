"""Parse the SEV-SNP ATTESTATION_REPORT binary structure.

Reading ``report.bin`` directly, rather than regexing ``snpguest display
report``, removes a dependency on a CLI's human-readable output format. The
binary layout is fixed by the SEV-SNP ABI and, unlike the CLI text, the report
is *self-describing*: VERSION is the first four bytes, so every report states
which layout it uses and can be checked on the spot.

Layout is version-dependent in practice — the report version tracks firmware,
which tracks CPU generation — but versions have only ever *appended* fields.
Everything below 0x188 is common to v2 and v3; the CPUID family/model/stepping
triple at 0x188 exists only in v3+.

**TCB_VERSION is the exception, and it is not version-dependent but
*generation*-dependent.** The ``sev`` crate decodes it two different ways
(``from_legacy_bytes`` vs ``from_turin_bytes``), and the layouts are
incompatible and indistinguishable from the eight bytes alone:

===========  =====================  ====================
byte         Milan / Genoa          Turin / Venice
===========  =====================  ====================
0            BOOT_LOADER            FMC
1            TEE                    BOOT_LOADER
2            --                     TEE
3            --                     SNP
6            SNP                    --
7            MICROCODE              MICROCODE
===========  =====================  ====================

Decoding therefore requires knowing the processor generation. The authoritative
source is the **host's** CPUID — a report parsed here was produced by a guest on
this machine, and unlike the report's own CPUID copy it is present regardless of
report version. :func:`host_generation` reads it; :func:`parse` takes the result
as an argument so the parser itself stays a pure function of its input and can
be unit-tested without hardware.

When the report is v3+ it also carries a CPUID copy, and :func:`parse`
cross-checks the two. A mismatch means the report did not come from the machine
we are decoding it on, so it is raised rather than silently preferred either
way. Where no generation is supplied, the report's own CPUID is used if present.
An unrecognised processor raises: guessing a layout would produce
plausible-looking but wrong values with no error.

Offsets are confirmed against real reports rather than read off a spec. The
first such validation used a v3 report from an EPYC 9654 (Genoa, CPUID
19h/11h), cross-checked against independently known values:
GUEST_SVN/POLICY/FAMILY_ID/IMAGE_ID against the values the ID block was built
with, REPORTED_TCB against ``snphost ok``, AUTHOR_KEY_DIGEST against the known
all-zero author key, and CPUID against the CPU model. As further processors are
exercised, extend :data:`SUPPORTED_GENERATIONS` and record the validation here.

.. note::

   This module is a **short-term stand-in**. The right long-term source is
   ``snpguest``, which already parses reports correctly and generation-aware via
   the ``sev`` crate but currently exposes them only as human-readable text
   (``println!("{}", att_report)``). Once snpguest gains machine-readable
   output, this module should be replaced by consuming that output rather than
   extended to cover further processor generations.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

#: ATTESTATION_REPORT is a fixed-size structure.
REPORT_SIZE = 1184

#: Report versions whose layout we read. v3 is verified on hardware; v2 shares
#: the same layout for every field below 0x188.
KNOWN_VERSIONS = frozenset({2, 3})

#: TCB_VERSION byte layouts. See the module docstring for the two orderings.
TCB_LAYOUT_LEGACY = "legacy"
TCB_LAYOUT_TURIN = "turin"

#: Processor generations this module has been **validated against**, keyed by
#: CPUID family and an inclusive model range.
#:
#: This is deliberately a record of what has been exercised on real hardware,
#: not of what we believe we could decode. A certification harness reporting a
#: pass on silicon it has never run on is the failure this gate exists to
#: prevent, so an unrecognised processor raises rather than being decoded on
#: the assumption that a transcribed layout is right.
#:
#: Keyed on family/model *pairs*, not family/model/stepping triples: AMD scopes
#: SEV firmware images by family and model only — ``amd_sev_fam19h_model1xh``,
#: ``amd_sev_fam1ah_model0xh`` — and stepping appears nowhere in that
#: partitioning. snpguest's ``get_processor_model`` (``src/fetch.rs``) splits
#: the same way for VCEK lookup.
#:
#: To add a generation: run the ID block test on that hardware, confirm the
#: decoded fields against ``snphost show tcb`` and the values the ID block was
#: built with, then add the entry and note the validation in the docstring.
#: The layouts for generations not yet exercised here, taken from the ``sev``
#: crate, are:
#:
#:     0x19 / 0x00-0x0F  Milan          legacy
#:     0x19 / 0xA0-0xAF  Bergamo/Siena  legacy
#:     0x1A / 0x00-0x11  Turin          turin
SUPPORTED_GENERATIONS: tuple[tuple[int, range, str, str], ...] = (
    # (cpuid_family, model range, name, TCB layout)
    (0x19, range(0x10, 0x20), "Genoa", TCB_LAYOUT_LEGACY),  # EPYC 9654, v3 reports
)

# Field offsets. See module docstring for how these were validated.
_OFF_VERSION = 0x000
_OFF_GUEST_SVN = 0x004
_OFF_POLICY = 0x008
_OFF_FAMILY_ID = 0x010
_OFF_IMAGE_ID = 0x020
_OFF_VMPL = 0x030
_OFF_REPORT_DATA = 0x050
_OFF_MEASUREMENT = 0x090
_OFF_HOST_DATA = 0x0C0
_OFF_ID_KEY_DIGEST = 0x0E0
_OFF_AUTHOR_KEY_DIGEST = 0x110
_OFF_REPORT_ID = 0x140
_OFF_REPORTED_TCB = 0x180
_OFF_CPUID_FAM = 0x188  # v3+

_LEN_ID = 16
_LEN_MEASUREMENT = 48
_LEN_DIGEST = 48
_LEN_REPORT_DATA = 64
_LEN_HOST_DATA = 32
_LEN_REPORT_ID = 32


class ReportError(Exception):
    """Base class for attestation report problems."""


class ReportMalformed(ReportError):
    """The file is not a well-formed ATTESTATION_REPORT."""


class ReportUnsupportedVersion(ReportError):
    """The report declares a version whose layout we have not validated."""


class ReportUnsupportedCpu(ReportError):
    """The report comes from a processor this module has not been validated on.

    Raised rather than decoding on the assumption that a transcribed layout is
    correct — TCB_VERSION in particular is laid out differently on Turin, so a
    wrong guess yields plausible values rather than an error.
    """


@dataclass(frozen=True)
class TcbVersion:
    """Decoded SNP TCB_VERSION — the same values ``snphost ok`` prints.

    ``fmc`` exists only on Turin and later; it is ``None`` elsewhere, matching
    the ``sev`` crate's ``Option<u8>``.
    """

    bootloader: int
    tee: int
    snp: int
    microcode: int
    fmc: int | None = None

    @classmethod
    def from_bytes(cls, raw: bytes, layout: str) -> TcbVersion:
        """Decode the 8-byte TCB_VERSION using the given generation layout."""
        if layout == TCB_LAYOUT_TURIN:
            # byte 0 FMC, 1 BOOT_LOADER, 2 TEE, 3 SNP, 7 MICROCODE.
            return cls(
                fmc=raw[0],
                bootloader=raw[1],
                tee=raw[2],
                snp=raw[3],
                microcode=raw[7],
            )
        if layout == TCB_LAYOUT_LEGACY:
            # byte 0 BOOT_LOADER, 1 TEE, bytes 2-5 reserved, 6 SNP, 7 MICROCODE.
            return cls(bootloader=raw[0], tee=raw[1], snp=raw[6], microcode=raw[7])
        raise ReportUnsupportedCpu(f"unknown TCB layout {layout!r}")

    def __str__(self) -> str:
        base = (
            f"bootloader={self.bootloader} tee={self.tee} "
            f"snp={self.snp} microcode={self.microcode}"
        )
        return base if self.fmc is None else f"fmc={self.fmc} {base}"


@dataclass(frozen=True)
class AttestationReport:
    """The fields of an ATTESTATION_REPORT that we read."""

    version: int
    guest_svn: int
    policy: int
    family_id: bytes
    image_id: bytes
    vmpl: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    id_key_digest: bytes
    author_key_digest: bytes
    report_id: bytes
    #: ``None`` when the processor generation was unknown, since the byte
    #: layout differs between generations and cannot be guessed.
    reported_tcb: TcbVersion | None
    #: (family, model, stepping) — v3+ only, None on older reports.
    cpuid: tuple[int, int, int] | None
    #: Validated processor generation this report was decoded as, or "unknown".
    generation: str

    @property
    def id_block_used(self) -> bool:
        """True when ID_KEY_DIGEST is set, i.e. the guest launched with an ID block."""
        return any(self.id_key_digest)


def resolve_generation(family: int, model: int) -> tuple[str, str]:
    """Return ``(name, tcb_layout)`` for a CPUID family/model pair.

    Raises:
        ReportUnsupportedCpu: the pair is not in :data:`SUPPORTED_GENERATIONS`.
    """
    for fam, models, name, layout in SUPPORTED_GENERATIONS:
        if family == fam and model in models:
            return name, layout

    validated = ", ".join(
        f"{name} (family 0x{fam:02X} model 0x{models[0]:02X}-0x{models[-1]:02X})"
        for fam, models, name, _ in SUPPORTED_GENERATIONS
    )
    raise ReportUnsupportedCpu(
        f"CPUID family 0x{family:02X} model 0x{model:02X} has not been validated "
        f"against. Validated: {validated}. TCB_VERSION is laid out differently "
        f"across processor generations, so decoding anyway would produce "
        f"plausible but wrong values. See SUPPORTED_GENERATIONS in "
        f"sev_verify/attestation_report.py."
    )


def host_generation() -> tuple[str, str]:
    """Return ``(name, tcb_layout)`` for the CPU this process is running on.

    Reads ``/proc/cpuinfo``. This is the authoritative source when parsing a
    report produced by a guest on this machine: unlike the report's CPUID copy
    it is present regardless of report version.

    Raises:
        ReportUnsupportedCpu: family/model unreadable, or not validated.
    """
    family = model = None
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                key, _, value = line.partition(":")
                key = key.strip()
                if key == "cpu family" and family is None:
                    family = int(value.strip())
                elif key == "model" and model is None:
                    model = int(value.strip())
                if family is not None and model is not None:
                    break
    except OSError as exc:
        raise ReportUnsupportedCpu(f"could not read /proc/cpuinfo: {exc}") from exc

    if family is None or model is None:
        raise ReportUnsupportedCpu(
            "could not determine CPU family/model from /proc/cpuinfo"
        )
    return resolve_generation(family, model)


def parse(
    data: bytes, *, generation: tuple[str, str] | None = None
) -> AttestationReport:
    """Parse raw report bytes.

    Args:
        data: the raw 1184-byte ATTESTATION_REPORT.
        generation: ``(name, tcb_layout)``, normally from :func:`host_generation`.
            Decides the TCB_VERSION byte layout. If omitted, it is taken from
            the report's own CPUID when present (v3+); a v2 report then leaves
            ``reported_tcb`` as ``None`` rather than guessing a layout.

    Raises:
        ReportMalformed: wrong size.
        ReportUnsupportedVersion: layout not validated for that version.
        ReportUnsupportedCpu: the report's CPUID disagrees with *generation*, or
            names a processor that has not been validated against.
    """
    if len(data) != REPORT_SIZE:
        raise ReportMalformed(
            f"expected a {REPORT_SIZE}-byte ATTESTATION_REPORT, got {len(data)} bytes"
        )

    (version,) = struct.unpack_from("<I", data, _OFF_VERSION)
    if version not in KNOWN_VERSIONS:
        raise ReportUnsupportedVersion(
            f"report declares VERSION {version}; this parser has been validated "
            f"for {sorted(KNOWN_VERSIONS)}"
        )

    (guest_svn,) = struct.unpack_from("<I", data, _OFF_GUEST_SVN)
    (policy,) = struct.unpack_from("<Q", data, _OFF_POLICY)
    (vmpl,) = struct.unpack_from("<I", data, _OFF_VMPL)

    def field(off: int, length: int) -> bytes:
        return data[off:off + length]

    cpuid = None
    if version >= 3:
        cpuid = (
            data[_OFF_CPUID_FAM],
            data[_OFF_CPUID_FAM + 1],
            data[_OFF_CPUID_FAM + 2],
        )

    # Resolve the generation that decides the TCB_VERSION layout.
    if generation is not None and cpuid is not None:
        # Both available: they must agree, or this report did not come from the
        # machine we are decoding it on.
        report_gen = resolve_generation(cpuid[0], cpuid[1])
        if report_gen != generation:
            raise ReportUnsupportedCpu(
                f"report CPUID family 0x{cpuid[0]:02X} model 0x{cpuid[1]:02X} "
                f"resolves to {report_gen[0]}, but the caller supplied "
                f"{generation[0]}. The report does not appear to come from this "
                f"machine."
            )
    elif generation is None and cpuid is not None:
        generation = resolve_generation(cpuid[0], cpuid[1])

    if generation is not None:
        gen_name, tcb_layout = generation
        reported_tcb = TcbVersion.from_bytes(
            data[_OFF_REPORTED_TCB:_OFF_REPORTED_TCB + 8], tcb_layout
        )
    else:
        # v2 report and no generation supplied — the TCB layout is unknowable,
        # so leave it undecoded rather than assume one.
        gen_name, reported_tcb = "unknown", None

    return AttestationReport(
        version=version,
        guest_svn=guest_svn,
        policy=policy,
        family_id=field(_OFF_FAMILY_ID, _LEN_ID),
        image_id=field(_OFF_IMAGE_ID, _LEN_ID),
        vmpl=vmpl,
        report_data=field(_OFF_REPORT_DATA, _LEN_REPORT_DATA),
        measurement=field(_OFF_MEASUREMENT, _LEN_MEASUREMENT),
        host_data=field(_OFF_HOST_DATA, _LEN_HOST_DATA),
        id_key_digest=field(_OFF_ID_KEY_DIGEST, _LEN_DIGEST),
        author_key_digest=field(_OFF_AUTHOR_KEY_DIGEST, _LEN_DIGEST),
        report_id=field(_OFF_REPORT_ID, _LEN_REPORT_ID),
        reported_tcb=reported_tcb,
        cpuid=cpuid,
        generation=gen_name,
    )


def read(
    path: Path, *, generation: tuple[str, str] | None = None
) -> AttestationReport:
    """Read and parse an ATTESTATION_REPORT file.

    Args:
        path: the report file.
        generation: forwarded to :func:`parse`; see its docstring.

    Raises:
        ReportMalformed: file missing or wrong size.
        ReportUnsupportedVersion: layout not validated for that version.
        ReportUnsupportedCpu: CPUID mismatch, or processor not validated.
    """
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise ReportMalformed(f"{path.name} not found") from exc
    return parse(data, generation=generation)
