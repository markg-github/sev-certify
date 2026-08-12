"""Detect which snpguest behavior profile is installed.

``snpguest --version`` cannot be used for this.  The ``--family-id`` contract
changed in commit 19fc1af ("preattestation: fix family_id and image_id
parsing"), which is in no tagged release, and ``Cargo.toml`` on virtee/main
still reads ``0.10.0``.  Both the v0.10.0 release and current main therefore
report ``snpguest 0.10.0`` while accepting mutually exclusive inputs:

    v0.10.0 release :  --family-id takes 16 ASCII characters
    virtee/main     :  --family-id takes 32 hex characters

The ``--help`` text does distinguish them, so that is what we probe.

The gate covers snpguest's *input* contract only.  Report fields are read
straight out of ``report.bin`` (see :mod:`sev_verify.attestation_report`), so
snpguest's output formatting is no longer something we depend on or need to
validate.

An encoding mismatch does fail loudly on its own — both builds reject the
other's spelling at ``snpguest generate id-block`` — so the gate is not
protecting against a silent wrong answer.  What it protects is the claim the
harness makes: we report results only for a snpguest we have actually
exercised, rather than producing a green run against an unvalidated build.
``--try-anyway`` is the escape hatch when you want the run regardless.
"""

from __future__ import annotations

import functools
import re
import shutil
import subprocess
from dataclasses import dataclass

# Profile identifiers.
PROFILE_V0_10_0_RELEASE = "v0_10_0_release"
PROFILE_UNKNOWN = "unknown"

# Only profiles we have exercised end-to-end on real hardware.
SUPPORTED_PROFILES = frozenset({PROFILE_V0_10_0_RELEASE})

# Family/image ID encodings.
ENCODING_ASCII16 = "ascii16"
ENCODING_HEX32 = "hex32"

_HELP_TIMEOUT_S = 5


@dataclass(frozen=True)
class SnpguestCaps:
    """What the installed snpguest can do, as far as we can tell."""

    profile: str
    family_id_encoding: str | None
    version: str | None
    reason: str

    @property
    def supported(self) -> bool:
        return self.profile in SUPPORTED_PROFILES


def _run(args: list[str]) -> str | None:
    """Run *args* and return combined output, or None if it could not run."""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=_HELP_TIMEOUT_S,
        )
    except Exception:
        return None
    # clap writes --help to stdout, but errors to stderr; take whichever has text.
    return proc.stdout or proc.stderr or ""


def _classify_help(help_text: str) -> tuple[str | None, str]:
    """Map ``generate id-block --help`` output to a family-ID encoding.

    Returns ``(encoding, reason)``; *encoding* is None when unrecognized.
    """
    # Bounded [\s\S] rather than [^\n] so a clap line-wrap between the option
    # and its description does not defeat the match.  If --family-id somehow
    # lacks the phrase we may pick up --image-id's; the two always agree.
    m = re.search(
        r"--family-id[\s\S]{0,400}?Has to be\s+(\d+)\s+characters",
        help_text,
        re.IGNORECASE,
    )
    if not m:
        return None, "could not find the --family-id contract in `snpguest generate id-block --help`"

    width = m.group(1)
    if width == "16":
        return ENCODING_ASCII16, "--family-id takes 16 ASCII characters"
    if width == "32":
        return (
            ENCODING_HEX32,
            "--family-id takes 32 hex characters (unreleased virtee/main behavior)",
        )
    return None, f"--family-id reports an unrecognized width of {width} characters"


def _detect_version() -> str | None:
    """Best-effort ``snpguest --version``; diagnostic only, never used to branch."""
    out = _run(["snpguest", "--version"])
    if not out:
        return None
    return out.strip().splitlines()[0] if out.strip() else None


@functools.lru_cache(maxsize=1)
def detect() -> SnpguestCaps:
    """Probe the installed snpguest once per process."""
    if shutil.which("snpguest") is None:
        return SnpguestCaps(
            profile=PROFILE_UNKNOWN,
            family_id_encoding=None,
            version=None,
            reason="snpguest not found on PATH",
        )

    version = _detect_version()
    help_text = _run(["snpguest", "generate", "id-block", "--help"])
    if help_text is None:
        return SnpguestCaps(
            profile=PROFILE_UNKNOWN,
            family_id_encoding=None,
            version=version,
            reason="`snpguest generate id-block --help` could not be run",
        )

    encoding, reason = _classify_help(help_text)
    profile = (
        PROFILE_V0_10_0_RELEASE if encoding == ENCODING_ASCII16 else PROFILE_UNKNOWN
    )
    return SnpguestCaps(
        profile=profile,
        family_id_encoding=encoding,
        version=version,
        reason=reason,
    )


def encode_id_field(value: str, encoding: str | None) -> str:
    """Render *value* as snpguest expects it for --family-id / --image-id.

    Both encodings describe the same 16 bytes, so the attestation report
    contains identical bytes either way and report verification is unaffected.
    An unknown encoding falls back to the validated ASCII form.
    """
    if encoding == ENCODING_HEX32:
        return value.encode("ascii").hex()
    return value
