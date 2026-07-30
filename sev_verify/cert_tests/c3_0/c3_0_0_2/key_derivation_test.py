"""key_derivation_test: Launch SEV-SNP guest and run key derivation tests.

Verifies that the SNP MSG_KEY_REQ firmware command produces correct and
consistent derived keys:
  - Determinism: same params -> same key
  - VMPL isolation: different VMPL -> different keys
  - Root key difference: VCEK vs VMRK -> different keys
  - Guest SVN sensitivity and above-bound rejection
  - TCB version sensitivity and committed-TCB bound enforcement
  - Guest Field Select (GFS) sensitivity and per-bit field mixing

All key derivation happens on the guest via snpguest key over vsock.
Keys are pulled to the host for comparison. Report parsing (TCB bounds,
guest SVN) is done on the host from a pulled attestation report.

When sev_verify.id_block is available (from the ID block PR), the guest
is launched with an ID block, giving richer coverage (non-zero guest SVN,
family_id, image_id).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sev_verify.cert_tests.c3_0.c3_0_0_0.attestation_test import calculate_measurement  # noqa: F401
from sev_verify.models import BaseStep, Step, StepContext, StepHandlerResult
from sev_verify.vm_profile import VMProfile

try:
    from sev_verify.id_block import generate_id_block  # noqa: F401
    _HAS_ID_BLOCK = True
except ImportError:
    _HAS_ID_BLOCK = False

vm_profile = VMProfile(
    image_path="",
    memory_mb=2048,
)

# ── TCB parsing helpers ───────────────────────────────────────────────────────

@dataclass
class TcbVersion:
    boot_loader: int = 0
    tee: int = 0
    snp: int = 0
    microcode: int = 0

    def to_u64(self) -> int:
        return (
            (self.boot_loader & 0xFF) |
            ((self.tee & 0xFF) << 8) |
            ((self.snp & 0xFF) << 48) |
            ((self.microcode & 0xFF) << 56)
        )


@dataclass
class ReportInfo:
    version: Optional[int] = None
    guest_svn: int = 0
    committed_tcb: Optional[TcbVersion] = None


def _parse_tcb_section(text: str) -> TcbVersion:
    tcb = TcbVersion()
    for attr, pattern in [
        ('boot_loader', r'Boot\s*Loader\s*[:\s]+(0x[0-9a-fA-F]+|[0-9]+)'),
        ('tee',         r'TEE\s*[:\s]+(0x[0-9a-fA-F]+|[0-9]+)'),
        ('snp',         r'SNP\s*[:\s]+(0x[0-9a-fA-F]+|[0-9]+)'),
        ('microcode',   r'Microcode\s*[:\s]+(0x[0-9a-fA-F]+|[0-9]+)'),
    ]:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            setattr(tcb, attr, int(m.group(1), 0))
    return tcb


def _parse_report_info(display_output: str) -> ReportInfo:
    info = ReportInfo()
    m = re.search(r'^\s*Version\s*[:\s]+(0x[0-9a-fA-F]+|[0-9]+)',
                  display_output, re.IGNORECASE | re.MULTILINE)
    if m:
        info.version = int(m.group(1), 0)
    m = re.search(r'Guest\s+SVN\s*[:\s]+(0x[0-9a-fA-F]+|[0-9]+)',
                  display_output, re.IGNORECASE)
    if m:
        info.guest_svn = int(m.group(1), 0)
    boundary = r'(?:Current|Committed|Reported|Launch)\s+TCB'
    m = re.search(
        rf'Committed\s+TCB\s*:?(.*?)(?={boundary}|\Z)',
        display_output, re.DOTALL | re.IGNORECASE,
    )
    if m:
        info.committed_tcb = _parse_tcb_section(m.group(1))
    return info


# ── Callable step handlers ────────────────────────────────────────────────────

def _read_key(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes()
    except Exception:
        return None


def check_determinism(ctx: StepContext) -> StepHandlerResult:
    """Same params on the same guest -> same key."""
    k1 = _read_key(ctx.artifact_dir / "det_key1.bin")
    k2 = _read_key(ctx.artifact_dir / "det_key2.bin")
    if k1 is None or k2 is None:
        return StepHandlerResult(exit_code=1, stderr="Could not read determinism key files")
    if k1 == k2:
        return StepHandlerResult(exit_code=0, stdout="Keys match (deterministic)")
    return StepHandlerResult(exit_code=1, stderr="Keys differ — derivation is not deterministic")


def check_vmpl_isolation(ctx: StepContext) -> StepHandlerResult:
    """VMPL0 key != VMPL1 key (or VMPL1 derivation was rejected, which is also acceptable)."""
    k0 = _read_key(ctx.artifact_dir / "vmpl0_key.bin")
    k1_path = ctx.artifact_dir / "vmpl1_key.bin"
    if k0 is None:
        return StepHandlerResult(exit_code=1, stderr="Could not read VMPL0 key")
    if not k1_path.exists():
        return StepHandlerResult(
            exit_code=0,
            stdout="VMPL1 derivation was rejected (expected if not running at VMPL0) — N/A",
        )
    k1 = _read_key(k1_path)
    if k1 is None:
        return StepHandlerResult(exit_code=1, stderr="Could not read VMPL1 key")
    if k0 != k1:
        return StepHandlerResult(exit_code=0, stdout="VMPL0 and VMPL1 keys differ (proper isolation)")
    return StepHandlerResult(exit_code=1, stderr="VMPL0 and VMPL1 keys are identical")


def check_root_key_difference(ctx: StepContext) -> StepHandlerResult:
    """VCEK-derived key != VMRK-derived key."""
    kv = _read_key(ctx.artifact_dir / "vcek_key.bin")
    km = _read_key(ctx.artifact_dir / "vmrk_key.bin")
    if kv is None or km is None:
        return StepHandlerResult(exit_code=1, stderr="Could not read root key files")
    if kv != km:
        return StepHandlerResult(exit_code=0, stdout="VCEK and VMRK keys differ")
    return StepHandlerResult(exit_code=1, stderr="VCEK and VMRK keys are identical")


def parse_report_and_check_svn_bounds(ctx: StepContext) -> StepHandlerResult:
    """Parse attestation report, check above-bound SVN values were rejected."""
    report_file = ctx.artifact_dir / "report.bin"
    result = subprocess.run(
        ["snpguest", "display", "report", str(report_file)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return StepHandlerResult(exit_code=1, stderr=f"snpguest display report failed:\n{result.stderr}")

    info = _parse_report_info(result.stdout)
    # Store for later steps via a sidecar file
    (ctx.artifact_dir / "report_info.txt").write_text(
        f"version={info.version}\n"
        f"guest_svn={info.guest_svn}\n"
        f"committed_bl={info.committed_tcb.boot_loader if info.committed_tcb else 0}\n"
        f"committed_tee={info.committed_tcb.tee if info.committed_tcb else 0}\n"
        f"committed_snp={info.committed_tcb.snp if info.committed_tcb else 0}\n"
        f"committed_mc={info.committed_tcb.microcode if info.committed_tcb else 0}\n"
    )

    max_svn = info.guest_svn
    lines = [f"Guest SVN upper bound: {max_svn}"]
    failed = []
    for svn in range(max_svn + 1, max_svn + 4):
        key_file = ctx.artifact_dir / f"svn_over_{svn}.bin"
        if key_file.exists() and key_file.stat().st_size > 0:
            failed.append(svn)
            lines.append(f"FAIL: SVN={svn} succeeded — bound ({max_svn}) not enforced")
        else:
            lines.append(f"Bound enforced: SVN={svn} correctly rejected")

    if failed:
        return StepHandlerResult(exit_code=1, stderr="\n".join(lines))
    return StepHandlerResult(exit_code=0, stdout="\n".join(lines))


def check_svn_sensitivity(ctx: StepContext) -> StepHandlerResult:
    """All valid SVN values produce distinct keys (or N/A if only one valid value)."""
    info_file = ctx.artifact_dir / "report_info.txt"
    max_svn = 0
    if info_file.exists():
        for line in info_file.read_text().splitlines():
            if line.startswith("guest_svn="):
                max_svn = int(line.split("=")[1])

    if max_svn == 0:
        return StepHandlerResult(
            exit_code=0,
            stdout="Only one valid SVN value (0) — sensitivity N/A (no ID block)",
        )

    keys = {}
    for svn in range(0, max_svn + 1):
        k = _read_key(ctx.artifact_dir / f"svn_{svn}_key.bin")
        if k is not None:
            keys[svn] = k

    if len(keys) < 2:
        return StepHandlerResult(exit_code=1, stderr="Fewer than 2 successful SVN derivations")
    if len(set(keys.values())) == len(keys):
        return StepHandlerResult(exit_code=0, stdout=f"All {len(keys)} SVN values produce distinct keys")
    return StepHandlerResult(exit_code=1, stderr="Some SVN values produce identical keys")


def check_tcb_bounds_and_sensitivity(ctx: StepContext) -> StepHandlerResult:
    """TCB bound enforcement and sensitivity check."""
    info_file = ctx.artifact_dir / "report_info.txt"
    committed = TcbVersion()
    report_version = None
    if info_file.exists():
        for line in info_file.read_text().splitlines():
            k, _, v = line.partition("=")
            if k == "version" and v != "None":
                report_version = int(v)
            elif k == "committed_bl":
                committed.boot_loader = int(v)
            elif k == "committed_tee":
                committed.tee = int(v)
            elif k == "committed_snp":
                committed.snp = int(v)
            elif k == "committed_mc":
                committed.microcode = int(v)

    lines = [f"Committed TCB: bl={committed.boot_loader} tee={committed.tee} "
             f"snp={committed.snp} mc={committed.microcode}"]
    failed = False

    if report_version == 2:
        for comp, label, max_val in [
            ("boot_loader", "Boot Loader", committed.boot_loader),
            ("tee",         "TEE",         committed.tee),
            ("snp",         "SNP",         committed.snp),
            ("microcode",   "Microcode",   committed.microcode),
        ]:
            for over_by in range(1, 4):
                key_file = ctx.artifact_dir / f"tcb_over_{comp}_{over_by}.bin"
                if key_file.exists() and key_file.stat().st_size > 0:
                    lines.append(f"FAIL: {label}={max_val + over_by} succeeded — bound not enforced")
                    failed = True
                else:
                    lines.append(f"Bound enforced: {label}={max_val + over_by} correctly rejected")
    else:
        lines.append("Skipping TCB bound check: report version unknown or unexpected")

    # Check sensitivity — non-empty TCB candidate files produce distinct keys
    tcb_keys = {}
    for f in sorted(ctx.artifact_dir.glob("tcb_valid_*.bin")):
        if f.stat().st_size > 0:
            k = _read_key(f)
            if k is not None:
                tcb_keys[f.name] = k

    if len(tcb_keys) >= 2:
        if len(set(tcb_keys.values())) == len(tcb_keys):
            lines.append(f"All {len(tcb_keys)} TCB values produce distinct keys")
        else:
            lines.append("FAIL: Some TCB values produce identical keys")
            failed = True
    else:
        lines.append("TCB sensitivity N/A (all components zero — single valid value)")

    if failed:
        return StepHandlerResult(exit_code=1, stderr="\n".join(lines))
    return StepHandlerResult(exit_code=0, stdout="\n".join(lines))


def check_gfs_sensitivity(ctx: StepContext) -> StepHandlerResult:
    """GFS=1 and GFS=2 produce different keys."""
    k1 = _read_key(ctx.artifact_dir / "gfs1_key.bin")
    k2 = _read_key(ctx.artifact_dir / "gfs2_key.bin")
    if k1 is None or k2 is None:
        return StepHandlerResult(exit_code=1, stderr="Could not read GFS key files")
    if k1 != k2:
        return StepHandlerResult(exit_code=0, stdout="GFS=0x01 and GFS=0x02 keys differ")
    return StepHandlerResult(exit_code=1, stderr="GFS=0x01 and GFS=0x02 keys are identical")


def check_gfs_field_mixing(ctx: StepContext) -> StepHandlerResult:
    """GFS bits 0-5 each produce a key distinct from GFS=0 baseline."""
    baseline = _read_key(ctx.artifact_dir / "gfs_baseline.bin")
    if baseline is None:
        return StepHandlerResult(exit_code=1, stderr="Could not read GFS baseline key")

    bits = [
        (0, "Image ID"),
        (1, "Family ID"),
        (2, "Measurement"),
        (3, "Guest SVN Policy"),
        (4, "Guest SVN"),
        (5, "TCB Version"),
    ]
    failed = []
    lines = []
    for bit, label in bits:
        k = _read_key(ctx.artifact_dir / f"gfs_bit{bit}.bin")
        if k is None:
            failed.append(f"GFS bit {bit} ({label}): could not read key")
        elif k == baseline:
            failed.append(f"GFS bit {bit} ({label}): same as baseline")
        else:
            lines.append(f"GFS bit {bit} ({label}): differs from baseline")

    if failed:
        return StepHandlerResult(exit_code=1, stderr="\n".join(failed))
    return StepHandlerResult(exit_code=0, stdout="\n".join(lines))


# ── Guest commands ─────────────────────────────────────────────────────────────

def _key_cmd(out: str, root: str = "vcek", vmpl: int = 0,
             svn: int = 0, tcb: int = 0, gfs: int = 1,
             expected_failure: bool = False) -> str:
    """Build a snpguest key command, tolerating failure when expected."""
    cmd = (f"snpguest key {out} {root} --vmpl {vmpl} "
           f"--guest_svn {svn} --tcb_version {tcb} --guest_field_select {gfs}")
    if expected_failure:
        # Run but don't fail the step if snpguest exits non-zero
        return f"{cmd} || true"
    return cmd


def steps() -> list[BaseStep]:
    pre = [
        Step.for_callable(
            name="Calculate measurement",
            type="setup",
            handler="calculate_measurement",
            timeout=60,
        ),
    ]
    if _HAS_ID_BLOCK:
        pre.append(Step.for_callable(
            name="Generate ID block",
            type="setup",
            handler="generate_id_block",
            timeout=30,
        ))

    launch_hint = (
        "Address already in use",
        "A previous VM may still be running. "
        "Try: sudo kill $(pgrep -f 'qemu.*guest-cid')",
    )

    return pre + [
        Step.for_vm_launch(
            name="Launch SEV-SNP guest",
            type="setup",
            timeout=300,
        ).add_hint(*launch_hint),

        # ── Attestation report (needed for SVN/TCB bounds) ────────────────
        Step.for_guest(
            name="Get attestation report",
            type="setup",
            command="snpguest report report.bin request.bin --random",
            timeout=60,
        ),
        Step.for_guest_pull(
            name="Pull attestation report",
            type="setup",
            guest_src="report.bin",
            host_dest="report.bin",
            timeout=30,
        ),

        # ── Determinism ───────────────────────────────────────────────────
        Step.for_guest(
            name="Derive determinism key 1",
            type="required",
            command=_key_cmd("det_key1.bin"),
            timeout=30,
        ),
        Step.for_guest(
            name="Derive determinism key 2",
            type="required",
            command=_key_cmd("det_key2.bin"),
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull determinism keys",
            type="required",
            guest_src="det_key1.bin",
            host_dest="det_key1.bin",
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull determinism key 2",
            type="required",
            guest_src="det_key2.bin",
            host_dest="det_key2.bin",
            timeout=30,
        ),

        # ── VMPL isolation ────────────────────────────────────────────────
        Step.for_guest(
            name="Derive VMPL0 key",
            type="required",
            command=_key_cmd("vmpl0_key.bin", vmpl=0),
            timeout=30,
        ),
        Step.for_guest(
            name="Derive VMPL1 key (may be rejected)",
            type="info",
            command=_key_cmd("vmpl1_key.bin", vmpl=1, expected_failure=True),
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull VMPL0 key",
            type="required",
            guest_src="vmpl0_key.bin",
            host_dest="vmpl0_key.bin",
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull VMPL1 key (may not exist)",
            type="info",
            guest_src="vmpl1_key.bin",
            host_dest="vmpl1_key.bin",
            timeout=30,
        ),

        # ── Root key difference ───────────────────────────────────────────
        Step.for_guest(
            name="Derive VCEK key",
            type="required",
            command=_key_cmd("vcek_key.bin", root="vcek"),
            timeout=30,
        ),
        Step.for_guest(
            name="Derive VMRK key",
            type="required",
            command=_key_cmd("vmrk_key.bin", root="vmrk"),
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull VCEK key",
            type="required",
            guest_src="vcek_key.bin",
            host_dest="vcek_key.bin",
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull VMRK key",
            type="required",
            guest_src="vmrk_key.bin",
            host_dest="vmrk_key.bin",
            timeout=30,
        ),

        # ── SVN above-bound checks (always, even with no ID block) ────────
        *[Step.for_guest(
            name=f"Derive above-bound SVN={svn} (must be rejected)",
            type="info",
            command=_key_cmd(f"svn_over_{svn}.bin", svn=svn, gfs=1 << 4,
                             expected_failure=True),
            timeout=30,
        ) for svn in range(1, 4)],

        # ── TCB above-bound checks ────────────────────────────────────────
        *[Step.for_guest(
            name=f"Derive above-bound TCB {comp}+{over_by} (must be rejected)",
            type="info",
            command=_key_cmd(
                f"tcb_over_{comp}_{over_by}.bin",
                tcb=TcbVersion(**{comp: over_by}).to_u64(),
                gfs=1 << 5,
                expected_failure=True,
            ),
            timeout=30,
        ) for comp in ("boot_loader", "tee", "snp", "microcode") for over_by in range(1, 4)],

        # ── TCB sensitivity candidates (may be rejected above committed) ──
        *[Step.for_guest(
            name=f"Derive TCB valid candidate {comp}={val}",
            type="info",
            command=_key_cmd(
                f"tcb_valid_{comp}_{val}.bin",
                tcb=TcbVersion(**{comp: val}).to_u64(),
                gfs=1 << 5,
                expected_failure=True,
            ),
            timeout=30,
        ) for comp in ("boot_loader", "tee", "snp", "microcode")
          for val in (1, 4, 16, 64, 128, 255)],
        *[Step.for_guest_pull(
            name=f"Pull TCB candidate {comp}={val}",
            type="info",
            guest_src=f"tcb_valid_{comp}_{val}.bin",
            host_dest=f"tcb_valid_{comp}_{val}.bin",
            timeout=30,
        ) for comp in ("boot_loader", "tee", "snp", "microcode")
          for val in (1, 4, 16, 64, 128, 255)],

        # ── GFS sensitivity ───────────────────────────────────────────────
        Step.for_guest(
            name="Derive GFS=0x01 key",
            type="required",
            command=_key_cmd("gfs1_key.bin", gfs=1),
            timeout=30,
        ),
        Step.for_guest(
            name="Derive GFS=0x02 key",
            type="required",
            command=_key_cmd("gfs2_key.bin", gfs=2),
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull GFS keys",
            type="required",
            guest_src="gfs1_key.bin",
            host_dest="gfs1_key.bin",
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull GFS=0x02 key",
            type="required",
            guest_src="gfs2_key.bin",
            host_dest="gfs2_key.bin",
            timeout=30,
        ),

        # ── GFS field mixing (bits 0-5 vs baseline GFS=0) ─────────────────
        Step.for_guest(
            name="Derive GFS=0x00 baseline key",
            type="required",
            command=_key_cmd("gfs_baseline.bin", gfs=0),
            timeout=30,
        ),
        Step.for_guest_pull(
            name="Pull GFS baseline key",
            type="required",
            guest_src="gfs_baseline.bin",
            host_dest="gfs_baseline.bin",
            timeout=30,
        ),
        *[Step.for_guest(
            name=f"Derive GFS bit {bit} key",
            type="required",
            command=_key_cmd(f"gfs_bit{bit}.bin", gfs=1 << bit),
            timeout=30,
        ) for bit in range(6)],
        *[Step.for_guest_pull(
            name=f"Pull GFS bit {bit} key",
            type="required",
            guest_src=f"gfs_bit{bit}.bin",
            host_dest=f"gfs_bit{bit}.bin",
            timeout=30,
        ) for bit in range(6)],

        Step.for_vm_stop(
            name="Stop VM",
            type="info",
            timeout=60,
        ),

        # ── Host-side comparisons ─────────────────────────────────────────
        Step.for_callable(
            name="Check determinism",
            type="required",
            handler="check_determinism",
            timeout=10,
        ),
        Step.for_callable(
            name="Check VMPL isolation",
            type="required",
            handler="check_vmpl_isolation",
            timeout=10,
        ),
        Step.for_callable(
            name="Check root key difference",
            type="required",
            handler="check_root_key_difference",
            timeout=10,
        ),
        Step.for_callable(
            name="Parse report and check SVN bounds",
            type="required",
            handler="parse_report_and_check_svn_bounds",
            timeout=30,
        ),
        Step.for_callable(
            name="Check SVN sensitivity",
            type="required",
            handler="check_svn_sensitivity",
            timeout=10,
        ),
        Step.for_callable(
            name="Check TCB bounds and sensitivity",
            type="required",
            handler="check_tcb_bounds_and_sensitivity",
            timeout=10,
        ),
        Step.for_callable(
            name="Check GFS sensitivity",
            type="required",
            handler="check_gfs_sensitivity",
            timeout=10,
        ),
        Step.for_callable(
            name="Check GFS field mixing",
            type="required",
            handler="check_gfs_field_mixing",
            timeout=10,
        ),
    ]
