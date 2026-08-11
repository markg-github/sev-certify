"""id_block_test: Verify ID block acceptance, report field binding, and rejection.

Positive path: launch an SEV-SNP guest with a valid ID block, fetch the
attestation report, and verify that the hardware report reflects the ID block
fields (guest_svn, policy, family_id, image_id).

Negative path: attempt three launches that must fail:
  1. ID block with a corrupted measurement (digest mismatch)
  2. Policy incompatible with the platform (SMT=0 on an SMT-active host)
  3. Impossibly high ABI major version (ABI_MAJOR=255)
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from sev_verify.id_block import (
    DEFAULT_FAMILY_ID,
    DEFAULT_GUEST_SVN,
    DEFAULT_IMAGE_ID,
    DEFAULT_POLICY,
    calculate_measurement,
    generate_id_block,
)
from sev_verify.models import BaseStep, Step, StepContext, StepHandlerResult
from sev_verify.vm_profile import VMProfile

vm_profile = VMProfile(
    image_path="",
    memory_mb=2048,
)


# ── Report parsing (snpguest display report) ──────────────────────────────────


def _parse_hex_line(text: str) -> bytes:
    """Parse space-separated hex bytes like '73 65 76 ...' into bytes."""
    return bytes(int(b, 16) for b in text.strip().split())


def _parse_report_field(display_output: str, pattern: str) -> str | None:
    m = re.search(pattern, display_output, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def verify_id_block_fields(ctx: StepContext) -> StepHandlerResult:
    """Parse the attestation report and compare ID block fields to expected values."""
    report_file = ctx.artifact_dir / "report.bin"
    if not report_file.exists():
        return StepHandlerResult(exit_code=1, stderr="report.bin not found")

    result = subprocess.run(
        ["snpguest", "display", "report", str(report_file)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return StepHandlerResult(
            exit_code=1,
            stderr=f"snpguest display report failed:\n{result.stderr}",
        )

    output = result.stdout
    errors = []

    family_id = os.environ.get("ID_BLOCK_FAMILY_ID", DEFAULT_FAMILY_ID)
    image_id = os.environ.get("ID_BLOCK_IMAGE_ID", DEFAULT_IMAGE_ID)
    guest_svn = int(os.environ.get("ID_BLOCK_GUEST_SVN", DEFAULT_GUEST_SVN))
    policy = os.environ.get("ID_BLOCK_POLICY", DEFAULT_POLICY)
    policy_int = int(policy, 0)

    # Guest SVN
    svn_str = _parse_report_field(output, r"Guest\s+SVN\s*:\s*(0x[0-9a-fA-F]+|\d+)")
    if svn_str is not None:
        report_svn = int(svn_str, 0)
        if report_svn != guest_svn:
            errors.append(f"guest_svn: expected {guest_svn}, got {report_svn}")
    else:
        errors.append("guest_svn: not found in report")

    # Policy — snpguest prints "Guest Policy (0x<hex>):"
    policy_str = _parse_report_field(output, r"Guest\s+Policy\s*\(\s*(0x[0-9a-fA-F]+)\s*\)")
    if policy_str is not None:
        report_policy = int(policy_str, 16)
        if report_policy != policy_int:
            errors.append(f"policy: expected {hex(policy_int)}, got {hex(report_policy)}")
    else:
        errors.append("policy: not found in report")

    # Family ID — snpguest prints hex bytes on a line after "Family ID:"
    fam_match = re.search(
        r"Family\s+ID\s*:\s*\n\s*((?:[0-9a-fA-F]{2}\s*)+)",
        output, re.IGNORECASE,
    )
    if fam_match:
        report_family = _parse_hex_line(fam_match.group(1))
        expected_family = family_id.encode("ascii").ljust(16, b"\x00")
        if report_family != expected_family:
            errors.append(
                f"family_id: expected {expected_family.hex()}, got {report_family.hex()}"
            )
    else:
        errors.append("family_id: not found in report")

    # Image ID
    img_match = re.search(
        r"Image\s+ID\s*:\s*\n\s*((?:[0-9a-fA-F]{2}\s*)+)",
        output, re.IGNORECASE,
    )
    if img_match:
        report_image = _parse_hex_line(img_match.group(1))
        expected_image = image_id.encode("ascii").ljust(16, b"\x00")
        if report_image != expected_image:
            errors.append(
                f"image_id: expected {expected_image.hex()}, got {report_image.hex()}"
            )
    else:
        errors.append("image_id: not found in report")

    if errors:
        return StepHandlerResult(exit_code=1, stderr="\n".join(errors))
    return StepHandlerResult(
        exit_code=0,
        stdout=(
            f"All ID block fields match: svn={guest_svn} policy={hex(policy_int)} "
            f"family_id={family_id!r} image_id={image_id!r}"
        ),
    )


# ── Negative-test profile mutation helpers ────────────────────────────────────


def _regenerate_id_block(
    ctx: StepContext, measurement: str, policy: str,
) -> StepHandlerResult:
    """Generate a fresh ID block with the given measurement and policy, update ctx.profile."""
    family_id = os.environ.get("ID_BLOCK_FAMILY_ID", DEFAULT_FAMILY_ID)
    image_id = os.environ.get("ID_BLOCK_IMAGE_ID", DEFAULT_IMAGE_ID)
    guest_svn = os.environ.get("ID_BLOCK_GUEST_SVN", DEFAULT_GUEST_SVN)

    id_key = ec.generate_private_key(ec.SECP384R1())
    auth_key = ec.generate_private_key(ec.SECP384R1())

    id_block_file = ctx.artifact_dir / "neg-id-block.b64"
    id_auth_file = ctx.artifact_dir / "neg-id-auth.b64"

    with tempfile.TemporaryDirectory() as tmpdir:
        id_key_path = Path(tmpdir) / "id-key.pem"
        auth_key_path = Path(tmpdir) / "auth-key.pem"
        id_key_path.write_bytes(
            id_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        )
        auth_key_path.write_bytes(
            auth_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        )

        result = subprocess.run(
            [
                "snpguest", "generate", "id-block",
                str(id_key_path), str(auth_key_path),
                measurement,
                "--family-id", family_id,
                "--image-id", image_id,
                "--svn", guest_svn,
                "--policy", policy,
                "--id-file", str(id_block_file),
                "--auth-file", str(id_auth_file),
            ],
            capture_output=True, text=True, check=False,
        )

    if result.returncode != 0:
        return StepHandlerResult(
            exit_code=1,
            stderr=f"snpguest generate id-block failed:\n{result.stderr}",
        )

    ctx.profile = replace(
        ctx.profile,
        id_block=id_block_file.read_text().strip(),
        id_auth=id_auth_file.read_text().strip(),
        policy=policy,
    )
    return StepHandlerResult(exit_code=0)


def set_bad_measurement(ctx: StepContext) -> StepHandlerResult:
    """Regenerate the ID block with a corrupted measurement to cause digest mismatch."""
    measurement_file = ctx.artifact_dir / "guest_measurement.txt"
    if not measurement_file.exists():
        return StepHandlerResult(exit_code=1, stderr="guest_measurement.txt not found")

    real = measurement_file.read_text().strip()
    # Flip the first hex byte after any 0x prefix
    if real.lower().startswith("0x"):
        prefix, hex_body = real[:2], real[2:]
    else:
        prefix, hex_body = "", real
    flipped_byte = "00" if hex_body[:2].lower() != "00" else "ff"
    flipped = prefix + flipped_byte + hex_body[2:]

    policy = os.environ.get("ID_BLOCK_POLICY", DEFAULT_POLICY)
    hr = _regenerate_id_block(ctx, flipped, policy)
    if hr.exit_code != 0:
        return hr
    return StepHandlerResult(
        exit_code=0,
        stdout=f"Set bad measurement: {flipped[:18]}... (real: {real[:18]}...)",
    )


def set_incompatible_policy(ctx: StepContext) -> StepHandlerResult:
    """Regenerate the ID block with a policy the platform cannot satisfy.

    Checks whether SMT is active on the host.  If so, regenerates the ID block
    (and QEMU launch policy) with SMT=0 — the firmware must reject because the
    platform cannot guarantee single-threaded execution.
    """
    smt_path = Path("/sys/devices/system/cpu/smt/active")
    if not smt_path.exists():
        return StepHandlerResult(
            exit_code=1,
            stderr="Cannot determine SMT status: /sys/devices/system/cpu/smt/active not found",
        )
    smt_active = smt_path.read_text().strip() == "1"
    if not smt_active:
        return StepHandlerResult(
            exit_code=1,
            stderr="SMT is not active on this host; cannot test SMT policy incompatibility",
        )

    measurement_file = ctx.artifact_dir / "guest_measurement.txt"
    if not measurement_file.exists():
        return StepHandlerResult(exit_code=1, stderr="guest_measurement.txt not found")

    measurement = measurement_file.read_text().strip()
    policy = os.environ.get("ID_BLOCK_POLICY", DEFAULT_POLICY)
    policy_int = int(policy, 0)
    # Clear SMT bit (16) — guest demands no SMT, but host has SMT active
    incompatible_policy = hex(policy_int & ~(1 << 16))

    hr = _regenerate_id_block(ctx, measurement, incompatible_policy)
    if hr.exit_code != 0:
        return hr
    return StepHandlerResult(
        exit_code=0,
        stdout=f"Set incompatible policy {incompatible_policy} (SMT=0, host SMT active)",
    )


def set_bad_abi_version(ctx: StepContext) -> StepHandlerResult:
    """Regenerate the ID block with an impossibly high ABI major version.

    The policy's ABI_MAJOR field (bits 15:8) specifies the minimum firmware
    ABI version required.  Setting it to 255 guarantees the firmware cannot
    satisfy the requirement on any current platform.
    """
    measurement_file = ctx.artifact_dir / "guest_measurement.txt"
    if not measurement_file.exists():
        return StepHandlerResult(exit_code=1, stderr="guest_measurement.txt not found")

    measurement = measurement_file.read_text().strip()
    policy = os.environ.get("ID_BLOCK_POLICY", DEFAULT_POLICY)
    policy_int = int(policy, 0)
    # Set ABI_MAJOR (bits 15:8) to 255
    bad_policy = (policy_int & ~0xFF00) | (0xFF << 8)
    bad_policy_hex = hex(bad_policy)

    hr = _regenerate_id_block(ctx, measurement, bad_policy_hex)
    if hr.exit_code != 0:
        return hr
    return StepHandlerResult(
        exit_code=0,
        stdout=f"Set policy {bad_policy_hex} (ABI_MAJOR=255)",
    )


# ── Steps ─────────────────────────────────────────────────────────────────────


def steps() -> list[BaseStep]:
    return [
        # ── Positive: launch with valid ID block, verify report fields ──
        Step.for_callable(
            name="Calculate measurement",
            type="setup",
            handler="calculate_measurement",
            timeout=60,
        ),
        Step.for_callable(
            name="Generate ID block",
            type="setup",
            handler="generate_id_block",
            timeout=30,
        ),
        Step.for_vm_launch(
            name="Launch with valid ID block",
            type="setup",
            timeout=300,
        ).add_hint(
            "Address already in use",
            "A previous VM may still be running. "
            "Try: sudo kill $(pgrep -f 'qemu.*guest-cid')",
        ),
        Step.for_guest(
            name="Get attestation report",
            type="required",
            command="snpguest report report.bin request.bin --random",
            timeout=60,
        ),
        Step.for_guest_pull(
            name="Pull attestation report",
            type="required",
            guest_src="report.bin",
            host_dest="report.bin",
            timeout=120,
        ),
        Step.for_vm_stop(
            name="Stop VM",
            type="info",
            timeout=60,
        ),
        Step.for_callable(
            name="Verify ID block fields in report",
            type="required",
            handler="verify_id_block_fields",
            timeout=30,
        ),

        # ── Negative: bad measurement (digest mismatch) ──
        Step.for_callable(
            name="Set bad measurement in ID block",
            type="required",
            handler="set_bad_measurement",
            timeout=30,
        ),
        Step.for_vm_launch(
            name="Launch with bad measurement (expect rejection)",
            type="required",
            expected_result="exit_code:1",
            timeout=300,
        ),
        Step.for_vm_stop(
            name="Stop VM (after bad measurement)",
            type="info",
            timeout=60,
        ),

        # ── Negative: incompatible policy (SMT=0 on SMT-active host) ──
        Step.for_callable(
            name="Set incompatible policy (SMT)",
            type="required",
            handler="set_incompatible_policy",
            timeout=30,
        ),
        Step.for_vm_launch(
            name="Launch with SMT-incompatible policy (expect rejection)",
            type="required",
            expected_result="exit_code:1",
            timeout=300,
        ),
        Step.for_vm_stop(
            name="Stop VM (after SMT policy)",
            type="info",
            timeout=60,
        ),

        # ── Negative: impossible ABI version ──
        Step.for_callable(
            name="Set impossible ABI version",
            type="required",
            handler="set_bad_abi_version",
            timeout=30,
        ),
        Step.for_vm_launch(
            name="Launch with impossible ABI version (expect rejection)",
            type="required",
            expected_result="exit_code:1",
            timeout=300,
        ),
        Step.for_vm_stop(
            name="Stop VM (after ABI version)",
            type="info",
            timeout=60,
        ),
    ]
