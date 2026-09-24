"""cpu_profile_survey: launch the guest under several QEMU CPU profiles and
record the real, hardware-measured launch digest, guest CPUID, and QEMU
command line for each.

This is reconnaissance for the host-passthrough experiment on
exp/passthrough-launch-digest: before relying on ``-cpu host``, we want to
see, on real hardware, how the actual attestation-report MEASUREMENT and
guest-visible CPUID change (or don't) across a few fixed named profiles and
true passthrough.

PROFILES is deliberately Milan-appropriate: QEMU/KVM will not let a guest CPU
model expose features the physical silicon lacks, so on Milan-generation
hardware only Milan-generation-or-older named profiles are valid (EPYC-v4,
EPYC-Milan-v2, EPYC-Rome-v3, ...). Adjust the list (or make it host-aware)
before running this on newer silicon.

Each profile's block is independent: "Launch" is type="required" rather than
"setup" so one profile failing to launch (e.g. an incompatible CPU model)
does not skip the remaining profiles. "Capture data" is a single callable
that checks whether the launch actually succeeded before touching the guest,
so a failed launch produces one clear message instead of a cascade of vsock
errors against a guest that never came up.
"""

from __future__ import annotations

from dataclasses import replace

from sev_verify import attestation_report
from sev_verify.guest_vsock import GuestVsockError, fetch_guest_file_bytes, run_guest_command
from sev_verify.models import BaseStep, Step, StepContext, StepHandlerResult
from sev_verify.vm_profile import VMProfile

vm_profile = VMProfile(
    image_path="",
    memory_mb=2048,
)

#: (slug, QEMU -cpu value). See module docstring for the Milan-only caveat.
#: "host" is CPU passthrough, not a named model.
PROFILES: tuple[tuple[str, str], ...] = (
    ("epyc-v4", "EPYC-v4"),
    ("epyc-milan-v2", "EPYC-Milan-v2"),
    ("epyc-rome-v3", "EPYC-Rome-v3"),
    ("host-passthrough", "host"),
)

#: Guest-visible CPUID, read via /proc/cpuinfo — this is what the guest OS
#: actually sees, which is what would catch QEMU silently downgrading an
#: incompatible profile. Not to be confused with the attestation report's own
#: CPUID field, which always reflects the physical host regardless of -cpu.
#:
#: Four independent `grep -m1` calls, not one call with an alternation: a
#: single -m1 across all four patterns stops at the first matching LINE in
#: the whole file, which is always "cpu family" (it appears earliest in
#: /proc/cpuinfo) — silently dropping model/stepping/model name every time.
#: The guest agent runs this via shell=True, so `;` works.
_GUEST_CPUID_COMMAND = (
    "grep -m1 '^cpu family' /proc/cpuinfo; "
    "grep -m1 '^model[[:space:]]*:' /proc/cpuinfo; "
    "grep -m1 '^stepping' /proc/cpuinfo; "
    "grep -m1 '^model name' /proc/cpuinfo"
)


def _set_cpu_profile(ctx: StepContext, cpu_model: str) -> StepHandlerResult:
    ctx.profile = replace(ctx.profile, cpu_model=cpu_model)
    return StepHandlerResult(exit_code=0, stdout=f"cpu_model={cpu_model}")


def _make_set_profile_handler(cpu_model: str):
    def handler(ctx: StepContext) -> StepHandlerResult:
        return _set_cpu_profile(ctx, cpu_model)
    return handler


# One named handler per profile — run_callable_step looks handlers up by name
# on the module (ctx.module.<step.handler>), so each Step must reference a
# real, distinct module-level function. Built here instead of by hand to keep
# PROFILES the single source of truth.
for _slug, _cpu_model in PROFILES:
    globals()[f"set_profile_{_slug.replace('-', '_')}"] = _make_set_profile_handler(_cpu_model)


def capture_profile_data(ctx: StepContext) -> StepHandlerResult:
    """Record the actual HW measurement, guest CPUID, and QEMU command line.

    Guarded on ctx.launch: a failed launch (bad CPU model, etc.) produces one
    clear "launch: FAILED" line instead of a cascade of vsock errors from
    trying to talk to a guest that never came up.

    Written to a per-profile .txt artifact as well as returned in stdout:
    write_json/write_markdown only include step stdout for a *failing* test
    (see output.py's _step_dict), so a step that passes — which is every
    step here on a good run — would otherwise leave this data completely
    unrecoverable from the standard cert/GitHub-issue output.
    """
    cpu_model = ctx.profile.cpu_model
    safe_name = cpu_model.replace(" ", "_")
    lines = [f"cpu_model={cpu_model}"]

    launch = ctx.launch
    if launch is None or not launch.ok:
        reason = launch.message if launch is not None else "no launch attempt recorded"
        lines.append(f"launch: FAILED — {reason}")
        text = "\n".join(lines)
        (ctx.artifact_dir / f"profile_data_{safe_name}.txt").write_text(text + "\n")
        return StepHandlerResult(exit_code=0, stdout=text)

    lines.append(f"qemu_command={launch.command_line}")

    try:
        gcr = run_guest_command(ctx.profile, _GUEST_CPUID_COMMAND, timeout=15)
        guest_cpuid = gcr.stdout.strip() if gcr.ok else f"(command failed: {gcr.stderr.strip()})"
    except GuestVsockError as exc:
        guest_cpuid = f"(unavailable: {exc})"
    lines.append(f"guest_cpuid:\n{guest_cpuid}")

    try:
        run_guest_command(
            ctx.profile, "snpguest report report.bin request.bin --random", timeout=60,
        )
        data = fetch_guest_file_bytes(ctx.profile, "report.bin", timeout=30)
        report_path = ctx.artifact_dir / f"report_{safe_name}.bin"
        report_path.write_bytes(data)
        report = attestation_report.read(
            report_path, generation=attestation_report.host_generation(),
        )
        lines.append(f"actual_measurement=0x{report.measurement.hex()}")
        lines.append(f"report_cpuid={report.cpuid} report_generation={report.generation}")
    except (GuestVsockError, attestation_report.ReportError) as exc:
        lines.append(f"(attestation report unavailable: {exc})")

    text = "\n".join(lines)
    (ctx.artifact_dir / f"profile_data_{safe_name}.txt").write_text(text + "\n")
    return StepHandlerResult(exit_code=0, stdout=text)


def steps() -> list[BaseStep]:
    steps_list: list[BaseStep] = []
    for slug, _cpu_model in PROFILES:
        handler_name = f"set_profile_{slug.replace('-', '_')}"
        steps_list += [
            Step.for_callable(
                name=f"Set CPU profile: {slug}",
                type="setup",
                handler=handler_name,
                timeout=10,
            ),
            Step.for_vm_launch(
                name=f"Launch ({slug})",
                type="required",
                timeout=300,
            ).add_hint(
                "Address already in use",
                "A previous VM may still be running. "
                "Try: sudo kill $(pgrep -f 'qemu.*guest-cid')",
            ),
            Step.for_callable(
                name=f"Capture data ({slug})",
                type="info",
                handler="capture_profile_data",
                timeout=90,
            ),
            Step.for_vm_stop(
                name=f"Stop VM ({slug})",
                type="info",
                timeout=60,
            ),
        ]
    return steps_list
