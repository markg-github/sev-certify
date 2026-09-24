"""JSON and Markdown output writers for certification results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import CertificationResult, StepResult, TestResult


_RESULT_ICON = {
    "pass": ":white_check_mark:",
    "fail": ":x:",
    "error": ":boom:",
    "skip": ":fast_forward:",
}


def _group_tests_by_level(
    test_results: list[TestResult],
) -> tuple[dict[str, list[TestResult]], list[TestResult]]:
    """Group test results by level, separating unlabeled tests."""
    by_level: dict[str, list[TestResult]] = {}
    unlabeled: list[TestResult] = []
    for tr in test_results:
        if tr.test.level:
            by_level.setdefault(tr.test.level, []).append(tr)
        else:
            unlabeled.append(tr)
    return by_level, unlabeled


def _step_dict(sr: StepResult, *, test_passing: bool) -> dict[str, Any]:
    # A step whose findings ARE the point of the test (always_report_output)
    # keeps its output even when the enclosing test passes — otherwise a
    # step like a CPU survey's data capture would vanish silently on a
    # clean run, which is exactly the run that matters most for reporting.
    include_output = (not test_passing) or sr.step.always_report_output
    d: dict[str, Any] = {
        "name": sr.step.name,
        "type": sr.step.type,
        "kind": sr.step.kind,
        "result": sr.result,
    }
    if sr.step.kind == "callable" and sr.step.handler:
        d["handler"] = sr.step.handler
    if sr.duration_ms is not None:
        d["duration_ms"] = sr.duration_ms
    if include_output:
        if sr.stdout:
            d["stdout"] = sr.stdout
        if sr.stderr:
            d["stderr"] = sr.stderr
        if sr.exit_code is not None:
            d["exit_code"] = sr.exit_code
    return d


def _test_dict(tr: TestResult) -> dict[str, Any]:
    passing = tr.result == "pass"
    return {
        "name": tr.test.name,
        "description": tr.test.description,
        "scope": tr.test.scope,
        "level": tr.test.level or None,
        "result": tr.result,
        "started_at": tr.started_at,
        "completed_at": tr.completed_at,
        "steps": [
            _step_dict(sr, test_passing=passing)
            for sr in tr.step_results
        ],
    }


def write_json(
    cr: CertificationResult,
    certified_level: str | None,
    output_dir: Path,
    *,
    environment: dict[str, str | None] | None = None,
) -> Path:
    """Write machine-readable JSON certification result."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Group tests by level, preserving manifest ordering
    tests_by_level, unlabeled = _group_tests_by_level(cr.test_results)

    levels_out = []
    for level in cr.certification.all_levels:
        trs = tests_by_level.get(level, [])
        level_result = "pass" if all(t.result == "pass" for t in trs) else "fail"
        if not trs:
            level_result = "skip"
        levels_out.append({
            "level": level,
            "result": level_result,
            "tests": [_test_dict(tr) for tr in trs],
        })

    doc: dict[str, Any] = {
        "schema_version": "1.0",
        "certification_version": cr.certification.version,
        "description": cr.certification.description,
        "result": cr.result,
        "certified_level": certified_level,
        "max_certification_level": cr.certification.max_certification_level,
        "started_at": cr.started_at,
        "completed_at": cr.completed_at,
        "levels": levels_out,
    }

    if environment and "launch_digest" in environment:
        # A fact about the certified guest launch, not host tooling — kept
        # top-level (sibling to certified_level) rather than folded into
        # "environment" below, and excluded from that dict so it isn't
        # reported twice.
        doc["launch_digest"] = environment["launch_digest"]

    if environment:
        env_rest = {k: v for k, v in environment.items() if k != "launch_digest"}
        if env_rest:
            doc["environment"] = env_rest

    if unlabeled:
        doc["unlabeled_tests"] = [_test_dict(tr) for tr in unlabeled]

    dest = output_dir / f"cert-{cr.certification.version}.json"
    dest.write_text(json.dumps(doc, indent=2) + "\n")
    return dest


def _fmt_duration_md(ms: int | None) -> str:
    if ms is None:
        return ""
    if ms >= 1000:
        return f"{ms / 1000:.1f}s"
    return f"{ms}ms"


def _render_environment_lines(environment: dict[str, str | None]) -> list[str]:
    """Render the '## Environment' section body (bullet lines only, no heading)."""
    env_lines: list[str] = []
    if environment.get("host_cpu_model_name"):
        cpu_line = environment["host_cpu_model_name"]
        fms = (environment.get("host_cpu_family"), environment.get("host_cpu_model"),
               environment.get("host_cpu_stepping"))
        if all(v is not None for v in fms):
            cpu_line = f"{cpu_line} (family {fms[0]}, model {fms[1]}, stepping {fms[2]})"
        env_lines.append(f"- **Host CPU:** {cpu_line}")
    if environment.get("host_os_pretty_name"):
        env_lines.append(f"- **Host OS:** {environment['host_os_pretty_name']}")
    elif environment.get("host_os_name"):
        host_os = environment["host_os_name"]
        if environment.get("host_os_release"):
            host_os = f"{host_os} {environment['host_os_release']}"
        env_lines.append(f"- **Host OS:** {host_os}")
    if environment.get("kernel_version"):
        env_lines.append(f"- **Host kernel:** {environment['kernel_version']}")
    if environment.get("guest_os_pretty_name"):
        env_lines.append(f"- **Guest OS:** {environment['guest_os_pretty_name']}")
    elif environment.get("guest_os_name"):
        guest_os = environment["guest_os_name"]
        if environment.get("guest_os_release"):
            guest_os = f"{guest_os} {environment['guest_os_release']}"
        env_lines.append(f"- **Guest OS:** {guest_os}")
    if environment.get("qemu_version"):
        env_lines.append(f"- **QEMU:** {environment['qemu_version']}")
    elif environment.get("qemu_binary"):
        env_lines.append(f"- **QEMU:** {environment['qemu_binary']}")
    if environment.get("ovmf_version"):
        env_lines.append(f"- **OVMF:** {environment['ovmf_version']}")
    elif environment.get("ovmf_path"):
        env_lines.append(f"- **OVMF:** {environment['ovmf_path']}")
    return env_lines


def _render_cert_section(
    cr: CertificationResult,
    certified_level: str | None,
    *,
    with_subheader: bool,
) -> list[str]:
    """Render one certification's level tables + details section.

    ``with_subheader`` adds a "## <description>" heading plus this
    certification's own certified/max level lines — used by the combined
    report, where multiple certifications share one document and each needs
    to say which level *it* achieved. write_markdown (single-certification)
    passes False since that information is already in its own top header.
    """
    lines: list[str] = []
    w = lines.append

    if with_subheader:
        w(f"## {cr.certification.description}")
        w("")
        w(f"**Certified level:** {certified_level or 'none'}")
        if cr.certification.max_certification_level:
            w(f"**Max certification level:** {cr.certification.max_certification_level}")
        w("")

    tests_by_level, unlabeled = _group_tests_by_level(cr.test_results)

    # Tests worth expanding below: failures need it to say why, and a
    # passing test with an always_report_output step needs it too — that
    # step's findings are otherwise invisible (see _step_dict).
    detail_tests: list[TestResult] = []

    def _needs_detail(tr: TestResult) -> bool:
        return tr.result != "pass" or any(
            sr.step.always_report_output for sr in tr.step_results
        )

    for level in cr.certification.all_levels:
        trs = tests_by_level.get(level, [])
        if not trs:
            continue
        w(f"### Level {level}")
        w("")
        w("| Test | Description | Result |")
        w("|------|-------------|--------|")
        for tr in trs:
            icon = _RESULT_ICON.get(tr.result, tr.result)
            w(f"| {tr.test.name} | {tr.test.description} | {icon} |")
            if _needs_detail(tr):
                detail_tests.append(tr)
        w("")

    if unlabeled:
        w("### Other Tests")
        w("")
        w("| Test | Description | Result |")
        w("|------|-------------|--------|")
        for tr in unlabeled:
            icon = _RESULT_ICON.get(tr.result, tr.result)
            w(f"| {tr.test.name} | {tr.test.description} | {icon} |")
            if _needs_detail(tr):
                detail_tests.append(tr)
        w("")

    if detail_tests:
        w("### Details")
        w("")
        for tr in detail_tests:
            w("<details>")
            w(f"<summary>{tr.test.name} ({tr.result})</summary>")
            w("")
            for sr in tr.step_results:
                if sr.result in ("pass", "skip") and not sr.step.always_report_output:
                    continue
                w(f"**{sr.step.name}** — {sr.result}")
                duration = _fmt_duration_md(sr.duration_ms)
                if duration:
                    w(f"Duration: {duration}")
                if sr.stderr:
                    w("```")
                    w(sr.stderr.rstrip())
                    w("```")
                elif sr.stdout:
                    w("```")
                    w(sr.stdout.rstrip())
                    w("```")
            w("")
            w("</details>")
            w("")

    return lines


def write_markdown(
    cr: CertificationResult,
    certified_level: str | None,
    output_dir: Path,
    *,
    environment: dict[str, str | None] | None = None,
) -> Path:
    """Write human-readable Markdown certification report."""
    output_dir.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    w = lines.append

    if certified_level:
        w(f"# Achieved Certification Level {certified_level}")
    else:
        w("# Failed to Achieve a Certification Level")
    w("")
    w(f"**Certified level:** {certified_level or 'none'}")
    if cr.certification.max_certification_level:
        w(f"**Max certification level:** {cr.certification.max_certification_level}")
    if environment and "launch_digest" in environment:
        digest = environment["launch_digest"]
        w(f"**Launch digest:** {f'0x{digest}' if digest else 'unavailable'}")
    w(f"**Started:** {cr.started_at}")
    w(f"**Completed:** {cr.completed_at}")
    w("")

    if environment:
        env_lines = _render_environment_lines(environment)
        if env_lines:
            w("## Environment")
            w("")
            for el in env_lines:
                w(el)
            w("")

    lines.extend(_render_cert_section(cr, certified_level, with_subheader=False))

    dest = output_dir / f"cert-{cr.certification.version}.md"
    dest.write_text("\n".join(lines) + "\n")
    return dest


def write_combined_json(
    results: list[tuple[CertificationResult, str | None]],
    output_dir: Path,
    *,
    environment: dict[str, str | None] | None = None,
) -> Path:
    """Write one JSON document covering every certification run this invocation.

    dispatch only accepts one ``beacon report`` call per boot (confirmed on
    real hardware — a second call in the same boot fails with "no dispatch
    services found"), so every manifest that ran must land in a single file.
    Each entry under "certifications" has the same shape write_json's single
    document has at its top level; environment/launch_digest are hoisted out
    since they're constant across every manifest in one run.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    certifications: list[dict[str, Any]] = []
    for cr, certified_level in results:
        tests_by_level, unlabeled = _group_tests_by_level(cr.test_results)
        levels_out = []
        for level in cr.certification.all_levels:
            trs = tests_by_level.get(level, [])
            level_result = "pass" if all(t.result == "pass" for t in trs) else "fail"
            if not trs:
                level_result = "skip"
            levels_out.append({
                "level": level,
                "result": level_result,
                "tests": [_test_dict(tr) for tr in trs],
            })

        entry: dict[str, Any] = {
            "certification_version": cr.certification.version,
            "description": cr.certification.description,
            "result": cr.result,
            "certified_level": certified_level,
            "max_certification_level": cr.certification.max_certification_level,
            "started_at": cr.started_at,
            "completed_at": cr.completed_at,
            "levels": levels_out,
        }
        if unlabeled:
            entry["unlabeled_tests"] = [_test_dict(tr) for tr in unlabeled]
        certifications.append(entry)

    started = [cr.started_at for cr, _ in results if cr.started_at]
    completed = [cr.completed_at for cr, _ in results if cr.completed_at]

    doc: dict[str, Any] = {
        "schema_version": "1.0",
        "certifications": certifications,
        "started_at": min(started) if started else None,
        "completed_at": max(completed) if completed else None,
    }

    if environment and "launch_digest" in environment:
        doc["launch_digest"] = environment["launch_digest"]
    if environment:
        env_rest = {k: v for k, v in environment.items() if k != "launch_digest"}
        if env_rest:
            doc["environment"] = env_rest

    dest = output_dir / "cert-combined.json"
    dest.write_text(json.dumps(doc, indent=2) + "\n")
    return dest


def write_combined_markdown(
    results: list[tuple[CertificationResult, str | None]],
    output_dir: Path,
    *,
    environment: dict[str, str | None] | None = None,
) -> Path:
    """Write one Markdown document covering every certification run this invocation.

    See write_combined_json for why this must be a single document. Does not
    embed the raw sev-verify.log — that file doesn't exist yet while this
    process is still running (an outer shell tees it), so appending a
    conditionally-trimmed tail on failure is beacon-report.sh's job, same as
    it always has been; it just now reads this one file instead of looping.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    w = lines.append

    w("# SEV Certification Results")
    w("")
    if environment and "launch_digest" in environment:
        digest = environment["launch_digest"]
        w(f"**Launch digest:** {f'0x{digest}' if digest else 'unavailable'}")
    w("")

    if environment:
        env_lines = _render_environment_lines(environment)
        if env_lines:
            w("## Environment")
            w("")
            for el in env_lines:
                w(el)
            w("")

    for cr, certified_level in results:
        lines.extend(_render_cert_section(cr, certified_level, with_subheader=True))

    dest = output_dir / "cert-combined.md"
    dest.write_text("\n".join(lines) + "\n")
    return dest
