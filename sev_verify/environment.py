"""Detect host environment versions (QEMU, kernel, OVMF, OS) for reporting."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess

from .os_info import get_host_os_info


def _get_qemu_version(binary: str) -> str | None:
    """Run ``<binary> --version`` and parse the version string."""
    resolved = shutil.which(binary)
    if not resolved:
        return None
    try:
        proc = subprocess.run(
            [resolved, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        first_line = proc.stdout.split("\n", 1)[0]
        prefix = "QEMU emulator version "
        if first_line.startswith(prefix):
            return first_line[len(prefix):]
        return None
    except Exception:
        return None


def _get_kernel_version() -> str | None:
    """Return the running kernel release string."""
    try:
        return platform.release()
    except Exception:
        return None


def _get_ovmf_version(path: str) -> str | None:
    """Try dpkg then rpm to find the package version owning *path*."""
    if not os.path.exists(path):
        return None

    # dpkg -S /path -> "package: /path"
    try:
        proc = subprocess.run(
            ["dpkg", "-S", path],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            pkg = proc.stdout.strip().split(":", 1)[0]
            info = subprocess.run(
                ["dpkg", "-s", pkg],
                capture_output=True, text=True, timeout=5,
            )
            for line in info.stdout.splitlines():
                if line.startswith("Version:"):
                    version = line.split(":", 1)[1].strip()
                    return f"{version} ({pkg})"
    except Exception:
        pass

    # rpm -qf /path -> "package-version"
    try:
        proc = subprocess.run(
            ["rpm", "-qf", path],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass

    return None


def _get_host_cpuid() -> dict[str, str | None]:
    """Read host CPU family/model/stepping and identifying strings from /proc/cpuinfo.

    Family/model/stepping decide the TCB_VERSION byte layout used elsewhere
    (see attestation_report.py); "model name" is only for human identification
    in reports and isn't parsed by anything.
    """
    fields: dict[str, str | None] = {
        "host_cpu_family": None,
        "host_cpu_model": None,
        "host_cpu_stepping": None,
        "host_cpu_model_name": None,
    }
    key_to_field = {
        "cpu family": "host_cpu_family",
        "model": "host_cpu_model",
        "stepping": "host_cpu_stepping",
        "model name": "host_cpu_model_name",
    }
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                key, _, value = line.partition(":")
                field_name = key_to_field.get(key.strip())
                if field_name and fields[field_name] is None:
                    fields[field_name] = value.strip()
                if all(fields.values()):
                    break
    except OSError:
        pass
    return fields


def detect_environment(
    *,
    qemu_binary: str = "qemu-system-x86_64",
    ovmf_path: str | None = None,
) -> dict[str, str | None]:
    """Return a dict of detected host component versions.

    All detection is best-effort: failures produce ``None`` values.
    """
    host_os = get_host_os_info()
    return {
        "qemu_version": _get_qemu_version(qemu_binary),
        "qemu_binary": qemu_binary,
        "kernel_version": _get_kernel_version(),
        "ovmf_version": _get_ovmf_version(ovmf_path) if ovmf_path else None,
        "ovmf_path": ovmf_path,
        "host_os_name": host_os.get("host_os_name"),
        "host_os_release": host_os.get("host_os_release"),
        "host_os_pretty_name": host_os.get("host_os_pretty_name"),
        **_get_host_cpuid(),
    }
