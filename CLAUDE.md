# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`sev-certify` is a framework for testing and certifying operating system support for AMD Secure Encrypted Virtualization (SEV) features — specifically SEV-SNP (Secure Nested Paging). It builds host and guest OS images using [`mkosi`](https://github.com/systemd/mkosi), which are then booted on AMD EPYC hardware to run automated certification tests. Results are reported as GitHub Issues.

## Build Commands

Building images requires `mkosi` (see version in `build-and-release.yml` — currently Ubuntu Plucky's `25.3`):

```bash
# Build a guest image
sudo mkosi --image-id=guest-<distro>-<release> -C images/guest-<distro>-<release>/ build

# Build a host image
sudo mkosi --image-id=host-<distro>-<release> -C images/host-<distro>-<release>/ build

# Preview merged config before building
sudo mkosi --image-id=... -C images/.../ cat-config
sudo mkosi --image-id=... -C images/.../ summary

# Example for Ubuntu 25.04
sudo mkosi --image-id=guest-ubuntu-25.04 -C images/guest-ubuntu-25.04/ build
sudo mkosi --image-id=host-ubuntu-25.04  -C images/host-ubuntu-25.04/  build
```

**Ubuntu AppArmor note**: AppArmor-related mkosi permission errors are a known issue — see [systemd/mkosi#3265](https://github.com/systemd/mkosi/issues/3265).

Built `.efi` artifacts land at `images/<image-name>/<image-name>.efi`.

## Running Tests

Tests only run inside a booted SNP-enabled guest VM on AMD EPYC hardware. They are automated via systemd services that run on boot.

**Manual guest test execution** (once inside an SNP-enabled guest):
```bash
# Key derivation tests
/usr/local/lib/scripts/snpguest_key_derivation.py
/usr/local/lib/scripts/snpguest_key_derivation.py --debug    # verbose output
/usr/local/lib/scripts/snpguest_key_derivation.py --gfs-sweep  # diagnostic GFS sweep

# View test results via journal
journalctl -u key-derivation.service
journalctl -u attestation-workflow.service

# Check status log files (JSON format)
cat /usr/local/lib/key_derivation_status
cat /usr/local/lib/attestation_status
```

**View guest logs from the host** (guest journals are forwarded to host via systemd-journal-remote):
```bash
journalctl -D /var/log/journal/guest-logs -f -u <service-name>
```

**Lint** (CI only): Commit messages are linted for [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) via `lint.yml`.

## Architecture

### Image Composition via mkosi Modules

Images are built by composing modular `mkosi.conf` snippets from `modules/`. An image's `mkosi.conf` in `images/<image>/` includes the relevant module tree:

- **Host images** include: `modules/build/host` → which pulls in `system/host`, `launch/host`, `test/host`, `report/host`, `stop/host`, plus common modules.
- **Guest images** include: `modules/build/guest` → which pulls in `system/guest`, `test/guest`, `report/guest`, `stop/guest`.

### Module Directory Structure

```
modules/
├── build/       # mkosi build-time configuration (packages, build scripts)
│   ├── common/  # Shared: network, snpguest CLI install, kernel modules
│   ├── host/    # Host-specific: beacon, embed-guest-image, snphost, QEMU formatting
│   └── guest/   # Guest-specific: targets, journal upload
├── system/      # Boot phase: snphost-ok / snpguest-ok checks, beacon
├── launch/      # Host-only: launch-guest.sh (QEMU invocation), measurement verification
├── test/        # Test services:
│   ├── host/    # (placeholder, future host tests)
│   └── guest/
│       ├── attestation-workflow/  # snpguest_attestation.sh (bash)
│       ├── attestation-result/    # Records attestation step status to journal
│       └── key-derivation/        # snpguest_key_derivation.py (Python)
├── report/      # Certificate generation (Python), guest log display
├── stop/        # Beacon report, reboot or login-shell on completion
└── ssh-support/ # Debug SSH access to host/guest
```

### Systemd Target Workflow

Both host and guest follow a custom systemd target chain:

```
system.target → boot.target → [launch.target (host only)] → test.target → report.target → stop.target
```

Each phase is a custom target with services depending on the previous target. The `*-done.service` units signal completion of each phase.

### Guest Launch Mechanism

The host embeds the guest `.efi` at `/usr/local/lib/guest-image/guest.efi` (see `modules/build/host/embed-guest-image/`). At runtime, `launch-guest.sh` invokes QEMU with SEV-SNP parameters:
- CPU: `EPYC-v4`
- Guest measurement hash passed as `host-data` to the SNP object
- OVMF: `/usr/share/ovmf/OVMF.amdsev.fd` or `/usr/share/edk2/ovmf/OVMF.amdsev.fd`

### Certificate Generation (Python)

Located in `modules/report/host/sev-certificate-generator/`. Run automatically as a systemd service after tests complete:

- `generate_sev_certificate.py` — entry point; calls `SEV_Certificate.generate_sev_certificate()`
- `sev_certificate_version_3_0_0_0.py` — parses host and guest journal logs, formats the certificate
- `service/service.py` — `Service` class: extracts service status/errors from journald
- `test_environment/` — collects host OS, hardware, and guest environment metadata

The certificate generator discovers test services via the `SNPHOST_TEST=3.0.0-0` and `SNPGUEST_TEST=3.0.0-0` systemd journal metadata fields. Test status is inferred from journal messages (`Deactivated successfully` = passed, `Failed to start` = failed).

### Key Derivation Test Details

`snpguest_key_derivation.py` tests six properties of SNP key derivation using the `snpguest key` CLI:
1. **Determinism** — same params → same key
2. **VMPL Isolation** — VMPL 0 ≠ VMPL 1 keys
3. **Root Key Difference** — VCK (`vcek` CLI arg) ≠ VMRK keys
4. **Guest SVN Sensitivity** — requires `--guest_field_select` bit 4 set
5. **TCB Sensitivity** — requires `--guest_field_select` bit 5 set; bounds from `CommittedTcb` in attestation report
6. **Guest Field Select Sensitivity** — GFS=0x01 ≠ GFS=0x02

**Important naming note**: In the `snpguest` CLI, the argument `"vcek"` for root key selection actually selects the **VCK** (Versioned Chip Key, a symmetric key), *not* the VCEK (the asymmetric signing key used in attestation). This is a naming inconsistency in the snpguest tool.

### Journal-Based Test Results

Tests communicate pass/fail to the certificate generator via journald. Each test emits JSON lines:
```json
{"test_name": "0"}   // 0 = passed
{"test_name": "1"}   // non-zero = failed
```

The certificate generator reads these via `journalctl -D /var/log/journal/guest-logs/ -u <service> -o cat` and parses the JSON.

## Adding a New OS

1. Create `images/host-<distro>-<release>/mkosi.conf` and `images/guest-<distro>-<release>/mkosi.conf`
2. Include the appropriate module path (`../../modules/build/host` or `../../modules/build/guest`)
3. Specify `Distribution`, `Release`, and required `Packages`
4. Add to the `distro matrix` in `.github/workflows/build-and-release.yml`

See `docs/how-to-add-new-os-images.md` for required package lists.

## Commit Style

All commits must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Allowed types: `feat`, `fix`, `build`, `chore`, `ci`, `docs`, `style`, `refactor`, `perf`, `test`.

PRs must be signed-off (`git commit -s`) and approved by maintainers before merge.
