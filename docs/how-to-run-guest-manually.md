The typical way to run tests is fully automated, including running guests automatically. However if you're developing tests or isolating an issue, you may find it useful to run guests manually. The following instructions assume you are running on AMD EPYC hardware that has been fully enabled for SEV.

# Prerequisites

Ensure that you are running on an AMD EPYC hardware & kernel combination that is fully enabled for SEV 3.0 (SNP). See the [AMD SEV Tuning Guide](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/tuning-guides/58207-using-sev-with-amd-epyc-processors.pdf) for supported kernel levels and firmware enablement instructions.

You can verify this by running the following command and resolving any failures:

```
snphost ok
```

If you are using a host image built by this repository, snphost is already installed in /usr/local/bin/snphost. If you are not, you will need to download it here: https://github.com/virtee/snphost

# How to Run

1. Download or build artifacts for your relevant guest distro.

Guest images are available for download in sev-certify release assets: https://github.com/AMDEPYC/sev-certify/releases. Unzip them if necessary.

Alternatively, images can be built by cloning this repository and running `mkosi` on the appropriate directory. Target any of the [`image/` directories](https://github.com/AMDEPYC/sev-certify/tree/main/images) to build those distro-specific artifacts:

```
sudo mkosi --image-id=guest-fedora-41 -C images/guest-fedora-41 build
```

Resulting image, kernel, boot ramfs will be deposited in the targeted directory.

2. <ins>**Launch SNP Guest:** </ins>   Run an SNP guest with the direct boot options and kernel-hashes=on for the confidential guest measured boot:

```sh
$ qemu-system-x86_64 \
  -enable-kvm \
  -machine q35,memory-encryption=sev0,memory-backend=ram1 \
  -cpu EPYC-v4 \
  -monitor none \
  -display none \
  -object memory-backend-memfd,id=ram1,size=2048M \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on \
  -bios ${OVMF_PATH} \
  -kernel ${EFI_PATH} \
  -device vhost-vsock-pci,guest-cid=3,id=vsock0 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0
```

- `$EFI_PATH`: 
  - If you're running inside a host image from this repository, the guest image is embedded at: `/usr/local/lib/guest-image/guest.efi`.
  - Otherwise, set this to the path of the guest image downloaded/built in step 1.

- `$OVMF_PATH`: either `/usr/share/ovmf/OVMF.amdsev.fd` or `/usr/share/edk2/ovmf/OVMF.amdsev.fd`, depending on your distro.

## QEMU Options Explained

| Option | Description |
|--------|-------------|
| `-enable-kvm` | Enable hardware virtualization via KVM |
| `-machine q35,memory-encryption=sev0,memory-backend=ram1` | Use Q35 machine type with SEV memory encryption and memfd backend |
| `-cpu EPYC-v4` | Emulate AMD EPYC CPU (required for SEV-SNP) |
| `-monitor none` | Disable QEMU monitor |
| `-display none` | Disable graphical display (headless) |
| `-object memory-backend-memfd,id=ram1,size=2048M` | Allocate 2GB guest memory using memfd (required for SEV) |
| `-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on` | Configure SEV-SNP guest with C-bit position 51 and kernel hash measurement |
| `-bios ${OVMF_PATH}` | Path to AMD SEV-compatible OVMF firmware |
| `-kernel ${EFI_PATH}` | Path to guest EFI image for direct boot |
| `-device vhost-vsock-pci,guest-cid=3,id=vsock0` | Enable vsock device for host↔guest communication (CID 3 is the first valid guest CID) |
| `-netdev user,id=net0` | User-mode NAT networking for guest outbound Internet access |
| `-device virtio-net-pci,netdev=net0` | Virtio network device attached to user-mode NAT |

## Vsock Agent

The guest images built by this repository include a vsock exec agent that listens on port 5000. This agent enables the `sev-verify` tool to execute commands inside the guest and retrieve the results without requiring SSH or console access.

To use the vsock agent from the host:

1. The guest must be running with the `-device vhost-vsock-pci,guest-cid=3` option
2. The vsock agent starts automatically on boot and listens on vsock port 5000
3. The `sev-verify` tool connects to CID 3, port 5000 to run attestation tests

If you need to use a different CID (e.g., when running multiple guests), change `guest-cid=3` to another value >= 3 (CID 2 is reserved for the host).

## Optional SEV-SNP Parameters

The `sev-snp-guest` object supports additional parameters:

| Parameter | Description |
|-----------|-------------|
| `host-data="<hex-or-base64>"` | 32-byte host-provided data included in attestation reports |
| `policy=<hex-value>` | SEV-SNP guest policy (e.g., `policy=0x30000`) |
| `author-key-enabled=true` | Enable author key for ID block signing |

Example with additional parameters:

```sh
-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,host-data="0x...",policy=0x30000
```


