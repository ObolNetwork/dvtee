# OVMF

The guest firmware for SEV-SNP. It is the first thing the AMD secure
processor measures, so its exact bytes are part of every launch measurement:
a firmware we cannot rebuild is a measurement we cannot predict.

## What is built

| | |
|---|---|
| Source | [tianocore/edk2](https://github.com/tianocore/edk2) `edk2-stable202608`, commit `2970e5699ba6267f3384ffab20f96647578aebc8` |
| Platform | `OvmfPkg/AmdSev/AmdSevX64.dsc`, `RELEASE`, toolchain `GCC` |
| grub.efi | empty (we boot the kernel directly) |
| Toolchain | `ubuntu:24.04` by digest, packages from the Ubuntu snapshot `20261101T000000Z` |

`AmdSevX64` is the variant whose firmware checks the kernel, initrd and
cmdline against the hash table QEMU places in measured memory
(`kernel-hashes=on`). The generic `OvmfPkgX64` links `BlobVerifierLibNull` and
skips that check, so the host could boot another kernel under the same
measurement.

`AmdSevX64` also embeds a grub that opens an encrypted disk with a secret
injected at launch. run.sh boots a UKI with `-kernel`, so grub never runs and
`build.sh` leaves `grub.efi` empty. That keeps grub (GPL-3.0) out of the firmware.

## Build

```sh
make ovmf      # out/ovmf/OVMF.fd, OVMF.fd.sha256, OVMF.snp-ovmf-hash, BUILDINFO, licenses/
make measure   # expected launch measurement of the guest run.sh starts
```

CI (`.github/workflows/ovmf.yml`) builds it twice on different runner images
and fails unless the outputs are identical. Each run's summary carries the
firmware sha256 and the SNP OVMF hash; the `ovmf` artifact is the firmware to
use.

## Measurement

`vm-scripts/measure.sh` computes the launch digest from this firmware, the UKI,
4 vCPUs of `EPYC-v4` and `--vmm-type QEMU`, with
[sev-snp-measure](https://github.com/virtee/sev-snp-measure) 0.0.13 pinned by
hash. Change the vCPU count or type in run.sh and the measurement changes too.
The kernel and initramfs are not reproducible yet (ROADMAP.md, finding 7), so a
measurement is only as good as the UKI it was computed from.

That script is for the old `vm-scripts/` image. For the mkosi image in `image/`, use
`scripts/expected-measurement.sh` (`make image-measure`). It uses the same sev-snp-measure pin, with
the launch parameters in `scripts/snp-params.env`.

## Licences

edk2 is BSD-2-Clause-Patent. The firmware also links code from its submodules
(OpenSSL: Apache-2.0; Brotli: MIT; and others). `build.sh` copies every
submodule's licence file into `out/ovmf/licenses/`. Ship that directory with
any image that includes the firmware.

## Updating

1. Pick a new `edk2-stable*` tag. Set `EDK2_TAG` and `EDK2_COMMIT` in `build.sh`
   and update the table above.
2. To take toolchain fixes, move `UBUNTU_SNAPSHOT` and the base image digest in
   the `Dockerfile`.
3. CI must show two identical builds. The new firmware hash means a new expected
   measurement for every guest image.
