#!/bin/bash
# Builds OVMF (OvmfPkg/AmdSev/AmdSevX64.dsc, RELEASE) from a pinned edk2 commit
# into OUT_DIR, with its licence notices, build info and the SNP OVMF hash.
# Runs inside the image from ovmf/Dockerfile: `make ovmf` from the repo root.
#
# AmdSevX64 is the variant that verifies the kernel, initrd and cmdline
# against the hash table QEMU puts in measured memory (kernel-hashes=on).
# OvmfPkgX64 links BlobVerifierLibNull and does not, so a host could swap
# the kernel under a matching measurement.
set -euo pipefail

EDK2_URL=https://github.com/tianocore/edk2.git
EDK2_TAG=edk2-stable202608
EDK2_COMMIT=2970e5699ba6267f3384ffab20f96647578aebc8
OUT_DIR=${1:-/out}

mkdir -p "$OUT_DIR"
git config --global advice.detachedHead false
git init -q edk2
cd edk2
git fetch -q --depth 1 "$EDK2_URL" "$EDK2_COMMIT"
git checkout -q FETCH_HEAD
test "$(git rev-parse HEAD)" = "$EDK2_COMMIT"
git submodule update -q --init --recursive --depth 1 --jobs 4 \
  || git submodule update -q --init --recursive --jobs 4

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

# AmdSevX64 embeds a grub.efi for booting an encrypted disk with an injected
# secret. We boot the kernel directly (QEMU -kernel), so leave it empty, as
# AMD's own builds did. grub.sh keeps a grub.efi newer than its inputs.
touch -d @1 OvmfPkg/AmdSev/Grub/grub.cfg OvmfPkg/AmdSev/Grub/grub.sh
: > OvmfPkg/AmdSev/Grub/grub.efi

make -s -C BaseTools -j "$(nproc)"
set +u
# shellcheck disable=SC1091
. ./edksetup.sh >/dev/null
set -u
build -q -n "$(nproc)" -t GCC -a X64 -b RELEASE -p OvmfPkg/AmdSev/AmdSevX64.dsc

cp Build/AmdSev/RELEASE_GCC/FV/OVMF.fd "$OUT_DIR/OVMF.fd"

# Licence notices: edk2 itself (BSD-2-Clause-Patent) and every submodule.
mkdir -p "$OUT_DIR/licenses"
cp License.txt "$OUT_DIR/licenses/edk2-License.txt"
git submodule foreach -q --recursive '
  for f in LICENSE* COPYING* License*; do
    [ -f "$f" ] || continue
    d="'"$OUT_DIR"'/licenses/$(echo "$displaypath" | tr / _)"
    mkdir -p "$d"; cp "$f" "$d/"
  done'

{
  echo "edk2_tag=$EDK2_TAG"
  echo "edk2_commit=$EDK2_COMMIT"
  echo "platform=OvmfPkg/AmdSev/AmdSevX64.dsc"
  echo "target=RELEASE_GCC"
  echo "grub_efi=empty"
  echo "gcc=$(gcc -dumpfullversion)"
  echo "nasm=$(nasm -v | awk '{print $3}')"
  echo "iasl=$(iasl -v 2>/dev/null | awk '/version/ {print $NF; exit}')"
  echo "sev_snp_measure=$(sev-snp-measure --version | awk '{print $NF}')"
} > "$OUT_DIR/BUILDINFO"

cd "$OUT_DIR"
sha256sum OVMF.fd > OVMF.fd.sha256
# The OVMF part of the SNP launch digest; measure.sh finishes it with the
# kernel, vCPUs and VMM type.
sev-snp-measure --mode snp:ovmf-hash --ovmf OVMF.fd > OVMF.snp-ovmf-hash
cat OVMF.fd.sha256 OVMF.snp-ovmf-hash BUILDINFO
