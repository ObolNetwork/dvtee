#!/bin/bash
# Builds the sev-signer guest image for AMD SEV-SNP into OUT_DIR:
#   sev-signer           static signer binary (also used on the host)
#   sev-signer.efi       UKI: kernel + initrd + command line, booted with -kernel
#   sev-signer.raw       disk image: erofs root + dm-verity hash partition
#   sev-signer.roothash  verity root hash (also on the UKI's command line)
#   SHA256SUMS, BUILDINFO
#
#   SNP_MIN_TCB=0x0000000000000000 image/build.sh [--profile debug|variant]
#
# SNP_MIN_TCB is the raw 64-bit minimum TCB mixed into the data disk key
# (`sev-signer sealing-key --snp-min-tcb`). It is host-specific and part of
# the measured initrd, so there is no default. docs/hardware-runbook.md shows
# how to read it from the platform.
#
# Needs: docker, git, python3 >= 3.9, apt and debian-archive-keyring (for
# mkosi's Debian tools tree), and unprivileged user namespaces or root.
set -euo pipefail

MKOSI_URL=https://github.com/systemd/mkosi.git
MKOSI_TAG=v27.1
MKOSI_COMMIT=ecf7f5702bb2052b7a69cab3fe7d37bc3b9ad77b

cd "$(dirname "$0")/.."
ROOT=$PWD
OUT_DIR=${OUT_DIR:-$ROOT/out/image}
PROFILE=
case ${1:-} in
"") ;;
--profile) PROFILE=${2:?--profile needs a name}; OUT_DIR=${OUT_DIR}-$PROFILE ;;
*) echo "usage: SNP_MIN_TCB=0x... $0 [--profile NAME]" >&2; exit 2 ;;
esac

: "${SNP_MIN_TCB:?set SNP_MIN_TCB, e.g. 0x0000000000000000 for the discovery build (docs/hardware-runbook.md)}"
[[ $SNP_MIN_TCB =~ ^0x[0-9a-fA-F]{16}$ ]] || { echo "SNP_MIN_TCB must be 0x + 16 hex digits" >&2; exit 2; }
SNP_MIN_TCB=$(tr 'A-F' 'a-f' <<<"$SNP_MIN_TCB")

log() { echo "[image] $*" >&2; }
mkdir -p "$OUT_DIR"

# 1. sev-signer, static, in the pinned toolchain image.
log "building sev-signer (signer/ at $(git rev-parse --short HEAD 2>/dev/null || echo unknown))"
docker build -q -t sev-signer-image-build -f image/signer.Dockerfile signer >/dev/null
cid=$(docker create sev-signer-image-build)
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$cid:/sev-signer" "$OUT_DIR/sev-signer"

# 2. Payload shared by the root and the initrd (ExtraTrees=%D/payload).
rm -rf image/payload
install -D -m 0755 "$OUT_DIR/sev-signer" image/payload/usr/bin/sev-signer
install -d -m 0755 image/payload/usr/lib/sev-signer
printf '%s\n' "$SNP_MIN_TCB" >image/payload/usr/lib/sev-signer/snp-min-tcb
chmod 0644 image/payload/usr/lib/sev-signer/snp-min-tcb

# 3. mkosi, pinned by commit.
MKOSI_DIR=$ROOT/out/mkosi-$MKOSI_TAG
if [[ ! -d $MKOSI_DIR/.git ]]; then
	git init -q "$MKOSI_DIR"
	git -C "$MKOSI_DIR" fetch -q --depth 1 "$MKOSI_URL" "$MKOSI_COMMIT"
	git -C "$MKOSI_DIR" -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
[[ $(git -C "$MKOSI_DIR" rev-parse HEAD) == "$MKOSI_COMMIT" ]] || { echo "mkosi checkout is not $MKOSI_COMMIT" >&2; exit 1; }

log "mkosi $MKOSI_TAG build ${PROFILE:+(profile $PROFILE)}"
args=(-C image --output-directory "$OUT_DIR" --force)
[[ -n $PROFILE ]] && args+=(--profile "$PROFILE")
"$MKOSI_DIR/bin/mkosi" "${args[@]}" build

# 4. Record what went in.
cd "$OUT_DIR"
for f in sev-signer.efi sev-signer.raw sev-signer.roothash; do
	[[ -s $f ]] || { echo "mkosi did not produce $f" >&2; exit 1; }
done
sha256sum sev-signer sev-signer.efi sev-signer.raw sev-signer.roothash >SHA256SUMS
{
	echo "git_commit=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
	echo "git_dirty=$(git -C "$ROOT" status --porcelain 2>/dev/null | grep -q . && echo yes || echo no)"
	echo "mkosi=$MKOSI_TAG $MKOSI_COMMIT"
	echo "profile=${PROFILE:-release}"
	echo "snp_min_tcb=$SNP_MIN_TCB"
	echo "roothash=$(cat sev-signer.roothash)"
	sed -n 's/^\(Snapshot\|Release\)=/\L\1=/p' "$ROOT/image/mkosi.conf"
} >BUILDINFO
cat SHA256SUMS BUILDINFO
