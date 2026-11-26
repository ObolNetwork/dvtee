#!/bin/bash
# SUPERSEDED by the mkosi image in image/ (see image/README.md). Kept for reference; do not use for keys.
# Prints the expected SEV-SNP launch measurement of the guest that run.sh
# starts: the OVMF from `make ovmf`, the UKI as -kernel with kernel-hashes=on,
# no separate initrd or cmdline (the UKI carries both), 4 vCPUs of EPYC-v4.
# Compare it with MEASUREMENT in the guest's attestation report.
#
#   vm-scripts/measure.sh [UKI] [OVMF]
#
# Runs sev-snp-measure from the pinned OVMF builder image, so the result does
# not depend on what is installed on this host. Keep VCPUS and VCPU_TYPE in
# step with run.sh: both are part of the measurement.
set -euo pipefail

cd "$(dirname "$0")/.."
UKI=${1:-vm-scripts/vmlinuz-mainline-sev.unsigned.efi}
OVMF=${2:-out/ovmf/OVMF.fd}
VCPUS=${VCPUS:-4}
VCPU_TYPE=${VCPU_TYPE:-EPYC-v4}
IMAGE=${OVMF_BUILDER_IMAGE:-obolnetwork/ovmf-builder}

for f in "$UKI" "$OVMF"; do
	[ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done

docker run --rm --network none \
	-v "$(realpath "$UKI"):/in/kernel:ro" -v "$(realpath "$OVMF"):/in/OVMF.fd:ro" \
	--entrypoint sev-snp-measure "$IMAGE" \
	--mode snp --vmm-type QEMU --vcpus "$VCPUS" --vcpu-type "$VCPU_TYPE" \
	--ovmf /in/OVMF.fd --kernel /in/kernel
