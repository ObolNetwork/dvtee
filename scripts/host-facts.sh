#!/bin/bash
# shellcheck disable=SC2016 # the bash -c snippets expand in the child shell
# Records the host facts the hardware results need: CPU, BIOS, kernel, SEV
# firmware and TCB, KVM parameters, QEMU. Run as root on the SNP host.
#
#   scripts/host-facts.sh OUT_DIR
#
# Missing tools are noted, not fatal. The chip ID identifies the machine but
# is not secret; it is what KDS certificates are fetched by.
set -uo pipefail

OUT=${1:?output directory}
mkdir -p "$OUT"
run() { # name, command...
	local name=$1; shift
	{ echo "\$ $*"; "$@" 2>&1; echo "(exit $?)"; } >"$OUT/$name.txt"
}

run uname uname -a
run os-release cat /etc/os-release
run cmdline cat /proc/cmdline
run lscpu lscpu
run microcode grep -m1 microcode /proc/cpuinfo
run bios bash -c 'for f in bios_vendor bios_version bios_date board_vendor board_name sys_vendor product_name; do printf "%s: " $f; cat /sys/class/dmi/id/$f 2>/dev/null || echo "?"; done'
run dmesg-sev bash -c "dmesg | grep -i -E 'sev|snp|rmp|ccp|kvm_amd|amd-vi|iommu' | head -n 200"
run kvm-amd bash -c 'for p in sev sev_es sev_snp; do printf "%s: " $p; cat /sys/module/kvm_amd/parameters/$p 2>/dev/null || echo "?"; done'
run sev-device ls -l /dev/sev
run qemu bash -c '${QEMU:-qemu-system-x86_64} --version'
run snphost-ok snphost ok
run snphost-tcb snphost show tcb
run snphost-identifier snphost show identifier
run docker docker --version
run python python3 --version
echo "host facts in $OUT" >&2
