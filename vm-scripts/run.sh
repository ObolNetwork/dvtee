#!/bin/bash

QEMU=${QEMU_SEV_PATH:=/root/AMDSEV/qemu/build/qemu-system-x86_64}
$QEMU \
--enable-kvm \
-cpu EPYC-v4 \
-machine q35 \
-smp 4 \
-m 2048M \
-no-reboot \
-vga none \
-nographic -serial mon:stdio \
-monitor pty \
-netdev user,ipv4=on,ipv6=off,net=10.0.0.1,host=10.0.0.2,hostfwd=tcp::10022-:22,id=vmnic \
-device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true,romfile= \
-device scsi-hd,drive=disk0 \
-drive if=none,id=disk0,format=qcow2,file=root.qcow2 \
-serial file:./qemu.log \
--trace "kvm_sev*" \
-D ./qemu-trace.log \
-global isa-debugcon.iobase=0x402 \
-machine memory-encryption=sev0,vmport=off \
-object memory-backend-memfd,id=ram1,size=2048M,share=true,prealloc=false \
-machine memory-backend=ram1 \
-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on \
-bios "${OVMF:-../out/ovmf/OVMF.fd}" \
-kernel ./vmlinuz-mainline-sev.unsigned.efi
