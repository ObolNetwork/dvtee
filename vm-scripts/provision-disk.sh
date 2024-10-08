#!/bin/bash
set -e
set -x

CMDLINE_TMPL="root=UUID=ALPUUID ds=nocloud;s=/ci; modules=sd-mod,usb-storage,ext4 rootfstype=ext4 console=ttyS0"

modprobe nbd

rm -f root.qcow2

curl https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-uefi-cloudinit-r0.qcow2 -O -L
qemu-img create -f qcow2 -o preallocation=metadata root.qcow2 50G
virt-resize --expand /dev/sda2 nocloud_alpine-3.20.3-x86_64-uefi-cloudinit-r0.qcow2 root.qcow2
qemu-nbd --connect=/dev/nbd9 root.qcow2
sleep 1
ROOT_UUID=$(blkid /dev/nbd9p2 -s UUID -o value)

mkdir  root-image
mount /dev/nbd9p2 root-image
mkdir root-image/ci
cp user-data root-image/ci
cp meta-data root-image/ci
cp ../out/x86_64/linux-mainline-sev-6.11-r1.apk root-image/ci
sync
umount root-image

rmdir root-image

qemu-nbd --disconnect /dev/nbd9

# build UKI
CMDLINE=$(echo $CMDLINE_TMPL | sed "s|ALPUUID|$ROOT_UUID|g")

ukify build \
  --linux ../out/vmlinuz-mainline-sev \
  --initrd ../out/initramfs-mainline-sev \
  --cmdline "$CMDLINE"
