#!/bin/bash
set -e
set -x

if [ "$1" = "clean" ]; then
  rm *.qcow2 *.efi
  exit 0
fi

CMDLINE_TMPL="root=UUID=ALPUUID ds=nocloud;s=/ci; modules=sd-mod,usb-storage,ext4 rootfstype=ext4 console=ttyS0"

sudo modprobe nbd

rm -f installer.qcow2

curl https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-uefi-cloudinit-r0.qcow2 -O -L
qemu-img create -f qcow2 -o preallocation=metadata installer.qcow2 10G
qemu-img create -f qcow2 -o preallocation=metadata root.qcow2 50G
virt-resize --expand /dev/sda2 nocloud_alpine-3.20.3-x86_64-uefi-cloudinit-r0.qcow2 installer.qcow2
sudo qemu-nbd --connect=/dev/nbd9 installer.qcow2
sleep 1
ROOT_UUID=$(sudo blkid /dev/nbd9p2 -s UUID -o value)

mkdir -p installer/installer-root-image
sudo mount /dev/nbd9p2 installer/installer-root-image
sudo mkdir -p installer/installer-root-image/ci
sudo cp installer/user-data installer/installer-root-image/ci
sudo cp installer/meta-data installer/installer-root-image/ci
sudo cp ../out/x86_64/linux-mainline-sev-6.11-r1.apk installer/installer-root-image/ci
sync
sudo umount installer/installer-root-image

rmdir installer/installer-root-image

sudo qemu-nbd --disconnect /dev/nbd9

# build UKI
CMDLINE=$(echo $CMDLINE_TMPL | sed "s|ALPUUID|$ROOT_UUID|g")

ukify build \
  --linux ../out/vmlinuz-mainline-sev \
  --initrd ../out/initramfs-mainline-sev \
  --cmdline "$CMDLINE"
