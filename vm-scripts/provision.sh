#!/bin/bash
set -e
set -x

if [ "$1" = "clean" ]; then
  rm *.qcow2 *.efi
  exit 0
fi

CMDLINE_TMPL="cryptroot=UUID=ALPUUID cryptdm=lvmcrypt cryptkey ds=nocloud;s=/ci; modules=sd-mod,usb-storage,ext4 rootfstype=ext4 console=ttyS0"

sudo modprobe nbd

sudo qemu-nbd --connect=/dev/nbd9 root.qcow2
sleep 1
ROOT_UUID=$(sudo blkid /dev/nbd9p1 -s UUID -o value)

mkdir -p root-image
sudo mount /dev/nbd9p1 root-image
sudo mkdir -p root-image/ci
sudo cp runtime/user-data root-image/ci
sudo cp runtime/meta-data root-image/ci
sudo cp ../out/x86_64/linux-mainline-sev-6.11-r1.apk root-image/ci
sync
sudo umount root-image

rmdir root-image

sudo qemu-nbd --disconnect /dev/nbd9

# build UKI
CMDLINE=$(echo $CMDLINE_TMPL | sed "s|ALPUUID|$ROOT_UUID|g")

ukify build \
  --linux ../out/vmlinuz-mainline-sev \
  --initrd ../out/initramfs-mainline-sev \
  --cmdline "$CMDLINE"
