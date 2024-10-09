#!/bin/bash
set -e
set -x

CMDLINE_TMPL="cryptroot=UUID=ALPUUID cryptkey ds=nocloud;s=/ci; modules=sd-mod,usb-storage,ext4,cryptsetup,keymap,cryptkey,kms rootfstype=ext4 console=ttyS0"

sudo qemu-nbd --connect=/dev/nbd9 root.qcow2
sleep 1
ROOT_UUID=$(sudo blkid /dev/nbd9p1 -s UUID -o value)

sudo qemu-nbd --disconnect /dev/nbd9

CMDLINE=$(echo $CMDLINE_TMPL | sed "s|ALPUUID|$ROOT_UUID|g")

ukify build \
  --linux ../out/vmlinuz-mainline-sev \
  --initrd ../out/initramfs-mainline-sev \
  --cmdline "$CMDLINE"
