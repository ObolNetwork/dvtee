#!/bin/bash
set -e
set -x

CMDLINE_TMPL="cryptroot=UUID=CRYPTALPUUID cryptdm=luks root=LABEL=ROOT cryptkey ds=nocloud;s=/ci; modules=sd-mod,usb-storage,ext4,cryptkey,cryptsetup,keymap,kms rootfstype=ext4 console=ttyS0 ro rd.emergency=reboot rd.shell=0 lsm=lockdown lockdown=confidentiality roothash=ROOTHASH"

sudo qemu-nbd --connect=/dev/nbd9 root.qcow2
sleep 1
CRYPTROOT_UUID=$(sudo blkid /dev/nbd9p1 -s UUID -o value)
mkdir -p keystore-dir
sudo mount /dev/nbd9p3 keystore-dir
ROOTHASH=$(cat keystore-dir/roothash.txt)
sudo umount keystore-dir
sudo rmdir keystore-dir
sudo qemu-nbd --disconnect /dev/nbd9

CMDLINE=$(echo $CMDLINE_TMPL | sed "s|CRYPTALPUUID|$CRYPTROOT_UUID|g" | sed "s|ROOTHASH|$ROOTHASH|g")

ukify build \
  --linux ../out/vmlinuz-mainline-sev \
  --initrd ../out/initramfs-mainline-sev \
  --cmdline "$CMDLINE"
