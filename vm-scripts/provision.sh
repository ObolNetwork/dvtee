#!/bin/bash
set -e
set -x

CMDLINE_TMPL="cryptroot=LABEL=ROOT cryptdm=lvmcrypt cryptkey ds=nocloud;s=/ci; modules=sd-mod,usb-storage,ext4 rootfstype=ext4 console=ttyS0"

ukify build \
  --linux ../out/vmlinuz-mainline-sev \
  --initrd ../out/initramfs-mainline-sev \
  --cmdline "$CMDLINE"
