#!/bin/bash
set -e
set -x

if [ "$1" = "clean" ]; then
  rm -f *.qcow2 *.efi *.bin
  exit 0
fi

USER_INSTALL=

# if there's exactly an argument that isn't "clean", use it as the directory to fetch
# user-install data from.
if [ $# -eq 1 ]; then
  # check that there is a "user-install.sh" file in the directory.
  # if it's there, assign $1 to USER_INSTALL, so that it can be copied later to the CI
  # directory.
  if [ -e $1/user-install.sh ]; then
    USER_INSTALL=$1
  else
    echo "User install directory specified, but it doesn't contain an 'user-install.sh' script."
    exit 42
  fi
fi

CMDLINE_TMPL="root=UUID=ALPUUID ds=nocloud;s=/ci; modules=sd-mod,usb-storage,ext4 rootfstype=ext4 console=ttyS0 installer=yes"

sudo modprobe nbd

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
sudo cp installer/install.sh installer/installer-root-image/ci
sudo cp installer/setup-alpine-answers installer/installer-root-image/ci
sudo cp -r runtime installer/installer-root-image/ci 

if [ -n "${USER_INSTALL}" ]; then 
  sudo mkdir -p installer/installer-root-image/ci/user-install
  sudo cp -r $USER_INSTALL/* installer/installer-root-image/ci/user-install
fi

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
