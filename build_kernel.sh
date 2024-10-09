#!/bin/sh

set -x
set -e

CMD=$1

function build_initramfs() {
  # install kernel package so that initramfs can be built
  doas apk add /src/out/x86_64/*.apk --allow-untrusted
  
  # tell the kernel to load sev-guest on boot
  echo "sev-guest" | doas tee /etc/modules-load.d/sev-guest.conf
  
  # setup rust
  doas apk add rustup perl pkgconfig openssl-dev openssl mkinitfs
  rustup-init -y
  
  # install snpguest for initramfs inclusion
  ~/.cargo/bin/cargo install snpguest

  # copy snpguest binary to /bin so that mkinitfs will move it in the appropriate directory (lol)
  doas cp /home/builder/.cargo/bin/snpguest /bin
  
  # generate an updated initramfs with sevguest and sev kernel module inside
  doas mkinitfs \
    -P /src/mkinitfs-features \
    -c /src/mkinitfs.conf \
    -o /src/out/initramfs-mainline-sev \
    -i /src/initramfs-init \
    $(ls /boot/config-*-mainline-sev | cut -c14-)
}

# this command assumes that /src is a mounted volume
if [ "$CMD" == "checksum" ]; then 
  cd /src
  abuild checksum
  exit 0
fi

if [ "$CMD" == "initramfs" ]; then
  cd /src
  build_initramfs
  exit 0
fi

if [ "$CMD" == "initramfs-runtime" ]; then
  cd /src
  rm mkinitfs.conf
  mv mkinitfs.runtime.conf mkinitfs.conf
  build_initramfs
  exit 0
fi

# build kernel stored at /src and output to /src/out
abuild -rK -m -P /src/out

if [ "$CMD" = "complete" ]; then
  build_initramfs
  # copy vmlinuz-mainline-sev to out directory, we already have an initramfs from the previous step
  doas cp /boot/vmlinuz-mainline-sev /src/out
fi

# cleanup out directory a bit
doas chown builder:wheel /src/out/*
