#!/bin/sh

set -x
set -e

# build kernel stored at /src and output to /src/out
abuild -rK -m -P /src/out

# install kernel package so that initramfs can be built
doas apk add /src/out/x86_64/*.apk

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

# copy vmlinuz-mainline-sev to out directory, we already have an initramfs from the previous step
doas cp /boot/vmlinuz-mainline-sev /src/out

# cleanup out directory a bit
mv /src/out/x86_64/*.apk /src/out
doas chown builder:wheel /src/out/*
doas rm -rf /src/out/x86_64
