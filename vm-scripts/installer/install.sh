#!/bin/sh

set -ex

DEST=/dev/sdb

alias p="parted -sa optimal $DEST"

# create msdos partition table
p mklabel gpt

# create one large root partition which will be encrypted with cryptsetup
# create a small plaintext partition to bridge the gap between first boot and subsequent boots
p mkpart p 0G 49G
p mkpart p 50G 100%

mkfs.ext4 /dev/sdb2
mkdir -p /mnt/keystore 
mount /dev/sdb2 /mnt/keystore

# encrypt root with the "empty key", we'll derive and encrypt an SNP key later.
echo "0" > /mnt/keystore/crypto_key.bin
touch /mnt/keystore/no-snp-key

# format with cryptsetup using the crypto_key.bin generated before
cryptsetup -v \
   -c aes-xts-plain64 \
   -s 512 \
   --hash sha512 \
   --pbkdf pbkdf2 \
   --iter-time 5000 \
   --use-random \
   -d /mnt/keystore/crypto_key.bin \
   -q \
   luksFormat \
   ${DEST}1

# unlock it
cryptsetup open -d /mnt/keystore/crypto_key.bin /dev/sdb1 root

# create an ext4 filesystem
mkfs.ext4 -L ROOT /dev/mapper/root

# remove linux-mainline-sev package in order for the installation to proceed without issues
apk del linux-mainline-sev

# mount root filesystem
mkdir -p /mnt/root
mount /dev/mapper/root /mnt/root
setup-disk -m sys -v -k lts /mnt/root

# enable cloud-init on the destination drive
chroot /mnt/root setup-cloud-init
chroot /mnt/root cloud-init clean --logs

# copy cloud-init over to the new root
rm -rf /mnt/root/ci/*
mkdir -p /mnt/root/ci
cp -r /ci/runtime/* /mnt/root/ci
cp /ci/linux-mainline-sev-6.11-r1.apk /mnt/root/ci/linux-mainline-sev-6.11-r1.apk
