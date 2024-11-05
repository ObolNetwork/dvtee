#!/bin/sh

set -ex

DEST=/dev/sdb

alias p="parted -sa optimal $DEST"

# create msdos partition table
p mklabel gpt

# Partition scheme:
# - root partition: 30GB
# - verity partition: 6GB
# - /var: 2GB
# - /home: 11GB
# - plaintext partition: 1GB
# create one large root partition which will be encrypted with cryptsetup
# create a small plaintext partition to bridge the gap between first boot and subsequent boots
p mkpart p 0G 30G   # 1: root
p mkpart p 30G 36G  # 2: verity
p mkpart p 36G 38G  # 3: /var
p mkpart p 38G 49G  # 4: /home
p mkpart p 49G 100% # 5: plaintext partition

mkfs.ext4 -L VAR ${DEST}3
mkfs.ext4 -L HOME ${DEST}4
mkfs.ext4 -L PLAINTEXT ${DEST}5

mkdir -p /mnt/keystore 
mount ${DEST}5 /mnt/keystore

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
cryptsetup open -d /mnt/keystore/crypto_key.bin ${DEST}1 root

# create an ext4 filesystem
mkfs.ext4 -L ROOT /dev/mapper/root

# mount root filesystem
mkdir -p /mnt/root
mount /dev/mapper/root /mnt/root
mkdir -p /mnt/root/var
mkdir -p /mnt/root/home
mount ${DEST}3 /mnt/root/var
mount ${DEST}4 /mnt/root/home
setup-disk -m sys -v -k lts /mnt/root

# enable cloud-init on the destination drive
chroot /mnt/root setup-cloud-init
chroot /mnt/root cloud-init clean --logs

# copy cloud-init over to the new root
rm -rf /mnt/root/ci/*
mkdir -p /mnt/root/ci
cp -r /ci/runtime/* /mnt/root/ci
cp /ci/linux-mainline-sev-6.11-r1.apk /mnt/root/ci/linux-mainline-sev-6.11-r1.apk

# prepare for chroot
mkdir -p /mnt/root/proc /mnt/root/sys /mnt/root/dev
mount -t proc /proc /mnt/root/proc
mount --rbind /sys /mnt/root/sys
mount --rbind /dev /mnt/root/dev

cat << EOF | chroot /mnt/root
set -ex

adduser -D signer
echo -e "signer:signer" | chpasswd
echo -e "root:root" | chpasswd

echo "permit nopass signer" > /etc/doas.conf
echo "permit persist :wheel" >> /etc/doas.conf

echo "sev-guest" > /etc/modules-load.d/sev-guest.conf

apk add perl pkgconfig openssl openssl-dev alpine-sdk vim curl uuidgen rustup parted cryptsetup

# setup a machine-id
uuidgen > /etc/machine-id

# install mainline-sev kernel
apk add --allow-untrusted /ci/linux-mainline-sev-6.11-r1.apk

# install rust
echo "Installing latest Rust for user 'signer'"
su -c "rustup-init -y" - signer

# install snpguest
echo "Installing latest snpguest for user 'signer'"
su -c "/home/signer/.cargo/bin/cargo install snpguest" - signer

# load sev-guest kernel module
modprobe sev-guest
EOF

# !!! ALL CHANGES TO ROOT FS MUST HAPPEN BEFORE THIS !!!

# setup verity
veritysetup format /dev/mapper/root ${DEST}2 | grep Root | cut -f2 >> /mnt/keystore/roothash.txt
echo "ROOT HASH: $(cat /mnt/keystore/roothash.txt)"
