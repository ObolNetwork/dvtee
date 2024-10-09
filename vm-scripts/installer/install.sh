#!/bin/sh

set -ex

DEST=/dev/sdb

alias p="parted -sa optimal $DEST"

# create msdos partition table
p mklabel gpt

# create one large root partition which will be encrypted with cryptsetup
# no need for esp or boot since qemu will load the kernel for us
p mkpart p 0G 100%

# generate a derived key from AMD-SEV SNP subsystem and store it to /crypto_key.bin
/home/signer/.cargo/bin/snpguest key /crypto_key.bin vcek --guest_file_select 111111

# format with cryptsetup using the crypto_key.bin generated before
cryptsetup -v \
   -c aes-xts-plain64 \
   -s 512 \
   --hash sha512 \
   --pbkdf pbkdf2 \
   --iter-time 5000 \
   --use-random \
   -d /crypto_key.bin \
   -q \
   luksFormat \
   ${DEST}1

# unlock it
cryptsetup open -d /crypto_key.bin /dev/sdb1 root

# create an ext4 filesystem
mkfs.ext4 /dev/mapper/root

# run setup-alpine with answer file
setup-alpine -f /ci/setup-alpine-answers
