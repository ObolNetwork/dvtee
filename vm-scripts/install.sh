#!/bin/sh

DEST=/dev/sdb

alias p="parted -sa optimal $DEST"

# create msdos partition table
p mklabel gpt

# create one large root partition which will be encrypted with cryptsetup
# no need for esp or boot since qemu will load the kernel for us
p mkpart p 0 100%
