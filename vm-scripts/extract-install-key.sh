#!/bin/sh

set -ex

sudo qemu-nbd --connect=/dev/nbd9 root.qcow2
sleep 1

mkdir root-key
sudo mount /dev/nbd9p2 root-key
sudo cp root-key/crypto_key.bin ./
sudo umount root-key
sudo qemu-nbd --disconnect /dev/nbd9
rmdir root-key
