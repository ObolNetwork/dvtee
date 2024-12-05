# `sev-signer`

Run a web3signer-enabled signing software in an AMD SEV-SNP virtual machine.

## Requirements

To run this repository on Ubuntu, you need:
 - guestfs-tools
 - systemd-ukify
 - systemd-boot

## Building a SEV-enabled Alpine Linux kernel

Run:

```
make kernel
```

The `Makefile` will build an Alpine Linux-based Docker image builder, compile a Linux kernel tailored to be run as a
guest in an AMD SEV-SNP virtual machine, and an initramfs with all the tooling needed to decrypt its VM disk with a
derived key.


## Other `Makefile` targets

 - `just-kernel`: builds just the kernel image and packages, bypassing initramfs
 - `just-initramfs`: builds just the initramfs, bypassing the kernel image and packages
 - `docker-image`: builds the Docker image used to compile the initramfs and kernel images, packages
 - `kernel-checksum`: builds checksums for the Alpine build system to use during the kernel build process
 - `clean`: cleans the `out` directory


## How to use

> [!NOTE]
> As of now this process does not allow for SSH access, the terminal you see at the end of this process is your only
> way of accessing the encrypted VM.
>
> This issue will be addressed at a later date.

> [!NOTE]
> The default user logins are `root`:`root` and `signer`:`signer`.
>
> `signer` user has `doas` privileges, no password needed.
> 
> In production, the image will not support any form of remote login.

1. build the kernel image and initramfs:
   ```
   make kernel 
   ```
2. move in the `vm-scripts` directory and provision the installer disks:
   ```
   cd vm-scripts
   bash ./provision-installer.sh clean # !!! This command will ERASE any existing VM disk!
   bash ./provision-installer.sh
   ```
3. run the installer VM:
   ```
    bash ./run-installer.sh
   ```
4. provision the final [UKI](https://wiki.archlinux.org/title/Unified_kernel_image) for the encrypted VM:
   ```
   bash ./provision.sh 
   ```
5. run the encrypted VM:
   ```
   bash ./run.sh 
   ```

## Git Hooks

You can find some useful git hooks in the `.githooks` directory.
To use them, run the following command after cloning this repository:

```sh
git config --local core.hooksPath .githooks
````
