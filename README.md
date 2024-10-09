# `sev-signer`

Run a web3signer-enabled signing software in an AMD SEV-SNP virtual machine.

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

1. build the kernel image and initramfs:
   ```
   make kernel 
   ```
2. move in the `vm-scripts` directory and provision disks:
   ```
   cd vm-scripts
   bash ./provision-disk.sh
   ```
3. run!
   ```
    bash run.sh
   ```

## Git Hooks

You can find some useful git hooks in the `.githooks` directory.
To use them, run the following command after cloning this repository:

```sh
git config --local core.hooksPath .githooks
````
