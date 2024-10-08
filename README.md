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
