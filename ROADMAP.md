# sev-signer: status and roadmap

Assessment from October 2026 of where `sev-signer` (and its siblings `consigner`, `dvtee`,
`remote-signer`) stand as the basis for a Web3Signer-like signer in AMD SEV-SNP (later Intel TDX / Arm
CCA) for Obol distributed validators. It also lists what the `feat/tee-signer` branch adds, and what is
left before it can be deployed in production.

## TL;DR

* **No repo was close.** Before this branch, no repo had a working, correct, TEE-hosted BLS signer:
  * `sev-signer` had a hardened-image idea but no signer.
  * The PoC (`poc/`, `dvtee`) had a signer (stock Web3Signer) but no hardening.
  * `consigner`, the Rust signer, produced invalid signatures for several duty types and had no
    slashing protection.
* **`remote-signer` is a different product.** It is a secp256k1 EVM wallet signer for Obol Stack
  agents. It is reasonable code with good engineering hygiene, but nothing in it signs validator duties.
* **This branch adds `signer/` (`tee-signer`).** It is a small Rust Web3Signer-compatible eth2 signer
  with:
  * recomputed signing roots, cross-checked against go-eth2-client and herumi BLS for all 13 request
    types;
  * durable EIP-3076 slashing protection;
  * TLS terminated inside the guest, plus optional pinned-cert mTLS;
  * a vendor-neutral attestation endpoint (configfs-tsm) that binds the evidence to the TLS key and the
    BLS key set.
* **The biggest remaining gap is the guest image, not the signer.** The current Alpine image is unsafe
  as built (details below). Replace it with a reproducible mkosi image rather than patching it.

## Findings

### sev-signer (image tooling, last touched January 2025)

Good ideas worth keeping:

* UKI boot with `kernel-hashes=on`, so kernel, initramfs and cmdline are measured.
* The dm-verity root hash on the measured cmdline.
* A disk key derived from the SNP measurement.

As built, though, the image does not protect a signer:

| # | Severity | Finding |
|---|----------|---------|
| 1 | Critical | **`/var` and `/home` are plain ext4 with no encryption or integrity** (`install.sh` partitions 3 and 4). The root is read-only, so these are the *only* writable locations. Any key, password or slashing DB would sit in cleartext on host-controlled disk. Only the immutable root, which is public code, is encrypted. That is backwards. |
| 2 | Critical | **The host can get a shell inside the guest.** Accounts are `root:root` and `signer:signer` with `doas nopass`. openssh is installed and port 22 is forwarded. The serial console is on stdio. Every failed initramfs step (`eend`) drops to `/bin/busybox sh`; `rd.shell=0` is not honoured by this init. All of this is part of the *measured* image, so a valid attestation would vouch for an image the host can log into. |
| 3 | Critical | **The first-boot step that seals the disk to the SNP key looks unable to run as written** (not run on hardware). It lives in `runtime/user-data`, but `install.sh` disables cloud-init on the target root. It also writes `/crypto_keyfile.bin` and creates `/tmp/canary` on a root mounted read-only. If it doesn't run, the disk stays unlocked by the literal key `"0\n"`. |
| 4 | High | **Host-writable code runs inside the TEE.** `snpguest` is executed from `/home/signer/.cargo/bin`, which lives on the unauthenticated `/home` partition. |
| 5 | High | **A firmware update bricks the disk.** The key is derived with `--guest_file_select 111111`, which includes TCB version. Any AMD firmware or microcode TCB update changes the key, with no recovery path. |
| 6 | High | **No attestation flow.** Nothing produces or verifies a report for a remote party, and nothing binds a channel key to it. |
| 7 | High | **Not reproducible, so there is no expected measurement to compare against.** OVMF is now built reproducibly from pinned edk2 (`ovmf/`); the old blob is gone. Alpine and kernel 6.11 (EOL) are unpinned, `cargo install snpguest` takes the latest version at build time, and packages are installed with `apk --allow-untrusted`. |
| 8 | Medium | LUKS without integrity (no dm-integrity/AEAD): the host can tamper with or replay ciphertext sectors. There is also no rollback protection for state, which matters for slashing protection. |
| 9 | Low | The `Makefile` `provision-*`/`run-*` targets `cd` on a separate recipe line, so they run from the wrong directory. |

`poc/` and `dvtee` (an earlier copy of the same PoC) run stock `consensys/web3signer:develop`
(unpinned) inside an Ubuntu SNP guest that the operator administers over SSH:

* `eth2.slashing-protection-enabled: false`.
* Keystore passwords are `chmod 444` next to the keystores.
* `StrictHostKeyChecking no`.
* The attestation report is fetched, but its verification is a `TODO`.

They are useful as a demo of the DKG-in-TEE flow, but provide no security boundary.

### consigner (Rust Web3Signer PoC, October 2024)

* **Wrong signatures:**
  * RANDAO is signed with `DOMAIN_BEACON_PROPOSER`.
  * `AGGREGATE_AND_PROOF` is signed with `DOMAIN_SELECTION_PROOF`.
  * Deneb block headers use `state_root` as `body_root`.
  * The domain epoch is always `fork.epoch`, so the previous fork version is never used.
  * Exits and validator registrations hard-code mainnet constants.
* **Root handling is inverted.** `has_provided_root = root.is_empty()`, so a client-provided
  `signingRoot` is ignored. Most types also `unwrap()` it and panic when it is absent.
* **Not up to date:**
  * Sync committee types are `todo!()`.
  * It is pinned to Lighthouse 5.3, so it has no Electra or Fulu support.
* **No slashing protection.** The EIP-3076 payload is parsed on import, then dropped.
* **Secret key exposure:**
  * Keys are written in cleartext to SurrealDB/RocksDB.
  * They are logged at debug level (`log::debug!("{key:?}")` on a struct deriving `Debug` that
    includes the secret).
  * The keystore import endpoint has no authentication or TLS.

Recommendation: archive it. `signer/` supersedes it.

### remote-signer (Obol Stack EVM wallet signer, active)

* **Engineering hygiene is good:**
  * `secrecy` for secrets;
  * a distroless, non-root image;
  * CI, cargo-deny and renovate;
  * constant-time bearer token comparison;
  * integration tests.
* **Not relevant to validators.** It signs secp256k1 transactions and messages, so nothing in it
  helps BLS validator signing.
* **Things to tighten for its own use case:**
  * It binds `0.0.0.0` with auth off by default.
  * `/sign/{address}/hash` is a blind signing oracle.
  * One password unlocks every keystore.
* **TEE fit.** It could later share the same confidential-VM base image (agent wallets in a TEE), but
  it does not belong on the validator signer's critical path.
* **Local testing.** Its dev-dependency `reqwest` needs `libssl-dev` to build tests locally.

## What `signer/` (tee-signer) does now

* **Web3Signer eth2 API.** `POST /api/v1/eth2/sign/{pubkey}`, `GET /api/v1/eth2/publicKeys`,
  `/upcheck` and `/healthcheck`, with text or JSON responses selected by `Accept`.
* **All 13 request types through Fulu.** ATTESTATION, BLOCK_V2 (header), RANDAO_REVEAL,
  AGGREGATION_SLOT, AGGREGATE_AND_PROOF (v1 and V2/Electra), the three sync committee types,
  VOLUNTARY_EXIT (EIP-7044), VALIDATOR_REGISTRATION and DEPOSIT.
* **Never signs a client-provided root.** Each root is recomputed from the typed object, and the domain
  is chosen by request type. A mismatching `signingRoot` is rejected. A signer that blind-signs roots is
  a universal signing oracle, which would defeat the point of putting the key in a TEE.
* **Verified against an independent implementation.** Signing roots and signatures match go-eth2-client
  plus herumi BLS (`tests/vecgen`) byte for byte.
* **Network pinning.** Requests whose `genesis_validators_root` differs from the configured network are
  rejected (mainnet, hoodi, sepolia, or custom).
* **Policy.** Exits are allowed by default (Lido DVs need them); deposits are denied by default.
* **Slashing protection.** Per-key low watermarks, fsynced before the signature is released. Supports
  EIP-3076 import at startup and `slashing-export`.
* **Keystores.** Loads EIP-2335 keystores in charon's `validator_keys/` layout (scrypt and pbkdf2,
  NFKD password processing).
* **TLS.** Rustls TLS inside the guest. The key is generated on first boot into the data directory, and
  client certificates can optionally be pinned in Web3Signer `knownClients` format. Lighthouse and Teku
  both support both.
* **Attestation.** `GET /api/v1/tee/attestation?nonce=` uses configfs-tsm, so the same code serves
  SEV-SNP, TDX and CCA. REPORT_DATA binds the nonce, the TLS certificate and the BLS key set.
* **Offline evidence check.** `tee-signer verify-evidence` checks the binding, the debug policy bit and
  the expected measurement.
* **Footprint.** About 2,500 lines of Rust including unit tests. There is no consensus types library; SSZ merkleization is
  hand-rolled in about 100 lines and covered by the vectors.

**Not yet verified:** it has not run inside a real SNP guest. The configfs-tsm path and the SNP and TDX
report offsets come from the specs; they have not been exercised on hardware.

## Path to production for Obol DVs

### DV-specific design choices

1. **Generate shares inside the TEE.** Run `charon dkg` inside the guest so a key share never exists
   outside it. The PoC already showed this flow.
2. **Recover by resharing, not by key export.** If a TEE node is lost (hardware failure, or a TCB change
   that alters the sealing key), the cluster still signs at threshold, and `charon edit
   replace-operator` / `recreate-private-keys` brings in a replacement. This makes strict sealing
   acceptable: no export path is needed, so there is none to attack.
3. **A compromised node holds only one share.** Below-threshold compromise cannot produce slashable
   signatures. What the TEE adds is protection for the share against a compromised host (theft,
   cloning, using the signer as an oracle), and in-TEE slashing protection.

### Phases

**Phase 1: a minimal guest that can be trusted (biggest gap)**

* Build the image with **mkosi**: reproducible builds, a UKI, a dm-verity root via systemd-repart, and
  a data partition on LUKS2 with dm-integrity (AEAD).
* No shell, no getty, no sshd and no passwords. The only network listener is tee-signer (plus charon
  for DKG). Logs go out over the network or the serial console.
* Pin and build the kernel from source (OVMF: done, see `ovmf/`).
* Publish expected launch measurements computed with `sev-snp-measure`.
* Seal the data key with the SNP derived key using `MEASUREMENT | POLICY` and a pinned **minimum**
  TCB (snpguest `--tcb_version`), not the current TCB. That way firmware updates don't brick the disk
  and downgrades below the minimum can't unseal it.

**Phase 2: attestation in the operator workflow**

* Add a verifier that checks the AMD chain (ARK → ASK → VCEK from KDS), the report signature, the
  measurement, the policy (debug off, SMT/migration policy) and the binding. Wrap
  `snpguest verify` / `sev` crate or ship a Go verifier.
* Pin the attested TLS certificate in the validator client's web3signer configuration.
* Optionally, have charon verify the signer's evidence at startup and periodically, and expose it
  as a metric.

**Phase 3: hardening the state**

* **Anti-rollback for slashing protection.** The host can restore an old disk snapshot. Cheap
  mitigations:
  * refuse to sign until the signer has observed the chain head and set its watermarks to at least
    `head_epoch - 1`. This works like doppelganger detection: it keys off a quorum of beacon nodes
    or the charon cluster's view;
  * use SNP SecureTSC (Genoa and later) for monotonic time.
* **Defence in depth for the threshold.** Charon cluster consensus means only agreed duties reach
  the signer. The signer could also refuse slot or epoch far from wall clock.
* Prometheus metrics, rate limits and fuzzing of the request parsers.

**Phase 4: Intel and Arm**

* The signer already uses configfs-tsm.
* The image needs TDX-capable OVMF/TDVF builds and RTMR-based measurement.
* **TDX has no sealing-key primitive.** Its data key must come from a key broker (attested KMS), or
  from re-running DKG/reshare into each new TD. The DV reshare path above makes the second option
  viable without new infrastructure.

### Hosting reality check

* `kernel-hashes=on` with a custom OVMF requires a host you control: bare-metal SNP or a
  provider that lets you launch your own SNP guests. Azure, GCP and AWS confidential VMs use their own
  firmware or paravisor, which changes what the measurement covers and how the disk key is sealed.
* SEV-SNP's threat model assumes the hypervisor is malicious, but physical attacks are out of scope.
  Physical memory attacks (BadRAM, Battering RAM) work against a party with access to the DIMMs. A
  datacenter-level adversary is therefore only partly covered. This matters for the product's
  positioning.
