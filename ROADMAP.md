# sev-signer: status and roadmap

Where `sev-signer` stands as a Web3Signer-compatible BLS signer for Obol distributed validators,
running in AMD SEV-SNP (later Intel TDX and Arm CCA), and what is left before it can hold real keys.
It was first written in October 2026 and is updated as the work moves.

This repo is published early, before end-to-end testing or hardening, so that others building TEE
signers can compare designs. Nothing here has run on SEV-SNP hardware or been audited. See
[Known gaps](#known-gaps) before drawing conclusions from the code.

## TL;DR

* **The signer (`signer/`, binary `sev-signer`) is a small Rust Web3Signer-compatible eth2 signer**
  with:
  * recomputed signing roots, cross-checked against go-eth2-client and herumi BLS for all 13 request
    types;
  * durable EIP-3076 slashing protection;
  * TLS terminated inside the guest, plus optional pinned-cert mTLS;
  * a vendor-neutral attestation endpoint (configfs-tsm) that binds the evidence to the TLS key and the
    BLS key set.
* **The biggest remaining gap is the guest image, not the signer.** The current Alpine image is unsafe
  as built (details below). Replace it with a reproducible mkosi image rather than patching it.
* **It is meant to be one share in a DV cluster, not a solo signer.** The design leans on the cluster
  for key generation (DKG inside the guest), recovery (reshare) and, later, anti-rollback. See
  [Where it fits](#where-it-fits-one-diverse-share-in-a-cluster).

## Findings

### Guest image tooling (2024 prototype, last touched January 2025)

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

`poc/` runs stock Web3Signer inside an Ubuntu SNP guest that the operator administers over SSH, with
slashing protection off and attestation verification left as a TODO. It demonstrates the
DKG-in-TEE flow but provides no security boundary.

Earlier Obol prototypes (an older copy of `poc/`, and a Rust Web3Signer prototype from 2024) were
reviewed at the same time and are superseded by `signer/`.

## What the signer does now

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
* **Offline evidence check.** `sev-signer verify-evidence` checks the binding, the debug policy bit and
  the expected measurement.
* **Footprint.** About 2,500 lines of Rust including unit tests. There is no consensus types library; SSZ merkleization is
  hand-rolled in about 100 lines and covered by the vectors.

**Not yet verified:** it has not run inside a real SNP guest. The configfs-tsm path and the SNP and TDX
report offsets come from the specs; they have not been exercised on hardware.

## Where it fits: one diverse share in a cluster

Cloud TEE signers, such as [lidofinance/tee-signer](https://github.com/lidofinance/tee-signer) on AWS
Nitro, Azure SEV-SNP and GCP Confidential Space, seal keys with a cloud KMS policy. sev-signer takes
the other branch: bare-metal SEV-SNP, with the chip as the sealing root. The two fail in different ways, which
is the point of running both in one cluster.

| | Cloud-KMS-sealed TEE signers (typical) | sev-signer (target design) |
|---|---|---|
| Sealing root | Cloud KMS / Key Vault policy | SNP derived key (`MSG_KEY_REQ`) over measurement, policy and a minimum TCB |
| Who else can unseal | The cloud vendor and its recovery processes | Nobody but AMD firmware; physical DIMM attacks are out of scope |
| Key creation | Often a dealer outside the TEE, then import | `charon dkg` inside the guest; the share never exists outside it |
| Recovery | Re-import of shares kept outside the TEE, or a TEE-to-TEE handover | charon reshare or `replace-operator` |
| Upgrade | New image key policy, then re-import or handover | Reshare into the new image's measurement |
| Hosting | Cloud confidential VMs | Bare-metal SNP you control, with your own OVMF and UKI |

Cluster shape guidance that follows from this:

* **No 1-of-1.** Any single TEE signer is a single point of failure for liveness and, with a hostile
  host, for safety. Use threshold.
* **Chip-family and vendor diversity.** No chip family, cloud or codebase should hold two shares. If
  another share runs on SNP in a cloud, run that one on Nitro or TDX instead, so one SNP firmware bug
  never hits two shares.
* **Leave liveness headroom.** TEE signers have more ways to be down than a plain key (restarts,
  attestation, re-provisioning). Size for n − t ≥ 2, so one signer can be mid-upgrade while another
  fails.

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
4. **Proposed: peers attest each other's signers** (needs charon changes). Each charon node fetches
   and verifies its peers' signer evidence at startup and on a timer, and exposes the result as a metric and a cluster health check.
   The cluster then knows how many of its shares are actually TEE-protected. No single-operator
   signer can offer that.
5. **Proposed: the cluster as anti-rollback witness** (needs charon changes). A TEE cannot stop the
   host from restoring an old disk snapshot, which rolls back slashing watermarks. In a DV, the other nodes know the latest duties the
   cluster agreed on. After a restart, the signer would refuse to sign until its watermarks are at or
   above what a threshold of peers report. Phase 3 builds on this. It needs no monotonic counter and
   no extra infrastructure.
6. **Clones are a host capability to design for.** A host can boot two guests from the same image.
   Both pass attestation and, if sealing is to `MEASUREMENT | POLICY`, both derive the same disk key.
   Within one cluster a clone holds the same share, so it cannot reach threshold on its own. It can
   still double-sign with that share, which the peer witness above and charon's consensus must catch.

### Phases

**Phase 1: a minimal guest that can be trusted (biggest gap)**

* Build the image with **mkosi**: reproducible builds, a UKI, a dm-verity root via systemd-repart, and
  a data partition on LUKS2 with dm-integrity (AEAD).
* No shell, no getty, no sshd and no passwords. The only network listener is sev-signer (plus charon
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
* Have charon verify peers' signer evidence at startup and periodically, and expose it as a metric
  (design choice 4).

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
* **Open decision: bare metal first, or cloud confidential VMs too.** Bare metal you control gives the
  full story above (own firmware, every boot component measured, the disk sealed to the measurement),
  but fewer operators can run it. Cloud CVMs are what operators can get, but the cloud supplies the
  firmware or paravisor and the disk key would come from a cloud vTPM or KMS. That is the cloud-KMS
  branch in the table above, which other projects already cover. Not decided yet; bare metal is
  what makes this a diverse share.

## Known gaps

The honest state today. None of these are hidden; most are planned in the phases above.

| Area | State |
|---|---|
| Hardware | Never run in a real SNP guest. configfs-tsm reading and the SNP/TDX report offsets come from the specs. |
| End-to-end | Never driven by a real validator client or charon cluster. Tested with vectors and curl only. |
| Attestation verification | `verify-evidence` checks the binding, debug bit and measurement, but not the AMD chain (ARK → ASK → VCEK) or the report signature. |
| Minimum TCB | Not enforced by the verifier or by sealing. |
| Guest image | The 2024 Alpine image is unsafe for keys (see Findings). The mkosi image is not started. |
| Anti-rollback | None. A restored disk snapshot rolls back slashing watermarks. |
| Forks | Request types through Fulu. The new Gloas signing domains (PTC attestations, proposer preferences, payload envelopes) are not implemented. |
| Exits | `VOLUNTARY_EXIT` is allowed by default for any authorised client. A DV partial exit is harmless below threshold, but production should default to off or gate it. |
| Operations | No metrics, rate limits or request-parser fuzzing. |
| Review | Unaudited, with no external review yet. |
