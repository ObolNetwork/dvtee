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
  * recomputed signing roots for every request type through Gloas, cross-checked against
    go-eth2-client with herumi BLS, the consensus spec tests and Web3Signer's own examples;
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
* **Request types through Gloas.** ATTESTATION, BLOCK_V2 (header), RANDAO_REVEAL,
  AGGREGATION_SLOT, AGGREGATE_AND_PROOF (v1 and V2, phase0 to Gloas), the three sync committee types,
  VOLUNTARY_EXIT (EIP-7044), VALIDATOR_REGISTRATION and DEPOSIT, plus the Gloas types
  PAYLOAD_ATTESTATION_MESSAGE, PROPOSER_PREFERENCES, EXECUTION_PAYLOAD_ENVELOPE (self-built blocks
  only, and only for a block this signer signed) and BUILDER_REQUEST_AUTH. EXECUTION_PAYLOAD_BID is
  refused: it is a builder's message.
* **Fork schedule.** Presets carry each fork's version and epoch, and `--network-config` loads a
  standard consensus `config.yaml` (devnets). A request's fork version and schema must match the fork
  at its slot.
* **Never signs a client-provided root.** Each root is recomputed from the typed object, and the domain
  is chosen by request type. A mismatching `signingRoot` is rejected. A signer that blind-signs roots is
  a universal signing oracle, which would defeat the point of putting the key in a TEE.
* **Verified against an independent implementation.** Signing roots and signatures match go-eth2-client
  plus herumi BLS (`tests/vecgen`) byte for byte.
* **Network pinning.** Requests whose `genesis_validators_root` differs from the configured network are
  rejected (mainnet, hoodi, sepolia, or custom).
* **Policy.** Exits are allowed by default; deposits are denied by default.
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
* **Footprint.** No consensus types library. SSZ merkleization, including the progressive types Gloas
  uses (EIP-7916, EIP-7495), is hand-rolled and checked against the consensus spec tests (v1.7.0-beta.4
  `ssz_static`) and the ssz-specs progressive vectors.

**Not yet verified:** it has not run inside a real SNP guest. The configfs-tsm path and the SNP and TDX
report offsets come from the specs; they have not been exercised on hardware.

## Where it fits: one diverse share in a cluster


Cloud TEE signers, such as [lidofinance/tee-signer](https://github.com/lidofinance/tee-signer) on AWS
Nitro, Azure SEV-SNP and GCP Confidential Space, seal keys with a cloud KMS policy, so the cloud vendor stays in the trust base for the key itself.
sev-signer is chip-specific instead: AMD SEV-SNP, with the chip as the sealing root and attestation
checked against AMD's own certificate chain. It still runs on rented machines, but the provider can stop
it, not unseal it. The two fail in different ways, which is the point of running both in one cluster.

| | Cloud-KMS-sealed TEE signers (typical) | sev-signer (target design) |
|---|---|---|
| Sealing root | Cloud KMS / Key Vault policy | SNP derived key (`MSG_KEY_REQ`) over measurement, policy and a minimum TCB |
| Who else can unseal | The cloud vendor and its recovery processes | Nobody but AMD firmware; physical DIMM attacks are out of scope |
| Key creation | Often a dealer outside the TEE, then import | Charon DKG pushes the share over attested TLS (plan A), or `charon dkg` runs inside the guest (plan B) |
| Recovery | Re-import of shares kept outside the TEE, or a TEE-to-TEE handover | charon reshare or `replace-operator` |
| Upgrade | New image key policy, then re-import or handover | Reshare into the new image's measurement |
| Hosting | AWS Nitro, Azure and GCP confidential VMs | Operator-controlled AMD SEV-SNP hardware first (owned or rented bare metal); cloud SNP guests that reach the chip directly (AWS EC2) as an option |
| Attestation trust | Cloud-signed tokens or cloud PKI | The raw SNP report, checked against AMD's chain |

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

1. **Key shares only enter the guest encrypted to it.**
   * **Plan A: the keymanager API.** `charon dkg --keymanager-address … --keymanager-auth-token …`
     already pushes new shares to a keymanager instead of writing them to disk. sev-signer would
     implement the keymanager import endpoint (`POST /eth/v1/keystores`, bearer token as the spec
     requires) on the mTLS listener.
     * Charon would first verify the signer's attestation and pin the TLS certificate bound into it.
       Then the keystore and its password reach only the measured guest.
     * That is a small extension on charon's side, and possibly in the keymanager API, if we want
       the share encrypted to a guest key rather than only protected by TLS.
     * Limit: the share still exists in charon's memory on the DKG host during the ceremony.
   * **Plan B: `charon dkg` inside the guest.** The share is then generated inside and never exists
     outside it. The PoC showed this flow. It costs running charon in the image during DKG and
     reshares.
2. **Recover by resharing, not by key export.** If a TEE node is lost (hardware failure, a TCB change
   that alters the sealing key, or a cloud stop/start that lands the VM on a different chip), the cluster still signs at threshold, and `charon edit
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
7. **Proposed: settings are pinned, not flags.**
   * The fee recipient for builder registrations, and whether exits are allowed, are fixed when the
     signer is provisioned. They are stored on the sealed disk.
   * `VALIDATOR_REGISTRATION` is refused unless its fee recipient matches. The natural source is the
     cluster lock, which every operator signed.
   * Exits stay allowed by default (see Known gaps), but flipping that, or changing the fee
     recipient, needs an explicit operator-signed configuration change, not a restart with a new flag.
   * In a DV, a change then needs a threshold of operators to confirm it on their own signers, which
     matches charon's existing `feerecipient sign` flow.

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
  and downgrades below the minimum can't unseal it. The signer side is done (`sev-signer sealing-key`,
  untested on hardware); the image still has to call it from the initrd.

**Phase 2: attestation in the operator workflow**

* Add a verifier that checks the AMD chain (ARK → ASK → VCEK from KDS), the report signature, the
  measurement, the policy (debug off, SMT/migration policy) and the binding. Wrap
  `snpguest verify` / `sev` crate or ship a Go verifier.
* Pin the attested TLS certificate in the validator client's web3signer configuration.
* Have charon verify peers' signer evidence at startup and periodically, and expose it as a metric
  (design choice 4).
* **Client authentication in depth: mTLS and a bearer token.**
  * **Why two secrets.** sev-signer pins client certificates, so a public CA failure can't forge a
    client. But a client key can still be weakly generated or leak; in October 2026 a public CA's
    intermediate keys turned out to be derivable from their certificates. A second, independently
    generated secret covers that case.
  * **Where it is required.** The keymanager import endpoint (design choice 1) needs the token
    anyway, because the keymanager API specifies a bearer token.
  * **Public listener.** `--public-listen` serves health and attestation on a second TLS port with
    the same certificate and no client authentication, so peers can fetch evidence while signing
    stays behind mTLS.
  * **mTLS.** Keep pinned client certificates (`--tls-known-clients`) on by default.
  * **Bearer token.** Add `--auth-token-file`.
    * Require `Authorization: Bearer <token>` on `/api/v1/eth2/*`, compared in constant time.
    * Also accept the token as the password of HTTP Basic auth, because validator clients can only
      put credentials in the URL (`https://x:<token>@signer`).
    * Answer missing credentials with `401` and `WWW-Authenticate: Basic`. Teku only sends Basic
      credentials after that challenge.
    * The public listener is unaffected.
    * Never accept the token in a query string, and never log the `Authorization` header or URL
      userinfo.
  * **Validator client support** (devnet survey, see [`signer/README.md`](signer/README.md#validator-clients)).
    No client has a header option. Lighthouse, Prysm and Nimbus send URL credentials as Basic auth
    on every request; Teku does after a `401` challenge, over HTTPS only. Only Lighthouse and Teku
    support a client certificate. Lodestar supports neither, so a Lodestar signer is protected only
    by network isolation until upstream adds one of them.
  * **Provisioning.** Generate the token in the guest at first start and store it on the sealed disk.
    Hand it out once, over the attested, mTLS-authenticated channel. Rotate it by restarting with a
    new file.

**Phase 3: hardening the state**

* **Anti-rollback for slashing protection.** The host can restore an old disk snapshot. Cheap
  mitigations:
  * refuse to sign until the signer has observed the chain head and set its watermarks to at least
    `head_epoch - 1`. This works like doppelganger detection: it keys off a quorum of beacon nodes
    or the charon cluster's view;
  * use SNP SecureTSC (Genoa and later) for monotonic time.
* **Defence in depth for the threshold.** Charon cluster consensus means only agreed duties reach
  the signer. The signer could also refuse slot or epoch far from wall clock.
* Prometheus metrics and fuzzing of the request parsers.

**Phase 4: Intel and Arm**

* The signer already uses configfs-tsm.
* The image needs TDX-capable OVMF/TDVF builds and RTMR-based measurement.
* **TDX has no sealing-key primitive.** Its data key must come from a key broker (attested KMS), or
  from re-running DKG/reshare into each new TD. The DV reshare path above makes the second option
  viable without new infrastructure.

### Hosting

**Decision: operator-controlled AMD SEV-SNP hardware first, cloud SNP as an option.** The primary
target is EPYC (Milan or later) servers the operator owns or rents as bare metal, with our own pinned
OVMF build. Cloud SNP guests that reach the chip directly (AWS EC2 SNP instances) are a secondary
target. The aim is to take every third party out of key custody, not to be cloud-agnostic.

* **Why chip-specific.** Only SNP gives the guest a sealing key derived by the chip (`MSG_KEY_REQ`),
  so no KMS policy, IAM role or support process can release the key. Intel TDX has no equivalent,
  so a TDX signer needs an external key broker, which brings the cloud back into key custody.
* **Platforms that don't fit.** Azure confidential VMs run a paravisor between the guest and the
  chip, and Nitro Enclaves are not SNP. Both put the cloud back in the attestation or sealing path.
* **What the cloud still controls.** It supplies the launch firmware on EC2, so we pin and verify a
  published measurement rather than our own OVMF build (`ovmf/` stays for VPS and bare-metal hosts).
  It can stop the VM, roll back its disk, or attack the hardware physically. SEV-SNP's threat model
  leaves physical memory attacks (BadRAM, Battering RAM) out of scope.
* **Host moves lose the sealed share.** A chip-derived key is unique to one physical CPU, so a
  stop/start or host migration lands the VM on a chip that can't unseal its data. In a DV cluster
  that is a lost node: the cluster keeps signing at threshold, and `charon edit replace-operator` or a
  reshare brings it back. Plan operations around it, and size clusters with n − t ≥ 2.
* **To verify on real instances:** that EC2 SNP guests get `/dev/sev-guest` derived keys and the raw
  report, and what the launch measurement covers there (firmware only, or kernel, initramfs and
  command line too).

## Known gaps

The honest state today. None of these are hidden; most are planned in the phases above.

| Area | State |
|---|---|
| Hardware | Never run in a real SNP guest. configfs-tsm reading and the SNP/TDX report offsets come from the specs. The SNP derived-key ioctl behind `sealing-key` is pinned to the kernel UAPI header by tests but has not been run. Everything else can be developed on any Linux machine with the `insecure-dev` platform (see [`signer/README.md`](signer/README.md)). |
| End-to-end | `e2e/devnet/` runs a Kurtosis devnet with a 3-of-4 charon cluster where Lighthouse, Teku, Lodestar and Prysm each sign through their own sev-signer (insecure-dev). Over two runs: charon accepted every partial signature, every duty type including aggregates reached the chain, DV duties kept working with one node down, and slashing protection held across signer restarts. Runs are manual (about 4 GB of RAM, 15–40 minutes), not in CI. Only the insecure-dev platform has been tested. `e2e/simnet.sh` is a lighter local smoke test on charon's beacon mock. |
| Attestation verification | `verify-evidence` checks the binding, debug bit and measurement, but not the AMD chain (ARK → ASK → VCEK) or the report signature. |
| Minimum TCB | `sealing-key` mixes a pinned minimum TCB into the SNP key. The verifier does not check it yet. |
| Guest image | The 2024 Alpine image is unsafe for keys (see Findings). The mkosi image is not started. |
| Anti-rollback | None. A restored disk snapshot rolls back slashing watermarks. |
| Forks | Gloas types implemented against consensus-specs v1.7.0-beta.4 and remote-signing-api v1.4.0, and checked against the spec tests, go-eth2-client and Web3Signer's examples, but not yet run against validator clients on a Gloas devnet. The domains of the four new types have only go-eth2-client as an outside check. Gloas is still changing upstream, so each spec release needs re-checking. |
| Exits | By design, not a gap: `VOLUNTARY_EXIT` is permitted for any authorised client and is not rate limited. In a DV each signer holds one share, so an exit needs a threshold of operators to sign. |
| Operations | No metrics or request-parser fuzzing. |
| Client auth | Pinned-cert mTLS on the signing listener, plus an optional public listener for health and evidence. A token as a second factor is planned (Phase 2). Lodestar, Prysm and Nimbus can't present a client certificate, and Lodestar can't send a token either. |
| Key import | Keystores and password files are read from a directory. Encrypted import over the keymanager API, or DKG inside the guest, is planned (design choice 1). |
| Pinned settings | `VALIDATOR_REGISTRATION` signs any fee recipient, and exits and deposits are startup flags. Pinned, operator-confirmed settings are planned (design choice 7). |
| Review | Unaudited, with no external review yet. |
