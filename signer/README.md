# sev-signer

A Web3Signer-compatible eth2 BLS remote signer, built to run inside a confidential VM. It targets
AMD SEV-SNP today, and Intel TDX and Arm CCA through Linux configfs-tsm. See `../ROADMAP.md` for
status and the remaining work.

## Run

```sh
cargo build --release
./target/release/sev-signer serve \
  --network hoodi \
  --keystores-dir /path/to/.charon/validator_keys \
  --data-dir /var/lib/sev-signer \
  --listen 0.0.0.0:9000 \
  --tls-san signer.internal \
  --tls-known-clients knownClients.txt \ # optional mTLS, with roles
  --cluster-lock /path/to/.charon/cluster-lock.json   # pins fee recipients
```

* **TLS.** On first start the signer generates a TLS key and a self-signed certificate in
  `<data-dir>/tls/`. Configure the validator client to trust `cert.pem`. In a TEE deployment, obtain
  the certificate from attestation evidence rather than from the disk.
* **Public listener.** `--public-listen <addr>` adds a second TLS port with the same certificate and
  no client authentication. It serves only `/upcheck`, `/healthcheck` and `/api/v1/tee/attestation`,
  so peers and monitoring can fetch evidence while signing stays behind mTLS.
* **Client roles.** `knownClients.txt` takes an optional third column with each certificate's roles,
  comma-separated: `duties` (every validator duty, registrations and Gloas duties included), `exit`
  (`VOLUNTARY_EXIT`) and `deposit` (`DEPOSIT`, which `--allow-deposits` must also enable). Anything
  not granted gets 403. Give the validator client `duties`, and give `exit` to a separate certificate
  held by whoever signs exits:
  ```
  vc-node0 59:E9:72:...:2F:DA duties
  ops      0B:41:84:...:25:A8 exit
  ```
  A line without a third column (Web3Signer's format) gets `duties,exit`, as every client did before
  roles; the signer logs a warning.
* **Cluster lock.** `--cluster-lock` pins the signer to a charon cluster lock on first start. The
  signer checks the lock's hashes and aggregate signature, requires every loaded key to be one of its
  public shares at a single operator index, and stores the lock in `<data-dir>/cluster-lock.json`.
  After that it refuses to start with any other lock. A new lock means new shares, so it needs a new
  signer (a reshare or recover into a fresh guest), not a restart. While pinned:
  * `VALIDATOR_REGISTRATION` must carry the lock's fee recipient and the share's validator pubkey;
  * Gloas `PROPOSER_PREFERENCES` and self-built `EXECUTION_PAYLOAD_ENVELOPE`s must carry the lock's
    fee recipient;
  * gas limits are not pinned, and pre-Gloas blocks are signed as headers, so their fee recipient
    can't be checked;
  * charon's runtime fee recipient changes (proposer configuration) don't apply to a pinned signer:
    their requests are refused.

  The lock hash is bound into attestation evidence (see below). Lock versions v1.7.0 to v1.11.0 are
  supported.
* **Development without TLS.** `--insecure-http` serves plain HTTP. It disables attestation.
* **Configuration from the environment.** Every flag also reads a `SEV_SIGNER_*` environment variable
  (see `--help`).

### Networks

The signer needs each network's genesis validators root and fork schedule. It cannot take them from
the request.

* **`--network mainnet|hoodi|sepolia`.** These presets carry every fork version and epoch up to Gloas.
  Gloas is not scheduled on mainnet or Hoodi. It is scheduled on Sepolia at epoch 353024.
* **`--network <path/to/config.yaml> --genesis-validators-root <hex>`.** As with Web3Signer's and
  Teku's `--network`, a value that is a path (it contains `/` or ends in `.yaml`) is read as a standard
  consensus `config.yaml`, such as a Kurtosis devnet's `network-configs/config.yaml`. The config file
  has no genesis validators root, so it is passed separately (Web3Signer learns it from the first
  request instead; sev-signer pins it). URLs are not fetched. Use it
  for devnets, and for a public network whose schedule changed after this build. Only flat
  `KEY: value` lines are read. The config is refused if `PRESET_BASE` is not `mainnet`, if the
  schedule is inconsistent, or if it schedules a fork after Gloas.
* **`--network custom:<gvr>:<genesis_fork_version>:<capella_fork_version>`.** This still works but has
  no fork schedule. Versions are taken from the request, and the Gloas-only request types are refused.

## API

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/v1/eth2/sign/{pubkey}` | Web3Signer request body. Returns `0x…` as text, or `{"signature"}` with `Accept: application/json`. Status codes: 400 invalid request, 403 blocked by policy, 404 unknown key, 412 slashing protection. |
| `GET` | `/api/v1/eth2/publicKeys` | |
| `GET` | `/upcheck`, `/healthcheck` | |
| `GET` | `/api/v1/tee/attestation?nonce=<32-byte hex>` | Raw configfs-tsm evidence, plus the TLS certificate, pubkeys and pinned cluster lock hash bound into REPORT_DATA. |

Supported request types:
* `ATTESTATION`, `BLOCK_V2` (`block_header` only)
* `RANDAO_REVEAL`, `AGGREGATION_SLOT`
* `AGGREGATE_AND_PROOF` and `AGGREGATE_AND_PROOF_V2`
* `SYNC_COMMITTEE_MESSAGE`, `SYNC_COMMITTEE_SELECTION_PROOF`, `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF`
* `VOLUNTARY_EXIT` (EIP-7044), `VALIDATOR_REGISTRATION`, `DEPOSIT` (off by default)
* Gloas, as in remote-signing-api v1.4.0:
  * `PAYLOAD_ATTESTATION_MESSAGE`, `PROPOSER_PREFERENCES` and `BUILDER_REQUEST_AUTH`;
  * `EXECUTION_PAYLOAD_ENVELOPE`, for self-built payloads only (see below);
  * the `GLOAS` versions of `BLOCK_V2` and `AGGREGATE_AND_PROOF_V2`.
* `EXECUTION_PAYLOAD_BID` is always refused with 403. Builders sign bids, validators do not.

The signer always recomputes the signing root itself. A `signingRoot` sent by the client is only
compared against the computed one.

The network's fork schedule decides what a request may claim:
* **V2 requests.** The `version` of a V2 request must name the fork at its slot. This applies to
  `BLOCK_V2`, `AGGREGATE_AND_PROOF_V2` and the Gloas types.
* **Gloas-only types.** These also need Gloas to be active at their slot.
* **v1 `AGGREGATE_AND_PROOF`.** Lighthouse and Teku still send the v1 type after Electra. It carries no
  version, so the fork at the aggregate's slot picks the attestation schema: phase0, Electra, or the
  Gloas progressive container. `committee_bits` must be present from Electra on and absent before.
* **`PROPOSER_PREFERENCES`.** The domain uses the fork version of the proposal epoch from the schedule,
  not `fork_info`, because preferences for the first Gloas slots are signed before the fork.
  `BUILDER_REQUEST_AUTH` has no `fork_info`. Its domain uses the genesis fork version and a zero
  genesis validators root.
* **`EXECUTION_PAYLOAD_ENVELOPE`.** The signer only signs an envelope with `builder_index` equal to
  `BUILDER_INDEX_SELF_BUILD` whose `beacon_block_root` and `payload.slot_number` match the last block
  this key signed. Other builders' envelopes get 403. An envelope for a block the key did not sign gets
  412. The block's root is recorded with its slashing watermark.
* **Body size.** Sign requests may be up to 32 MiB, enough for a full execution payload in JSON.

Rejected requests (4xx) are logged at `warn` with the reason. Request bodies are not logged.

## Validator clients

Tested on a Kurtosis devnet (Electra and Fulu at genesis, 32-slot epochs) with each client signing
through its own sev-signer as one operator of a 3-of-4 charon cluster. The harness is
[`e2e/devnet/`](../e2e/devnet/README.md).

| Client | Version | Works | Pinned server cert | mTLS client cert | Credentials in URL (`https://x:token@…`) |
|---|---|---|---|---|---|
| Lighthouse | v8.3.3 | yes | `root_certificate_path` | `client_identity_path` + `_password` (PKCS#12) | Basic, sent on every request |
| Teku | 26.10.3 | yes | `--validators-external-signer-truststore` (PKCS#12) | `--validators-external-signer-keystore` | Basic, HTTPS only, sent after a `401` with `WWW-Authenticate: Basic` |
| Lodestar | v1.50.1 | yes | `NODE_EXTRA_CA_CERTS` | none | rejected at startup |
| Prysm | v7.3.1 | yes | `SSL_CERT_FILE` | none | Basic, sent on every request |
| Nimbus | v26.10.2 | no | none: ignores IP SANs, and has no CA option | none | Basic, sent on every request |

Each client signed attestations, blocks, RANDAO reveals, aggregation selection proofs, aggregates
and all sync committee kinds; Lighthouse also signed builder registrations. Lighthouse and Teku send
aggregates as the v1 `AGGREGATE_AND_PROOF` type, Lodestar and Prysm as `AGGREGATE_AND_PROOF_V2`.
Charon verified every partial signature it received, and threshold aggregates combining v1 and v2
partials were accepted on chain.

## Verifying a signer

```sh
NONCE=$(openssl rand -hex 32)
curl --cacert cert.pem "https://signer:9000/api/v1/tee/attestation?nonce=$NONCE" > evidence.json
sev-signer verify-evidence --evidence evidence.json --nonce $NONCE --expected-measurement <hex> \
  --expected-cluster-lock-hash $(jq -r .lock_hash cluster-lock.json)
# then verify the report's hardware signature, e.g. for SEV-SNP:
#   jq -r .report evidence.json | xxd -r -p > report.bin   (strip the 0x prefix first)
#   snpguest fetch ca ...; snpguest fetch vcek ...; snpguest verify attestation ...
```

`verify-evidence` checks:
* the REPORT_DATA binding (nonce, TLS certificate, BLS keys and, when pinned, the cluster lock hash);
* with `--expected-cluster-lock-hash`, that the signer is pinned to your lock;
* that the guest debug policy is off;
* the launch measurement.

It does **not** verify the AMD or Intel signature chain yet.

## Sealing key

`sev-signer sealing-key` writes a 32-byte key to stdout, for example to unlock the data disk with
`cryptsetup open --key-file=-`. On SEV-SNP it asks the firmware for a key derived from the chip's
VCEK, the launch measurement, the guest policy and a pinned minimum TCB
(`--snp-min-tcb <raw TCB_VERSION hex>`), then derives a per-purpose key from it (`--purpose`,
default `data-disk`). Only the same measured image on the same chip can derive it. A host move
changes the chip, so the key is lost. That is why the design relies on charon `replace-operator` or a
reshare for recovery.

This path has not yet been run on an SNP guest. The kernel struct layouts are pinned by unit tests.

## Development without SEV-SNP (`insecure-dev`)

A build with `--features insecure-dev` adds `--platform insecure-dev`, a software stand-in for the
TEE. It lets the rest of the system be built and tested on any Linux machine: e2e with a validator
client and charon, the disk-unlock flow, and the verifier.

```sh
cargo build --features insecure-dev
./target/debug/sev-signer serve --platform insecure-dev \
  --insecure-dev-root-key ./dev-root.key \
  --network hoodi --keystores-dir … --data-dir ./data
```

* **No security.** Keys are readable by the host and evidence is unsigned.
* **Mainnet is refused.** The check uses the genesis validators root and fork version, so `custom:`
  doesn't get around it.
* **Evidence.** The provider is `insecure_dev`, in the SNP report layout. The measurement is the
  SHA-384 of the running binary, and the debug policy bit is set. `verify-evidence` rejects it
  unless you pass `--allow-insecure-dev`.
* **Sealing key.** It is derived from the root key file, which is created if missing. Keep the file
  outside the data dir. Delete it to simulate a host move.
* **Not in release images.** Release builds (the `Dockerfile`) never enable the feature. A default
  build rejects `--platform insecure-dev`.

## Slashing protection

* **Storage.** One JSON watermark file per key in `<data-dir>/slashing/`, pinned to the network's
  genesis validators root.
* **Block roots.** The block watermark also records the signed block's root (`block_root`). Records
  written before this field existed still load. An identical re-sign of the same block fills the field
  in. Until then, and after an interchange import, the key has no block root on record, so no
  execution payload envelope is signed for that block.
* **Import.** Import EIP-3076 history with `--slashing-protection-import file.json` at startup.
* **Export.** Export it with `sev-signer slashing-export --data-dir … --network …`.

## Tests

```sh
cargo test
cargo test --features insecure-dev
```

* **Test vectors.** `tests/vectors/` holds request bodies, signing roots and signatures, plus EIP-2335
  keystores. They were generated by `tests/vecgen` with upstream go-eth2-client v0.30.3, herumi BLS and
  the wealdtech keystore encryptor. This is the stack charon uses, without charon's go-eth2-client
  fork.
* **Regenerating them.** Run `cd tests/vecgen && go run . ../vectors`.
* **Gloas vectors.** The Gloas vectors use go-eth2-client's `spec/gloas`. They run on Hoodi with Gloas
  scheduled at epoch 60000 (`tests/vectors/gloas-config.yaml`).
* **Web3Signer examples.** `tests/web3signer_examples.rs` checks Web3Signer 26.9.0's OpenAPI Gloas
  request examples (Apache-2.0, vendored in `tests/vectors/`).
* **Spec tests.** The consensus spec tests (v1.7.0-beta.4 `ssz_static`) and the ssz-specs progressive
  vectors are not vendored. Fetch and run them with:

  ```sh
  scripts/fetch-spec-tests.sh            # streams ~1 GB, extracts ~1 MB into spec-tests/
  SPEC_TESTS_DIR=$PWD/spec-tests cargo test --test spec_tests -- --nocapture
  ```
