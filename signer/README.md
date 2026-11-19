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
  --tls-known-clients knownClients.txt   # optional mTLS
```

* **TLS.** On first start the signer generates a TLS key and a self-signed certificate in
  `<data-dir>/tls/`. Configure the validator client to trust `cert.pem`. In a TEE deployment, obtain
  the certificate from attestation evidence rather than from the disk.
* **Public listener.** `--public-listen <addr>` adds a second TLS port with the same certificate and
  no client authentication. It serves only `/upcheck`, `/healthcheck` and `/api/v1/tee/attestation`,
  so peers and monitoring can fetch evidence while signing stays behind mTLS.
* **Development without TLS.** `--insecure-http` serves plain HTTP. It disables attestation.
* **Configuration from the environment.** Every flag also reads a `SEV_SIGNER_*` environment variable
  (see `--help`).

## API

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/v1/eth2/sign/{pubkey}` | Web3Signer request body. Returns `0x…` as text, or `{"signature"}` with `Accept: application/json`. Status codes: 400 invalid request, 403 blocked by policy, 404 unknown key, 412 slashing protection. |
| `GET` | `/api/v1/eth2/publicKeys` | |
| `GET` | `/upcheck`, `/healthcheck` | |
| `GET` | `/api/v1/tee/attestation?nonce=<32-byte hex>` | Raw configfs-tsm evidence, plus the TLS certificate and pubkeys bound into REPORT_DATA. |

Supported request types:
* `ATTESTATION`, `BLOCK_V2` (`block_header` only)
* `RANDAO_REVEAL`, `AGGREGATION_SLOT`
* `AGGREGATE_AND_PROOF` and `AGGREGATE_AND_PROOF_V2`
* `SYNC_COMMITTEE_MESSAGE`, `SYNC_COMMITTEE_SELECTION_PROOF`, `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF`
* `VOLUNTARY_EXIT` (EIP-7044), `VALIDATOR_REGISTRATION`, `DEPOSIT` (off by default)

The signer always recomputes the signing root itself. A `signingRoot` sent by the client is only
compared against the computed one. `AGGREGATE_AND_PROOF` (v1) accepts both the phase0 and the
Electra attestation, chosen by the presence of `committee_bits`, because Lighthouse and Teku still
send the v1 type after Electra.

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
sev-signer verify-evidence --evidence evidence.json --nonce $NONCE --expected-measurement <hex>
# then verify the report's hardware signature, e.g. for SEV-SNP:
#   jq -r .report evidence.json | xxd -r -p > report.bin   (strip the 0x prefix first)
#   snpguest fetch ca ...; snpguest fetch vcek ...; snpguest verify attestation ...
```

`verify-evidence` checks three things:
* the REPORT_DATA binding (nonce, TLS certificate and BLS keys);
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
* **Import.** Import EIP-3076 history with `--slashing-protection-import file.json` at startup.
* **Export.** Export it with `sev-signer slashing-export --data-dir … --network …`.

## Tests

```sh
cargo test
cargo test --features insecure-dev
```

* **Test vectors.** `tests/vectors/` holds request bodies, signing roots and signatures, plus EIP-2335
  keystores. They were generated by `tests/vecgen` with go-eth2-client, herumi BLS and the wealdtech
  keystore encryptor, the same stack charon uses.
* **Regenerating them.** Run `cd tests/vecgen && go run . ../vectors`.
