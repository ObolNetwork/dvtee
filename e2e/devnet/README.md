# e2e/devnet: sev-signer behind four validator clients on a Kurtosis devnet

This is a 3-of-4 charon distributed validator on a real local chain, where every operator signs through
its own sev-signer and runs a different VC. Unlike `e2e/simnet.sh`, which runs against charon's beacon
mock, the chain here is real: blocks, attestations and aggregates have to be valid and get included. This
checks VC wire-format compatibility (for example the v1 `AGGREGATE_AND_PROOF` type that Lighthouse and
Teku send after Electra), and checks that charon accepts every partial signature sev-signer produces.

```
Kurtosis enclave: geth + Lighthouse BN, plus a Lighthouse VC with genesis keys 0..55
relay ─┬─ pod0: charon0 + sev-signer0 + Lighthouse VC  (mTLS)
       ├─ pod1: charon1 + sev-signer1 + Teku VC        (mTLS)
       ├─ pod2: charon2 + sev-signer2 + Lodestar VC    (server TLS only)
       └─ pod3: charon3 + sev-signer3 + Prysm VC       (server TLS only)
```

- **Chain:** mainnet preset, 12 s slots, Electra and Fulu at genesis, and 64 genesis validators.
- **DV keys:** genesis keys 56–63, derived from the genesis mnemonic and split 3-of-4. No Kurtosis VC
  holds them.
- **Pods:** each pod's containers share one network namespace, so the VC reaches charon at
  `127.0.0.1:3600` and sev-signer at `https://127.0.0.1:9000`. Those addresses match the signer's
  self-signed certificate SANs.
- **TLS:** Lodestar and Prysm have no client-certificate option, so signers 2 and 3 run without
  `--tls-known-clients`. They trust the signer certificate through `NODE_EXTRA_CA_CERTS` and
  `SSL_CERT_FILE` respectively.
- **Nimbus is not included.** It cannot reach a signer with a self-signed certificate: it ignores IP SANs
  and has no CA option.

## Requirements

- Linux with Docker, and the user in the `docker` group.
- [Kurtosis CLI](https://docs.kurtosis.com/install) **1.22.2** (tested), with access to GitHub to fetch
  `github.com/ObolNetwork/ethereum-package@6.1.0-obol.6`.
- charon with `--testnet-capella-hard-fork`. It was tested with main `89e4b00` built from source.
- sev-signer built with `cargo build --locked --features insecure-dev`.
- About 4 GB of RAM (measured peak 3.7 GiB, of which 1.1 GiB is Kurtosis's own containers) and about 4 GB
  of images. The images, pulled on first use, are:
  - `sigp/lighthouse:v8.3.3`, `consensys/teku:26.10.3`, `chainsafe/lodestar:v1.50.1`,
    `offchainlabs/prysm-validator:v7.3.1`;
  - `ethereum/client-go:v1.17.10`, `protolambda/eth2-val-tools:latest`;
  - the Kurtosis engine and its supporting images.

## Run

```sh
CHARON=~/charon/charon SEV_SIGNER=signer/target/debug/sev-signer e2e/devnet/devnet.sh
```

`all` (the default) brings everything up, runs `SLOTS` slots (default 160, 5 epochs), prints a summary,
runs the checks below, then tears everything down. That takes about 40 minutes (`SLOTS=64` takes
about 14). State and logs go to `WORKDIR` (default `./devnet-work`, gitignored), and `logs/` keeps
every container's log after `down`. `WORKDIR` holds the DV key shares and client keys of a throwaway
devnet; delete it when done.

To keep the devnet up while you investigate, run the steps one at a time:
`up`, `keys`, `cluster`, `pods`, `wait`, `summary`, `checks` and `down`.

| Variable | Default | |
|---|---|---|
| `KURTOSIS` | `kurtosis` | CLI path |
| `ETH_PKG` | `github.com/ObolNetwork/ethereum-package@6.1.0-obol.6` | or a local checkout |
| `ENCLAVE` | `sev-signer-devnet` | enclave name, also the prefix of the harness containers |
| `WORKDIR` | `./devnet-work` | |
| `SLOTS` | `160` | slots for `wait` |
| `CHARON_DEBUG_NODES` | none | e.g. `1` to run charon1 at debug level |

## What it reports

**`summary`:**
- **sev-signer, per node:**
  - signatures by `kind`;
  - `rejected` (400/403, the `rejected sign request` warning);
  - `refused` (412 slashing).
- **charon, per node:** distinct duties broadcast to the BN, and the tracker's `Duty failed` lines, by
  duty type.
  - These come from the logs, because charon's tracker metrics stay at 0 in this setup (charon starts
    before genesis). The tracker logs nothing then either, so an empty `failed:` line proves nothing.
  - Compare `aggregator` against `attester`: with 64 validators, every attester is an aggregator.
- **charon logs:** invalid-partial-signature lines and expired-duty drops.
- **Chain:** DV proposals that landed on chain, and DV balances.

**`checks`, all against signer0 with node0's pinned client certificate:**
1. **Malformed request:** an attestation with `source.epoch > target.epoch` should get 400, produce a
   `rejected sign request` line, and leave the slashing file unchanged.
2. **Replay:** replay the attestation from signer0's latest slashing record, taken from the chain. The
   identical body should get 200, and a different `beacon_block_root` should get 412.
3. **Restart:** `docker restart` of signer0 should log `shutting down` and exit 0 within its 5 s drain,
   not hit Docker's 10 s SIGKILL. It also reports how long until `/upcheck` answers again; the debug
   build takes about 11 s to decrypt 8 keystores.
4. **Replay after the restart:** the same two requests should get the same results. The 412 now comes
   from the persisted DB.

## What healthy looks like

- Every signer has `rejected=0` and `refused=0` during normal operation.
- Every VC signs `ATTESTATION`, `AGGREGATION_SLOT` and the sync-committee kinds:
  - Lighthouse and Teku sign `AGGREGATE_AND_PROOF`; Lodestar and Prysm sign `AGGREGATE_AND_PROOF_V2`.
  - Lighthouse also signs `VALIDATOR_REGISTRATION`.
- No charon node logs an invalid partial signature.
- From epoch 1 on, `aggregator` covers every `attester` slot, and every DV proposal is on chain.
- Epoch 0 is warm-up, because Prysm starts signing at about slot 27 and Lodestar aggregates from about
  slot 35. Until then, some aggregator and sync-contribution duties can't reach 3 of 4.

## Teardown

`down` removes the harness containers and the enclave. It leaves the Kurtosis engine running. To remove
everything Kurtosis created, run:

```sh
kurtosis engine stop
# Kurtosis 1.22 also leaves its otel ClickHouse and collector containers and a few volumes behind:
docker ps -a | grep kurtosis-otel
docker volume ls | grep kurtosis
```
