# Proof of Concept

## Overview

This repository presents a proof of concept (PoC) for securely managing Distributed Validator (DV) secrets within an AMD SEV-SNP Trusted Execution Environment (TEE).
The two primary features include:
- **Secure Key Generation**: Enables Distributed Key Generation (DKG) through [Charon](https://github.com/ObolNetwork/charon), facilitating the generation of BLS key shares directly within the TEE.
- **Web3Signer Integration**: Provides signing capabilities through a Web3Signer API, enabling secure execution of consensus-related signing tasks while preserving security guarantees.

## Workflow
The workflow described below was obtained using an AMD EPYC 7313P platform supporting SEV-SNP.

### 1. Setup the host and launch an SNP guest
Setup the host machine by following the instructions described in the [sev-utils](https://github.com/amd/sev-utils/blob/main/docs/snp.md) repo from AMD.
> ℹ️ Because we used Ubuntu 24.04 `CLOUD_INIT_IMAGE_URL` was set to `"https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"` instead of `"https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"` and we added `hostfwd=tcp::9000-:9000` to the `-netdev` option in qemu cmdline since web3signer will be listening on port 9000.

Connect to the host and launch a guest
```
./<path_to_snp_script>/snp.sh launch-guest
```
and eventually run the attestation process to ensure the SNP guest was launched as expected.
```
./<path_to_snp_script>/snp.sh attest-guest
```

At the end of the process, you should be able to access the guest via SSH.
Before moving to the next steps, install docker on the guest as it will be required to run Charon and Web3Signer.
```
sudo apt update
sudo apt install docker-compose
```

### 2. Set the stage for the DKG
- Before running the DKG, each participant need to create its ENR and the cluster creator has to generate the cluster definition file as described in the [Obol docs](https://docs.obol.org/docs/start/quickstart_group).
At this stage, each participant should have a .charon directory containing `charon-enr-private-key` and `cluster-definition.json`.

- If not already done, clone this repo and head to the `poc` directory.
    ```
    git clone https://github.com/ObolNetwork/sev-signer
    cd sev-signer/poc
    ```
- In order to connect to the guest, copy the SSH private key from the host to your local machine by running
    ```
    scp root@<host>:/root/snp/launch/snp-guest-key ./
    ```
    where `<host>` refers to the IP address of the AMD SEV-SNP platform, and 

### 3. Run the DKG
Run the following command where `CHARON_DIR_PATH` points to the `.charon` directory.
```
./tools/dvtee.sh run-dkg CHARON_DIR_PATH
```
It will copy both the ENR private key as well as the cluster configuration file to guest in order to connect to the other operators and run the DKG.

### 4. Start Web3Signer
- First generate a client self-signed PKCS12 keystore that will be used to establish TLS communications with Web3Signer.
    ```
    ./tools/gen_client_keystore.sh
    ```
    > ℹ️ The generated material will be stored in a directory named `w3s_tls`.

- Start the Web3Signer server by providing the previously generated client information file
    ```
    ./tools/dvtee.sh start-w3s w3s_tls/knownClient.txt
    ```
- The Web3Signer server should now listen requests on port 9000. Try to retrieve the BLS public keys available for signing requests by running
    ```
    curl --cert-type P12 --cert w3s_tls/client_keystore.p12:$(cat w3s_tls/password.txt) --cacert server_certificate.pem  https://<host>:9000/api/v1/eth2/publicKeys
    ```
which should return as many key shares as the number of validators specified in the cluster definition file.

### 5. Stop Web3Signer
Stop the Web3Signer server by running
    ```
    ./tools/dvtee.sh stop-w3s
    ```
