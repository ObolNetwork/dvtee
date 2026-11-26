#!/usr/bin/env bash
# Generates the TEST-ONLY fake AMD chains used by the negative tests in
# src/snp.rs. Same shape as AMD's (RSA-PSS SHA-384 CA certs, P-384 VCEK/VLEK
# with AMD's TCB and hwID extensions), but signed by throwaway keys. These
# keys and certificates are public and worthless; the verifier never trusts
# them outside `cargo test`.
#
# Usage: tests/fixtures/snp/fake/gen.sh   (from signer/; needs openssl 3)
set -euo pipefail
cd "$(dirname "$0")"

PSS=(-sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:48 -sigopt rsa_mgf1_md:sha384)
OID=1.3.6.1.4.1.3704.1
DAYS=36500
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ca() { # name subject [issuer_name]
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/$1.key"
  if [ $# -eq 2 ]; then
    openssl req -new -x509 -key "$tmp/$1.key" -subj "$2" -days $DAYS "${PSS[@]}" -out "$1.pem"
  else
    openssl req -new -key "$tmp/$1.key" -subj "$2" -out "$tmp/$1.csr"
    openssl x509 -req -in "$tmp/$1.csr" -CA "$3.pem" -CAkey "$tmp/$3.key" -set_serial 1 \
      -days $DAYS "${PSS[@]}" -out "$1.pem"
  fi
}

leaf() { # name subject issuer extfile
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1.key"
  openssl req -new -key "$1.key" -subj "$2" -out "$tmp/$1.csr"
  openssl x509 -req -in "$tmp/$1.csr" -CA "$3.pem" -CAkey "$tmp/$3.key" -set_serial 2 \
    -days $DAYS "${PSS[@]}" -extfile "$4" -extensions ext -out "$1.pem"
}

O="/O=sev-signer test (FAKE)"

# Milan: TCB bl=4 tee=1 snp=22 ucode=213 (two-byte INTEGER), 64-byte hwID.
cat > "$tmp/milan-vcek.cnf" <<EOF
[ext]
$OID.1 = ASN1:INTEGER:1
$OID.2 = ASN1:IA5STRING:Milan-B0
$OID.3.1 = ASN1:INTEGER:4
$OID.3.2 = ASN1:INTEGER:1
$OID.3.3 = ASN1:INTEGER:22
$OID.3.8 = ASN1:INTEGER:213
$OID.4 = DER:$(printf '%02x' $(seq 1 64) | sed 's/../&:/g; s/:$//')
EOF
# VLEK: same TCB, no hwID.
grep -v "^$OID.4 " "$tmp/milan-vcek.cnf" > "$tmp/milan-vlek.cnf"

# Turin: TCB fmc=2 bl=3 tee=1 snp=5 ucode=72, 8-byte hwID.
cat > "$tmp/turin-vcek.cnf" <<EOF
[ext]
$OID.1 = ASN1:INTEGER:1
$OID.2 = ASN1:IA5STRING:Turin
$OID.3.9 = ASN1:INTEGER:2
$OID.3.1 = ASN1:INTEGER:3
$OID.3.2 = ASN1:INTEGER:1
$OID.3.3 = ASN1:INTEGER:5
$OID.3.8 = ASN1:INTEGER:72
$OID.4 = DER:a1:a2:a3:a4:a5:a6:a7:a8
EOF

ca milan-ark "$O/CN=ARK-Milan"
ca milan-ask "$O/CN=SEV-Milan" milan-ark
ca milan-asvk "$O/CN=SEV-VLEK-Milan" milan-ark
leaf milan-vcek "$O/CN=SEV-VCEK" milan-ask "$tmp/milan-vcek.cnf"
leaf milan-vlek "$O/CN=SEV-VLEK" milan-asvk "$tmp/milan-vlek.cnf"

ca turin-ark "$O/CN=ARK-Turin"
ca turin-ask "$O/CN=SEV-Turin" turin-ark
leaf turin-vcek "$O/CN=SEV-VCEK" turin-ask "$tmp/turin-vcek.cnf"

# ring wants PKCS#8 for the leaf keys.
for k in milan-vcek milan-vlek turin-vcek; do
  openssl pkcs8 -topk8 -nocrypt -in "$k.key" -outform DER -out "$k.pk8"
  rm "$k.key"
done
