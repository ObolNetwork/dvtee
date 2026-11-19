#!/usr/bin/env bash
# Fetches the external SSZ test data that tests/spec_tests.rs checks the
# signer's hash_tree_root against, into signer/spec-tests/ (gitignored):
#
#   ssz-generic/       ethereum/ssz-specs fixtures for progressive lists,
#                      bitlists and containers (EIP-7916, EIP-7495)
#   mainnet/<fork>/ssz_static/<Type>/*/case_*/{value.json,roots.yaml}
#                      consensus-specs release test vectors, only the types
#                      the signer hashes; value.yaml is converted to JSON
#
# mainnet.tar.gz is ~1 GB: it is streamed and only the needed members are
# extracted, nothing else touches the disk. Each archive is extracted to a
# temporary directory and moved into place only once its sha256 matches.
#
# Needs curl, GNU tar, sha256sum and python3 with PyYAML (for the
# YAML -> JSON conversion). Run the tests with:
#
#   SPEC_TESTS_DIR=$PWD/spec-tests cargo test --test spec_tests -- --nocapture
set -euo pipefail

CS_VERSION=v1.7.0-beta.4
CS_MAINNET_SHA256=67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c
SSZ_VERSION=v0.1.0
SSZ_SHA256=e2a65f032b59835c26127295293ea1bc07d7ca0ea1fe0e4f1128dffed333f878

# fork:Type pairs from the consensus spec tests.
SSZ_STATIC=(
  gloas:AggregateAndProof gloas:Attestation gloas:AttestationData gloas:BeaconBlockHeader
  gloas:ExecutionPayload gloas:ExecutionPayloadEnvelope gloas:ExecutionRequests
  gloas:PayloadAttestationData gloas:ProposerPreferences gloas:Withdrawal
  fulu:AggregateAndProof fulu:Attestation
  deneb:AggregateAndProof deneb:Attestation
)

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/../spec-tests}
mkdir -p "$out"
out=$(cd "$out" && pwd)
tmp=$(mktemp -d "$out/.fetch.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# fetch URL SHA256 DEST [tar args...]: streams URL through tar into DEST,
# hashing the stream on the way, and fails on a hash mismatch.
fetch() {
  local url=$1 want=$2 dest=$3
  shift 3
  mkdir -p "$dest"
  rm -f "$tmp/pipe"
  mkfifo "$tmp/pipe"
  sha256sum <"$tmp/pipe" >"$tmp/sha256" &
  local hasher=$!
  echo "fetching $url" >&2
  # tar may stop at the end-of-archive marker; drain the rest so the hash
  # covers the whole file.
  curl -fsSL "$url" | tee "$tmp/pipe" | { tar -xzf - -C "$dest" "$@"; cat >/dev/null; }
  wait "$hasher"
  local got
  got=$(cut -d' ' -f1 "$tmp/sha256")
  if [[ $got != "$want" ]]; then
    echo "sha256 mismatch for $url: got $got, want $want" >&2
    exit 1
  fi
}

# ssz-specs: small, take the progressive fixtures.
fetch "https://github.com/ethereum/ssz-specs/releases/download/$SSZ_VERSION/ssz-test-vectors-$SSZ_VERSION.tar.gz" \
  "$SSZ_SHA256" "$tmp/ssz" --wildcards 'fixtures/ssz/ssz/test_progressive_*'
rm -rf "$out/ssz-generic"
mv "$tmp/ssz/fixtures/ssz/ssz" "$out/ssz-generic"

members=()
for ft in "${SSZ_STATIC[@]}"; do
  fork=${ft%%:*} type=${ft#*:}
  members+=("tests/mainnet/$fork/ssz_static/$type/*/value.yaml" "tests/mainnet/$fork/ssz_static/$type/*/roots.yaml")
done
fetch "https://github.com/ethereum/consensus-specs/releases/download/$CS_VERSION/mainnet.tar.gz" \
  "$CS_MAINNET_SHA256" "$tmp/cs" --wildcards "${members[@]}"

# value.yaml -> value.json. Integers become decimal strings (as in the beacon
# API), so uint256 fields keep their full value.
python3 -I - "$tmp/cs/tests/mainnet" <<'EOF'
import json, pathlib, sys
import yaml

def conv(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return [conv(x) for x in v]
    if isinstance(v, dict):
        return {k: conv(x) for k, x in v.items()}
    return v

n = 0
for p in pathlib.Path(sys.argv[1]).rglob("value.yaml"):
    with open(p) as f:
        value = yaml.safe_load(f)
    with open(p.with_suffix(".json"), "w") as f:
        json.dump(conv(value), f)
    p.unlink()
    n += 1
print(f"converted {n} cases", file=sys.stderr)
EOF

rm -rf "$out/mainnet"
mv "$tmp/cs/tests/mainnet" "$out/mainnet"
printf '%s\n' "consensus-specs $CS_VERSION" "ssz-specs $SSZ_VERSION" >"$out/VERSION"
echo "spec tests in $out" >&2
