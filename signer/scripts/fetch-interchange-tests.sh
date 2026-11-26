#!/usr/bin/env bash
# Fetches the EIP-3076 slashing protection interchange tests
# (eth-clients/slashing-protection-interchange-tests) that
# tests/interchange_tests.rs runs against the slashing database, into
# signer/interchange-tests/ (gitignored).
#
# v5.3.0 has no release asset, so the tag's source archive is pinned by its
# sha256 (commit bb7900688e). Only tests/generated/*.json is kept.
#
# Needs curl, GNU tar and sha256sum. Run the tests with:
#
#   INTERCHANGE_TESTS_DIR=$PWD/interchange-tests cargo test --test interchange_tests -- --nocapture
set -euo pipefail

VERSION=v5.3.0
SHA256=516d551cfb3e50e4ac2f42db0992f4ceb573a7cb1616d727a725c8161485329f
URL=https://github.com/eth-clients/slashing-protection-interchange-tests/archive/refs/tags/$VERSION.tar.gz

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/../interchange-tests}
mkdir -p "$out"
out=$(cd "$out" && pwd)
tmp=$(mktemp -d "$out/.fetch.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

echo "fetching $URL" >&2
curl -fsSL -o "$tmp/tests.tar.gz" "$URL"
got=$(sha256sum "$tmp/tests.tar.gz" | cut -d' ' -f1)
if [[ $got != "$SHA256" ]]; then
  echo "sha256 mismatch for $URL: got $got, want $SHA256" >&2
  exit 1
fi
mkdir "$tmp/x"
tar -xzf "$tmp/tests.tar.gz" -C "$tmp/x" --strip-components=2 --wildcards '*/tests/generated/*.json'

rm -rf "$out/generated"
mv "$tmp/x/generated" "$out/generated"
echo "slashing-protection-interchange-tests $VERSION" >"$out/VERSION"
echo "$(find "$out/generated" -name '*.json' | wc -l) interchange tests in $out" >&2
