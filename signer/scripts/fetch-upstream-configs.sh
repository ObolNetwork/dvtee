#!/usr/bin/env bash
# Fetches the current upstream network configs that the built-in presets are
# compared against (tests/upstream_presets.rs). Not pinned on purpose: the
# point is to notice upstream changes.
set -euo pipefail
dir=${1:-upstream-configs}
mkdir -p "$dir"
fetch() { curl -fsSL --retry 3 -o "$dir/$1.yaml" "$2"; }
fetch mainnet https://raw.githubusercontent.com/ethereum/consensus-specs/master/configs/mainnet.yaml
fetch hoodi https://raw.githubusercontent.com/eth-clients/hoodi/main/metadata/config.yaml
fetch sepolia https://raw.githubusercontent.com/eth-clients/sepolia/main/metadata/config.yaml
echo "fetched into $dir"
