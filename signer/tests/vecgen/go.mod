module vecgen

go 1.26

require github.com/attestantio/go-eth2-client v0.29.0

require github.com/herumi/bls-eth-go-binary v1.36.4

require (
	github.com/OffchainLabs/go-bitfield v0.0.0-20251031151322-f427d04d8506
	github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4 v1.4.1
)

require (
	github.com/emicklei/dot v1.6.4 // indirect
	github.com/fatih/color v1.10.0 // indirect
	github.com/ferranbt/fastssz v0.1.4 // indirect
	github.com/goccy/go-yaml v1.9.2 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

// We're replacing go-eth2-client with a branch off our fork. The branch is kept up to date with the latest attestantio versions.
replace github.com/attestantio/go-eth2-client => github.com/ObolNetwork/go-eth2-client v0.28.1-obol //nolint
