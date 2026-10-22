// Command vecgen produces cross-implementation test vectors for the Rust
// tee-signer: Web3Signer request bodies, the expected signing roots computed
// with go-eth2-client's SSZ implementation, and the expected BLS signatures
// computed with herumi BLS. It also writes EIP-2335 keystores produced by the
// same encryptor charon uses.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/OffchainLabs/go-bitfield"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

const slotsPerEpoch = 32

var (
	// Hoodi.
	gvr            = mustRoot("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
	genesisVersion = phase0.Version{0x10, 0x00, 0x09, 0x10}
	capellaVersion = phase0.Version{0x40, 0x00, 0x09, 0x10}
	prevVersion    = phase0.Version{0x60, 0x00, 0x09, 0x10}
	currVersion    = phase0.Version{0x70, 0x00, 0x09, 0x10}
	forkEpoch      = phase0.Epoch(50688)

	domainBeaconProposer       = phase0.DomainType{0x00, 0, 0, 0}
	domainBeaconAttester       = phase0.DomainType{0x01, 0, 0, 0}
	domainRandao               = phase0.DomainType{0x02, 0, 0, 0}
	domainDeposit              = phase0.DomainType{0x03, 0, 0, 0}
	domainVoluntaryExit        = phase0.DomainType{0x04, 0, 0, 0}
	domainSelectionProof       = phase0.DomainType{0x05, 0, 0, 0}
	domainAggregateAndProof    = phase0.DomainType{0x06, 0, 0, 0}
	domainSyncCommittee        = phase0.DomainType{0x07, 0, 0, 0}
	domainSyncSelectionProof   = phase0.DomainType{0x08, 0, 0, 0}
	domainContributionAndProof = phase0.DomainType{0x09, 0, 0, 0}
	domainApplicationBuilder   = phase0.DomainType{0x00, 0, 0, 0x01}
)

type vector struct {
	Name        string         `json:"name"`
	Request     map[string]any `json:"request"`
	SigningRoot string         `json:"signing_root"`
	Signature   string         `json:"signature"`
}

type output struct {
	SecretKey string   `json:"secret_key"`
	PublicKey string   `json:"public_key"`
	Vectors   []vector `json:"vectors"`
}

func main() {
	out := os.Args[1]
	must(bls.Init(bls.BLS12_381))
	must(bls.SetETHmode(bls.EthModeDraft07))

	var sk bls.SecretKey
	skBytes := mustBytes("3f5ad5a2c2e1b4e4b0f6a0b8a4b4b0a3b6a6b0c4d4f6a0b8a4b4b0a3b6a6b0c4")
	must(sk.Deserialize(skBytes))
	pk := sk.GetPublicKey().Serialize()
	var pubkey phase0.BLSPubKey
	copy(pubkey[:], pk)

	fork := map[string]any{
		"fork": map[string]any{
			"previous_version": hx(prevVersion[:]),
			"current_version":  hx(currVersion[:]),
			"epoch":            u(uint64(forkEpoch)),
		},
		"genesis_validators_root": hx(gvr[:]),
	}

	var vecs []vector
	add := func(name string, req map[string]any, objRoot phase0.Root, domain phase0.Domain) {
		sd := phase0.SigningData{ObjectRoot: objRoot, Domain: domain}
		root, err := sd.HashTreeRoot()
		must(err)
		sig := sk.SignHash(root[:])
		req["signingRoot"] = hx(root[:])
		vecs = append(vecs, vector{Name: name, Request: req, SigningRoot: hx(root[:]), Signature: hx(sig.Serialize())})
	}

	// ATTESTATION
	attData := &phase0.AttestationData{
		Slot:            phase0.Slot(uint64(forkEpoch)*slotsPerEpoch + 70),
		Index:           0,
		BeaconBlockRoot: mustRoot("aa000000000000000000000000000000000000000000000000000000000000bb"),
		Source:          &phase0.Checkpoint{Epoch: forkEpoch, Root: mustRoot("1100000000000000000000000000000000000000000000000000000000000022")},
		Target:          &phase0.Checkpoint{Epoch: forkEpoch + 2, Root: mustRoot("3300000000000000000000000000000000000000000000000000000000000044")},
	}
	add("attestation", map[string]any{
		"type":        "ATTESTATION",
		"fork_info":   fork,
		"attestation": attDataJSON(attData),
	}, htr(attData), domain(domainBeaconAttester, versionAt(attData.Target.Epoch), gvr))

	// ATTESTATION before the fork epoch uses previous_version.
	attOld := &phase0.AttestationData{
		Slot:            phase0.Slot(uint64(forkEpoch-1)*slotsPerEpoch + 3),
		Index:           0,
		BeaconBlockRoot: mustRoot("ab000000000000000000000000000000000000000000000000000000000000bb"),
		Source:          &phase0.Checkpoint{Epoch: forkEpoch - 3, Root: mustRoot("1200000000000000000000000000000000000000000000000000000000000022")},
		Target:          &phase0.Checkpoint{Epoch: forkEpoch - 1, Root: mustRoot("3400000000000000000000000000000000000000000000000000000000000044")},
	}
	add("attestation_previous_fork", map[string]any{
		"type":        "ATTESTATION",
		"fork_info":   fork,
		"attestation": attDataJSON(attOld),
	}, htr(attOld), domain(domainBeaconAttester, versionAt(attOld.Target.Epoch), gvr))

	// BLOCK_V2 (header)
	hdr := &phase0.BeaconBlockHeader{
		Slot:          phase0.Slot(uint64(forkEpoch)*slotsPerEpoch + 100),
		ProposerIndex: 12345,
		ParentRoot:    mustRoot("0101010101010101010101010101010101010101010101010101010101010101"),
		StateRoot:     mustRoot("0202020202020202020202020202020202020202020202020202020202020202"),
		BodyRoot:      mustRoot("0303030303030303030303030303030303030303030303030303030303030303"),
	}
	add("block_v2_fulu", map[string]any{
		"type":      "BLOCK_V2",
		"fork_info": fork,
		"beacon_block": map[string]any{
			"version": "FULU",
			"block_header": map[string]any{
				"slot":           u(uint64(hdr.Slot)),
				"proposer_index": u(uint64(hdr.ProposerIndex)),
				"parent_root":    hx(hdr.ParentRoot[:]),
				"state_root":     hx(hdr.StateRoot[:]),
				"body_root":      hx(hdr.BodyRoot[:]),
			},
		},
	}, htr(hdr), domain(domainBeaconProposer, versionAt(epochOf(hdr.Slot)), gvr))

	// RANDAO_REVEAL
	randaoEpoch := uint64(forkEpoch) + 3
	add("randao_reveal", map[string]any{
		"type":          "RANDAO_REVEAL",
		"fork_info":     fork,
		"randao_reveal": map[string]any{"epoch": u(randaoEpoch)},
	}, uint64Root(randaoEpoch), domain(domainRandao, versionAt(phase0.Epoch(randaoEpoch)), gvr))

	// AGGREGATION_SLOT
	aggSlot := uint64(forkEpoch)*slotsPerEpoch + 71
	add("aggregation_slot", map[string]any{
		"type":             "AGGREGATION_SLOT",
		"fork_info":        fork,
		"aggregation_slot": map[string]any{"slot": u(aggSlot)},
	}, uint64Root(aggSlot), domain(domainSelectionProof, versionAt(epochOf(phase0.Slot(aggSlot))), gvr))

	// AGGREGATE_AND_PROOF_V2 (ELECTRA attestation)
	aggBits := bitfield.NewBitlist(37)
	aggBits.SetBitAt(0, true)
	aggBits.SetBitAt(5, true)
	aggBits.SetBitAt(36, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(3, true)
	eap := &electra.AggregateAndProof{
		AggregatorIndex: 777,
		Aggregate: &electra.Attestation{
			AggregationBits: aggBits,
			Data:            attData,
			Signature:       sig96(0x0a),
			CommitteeBits:   committeeBits,
		},
		SelectionProof: sig96(0x0b),
	}
	add("aggregate_and_proof_v2_electra", map[string]any{
		"type":      "AGGREGATE_AND_PROOF_V2",
		"fork_info": fork,
		"aggregate_and_proof": map[string]any{
			"version": "ELECTRA",
			"data": map[string]any{
				"aggregator_index": u(uint64(eap.AggregatorIndex)),
				"aggregate": map[string]any{
					"aggregation_bits": hx(aggBits),
					"data":             attDataJSON(attData),
					"signature":        hx(eap.Aggregate.Signature[:]),
					"committee_bits":   hx(committeeBits),
				},
				"selection_proof": hx(eap.SelectionProof[:]),
			},
		},
	}, htr(eap), domain(domainAggregateAndProof, versionAt(epochOf(attData.Slot)), gvr))

	// AGGREGATE_AND_PROOF (phase0 attestation, v1 type)
	p0Bits := bitfield.NewBitlist(9)
	p0Bits.SetBitAt(2, true)
	p0ap := &phase0.AggregateAndProof{
		AggregatorIndex: 778,
		Aggregate: &phase0.Attestation{
			AggregationBits: p0Bits,
			Data:            attOld,
			Signature:       sig96(0x0c),
		},
		SelectionProof: sig96(0x0d),
	}
	add("aggregate_and_proof_phase0", map[string]any{
		"type":      "AGGREGATE_AND_PROOF",
		"fork_info": fork,
		"aggregate_and_proof": map[string]any{
			"aggregator_index": u(uint64(p0ap.AggregatorIndex)),
			"aggregate": map[string]any{
				"aggregation_bits": hx(p0Bits),
				"data":             attDataJSON(attOld),
				"signature":        hx(p0ap.Aggregate.Signature[:]),
			},
			"selection_proof": hx(p0ap.SelectionProof[:]),
		},
	}, htr(p0ap), domain(domainAggregateAndProof, versionAt(epochOf(attOld.Slot)), gvr))

	// SYNC_COMMITTEE_MESSAGE
	scSlot := uint64(forkEpoch)*slotsPerEpoch + 72
	scRoot := mustRoot("5500000000000000000000000000000000000000000000000000000000000066")
	add("sync_committee_message", map[string]any{
		"type":      "SYNC_COMMITTEE_MESSAGE",
		"fork_info": fork,
		"sync_committee_message": map[string]any{
			"beacon_block_root": hx(scRoot[:]),
			"slot":              u(scSlot),
		},
	}, scRoot, domain(domainSyncCommittee, versionAt(epochOf(phase0.Slot(scSlot))), gvr))

	// SYNC_COMMITTEE_SELECTION_PROOF
	sel := &altair.SyncAggregatorSelectionData{Slot: phase0.Slot(scSlot), SubcommitteeIndex: 2}
	add("sync_committee_selection_proof", map[string]any{
		"type":      "SYNC_COMMITTEE_SELECTION_PROOF",
		"fork_info": fork,
		"sync_aggregator_selection_data": map[string]any{
			"slot":               u(uint64(sel.Slot)),
			"subcommittee_index": u(sel.SubcommitteeIndex),
		},
	}, htr(sel), domain(domainSyncSelectionProof, versionAt(epochOf(sel.Slot)), gvr))

	// SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF
	cBits := bitfield.NewBitvector128()
	cBits.SetBitAt(1, true)
	cBits.SetBitAt(127, true)
	cap := &altair.ContributionAndProof{
		AggregatorIndex: 999,
		Contribution: &altair.SyncCommitteeContribution{
			Slot:              phase0.Slot(scSlot),
			BeaconBlockRoot:   scRoot,
			SubcommitteeIndex: 1,
			AggregationBits:   cBits,
			Signature:         sig96(0x0e),
		},
		SelectionProof: sig96(0x0f),
	}
	add("sync_committee_contribution_and_proof", map[string]any{
		"type":      "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
		"fork_info": fork,
		"contribution_and_proof": map[string]any{
			"aggregator_index": u(uint64(cap.AggregatorIndex)),
			"selection_proof":  hx(cap.SelectionProof[:]),
			"contribution": map[string]any{
				"slot":               u(uint64(cap.Contribution.Slot)),
				"beacon_block_root":  hx(scRoot[:]),
				"subcommittee_index": u(cap.Contribution.SubcommitteeIndex),
				"aggregation_bits":   hx(cBits),
				"signature":          hx(cap.Contribution.Signature[:]),
			},
		},
	}, htr(cap), domain(domainContributionAndProof, versionAt(epochOf(cap.Contribution.Slot)), gvr))

	// VOLUNTARY_EXIT (EIP-7044: always Capella fork version)
	exit := &phase0.VoluntaryExit{Epoch: forkEpoch + 5, ValidatorIndex: 4242}
	add("voluntary_exit", map[string]any{
		"type":      "VOLUNTARY_EXIT",
		"fork_info": fork,
		"voluntary_exit": map[string]any{
			"epoch":           u(uint64(exit.Epoch)),
			"validator_index": u(uint64(exit.ValidatorIndex)),
		},
	}, htr(exit), domain(domainVoluntaryExit, capellaVersion, gvr))

	// VALIDATOR_REGISTRATION (builder domain: genesis fork version, zero root)
	reg := &apiv1.ValidatorRegistration{
		GasLimit:  60000000,
		Timestamp: time.Unix(1760000000, 0),
		Pubkey:    pubkey,
	}
	copy(reg.FeeRecipient[:], mustBytes("00112233445566778899aabbccddeeff00112233"))
	add("validator_registration", map[string]any{
		"type": "VALIDATOR_REGISTRATION",
		"validator_registration": map[string]any{
			"fee_recipient": hx(reg.FeeRecipient[:]),
			"gas_limit":     u(reg.GasLimit),
			"timestamp":     u(uint64(reg.Timestamp.Unix())),
			"pubkey":        hx(pk),
		},
	}, htr(reg), domain(domainApplicationBuilder, genesisVersion, phase0.Root{}))

	// DEPOSIT (deposit domain: request's genesis_fork_version, zero root)
	dep := &phase0.DepositMessage{PublicKey: pubkey, Amount: 32000000000}
	dep.WithdrawalCredentials = mustBytes("010000000000000000000000c0ffee254729296a45a3885639ac7e10f9d54979")
	add("deposit", map[string]any{
		"type": "DEPOSIT",
		"deposit": map[string]any{
			"pubkey":                 hx(pk),
			"withdrawal_credentials": hx(dep.WithdrawalCredentials),
			"amount":                 u(uint64(dep.Amount)),
			"genesis_fork_version":   hx(genesisVersion[:]),
		},
	}, htr(dep), domain(domainDeposit, genesisVersion, phase0.Root{}))

	must(os.MkdirAll(out, 0o755))
	b, err := json.MarshalIndent(output{SecretKey: hx(skBytes), PublicKey: hx(pk), Vectors: vecs}, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, "signing_vectors.json"), b, 0o644))

	// EIP-2335 keystores, charon layout (keystore-N.json + keystore-N.txt).
	ksDir := filepath.Join(out, "keystores")
	must(os.MkdirAll(ksDir, 0o755))
	for i, cipher := range []string{"pbkdf2", "scrypt"} {
		password := "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
		enc := keystorev4.New(keystorev4.WithCipher(cipher))
		crypto, err := enc.Encrypt(skBytes, password)
		must(err)
		ks := map[string]any{
			"crypto":      crypto,
			"description": "tee-signer test vector",
			"pubkey":      hex.EncodeToString(pk),
			"path":        "m/12381/3600/0/0/0",
			"uuid":        fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i),
			"version":     4,
		}
		kb, err := json.MarshalIndent(ks, "", "  ")
		must(err)
		must(os.WriteFile(filepath.Join(ksDir, fmt.Sprintf("keystore-%d.json", i)), kb, 0o644))
		must(os.WriteFile(filepath.Join(ksDir, fmt.Sprintf("keystore-%d.txt", i)), []byte(password), 0o644))
	}
}

type hashRooter interface{ HashTreeRoot() ([32]byte, error) }

func htr(o hashRooter) phase0.Root {
	r, err := o.HashTreeRoot()
	must(err)
	return r
}

func domain(t phase0.DomainType, v phase0.Version, root phase0.Root) phase0.Domain {
	fd := phase0.ForkData{CurrentVersion: v, GenesisValidatorsRoot: root}
	fdr, err := fd.HashTreeRoot()
	must(err)
	var d phase0.Domain
	copy(d[:4], t[:])
	copy(d[4:], fdr[:28])
	return d
}

func versionAt(e phase0.Epoch) phase0.Version {
	if e < forkEpoch {
		return prevVersion
	}
	return currVersion
}

func epochOf(s phase0.Slot) phase0.Epoch { return phase0.Epoch(uint64(s) / slotsPerEpoch) }

func uint64Root(v uint64) phase0.Root {
	var r phase0.Root
	binary.LittleEndian.PutUint64(r[:8], v)
	return r
}

func attDataJSON(d *phase0.AttestationData) map[string]any {
	return map[string]any{
		"slot":              u(uint64(d.Slot)),
		"index":             u(uint64(d.Index)),
		"beacon_block_root": hx(d.BeaconBlockRoot[:]),
		"source":            map[string]any{"epoch": u(uint64(d.Source.Epoch)), "root": hx(d.Source.Root[:])},
		"target":            map[string]any{"epoch": u(uint64(d.Target.Epoch)), "root": hx(d.Target.Root[:])},
	}
}

func sig96(b byte) phase0.BLSSignature {
	var s phase0.BLSSignature
	for i := range s {
		s[i] = b
	}
	return s
}

func u(v uint64) string  { return fmt.Sprintf("%d", v) }
func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }
func mustBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func mustRoot(s string) phase0.Root {
	var r phase0.Root
	copy(r[:], mustBytes(s))
	return r
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
