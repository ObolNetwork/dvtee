//! Web3Signer eth2 request types and signing-root computation.
//!
//! The signer never signs a client-provided root: every root is recomputed
//! from the typed object, with the domain chosen here by request type. A
//! client-supplied `signingRoot` is only ever compared against the computed
//! one. Without this, a compromised validator client could pass the root of a
//! slashable attestation off as e.g. a RANDAO reveal.

use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::network::{ForkName, Network, SLOTS_PER_EPOCH};
use crate::ssz::{self, Root};

const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0x00, 0, 0, 0];
const DOMAIN_BEACON_ATTESTER: [u8; 4] = [0x01, 0, 0, 0];
const DOMAIN_RANDAO: [u8; 4] = [0x02, 0, 0, 0];
const DOMAIN_DEPOSIT: [u8; 4] = [0x03, 0, 0, 0];
const DOMAIN_VOLUNTARY_EXIT: [u8; 4] = [0x04, 0, 0, 0];
const DOMAIN_SELECTION_PROOF: [u8; 4] = [0x05, 0, 0, 0];
const DOMAIN_AGGREGATE_AND_PROOF: [u8; 4] = [0x06, 0, 0, 0];
const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0, 0, 0];
const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: [u8; 4] = [0x08, 0, 0, 0];
const DOMAIN_CONTRIBUTION_AND_PROOF: [u8; 4] = [0x09, 0, 0, 0];
const DOMAIN_APPLICATION_BUILDER: [u8; 4] = [0x00, 0, 0, 0x01];
const DOMAIN_BEACON_BUILDER: [u8; 4] = [0x0B, 0, 0, 0];
const DOMAIN_PTC_ATTESTER: [u8; 4] = [0x0C, 0, 0, 0];
const DOMAIN_PROPOSER_PREFERENCES: [u8; 4] = [0x0D, 0, 0, 0];
/// builder-specs Gloas: out-of-protocol builder API authentication.
const DOMAIN_BUILDER_REQUEST_AUTH: [u8; 4] = [0x0B, 0, 0, 0x01];

pub const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;
/// builder-specs Gloas `MAX_BUILDER_AUTH_DATA_SIZE`.
const MAX_BUILDER_AUTH_DATA_SIZE: usize = 4096;
const MAX_EXTRA_DATA_BYTES: usize = 32;

// Mainnet preset limits.
const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
const MAX_COMMITTEES_PER_SLOT: usize = 64;
const SYNC_SUBCOMMITTEE_SIZE: usize = 512 / 4;

// ---------------------------------------------------------------------------
// Primitive (de)serializers.

/// Unsigned integer accepted as a decimal string (beacon API style) or number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U64(pub u64);

impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            S(String),
            N(u64),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => Ok(U64(n)),
            Raw::S(s) => s.parse().map(U64).map_err(de::Error::custom),
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("hex value {s:?} must be 0x-prefixed"))?;
    hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes<const N: usize>(pub [u8; N]);

impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = decode_hex(&String::deserialize(d)?).map_err(de::Error::custom)?;
        let arr: [u8; N] = v.try_into().map_err(|v: Vec<u8>| {
            de::Error::custom(format!("expected {N} bytes, got {}", v.len()))
        })?;
        Ok(Bytes(arr))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexBytes(pub Vec<u8>);

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        decode_hex(&String::deserialize(d)?)
            .map(HexBytes)
            .map_err(de::Error::custom)
    }
}

/// `uint256` given as a decimal string (beacon API style), kept as its SSZ
/// (little-endian) encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct U256Le(pub [u8; 32]);

impl<'de> Deserialize<'de> for U256Le {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(de::Error::custom(format!(
                "uint256 must be a decimal string, got {s:?}"
            )));
        }
        // Little-endian 64-bit limbs; value = value * 10 + digit.
        let mut limbs = [0u64; 4];
        for digit in s.bytes().map(|b| u64::from(b - b'0')) {
            let mut carry = digit as u128;
            for limb in &mut limbs {
                let v = (*limb as u128) * 10 + carry;
                *limb = v as u64;
                carry = v >> 64;
            }
            if carry != 0 {
                return Err(de::Error::custom("uint256 overflow"));
            }
        }
        let mut out = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        Ok(U256Le(out))
    }
}

// ---------------------------------------------------------------------------
// Request types (https://consensys.github.io/web3signer/web3signer-eth2.html,
// Gloas types from ethereum/remote-signing-api v1.4.0).

#[derive(Deserialize, Debug)]
pub struct SignRequest {
    #[serde(rename = "signingRoot", default)]
    pub signing_root: Option<Bytes<32>>,
    #[serde(flatten)]
    pub body: SignBody,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum SignBody {
    #[serde(rename = "ATTESTATION")]
    Attestation {
        fork_info: ForkInfo,
        attestation: AttestationData,
    },
    #[serde(rename = "BLOCK_V2")]
    BlockV2 {
        fork_info: ForkInfo,
        beacon_block: BlockV2,
    },
    #[serde(rename = "RANDAO_REVEAL")]
    RandaoReveal {
        fork_info: ForkInfo,
        randao_reveal: EpochObj,
    },
    #[serde(rename = "AGGREGATION_SLOT")]
    AggregationSlot {
        fork_info: ForkInfo,
        aggregation_slot: SlotObj,
    },
    #[serde(rename = "AGGREGATE_AND_PROOF")]
    AggregateAndProof {
        fork_info: ForkInfo,
        aggregate_and_proof: AggregateAndProof,
    },
    #[serde(rename = "AGGREGATE_AND_PROOF_V2")]
    AggregateAndProofV2 {
        fork_info: ForkInfo,
        aggregate_and_proof: VersionedAggregateAndProof,
    },
    #[serde(rename = "SYNC_COMMITTEE_MESSAGE")]
    SyncCommitteeMessage {
        fork_info: ForkInfo,
        sync_committee_message: SyncCommitteeMessage,
    },
    #[serde(rename = "SYNC_COMMITTEE_SELECTION_PROOF")]
    SyncCommitteeSelectionProof {
        fork_info: ForkInfo,
        sync_aggregator_selection_data: SyncAggregatorSelectionData,
    },
    #[serde(rename = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF")]
    SyncCommitteeContributionAndProof {
        fork_info: ForkInfo,
        contribution_and_proof: ContributionAndProof,
    },
    #[serde(rename = "VOLUNTARY_EXIT")]
    VoluntaryExit {
        fork_info: ForkInfo,
        voluntary_exit: VoluntaryExit,
    },
    #[serde(rename = "VALIDATOR_REGISTRATION")]
    ValidatorRegistration {
        validator_registration: ValidatorRegistration,
    },
    #[serde(rename = "DEPOSIT")]
    Deposit { deposit: Deposit },
    #[serde(rename = "PAYLOAD_ATTESTATION_MESSAGE")]
    PayloadAttestationMessage {
        fork_info: ForkInfo,
        payload_attestation_message: Versioned<PayloadAttestationData>,
    },
    #[serde(rename = "PROPOSER_PREFERENCES")]
    ProposerPreferences {
        fork_info: ForkInfo,
        proposer_preferences: Versioned<ProposerPreferences>,
    },
    #[serde(rename = "EXECUTION_PAYLOAD_ENVELOPE")]
    ExecutionPayloadEnvelope {
        fork_info: ForkInfo,
        execution_payload_envelope: Box<Versioned<ExecutionPayloadEnvelope>>,
    },
    /// Builder bids are signed with builder keys, never validator keys; the
    /// body is not even parsed.
    #[serde(rename = "EXECUTION_PAYLOAD_BID")]
    ExecutionPayloadBid {},
    /// No `fork_info`: the domain uses the genesis fork version and a zero
    /// genesis validators root, like validator registrations.
    #[serde(rename = "BUILDER_REQUEST_AUTH")]
    BuilderRequestAuth {
        builder_request_auth: Versioned<BuilderRequestAuth>,
    },
}

/// `{"version": "GLOAS", "data": ...}` wrapper of the v1.4.0 request types.
#[derive(Deserialize, Debug)]
pub struct Versioned<T> {
    pub version: String,
    pub data: T,
}

#[derive(Deserialize, Debug)]
pub struct Fork {
    pub previous_version: Bytes<4>,
    pub current_version: Bytes<4>,
    pub epoch: U64,
}

#[derive(Deserialize, Debug)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Bytes<32>,
}

#[derive(Deserialize, Debug)]
pub struct Checkpoint {
    pub epoch: U64,
    pub root: Bytes<32>,
}

#[derive(Deserialize, Debug)]
pub struct AttestationData {
    pub slot: U64,
    pub index: U64,
    pub beacon_block_root: Bytes<32>,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Deserialize, Debug)]
pub struct BeaconBlockHeader {
    pub slot: U64,
    pub proposer_index: U64,
    pub parent_root: Bytes<32>,
    pub state_root: Bytes<32>,
    pub body_root: Bytes<32>,
}

#[derive(Deserialize, Debug)]
pub struct BlockV2 {
    pub version: String,
    #[serde(default)]
    pub block_header: Option<BeaconBlockHeader>,
    #[serde(default)]
    pub block: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
pub struct EpochObj {
    pub epoch: U64,
}

#[derive(Deserialize, Debug)]
pub struct SlotObj {
    pub slot: U64,
}

/// Attestation as carried inside an aggregate. `committee_bits` is present
/// from Electra on.
#[derive(Deserialize, Debug)]
pub struct Attestation {
    pub aggregation_bits: HexBytes,
    pub data: AttestationData,
    pub signature: Bytes<96>,
    #[serde(default)]
    pub committee_bits: Option<HexBytes>,
}

#[derive(Deserialize, Debug)]
pub struct AggregateAndProof {
    pub aggregator_index: U64,
    pub aggregate: Attestation,
    pub selection_proof: Bytes<96>,
}

#[derive(Deserialize, Debug)]
pub struct VersionedAggregateAndProof {
    pub version: String,
    pub data: AggregateAndProof,
}

#[derive(Deserialize, Debug)]
pub struct SyncCommitteeMessage {
    pub beacon_block_root: Bytes<32>,
    pub slot: U64,
}

#[derive(Deserialize, Debug)]
pub struct SyncAggregatorSelectionData {
    pub slot: U64,
    pub subcommittee_index: U64,
}

#[derive(Deserialize, Debug)]
pub struct SyncCommitteeContribution {
    pub slot: U64,
    pub beacon_block_root: Bytes<32>,
    pub subcommittee_index: U64,
    pub aggregation_bits: HexBytes,
    pub signature: Bytes<96>,
}

#[derive(Deserialize, Debug)]
pub struct ContributionAndProof {
    pub aggregator_index: U64,
    pub selection_proof: Bytes<96>,
    pub contribution: SyncCommitteeContribution,
}

#[derive(Deserialize, Debug)]
pub struct VoluntaryExit {
    pub epoch: U64,
    pub validator_index: U64,
}

#[derive(Deserialize, Debug)]
pub struct ValidatorRegistration {
    pub fee_recipient: Bytes<20>,
    pub gas_limit: U64,
    pub timestamp: U64,
    pub pubkey: Bytes<48>,
}

#[derive(Deserialize, Debug)]
pub struct Deposit {
    pub pubkey: Bytes<48>,
    pub withdrawal_credentials: Bytes<32>,
    pub amount: U64,
    pub genesis_fork_version: Bytes<4>,
}

// Gloas (consensus-specs v1.7.0-beta.4).

#[derive(Deserialize, Debug)]
pub struct PayloadAttestationData {
    pub beacon_block_root: Bytes<32>,
    pub slot: U64,
    pub payload_present: bool,
    pub blob_data_available: bool,
}

/// p2p-interface.md `ProposerPreferences`.
#[derive(Deserialize, Debug)]
pub struct ProposerPreferences {
    pub dependent_root: Bytes<32>,
    pub proposal_slot: U64,
    pub validator_index: U64,
    pub fee_recipient: Bytes<20>,
    pub target_gas_limit: U64,
}

/// builder-specs Gloas `BuilderRequestAuth`.
#[derive(Deserialize, Debug)]
pub struct BuilderRequestAuth {
    pub data: HexBytes,
    pub slot: U64,
}

#[derive(Deserialize, Debug)]
pub struct Withdrawal {
    pub index: U64,
    pub validator_index: U64,
    pub address: Bytes<20>,
    pub amount: U64,
}

#[derive(Deserialize, Debug)]
pub struct ExecutionPayload {
    pub parent_hash: Bytes<32>,
    pub fee_recipient: Bytes<20>,
    pub state_root: Bytes<32>,
    pub receipts_root: Bytes<32>,
    pub logs_bloom: Bytes<256>,
    pub prev_randao: Bytes<32>,
    pub block_number: U64,
    pub gas_limit: U64,
    pub gas_used: U64,
    pub timestamp: U64,
    pub extra_data: HexBytes,
    pub base_fee_per_gas: U256Le,
    pub block_hash: Bytes<32>,
    pub transactions: Vec<HexBytes>,
    pub withdrawals: Vec<Withdrawal>,
    pub blob_gas_used: U64,
    pub excess_blob_gas: U64,
    pub block_access_list: HexBytes,
    pub slot_number: U64,
}

#[derive(Deserialize, Debug)]
pub struct DepositRequest {
    pub pubkey: Bytes<48>,
    pub withdrawal_credentials: Bytes<32>,
    pub amount: U64,
    pub signature: Bytes<96>,
    pub index: U64,
}

#[derive(Deserialize, Debug)]
pub struct WithdrawalRequest {
    pub source_address: Bytes<20>,
    pub validator_pubkey: Bytes<48>,
    pub amount: U64,
}

#[derive(Deserialize, Debug)]
pub struct ConsolidationRequest {
    pub source_address: Bytes<20>,
    pub source_pubkey: Bytes<48>,
    pub target_pubkey: Bytes<48>,
}

#[derive(Deserialize, Debug)]
pub struct BuilderDepositRequest {
    pub pubkey: Bytes<48>,
    pub withdrawal_credentials: Bytes<32>,
    pub amount: U64,
    pub signature: Bytes<96>,
}

#[derive(Deserialize, Debug)]
pub struct BuilderExitRequest {
    pub source_address: Bytes<20>,
    pub pubkey: Bytes<48>,
}

#[derive(Deserialize, Debug)]
pub struct ExecutionRequests {
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<WithdrawalRequest>,
    pub consolidations: Vec<ConsolidationRequest>,
    pub builder_deposits: Vec<BuilderDepositRequest>,
    pub builder_exits: Vec<BuilderExitRequest>,
}

#[derive(Deserialize, Debug)]
pub struct ExecutionPayloadEnvelope {
    pub payload: ExecutionPayload,
    pub execution_requests: ExecutionRequests,
    pub builder_index: U64,
    pub beacon_block_root: Bytes<32>,
    pub parent_beacon_block_root: Bytes<32>,
}

// ---------------------------------------------------------------------------
// Hash tree roots.

impl Checkpoint {
    fn root(&self) -> Root {
        ssz::container(&[ssz::uint64(self.epoch.0), self.root.0])
    }
}

impl AttestationData {
    pub fn root(&self) -> Root {
        ssz::container(&[
            ssz::uint64(self.slot.0),
            ssz::uint64(self.index.0),
            self.beacon_block_root.0,
            self.source.root(),
            self.target.root(),
        ])
    }
}

impl BeaconBlockHeader {
    /// Equals the root of the full `BeaconBlock` it summarizes.
    pub fn root(&self) -> Root {
        ssz::container(&[
            ssz::uint64(self.slot.0),
            ssz::uint64(self.proposer_index.0),
            self.parent_root.0,
            self.state_root.0,
            self.body_root.0,
        ])
    }
}

/// The three SSZ shapes `Attestation` has had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationSchema {
    /// Phase0 to Deneb: `Bitlist[MAX_VALIDATORS_PER_COMMITTEE]`, no
    /// `committee_bits`.
    Phase0,
    /// Electra and Fulu (EIP-7549): adds `committee_bits`.
    Electra,
    /// Gloas (EIP-7688): `ProgressiveContainer` with a `ProgressiveBitList`.
    Gloas,
}

impl AttestationSchema {
    pub fn for_fork(fork: ForkName) -> Self {
        if fork >= ForkName::Gloas {
            AttestationSchema::Gloas
        } else if fork >= ForkName::Electra {
            AttestationSchema::Electra
        } else {
            AttestationSchema::Phase0
        }
    }
}

impl Attestation {
    pub fn root(&self, schema: AttestationSchema) -> Result<Root, String> {
        let committee_bits = || {
            self.committee_bits
                .as_ref()
                .ok_or_else(|| format!("{schema:?} attestation is missing committee_bits"))
        };
        match schema {
            AttestationSchema::Phase0 => {
                if self.committee_bits.is_some() {
                    return Err("pre-electra attestation must not have committee_bits".into());
                }
                Ok(ssz::container(&[
                    ssz::bitlist(&self.aggregation_bits.0, MAX_VALIDATORS_PER_COMMITTEE)?,
                    self.data.root(),
                    ssz::bytes_vector(&self.signature.0),
                ]))
            }
            AttestationSchema::Electra => Ok(ssz::container(&[
                ssz::bitlist(
                    &self.aggregation_bits.0,
                    MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT,
                )?,
                self.data.root(),
                ssz::bytes_vector(&self.signature.0),
                ssz::bitvector(&committee_bits()?.0, MAX_COMMITTEES_PER_SLOT)?,
            ])),
            AttestationSchema::Gloas => Ok(ssz::progressive_container_dense(&[
                ssz::progressive_bitlist(&self.aggregation_bits.0)?,
                self.data.root(),
                ssz::bytes_vector(&self.signature.0),
                ssz::bitvector(&committee_bits()?.0, MAX_COMMITTEES_PER_SLOT)?,
            ])),
        }
    }
}

impl AggregateAndProof {
    pub fn root(&self, schema: AttestationSchema) -> Result<Root, String> {
        Ok(ssz::container(&[
            ssz::uint64(self.aggregator_index.0),
            self.aggregate.root(schema)?,
            ssz::bytes_vector(&self.selection_proof.0),
        ]))
    }
}

impl PayloadAttestationData {
    pub fn root(&self) -> Root {
        ssz::container(&[
            self.beacon_block_root.0,
            ssz::uint64(self.slot.0),
            ssz::boolean(self.payload_present),
            ssz::boolean(self.blob_data_available),
        ])
    }
}

impl ProposerPreferences {
    pub fn root(&self) -> Root {
        ssz::container(&[
            self.dependent_root.0,
            ssz::uint64(self.proposal_slot.0),
            ssz::uint64(self.validator_index.0),
            ssz::bytes_vector(&self.fee_recipient.0),
            ssz::uint64(self.target_gas_limit.0),
        ])
    }
}

impl BuilderRequestAuth {
    pub fn root(&self) -> Result<Root, String> {
        if self.data.0.is_empty() {
            return Err("builder_request_auth data must not be empty".into());
        }
        Ok(ssz::container(&[
            ssz::byte_list(&self.data.0, MAX_BUILDER_AUTH_DATA_SIZE)?,
            ssz::uint64(self.slot.0),
        ]))
    }
}

impl Withdrawal {
    pub fn root(&self) -> Root {
        ssz::container(&[
            ssz::uint64(self.index.0),
            ssz::uint64(self.validator_index.0),
            ssz::bytes_vector(&self.address.0),
            ssz::uint64(self.amount.0),
        ])
    }
}

impl ExecutionPayload {
    pub fn root(&self) -> Result<Root, String> {
        let transactions: Vec<Root> = self
            .transactions
            .iter()
            .map(|tx| ssz::progressive_list_packed(&tx.0, tx.0.len()))
            .collect();
        let withdrawals: Vec<Root> = self.withdrawals.iter().map(Withdrawal::root).collect();
        Ok(ssz::progressive_container_dense(&[
            self.parent_hash.0,
            ssz::bytes_vector(&self.fee_recipient.0),
            self.state_root.0,
            self.receipts_root.0,
            ssz::bytes_vector(&self.logs_bloom.0),
            self.prev_randao.0,
            ssz::uint64(self.block_number.0),
            ssz::uint64(self.gas_limit.0),
            ssz::uint64(self.gas_used.0),
            ssz::uint64(self.timestamp.0),
            ssz::byte_list(&self.extra_data.0, MAX_EXTRA_DATA_BYTES)?,
            self.base_fee_per_gas.0,
            self.block_hash.0,
            ssz::progressive_list(&transactions),
            ssz::progressive_list(&withdrawals),
            ssz::uint64(self.blob_gas_used.0),
            ssz::uint64(self.excess_blob_gas.0),
            ssz::progressive_list_packed(&self.block_access_list.0, self.block_access_list.0.len()),
            ssz::uint64(self.slot_number.0),
        ]))
    }
}

impl ExecutionRequests {
    pub fn root(&self) -> Root {
        let deposits: Vec<Root> = self
            .deposits
            .iter()
            .map(|d| {
                ssz::container(&[
                    ssz::bytes_vector(&d.pubkey.0),
                    d.withdrawal_credentials.0,
                    ssz::uint64(d.amount.0),
                    ssz::bytes_vector(&d.signature.0),
                    ssz::uint64(d.index.0),
                ])
            })
            .collect();
        let withdrawals: Vec<Root> = self
            .withdrawals
            .iter()
            .map(|w| {
                ssz::container(&[
                    ssz::bytes_vector(&w.source_address.0),
                    ssz::bytes_vector(&w.validator_pubkey.0),
                    ssz::uint64(w.amount.0),
                ])
            })
            .collect();
        let consolidations: Vec<Root> = self
            .consolidations
            .iter()
            .map(|c| {
                ssz::container(&[
                    ssz::bytes_vector(&c.source_address.0),
                    ssz::bytes_vector(&c.source_pubkey.0),
                    ssz::bytes_vector(&c.target_pubkey.0),
                ])
            })
            .collect();
        let builder_deposits: Vec<Root> = self
            .builder_deposits
            .iter()
            .map(|d| {
                ssz::container(&[
                    ssz::bytes_vector(&d.pubkey.0),
                    d.withdrawal_credentials.0,
                    ssz::uint64(d.amount.0),
                    ssz::bytes_vector(&d.signature.0),
                ])
            })
            .collect();
        let builder_exits: Vec<Root> = self
            .builder_exits
            .iter()
            .map(|e| {
                ssz::container(&[
                    ssz::bytes_vector(&e.source_address.0),
                    ssz::bytes_vector(&e.pubkey.0),
                ])
            })
            .collect();
        ssz::progressive_container_dense(&[
            ssz::progressive_list(&deposits),
            ssz::progressive_list(&withdrawals),
            ssz::progressive_list(&consolidations),
            ssz::progressive_list(&builder_deposits),
            ssz::progressive_list(&builder_exits),
        ])
    }
}

impl ExecutionPayloadEnvelope {
    pub fn root(&self) -> Result<Root, String> {
        Ok(ssz::progressive_container_dense(&[
            self.payload.root()?,
            self.execution_requests.root(),
            ssz::uint64(self.builder_index.0),
            self.beacon_block_root.0,
            self.parent_beacon_block_root.0,
        ]))
    }
}

impl SyncCommitteeContribution {
    fn root(&self) -> Result<Root, String> {
        Ok(ssz::container(&[
            ssz::uint64(self.slot.0),
            self.beacon_block_root.0,
            ssz::uint64(self.subcommittee_index.0),
            ssz::bitvector(&self.aggregation_bits.0, SYNC_SUBCOMMITTEE_SIZE)?,
            ssz::bytes_vector(&self.signature.0),
        ]))
    }
}

impl ContributionAndProof {
    fn root(&self) -> Result<Root, String> {
        Ok(ssz::container(&[
            ssz::uint64(self.aggregator_index.0),
            self.contribution.root()?,
            ssz::bytes_vector(&self.selection_proof.0),
        ]))
    }
}

// ---------------------------------------------------------------------------
// Domains and signing roots.

fn compute_domain(domain_type: [u8; 4], fork_version: [u8; 4], gvr: &Root) -> Root {
    let fork_data_root = ssz::container(&[ssz::bytes_vector(&fork_version), *gvr]);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

fn compute_signing_root(object_root: &Root, domain: &Root) -> Root {
    ssz::container(&[*object_root, *domain])
}

fn epoch_at_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

impl ForkInfo {
    /// `get_domain` for the given epoch, using `fork_info` as the state's fork.
    fn domain(&self, domain_type: [u8; 4], epoch: u64) -> Root {
        let version = if epoch < self.fork.epoch.0 {
            self.fork.previous_version.0
        } else {
            self.fork.current_version.0
        };
        compute_domain(domain_type, version, &self.genesis_validators_root.0)
    }
}

/// What the slashing protection database must check before signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlashingCheck {
    /// `block_root` is the header's `hash_tree_root`, recorded so the
    /// block's execution payload envelope can be checked against it.
    Block {
        slot: u64,
        block_root: Root,
    },
    Attestation {
        source: u64,
        target: u64,
    },
    /// Not slashable, but only signed for a block this key signed: the
    /// latest signed block must be at `slot` with root `block_root`.
    OwnBlockPayload {
        slot: u64,
        block_root: Root,
    },
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub allow_voluntary_exits: bool,
    pub allow_deposits: bool,
}

#[derive(Debug)]
pub struct Prepared {
    pub kind: &'static str,
    pub signing_root: Root,
    pub slashing: Option<SlashingCheck>,
}

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("request is for a different network: genesis_validators_root 0x{0}")]
    WrongNetwork(String),
    #[error("{0} signing is disabled by policy")]
    Forbidden(&'static str),
    #[error("refused: {0}")]
    Refused(String),
}

impl From<String> for PrepareError {
    fn from(s: String) -> Self {
        PrepareError::Invalid(s)
    }
}

fn parse_version(version: &str) -> Result<ForkName, PrepareError> {
    ForkName::parse(version)
        .ok_or_else(|| PrepareError::Invalid(format!("unsupported fork version {version:?}")))
}

/// The request's `version` must name the fork the network is in at `slot`.
/// Without a known schedule (`custom:` networks) the request's word is taken.
fn check_version(net: &Network, version: &str, slot: u64) -> Result<ForkName, PrepareError> {
    let fork = parse_version(version)?;
    if let Some(scheduled) = net.fork_at_slot(slot)
        && scheduled.name != fork
    {
        return Err(PrepareError::Invalid(format!(
            "version {fork} does not match fork {} at slot {slot}",
            scheduled.name
        )));
    }
    Ok(fork)
}

/// Gloas-only request types: `version` must be GLOAS and the network must be
/// in Gloas at `slot` by its known schedule.
fn require_gloas(net: &Network, version: &str, slot: u64) -> Result<(), PrepareError> {
    if parse_version(version)? != ForkName::Gloas {
        return Err(PrepareError::Invalid(format!(
            "version must be GLOAS, got {version:?}"
        )));
    }
    match net.fork_at_slot(slot) {
        Some(f) if f.name == ForkName::Gloas => Ok(()),
        Some(f) => Err(PrepareError::Invalid(format!(
            "slot {slot} is in {}, not GLOAS",
            f.name
        ))),
        None => Err(PrepareError::Invalid(
            "Gloas request types need a network with a fork schedule (a preset or a config.yaml --network)"
                .into(),
        )),
    }
}

/// Validates a request and computes its signing root and slashing check.
pub fn prepare(
    req: &SignRequest,
    net: &Network,
    policy: &Policy,
) -> Result<Prepared, PrepareError> {
    let check_net = |fi: &ForkInfo| {
        if fi.genesis_validators_root.0 == net.genesis_validators_root {
            Ok(())
        } else {
            Err(PrepareError::WrongNetwork(hex::encode(
                fi.genesis_validators_root.0,
            )))
        }
    };

    let (kind, signing_root, slashing) = match &req.body {
        SignBody::Attestation {
            fork_info,
            attestation,
        } => {
            check_net(fork_info)?;
            let (source, target) = (attestation.source.epoch.0, attestation.target.epoch.0);
            if source > target {
                return Err(PrepareError::Invalid(
                    "attestation source epoch is after target".into(),
                ));
            }
            let domain = fork_info.domain(DOMAIN_BEACON_ATTESTER, target);
            (
                "ATTESTATION",
                compute_signing_root(&attestation.root(), &domain),
                Some(SlashingCheck::Attestation { source, target }),
            )
        }
        SignBody::BlockV2 {
            fork_info,
            beacon_block,
        } => {
            check_net(fork_info)?;
            let header = match (&beacon_block.block_header, &beacon_block.block) {
                (Some(h), None) => h,
                (None, Some(_)) => {
                    return Err(PrepareError::Invalid(
                        "full beacon blocks are not supported, send block_header".into(),
                    ));
                }
                _ => {
                    return Err(PrepareError::Invalid(
                        "exactly one of block_header or block is required".into(),
                    ));
                }
            };
            check_version(net, &beacon_block.version, header.slot.0)?;
            let block_root = header.root();
            let domain = fork_info.domain(DOMAIN_BEACON_PROPOSER, epoch_at_slot(header.slot.0));
            (
                "BLOCK_V2",
                compute_signing_root(&block_root, &domain),
                Some(SlashingCheck::Block {
                    slot: header.slot.0,
                    block_root,
                }),
            )
        }
        SignBody::RandaoReveal {
            fork_info,
            randao_reveal,
        } => {
            check_net(fork_info)?;
            let epoch = randao_reveal.epoch.0;
            let domain = fork_info.domain(DOMAIN_RANDAO, epoch);
            (
                "RANDAO_REVEAL",
                compute_signing_root(&ssz::uint64(epoch), &domain),
                None,
            )
        }
        SignBody::AggregationSlot {
            fork_info,
            aggregation_slot,
        } => {
            check_net(fork_info)?;
            let slot = aggregation_slot.slot.0;
            let domain = fork_info.domain(DOMAIN_SELECTION_PROOF, epoch_at_slot(slot));
            (
                "AGGREGATION_SLOT",
                compute_signing_root(&ssz::uint64(slot), &domain),
                None,
            )
        }
        SignBody::AggregateAndProof {
            fork_info,
            aggregate_and_proof,
        } => {
            check_net(fork_info)?;
            // Lighthouse and Teku keep sending the v1 type after Electra. The
            // v1 body carries no fork version, so the fork at the aggregate's
            // slot picks the schema, and `committee_bits` (Electra and later)
            // must agree with it. Without a known schedule (`custom:`), the
            // presence of `committee_bits` picks between Phase0 and Electra.
            // Either way the root is computed here and the domain is the
            // aggregate domain, so this cannot yield a slashable signature.
            let slot = aggregate_and_proof.aggregate.data.slot.0;
            let has_committee_bits = aggregate_and_proof.aggregate.committee_bits.is_some();
            let schema = match net.fork_at_slot(slot) {
                Some(f) => {
                    let schema = AttestationSchema::for_fork(f.name);
                    if has_committee_bits != (schema != AttestationSchema::Phase0) {
                        return Err(PrepareError::Invalid(format!(
                            "aggregate at slot {slot} ({}) {} committee_bits",
                            f.name,
                            if has_committee_bits {
                                "must not have"
                            } else {
                                "must have"
                            }
                        )));
                    }
                    schema
                }
                None if has_committee_bits => AttestationSchema::Electra,
                None => AttestationSchema::Phase0,
            };
            let domain = fork_info.domain(DOMAIN_AGGREGATE_AND_PROOF, epoch_at_slot(slot));
            (
                "AGGREGATE_AND_PROOF",
                compute_signing_root(&aggregate_and_proof.root(schema)?, &domain),
                None,
            )
        }
        SignBody::AggregateAndProofV2 {
            fork_info,
            aggregate_and_proof,
        } => {
            check_net(fork_info)?;
            let data = &aggregate_and_proof.data;
            let slot = data.aggregate.data.slot.0;
            let fork = check_version(net, &aggregate_and_proof.version, slot)?;
            let domain = fork_info.domain(DOMAIN_AGGREGATE_AND_PROOF, epoch_at_slot(slot));
            (
                "AGGREGATE_AND_PROOF_V2",
                compute_signing_root(&data.root(AttestationSchema::for_fork(fork))?, &domain),
                None,
            )
        }
        SignBody::SyncCommitteeMessage {
            fork_info,
            sync_committee_message: m,
        } => {
            check_net(fork_info)?;
            let domain = fork_info.domain(DOMAIN_SYNC_COMMITTEE, epoch_at_slot(m.slot.0));
            (
                "SYNC_COMMITTEE_MESSAGE",
                compute_signing_root(&m.beacon_block_root.0, &domain),
                None,
            )
        }
        SignBody::SyncCommitteeSelectionProof {
            fork_info,
            sync_aggregator_selection_data: d,
        } => {
            check_net(fork_info)?;
            let domain = fork_info.domain(
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                epoch_at_slot(d.slot.0),
            );
            let root =
                ssz::container(&[ssz::uint64(d.slot.0), ssz::uint64(d.subcommittee_index.0)]);
            (
                "SYNC_COMMITTEE_SELECTION_PROOF",
                compute_signing_root(&root, &domain),
                None,
            )
        }
        SignBody::SyncCommitteeContributionAndProof {
            fork_info,
            contribution_and_proof: c,
        } => {
            check_net(fork_info)?;
            let domain = fork_info.domain(
                DOMAIN_CONTRIBUTION_AND_PROOF,
                epoch_at_slot(c.contribution.slot.0),
            );
            (
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
                compute_signing_root(&c.root()?, &domain),
                None,
            )
        }
        SignBody::VoluntaryExit {
            fork_info,
            voluntary_exit: e,
        } => {
            check_net(fork_info)?;
            if !policy.allow_voluntary_exits {
                return Err(PrepareError::Forbidden("VOLUNTARY_EXIT"));
            }
            // EIP-7044: exits are always signed with the Capella fork version.
            let domain = compute_domain(
                DOMAIN_VOLUNTARY_EXIT,
                net.capella_fork_version,
                &net.genesis_validators_root,
            );
            let root = ssz::container(&[ssz::uint64(e.epoch.0), ssz::uint64(e.validator_index.0)]);
            ("VOLUNTARY_EXIT", compute_signing_root(&root, &domain), None)
        }
        SignBody::ValidatorRegistration {
            validator_registration: r,
        } => {
            let domain = compute_domain(
                DOMAIN_APPLICATION_BUILDER,
                net.genesis_fork_version,
                &[0u8; 32],
            );
            let root = ssz::container(&[
                ssz::bytes_vector(&r.fee_recipient.0),
                ssz::uint64(r.gas_limit.0),
                ssz::uint64(r.timestamp.0),
                ssz::bytes_vector(&r.pubkey.0),
            ]);
            (
                "VALIDATOR_REGISTRATION",
                compute_signing_root(&root, &domain),
                None,
            )
        }
        SignBody::Deposit { deposit: d } => {
            if !policy.allow_deposits {
                return Err(PrepareError::Forbidden("DEPOSIT"));
            }
            let domain = compute_domain(DOMAIN_DEPOSIT, d.genesis_fork_version.0, &[0u8; 32]);
            let root = ssz::container(&[
                ssz::bytes_vector(&d.pubkey.0),
                d.withdrawal_credentials.0,
                ssz::uint64(d.amount.0),
            ]);
            ("DEPOSIT", compute_signing_root(&root, &domain), None)
        }
        SignBody::PayloadAttestationMessage {
            fork_info,
            payload_attestation_message: m,
        } => {
            check_net(fork_info)?;
            let slot = m.data.slot.0;
            require_gloas(net, &m.version, slot)?;
            // validator.md get_payload_attestation_message_signature.
            let domain = fork_info.domain(DOMAIN_PTC_ATTESTER, epoch_at_slot(slot));
            (
                "PAYLOAD_ATTESTATION_MESSAGE",
                compute_signing_root(&m.data.root(), &domain),
                None,
            )
        }
        SignBody::ProposerPreferences {
            fork_info,
            proposer_preferences: p,
        } => {
            check_net(fork_info)?;
            let slot = p.data.proposal_slot.0;
            require_gloas(net, &p.version, slot)?;
            // validator.md get_signed_proposer_preferences: the fork version
            // of the proposal epoch (from the schedule, not fork_info, which
            // describes the current state: preferences for the first Gloas
            // epoch are signed before the fork).
            let version = net.fork_at_slot(slot).expect("checked above").version;
            let domain = compute_domain(
                DOMAIN_PROPOSER_PREFERENCES,
                version,
                &net.genesis_validators_root,
            );
            (
                "PROPOSER_PREFERENCES",
                compute_signing_root(&p.data.root(), &domain),
                None,
            )
        }
        SignBody::ExecutionPayloadEnvelope {
            fork_info,
            execution_payload_envelope: e,
        } => {
            check_net(fork_info)?;
            let env = &e.data;
            // verify_execution_payload_envelope: slot_number == the block's
            // slot. The slashing database checks that this key signed a block
            // with this root at this slot, which pins the slot.
            let slot = env.payload.slot_number.0;
            require_gloas(net, &e.version, slot)?;
            if env.builder_index.0 != BUILDER_INDEX_SELF_BUILD {
                return Err(PrepareError::Refused(format!(
                    "EXECUTION_PAYLOAD_ENVELOPE with builder_index {}: validator keys sign only self-built payloads",
                    env.builder_index.0
                )));
            }
            // builder.md get_execution_payload_envelope_signature: get_domain
            // at the state's (the block's) epoch.
            let domain = fork_info.domain(DOMAIN_BEACON_BUILDER, epoch_at_slot(slot));
            (
                "EXECUTION_PAYLOAD_ENVELOPE",
                compute_signing_root(&env.root()?, &domain),
                Some(SlashingCheck::OwnBlockPayload {
                    slot,
                    block_root: env.beacon_block_root.0,
                }),
            )
        }
        SignBody::ExecutionPayloadBid {} => {
            return Err(PrepareError::Refused(
                "EXECUTION_PAYLOAD_BID is signed by builders, not validators".into(),
            ));
        }
        SignBody::BuilderRequestAuth {
            builder_request_auth: a,
        } => {
            require_gloas(net, &a.version, a.data.slot.0)?;
            // builder-specs: compute_domain(DOMAIN_BUILDER_REQUEST_AUTH), i.e.
            // genesis fork version and a zero genesis validators root.
            let domain = compute_domain(
                DOMAIN_BUILDER_REQUEST_AUTH,
                net.genesis_fork_version,
                &[0u8; 32],
            );
            (
                "BUILDER_REQUEST_AUTH",
                compute_signing_root(&a.data.root()?, &domain),
                None,
            )
        }
    };

    if let Some(provided) = &req.signing_root
        && provided.0 != signing_root
    {
        return Err(PrepareError::Invalid(format!(
            "signingRoot 0x{} does not match computed root 0x{}",
            hex::encode(provided.0),
            hex::encode(signing_root)
        )));
    }

    Ok(Prepared {
        kind,
        signing_root,
        slashing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint256_decimal() {
        let p = |s: &str| serde_json::from_value::<U256Le>(serde_json::json!(s));
        assert_eq!(p("0").unwrap().0, [0; 32]);
        let mut one_word = [0u8; 32];
        one_word[8] = 1; // 2^64
        assert_eq!(p("18446744073709551616").unwrap().0, one_word);
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(p(max).unwrap().0, [0xff; 32]);
        assert!(
            p("115792089237316195423570985008687907853269984665640564039457584007913129639936")
                .is_err()
        );
        assert!(p("").is_err());
        assert!(p("0x10").is_err());
        assert!(p("-1").is_err());
    }
}
