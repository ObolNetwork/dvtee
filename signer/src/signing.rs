//! Web3Signer eth2 request types and signing-root computation.
//!
//! The signer never signs a client-provided root: every root is recomputed
//! from the typed object, with the domain chosen here by request type. A
//! client-supplied `signingRoot` is only ever compared against the computed
//! one. Without this, a compromised validator client could pass the root of a
//! slashable attestation off as e.g. a RANDAO reveal.

use serde::Deserialize;
use serde::de::{self, Deserializer};

use crate::network::{Network, SLOTS_PER_EPOCH};
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

// ---------------------------------------------------------------------------
// Request types (https://consensys.github.io/web3signer/web3signer-eth2.html).

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
    fn root(&self) -> Root {
        ssz::container(&[
            ssz::uint64(self.slot.0),
            ssz::uint64(self.proposer_index.0),
            self.parent_root.0,
            self.state_root.0,
            self.body_root.0,
        ])
    }
}

impl Attestation {
    fn root(&self, electra: bool) -> Result<Root, String> {
        if electra {
            let committee_bits = self
                .committee_bits
                .as_ref()
                .ok_or("electra attestation is missing committee_bits")?;
            Ok(ssz::container(&[
                ssz::bitlist(
                    &self.aggregation_bits.0,
                    MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT,
                )?,
                self.data.root(),
                ssz::bytes_vector(&self.signature.0),
                ssz::bitvector(&committee_bits.0, MAX_COMMITTEES_PER_SLOT)?,
            ]))
        } else {
            if self.committee_bits.is_some() {
                return Err("pre-electra attestation must not have committee_bits".into());
            }
            Ok(ssz::container(&[
                ssz::bitlist(&self.aggregation_bits.0, MAX_VALIDATORS_PER_COMMITTEE)?,
                self.data.root(),
                ssz::bytes_vector(&self.signature.0),
            ]))
        }
    }
}

impl AggregateAndProof {
    fn root(&self, electra: bool) -> Result<Root, String> {
        Ok(ssz::container(&[
            ssz::uint64(self.aggregator_index.0),
            self.aggregate.root(electra)?,
            ssz::bytes_vector(&self.selection_proof.0),
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
    Block { slot: u64 },
    Attestation { source: u64, target: u64 },
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
}

impl From<String> for PrepareError {
    fn from(s: String) -> Self {
        PrepareError::Invalid(s)
    }
}

fn is_electra_or_later(version: &str) -> Result<bool, PrepareError> {
    match version.to_ascii_uppercase().as_str() {
        "PHASE0" | "ALTAIR" | "BELLATRIX" | "CAPELLA" | "DENEB" => Ok(false),
        "ELECTRA" | "FULU" => Ok(true),
        other => Err(PrepareError::Invalid(format!(
            "unsupported fork version {other:?}"
        ))),
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
            is_electra_or_later(&beacon_block.version)?;
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
            let domain = fork_info.domain(DOMAIN_BEACON_PROPOSER, epoch_at_slot(header.slot.0));
            (
                "BLOCK_V2",
                compute_signing_root(&header.root(), &domain),
                Some(SlashingCheck::Block {
                    slot: header.slot.0,
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
            // Lighthouse and Teku keep sending the v1 type after Electra, with
            // an Electra attestation inside. The v1 body carries no fork
            // version, so `committee_bits` (Electra and later only) picks the
            // schema. Either way the root is computed here and the domain is
            // the aggregate domain, so this cannot yield a slashable signature.
            let electra = aggregate_and_proof.aggregate.committee_bits.is_some();
            let domain = fork_info.domain(
                DOMAIN_AGGREGATE_AND_PROOF,
                epoch_at_slot(aggregate_and_proof.aggregate.data.slot.0),
            );
            (
                "AGGREGATE_AND_PROOF",
                compute_signing_root(&aggregate_and_proof.root(electra)?, &domain),
                None,
            )
        }
        SignBody::AggregateAndProofV2 {
            fork_info,
            aggregate_and_proof,
        } => {
            check_net(fork_info)?;
            let electra = is_electra_or_later(&aggregate_and_proof.version)?;
            let data = &aggregate_and_proof.data;
            let domain = fork_info.domain(
                DOMAIN_AGGREGATE_AND_PROOF,
                epoch_at_slot(data.aggregate.data.slot.0),
            );
            (
                "AGGREGATE_AND_PROOF_V2",
                compute_signing_root(&data.root(electra)?, &domain),
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
