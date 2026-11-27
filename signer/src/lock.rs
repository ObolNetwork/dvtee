//! Charon cluster locks: parsing, the lock hash, and the checks the signer
//! runs before pinning itself to one.
//!
//! The lock hash is charon's SSZ-style hash (`cluster/ssz.go`), reproduced
//! here for lock versions v1.7.0 to v1.11.0 and checked against charon's own
//! test locks. Older versions have no builder registrations and are refused.
//!
//! What a valid lock proves here, and what it doesn't: `signature_aggregate`
//! is every public share of every validator signing the lock hash. Verifying
//! it, plus finding the signer's own shares at one operator index, catches a
//! wrong or corrupted lock. It does not stop a host from building a fake lock
//! around the real shares: the aggregate has no proof of possession, so other
//! "shares" can be chosen to cancel out the missing signatures. The real
//! anchor is the pin: the first lock is stored on the sealed disk, its hash
//! goes into the attestation evidence, and peers compare it with their own.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::ssz::{self, Root};

/// Reads a JSON `null` as an empty list. charon (Go) writes a nil slice as
/// `null` and hashes it as an empty list, e.g. `deposit_amounts` when
/// `--deposit-amounts` isn't given.
fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

const MAX_ENR: usize = 1024;
const MAX_NAME: usize = 256;
const MAX_UUID: usize = 64;
const MAX_VERSION: usize = 16;
const MAX_TIMESTAMP: usize = 32;
const MAX_DKG_ALGORITHM: usize = 32;
const MAX_OPERATORS: usize = 256;
const MAX_VALIDATORS: usize = 65536;
const MAX_DEPOSIT_AMOUNTS: usize = 256;
const MAX_K1_SIGS: usize = 32;
const K1_SIG_LEN: usize = 65;

const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("cluster lock: {0}")]
    Invalid(String),
    #[error("cluster lock version {0} is not supported (v1.7.0 to v1.11.0)")]
    Version(String),
}

fn invalid(msg: impl Into<String>) -> LockError {
    LockError::Invalid(msg.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Version {
    V1x7,
    V1x8,
    V1x9,
    V1x10,
    V1x11,
}

impl Version {
    fn parse(s: &str) -> Result<Self, LockError> {
        Ok(match s {
            "v1.7.0" => Self::V1x7,
            "v1.8.0" => Self::V1x8,
            "v1.9.0" => Self::V1x9,
            "v1.10.0" => Self::V1x10,
            "v1.11.0" => Self::V1x11,
            _ => return Err(LockError::Version(s.to_string())),
        })
    }
}

// ---------------------------------------------------------------------------
// JSON.

#[derive(Deserialize)]
struct LockJson {
    cluster_definition: DefinitionJson,
    distributed_validators: Vec<ValidatorJson>,
    #[serde(default)]
    signature_aggregate: String,
    lock_hash: String,
}

#[derive(Deserialize)]
struct DefinitionJson {
    #[serde(default)]
    name: String,
    #[serde(default)]
    creator: CreatorJson,
    operators: Vec<OperatorJson>,
    #[serde(default)]
    uuid: String,
    version: String,
    #[serde(default)]
    timestamp: String,
    num_validators: u64,
    threshold: u64,
    #[serde(default, deserialize_with = "null_as_empty")]
    validators: Vec<AddressesJson>,
    #[serde(default)]
    dkg_algorithm: String,
    fork_version: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    deposit_amounts: Vec<Value>,
    #[serde(default)]
    consensus_protocol: String,
    #[serde(default)]
    target_gas_limit: u64,
    #[serde(default)]
    compounding: bool,
    config_hash: String,
    definition_hash: String,
}

#[derive(Deserialize, Default)]
struct CreatorJson {
    #[serde(default)]
    address: String,
    #[serde(default)]
    config_signature: String,
}

#[derive(Deserialize)]
struct OperatorJson {
    #[serde(default)]
    address: String,
    #[serde(default)]
    enr: String,
    #[serde(default)]
    config_signature: String,
    #[serde(default)]
    enr_signature: String,
}

#[derive(Deserialize)]
struct AddressesJson {
    #[serde(default)]
    fee_recipient_address: String,
    #[serde(default)]
    withdrawal_address: String,
}

#[derive(Deserialize)]
struct ValidatorJson {
    distributed_public_key: String,
    public_shares: Vec<String>,
    #[serde(default)]
    deposit_data: Option<DepositJson>,
    #[serde(default, deserialize_with = "null_as_empty")]
    partial_deposit_data: Vec<DepositJson>,
    #[serde(default)]
    builder_registration: Option<BuilderRegistrationJson>,
}

#[derive(Deserialize)]
struct DepositJson {
    #[serde(default)]
    pubkey: String,
    #[serde(default)]
    withdrawal_credentials: String,
    #[serde(default)]
    amount: Value,
    #[serde(default)]
    signature: String,
}

#[derive(Deserialize)]
struct BuilderRegistrationJson {
    message: RegistrationJson,
    #[serde(default)]
    signature: String,
}

#[derive(Deserialize)]
struct RegistrationJson {
    #[serde(default)]
    fee_recipient: String,
    #[serde(default)]
    gas_limit: Value,
    #[serde(default)]
    timestamp: Value,
    #[serde(default)]
    pubkey: String,
}

fn hex_bytes(s: &str, field: &str) -> Result<Vec<u8>, LockError> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| invalid(format!("{field}: bad hex: {e}")))
}

/// Empty or exactly `n` bytes (charon hashes an absent value as zeros).
fn hex_n(s: &str, n: usize, field: &str) -> Result<Vec<u8>, LockError> {
    let b = hex_bytes(s, field)?;
    if !b.is_empty() && b.len() != n {
        return Err(invalid(format!("{field}: {} bytes, expected {n}", b.len())));
    }
    Ok(b)
}

fn hex_array<const N: usize>(s: &str, field: &str) -> Result<[u8; N], LockError> {
    hex_bytes(s, field)?
        .try_into()
        .map_err(|v: Vec<u8>| invalid(format!("{field}: {} bytes, expected {N}", v.len())))
}

/// A uint64 given as a JSON number or a decimal string.
fn json_u64(v: &Value, field: &str) -> Result<u64, LockError> {
    match v {
        Value::Null => Ok(0),
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| invalid(format!("{field}: not a uint64"))),
        Value::String(s) => s
            .parse()
            .map_err(|_| invalid(format!("{field}: not a uint64: {s:?}"))),
        _ => Err(invalid(format!("{field}: not a uint64"))),
    }
}

/// Registration timestamps are Unix seconds, or RFC 3339 in some writers.
fn json_unix_time(v: &Value, field: &str) -> Result<u64, LockError> {
    match v {
        Value::String(s) if s.contains('T') => {
            parse_rfc3339(s).ok_or_else(|| invalid(format!("{field}: bad timestamp {s:?}")))
        }
        _ => json_u64(v, field),
    }
}

/// Minimal RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`) to Unix seconds.
fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &s[19..];
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "Z" => 0,
        _ if rest.len() == 6 => {
            let sign = match &rest[..1] {
                "+" => 1,
                "-" => -1,
                _ => return None,
            };
            sign * (rest[1..3].parse::<i64>().ok()? * 3600 + rest[4..6].parse::<i64>().ok()? * 60)
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    u64::try_from(days * 86400 + h * 3600 + mi * 60 + sec - offset).ok()
}

// ---------------------------------------------------------------------------
// Charon's hash walker (dynamic-ssz `Hasher`), as far as the lock needs it.

#[derive(Default)]
struct Hasher {
    buf: Vec<u8>,
}

impl Hasher {
    fn index(&self) -> usize {
        self.buf.len()
    }

    /// Appends `b` zero-padded to a multiple of 32 bytes (nothing if empty).
    fn append_bytes32(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
        let rest = b.len() % 32;
        if rest != 0 {
            self.buf.resize(self.buf.len() + 32 - rest, 0);
        }
    }

    fn put_bytes(&mut self, b: &[u8]) {
        if b.len() <= 32 {
            self.append_bytes32(b);
        } else {
            let idx = self.index();
            self.append_bytes32(b);
            self.merkleize(idx);
        }
    }

    fn put_u64(&mut self, v: u64) {
        self.append_bytes32(&v.to_le_bytes());
    }

    fn put_bool(&mut self, v: bool) {
        self.append_bytes32(&[v as u8]);
    }

    fn put_u64_list(&mut self, values: &[u64], max: usize) {
        let idx = self.index();
        for v in values {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
        self.fill_up_to_32();
        self.merkleize_with_mixin(idx, values.len(), (max * 8).div_ceil(32));
    }

    fn fill_up_to_32(&mut self) {
        let rest = self.buf.len() % 32;
        if rest != 0 {
            self.buf.resize(self.buf.len() + 32 - rest, 0);
        }
    }

    fn chunks(&self, idx: usize) -> Vec<Root> {
        self.buf[idx..]
            .chunks(32)
            .map(|c| c.try_into().expect("buffer is 32-byte aligned"))
            .collect()
    }

    fn merkleize(&mut self, idx: usize) {
        let root = ssz::merkleize(&self.chunks(idx), None);
        self.buf.truncate(idx);
        self.buf.extend_from_slice(&root);
    }

    fn merkleize_with_mixin(&mut self, idx: usize, num: usize, limit_chunks: usize) {
        self.fill_up_to_32();
        let chunks = self.chunks(idx);
        let root = ssz::mix_in_length(&ssz::merkleize(&chunks, Some(limit_chunks)), num);
        self.buf.truncate(idx);
        self.buf.extend_from_slice(&root);
    }

    fn root(&self) -> Result<Root, LockError> {
        self.buf
            .as_slice()
            .try_into()
            .map_err(|_| invalid("hash walker did not end with one root"))
    }

    // charon `cluster/helpers.go`.

    fn put_byte_list(&mut self, b: &[u8], limit: usize, field: &str) -> Result<(), LockError> {
        if b.len() > limit {
            return Err(invalid(format!("{field}: longer than {limit} bytes")));
        }
        let idx = self.index();
        self.append_bytes32(b);
        self.merkleize_with_mixin(idx, b.len(), limit.div_ceil(32));
        Ok(())
    }

    /// `putBytesN`: empty or `n` bytes, left-padded to `n`.
    fn put_bytes_n(&mut self, b: &[u8], n: usize) {
        let mut padded = vec![0u8; n.saturating_sub(b.len())];
        padded.extend_from_slice(b);
        self.put_bytes(&padded);
    }

    /// `putBytesRaw`: appended as is, so an empty value appends nothing.
    fn put_bytes_raw(&mut self, b: &[u8]) {
        self.put_bytes(b);
    }

    fn put_hex_address(&mut self, s: &str, field: &str) -> Result<(), LockError> {
        let b = if s.is_empty() {
            Vec::new()
        } else {
            hex_array::<20>(s, field)?.to_vec()
        };
        self.put_bytes_n(&b, 20);
        Ok(())
    }

    fn put_k1_sig_list(&mut self, sigs: &[u8], field: &str) -> Result<(), LockError> {
        if !sigs.len().is_multiple_of(K1_SIG_LEN) {
            return Err(invalid(format!("{field}: not a multiple of 65 bytes")));
        }
        let num = sigs.len() / K1_SIG_LEN;
        if num > MAX_K1_SIGS {
            return Err(invalid(format!(
                "{field}: more than {MAX_K1_SIGS} signatures"
            )));
        }
        let idx = self.index();
        for sig in sigs.chunks(K1_SIG_LEN) {
            self.put_bytes(sig);
        }
        self.merkleize_with_mixin(idx, num, MAX_K1_SIGS);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hashes.

fn hash_definition(d: &DefinitionJson, v: Version, config_only: bool) -> Result<Root, LockError> {
    let mut h = Hasher::default();
    let idx = h.index();
    h.put_byte_list(d.uuid.as_bytes(), MAX_UUID, "uuid")?;
    h.put_byte_list(d.name.as_bytes(), MAX_NAME, "name")?;
    h.put_byte_list(d.version.as_bytes(), MAX_VERSION, "version")?;
    h.put_byte_list(d.timestamp.as_bytes(), MAX_TIMESTAMP, "timestamp")?;
    h.put_u64(d.num_validators);
    h.put_u64(d.threshold);
    h.put_byte_list(
        d.dkg_algorithm.as_bytes(),
        MAX_DKG_ALGORITHM,
        "dkg_algorithm",
    )?;
    h.put_bytes_n(&hex_n(&d.fork_version, 4, "fork_version")?, 4);

    // Operators.
    if d.operators.len() > MAX_OPERATORS {
        return Err(invalid("too many operators"));
    }
    let ops_idx = h.index();
    for o in &d.operators {
        let op_idx = h.index();
        h.put_hex_address(&o.address, "operator address")?;
        if !config_only {
            h.put_byte_list(o.enr.as_bytes(), MAX_ENR, "enr")?;
            let cs = hex_bytes(&o.config_signature, "config_signature")?;
            let es = hex_bytes(&o.enr_signature, "enr_signature")?;
            if v >= Version::V1x11 {
                h.put_k1_sig_list(&cs, "config_signature")?;
                h.put_k1_sig_list(&es, "enr_signature")?;
            } else {
                for (s, f) in [(&cs, "config_signature"), (&es, "enr_signature")] {
                    if !s.is_empty() && s.len() != K1_SIG_LEN {
                        return Err(invalid(format!("{f}: expected 65 bytes")));
                    }
                    h.put_bytes_n(s, K1_SIG_LEN);
                }
            }
        }
        h.merkleize(op_idx);
    }
    h.merkleize_with_mixin(ops_idx, d.operators.len(), MAX_OPERATORS);

    // Creator.
    let creator_idx = h.index();
    h.put_hex_address(&d.creator.address, "creator address")?;
    if !config_only {
        let cs = hex_bytes(&d.creator.config_signature, "creator config_signature")?;
        if v >= Version::V1x11 {
            h.put_k1_sig_list(&cs, "creator config_signature")?;
        } else {
            if !cs.is_empty() && cs.len() != K1_SIG_LEN {
                return Err(invalid("creator config_signature: expected 65 bytes"));
            }
            h.put_bytes_n(&cs, K1_SIG_LEN);
        }
    }
    h.merkleize(creator_idx);

    // Validator addresses.
    if d.validators.len() > MAX_VALIDATORS {
        return Err(invalid("too many validators"));
    }
    let vals_idx = h.index();
    for a in &d.validators {
        let a_idx = h.index();
        h.put_hex_address(&a.fee_recipient_address, "fee_recipient_address")?;
        h.put_hex_address(&a.withdrawal_address, "withdrawal_address")?;
        h.merkleize(a_idx);
    }
    h.merkleize_with_mixin(vals_idx, d.validators.len(), MAX_VALIDATORS);

    if v >= Version::V1x8 {
        if d.deposit_amounts.len() > MAX_DEPOSIT_AMOUNTS {
            return Err(invalid("too many deposit amounts"));
        }
        let amounts = d
            .deposit_amounts
            .iter()
            .map(|a| json_u64(a, "deposit_amounts"))
            .collect::<Result<Vec<_>, _>>()?;
        h.put_u64_list(&amounts, MAX_DEPOSIT_AMOUNTS);
    }
    if v >= Version::V1x9 {
        h.put_byte_list(
            d.consensus_protocol.as_bytes(),
            MAX_NAME,
            "consensus_protocol",
        )?;
    }
    if v >= Version::V1x10 {
        h.put_u64(d.target_gas_limit);
        h.put_bool(d.compounding);
    }
    if !config_only {
        h.put_bytes_n(&hex_n(&d.config_hash, 32, "config_hash")?, 32);
    }
    h.merkleize(idx);
    h.root()
}

fn hash_deposit(h: &mut Hasher, d: Option<&DepositJson>) -> Result<(), LockError> {
    let empty = DepositJson {
        pubkey: String::new(),
        withdrawal_credentials: String::new(),
        amount: Value::Null,
        signature: String::new(),
    };
    let d = d.unwrap_or(&empty);
    let idx = h.index();
    h.put_bytes_n(&hex_n(&d.pubkey, 48, "deposit pubkey")?, 48);
    h.put_bytes_n(
        &hex_n(&d.withdrawal_credentials, 32, "withdrawal_credentials")?,
        32,
    );
    h.put_u64(json_u64(&d.amount, "deposit amount")?);
    h.put_bytes_n(&hex_n(&d.signature, 96, "deposit signature")?, 96);
    h.merkleize(idx);
    Ok(())
}

fn hash_registration(h: &mut Hasher, r: Option<&BuilderRegistrationJson>) -> Result<(), LockError> {
    let idx = h.index();
    let msg_idx = h.index();
    let (fee_recipient, gas_limit, timestamp, pubkey, sig) = match r {
        Some(r) => (
            hex_n(&r.message.fee_recipient, 20, "registration fee_recipient")?,
            json_u64(&r.message.gas_limit, "registration gas_limit")?,
            json_unix_time(&r.message.timestamp, "registration timestamp")?,
            hex_n(&r.message.pubkey, 48, "registration pubkey")?,
            hex_n(&r.signature, 96, "registration signature")?,
        ),
        None => (Vec::new(), 0, unix_zero_time(), Vec::new(), Vec::new()),
    };
    h.put_bytes_raw(&fee_recipient);
    h.put_u64(gas_limit);
    h.put_u64(timestamp);
    h.put_bytes_n(&pubkey, 48);
    h.merkleize(msg_idx);
    h.put_bytes_n(&sig, 96);
    h.merkleize(idx);
    Ok(())
}

/// Go's zero `time.Time` as Unix seconds, which is what charon hashes for an
/// absent registration.
fn unix_zero_time() -> u64 {
    (-62_135_596_800i64) as u64
}

fn hash_validator(h: &mut Hasher, val: &ValidatorJson, v: Version) -> Result<(), LockError> {
    let idx = h.index();
    h.put_bytes_n(
        &hex_n(&val.distributed_public_key, 48, "distributed_public_key")?,
        48,
    );

    if val.public_shares.len() > MAX_OPERATORS {
        return Err(invalid("too many public shares"));
    }
    let shares_idx = h.index();
    for s in &val.public_shares {
        h.put_bytes_n(&hex_n(s, 48, "public_shares")?, 48);
    }
    h.merkleize_with_mixin(shares_idx, val.public_shares.len(), MAX_OPERATORS);

    if v == Version::V1x7 {
        hash_deposit(h, val.deposit_data.as_ref())?;
    } else {
        if val.partial_deposit_data.len() > MAX_DEPOSIT_AMOUNTS {
            return Err(invalid("too many partial deposits"));
        }
        let list_idx = h.index();
        for d in &val.partial_deposit_data {
            let d_idx = h.index();
            hash_deposit(h, Some(d))?;
            h.merkleize(d_idx);
        }
        h.merkleize_with_mixin(
            list_idx,
            val.partial_deposit_data.len(),
            MAX_DEPOSIT_AMOUNTS,
        );
    }
    hash_registration(h, val.builder_registration.as_ref())?;
    h.merkleize(idx);
    Ok(())
}

fn hash_lock(l: &LockJson, v: Version) -> Result<Root, LockError> {
    if l.distributed_validators.len() > MAX_VALIDATORS {
        return Err(invalid("too many validators"));
    }
    let mut h = Hasher::default();
    let idx = h.index();
    let def = hash_definition(&l.cluster_definition, v, false)?;
    h.buf.extend_from_slice(&def);
    let vals_idx = h.index();
    for val in &l.distributed_validators {
        hash_validator(&mut h, val, v)?;
    }
    h.merkleize_with_mixin(vals_idx, l.distributed_validators.len(), MAX_VALIDATORS);
    h.merkleize(idx);
    h.root()
}

/// Parses the JSON and checks the config, definition and lock hashes.
fn parse_checked(json: &[u8]) -> Result<(LockJson, Root), LockError> {
    let l: LockJson =
        serde_json::from_slice(json).map_err(|e| invalid(format!("bad JSON: {e}")))?;
    let d = &l.cluster_definition;
    let v = Version::parse(&d.version)?;

    let expect = |field: &str, given: &str, computed: Root| -> Result<(), LockError> {
        let given = hex_array::<32>(given, field)?;
        if given != computed {
            return Err(invalid(format!(
                "{field} 0x{} does not match the contents (0x{})",
                hex::encode(given),
                hex::encode(computed)
            )));
        }
        Ok(())
    };
    expect("config_hash", &d.config_hash, hash_definition(d, v, true)?)?;
    expect(
        "definition_hash",
        &d.definition_hash,
        hash_definition(d, v, false)?,
    )?;
    let lock_hash = hash_lock(&l, v)?;
    expect("lock_hash", &l.lock_hash, lock_hash)?;
    Ok((l, lock_hash))
}

// ---------------------------------------------------------------------------
// The checked lock.

/// One validator, as far as the signer cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockValidator {
    pub pubkey: [u8; 48],
    pub public_shares: Vec<[u8; 48]>,
    /// From the definition, which every operator signed.
    pub fee_recipient: [u8; 20],
}

#[derive(Clone, Debug)]
pub struct ClusterLock {
    pub lock_hash: Root,
    pub version: String,
    pub threshold: u64,
    pub validators: Vec<LockValidator>,
    signature_aggregate: Vec<u8>,
}

impl ClusterLock {
    /// Parses a lock and checks its hashes (config, definition and lock) and
    /// shape. Signatures are checked by [`ClusterLock::verify_aggregate`].
    pub fn parse(json: &[u8]) -> Result<Self, LockError> {
        let (l, lock_hash) = parse_checked(json)?;
        let d = &l.cluster_definition;

        let n = d.operators.len();
        if d.threshold == 0 || d.threshold as usize > n {
            return Err(invalid(format!(
                "threshold {} of {n} operators",
                d.threshold
            )));
        }
        if l.distributed_validators.len() as u64 != d.num_validators
            || d.validators.len() != l.distributed_validators.len()
        {
            return Err(invalid(
                "num_validators, definition validators and distributed validators disagree",
            ));
        }

        let mut validators = Vec::with_capacity(l.distributed_validators.len());
        for (i, (val, addrs)) in l
            .distributed_validators
            .iter()
            .zip(&d.validators)
            .enumerate()
        {
            if val.public_shares.len() != n {
                return Err(invalid(format!(
                    "validator {i}: {} public shares for {n} operators",
                    val.public_shares.len()
                )));
            }
            let pubkey = hex_array::<48>(&val.distributed_public_key, "distributed_public_key")?;
            let public_shares = val
                .public_shares
                .iter()
                .map(|s| hex_array::<48>(s, "public_shares"))
                .collect::<Result<Vec<_>, _>>()?;
            let fee_recipient =
                hex_array::<20>(&addrs.fee_recipient_address, "fee_recipient_address")
                    .map_err(|e| invalid(format!("validator {i}: {e}")))?;
            if let Some(r) = &val.builder_registration {
                let reg = hex_array::<20>(&r.message.fee_recipient, "registration fee_recipient")?;
                if reg != fee_recipient {
                    return Err(invalid(format!(
                        "validator {i}: builder registration fee recipient 0x{} differs from the definition's 0x{}",
                        hex::encode(reg),
                        hex::encode(fee_recipient)
                    )));
                }
            }
            validators.push(LockValidator {
                pubkey,
                public_shares,
                fee_recipient,
            });
        }

        Ok(Self {
            lock_hash,
            version: d.version.clone(),
            threshold: d.threshold,
            validators,
            signature_aggregate: hex_bytes(&l.signature_aggregate, "signature_aggregate")?,
        })
    }

    /// Every public share signed the lock hash (charon `VerifyAggregate`).
    pub fn verify_aggregate(&self) -> Result<(), LockError> {
        use blst::BLST_ERROR;
        use blst::min_pk::{PublicKey, Signature};

        let sig = Signature::sig_validate(&self.signature_aggregate, true)
            .map_err(|e| invalid(format!("signature_aggregate: {e:?}")))?;
        let pks = self
            .validators
            .iter()
            .flat_map(|v| &v.public_shares)
            .map(|s| PublicKey::key_validate(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid(format!("public share: {e:?}")))?;
        let refs: Vec<&PublicKey> = pks.iter().collect();
        match sig.fast_aggregate_verify(true, &self.lock_hash, BLS_DST, &refs) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(invalid(format!(
                "signature_aggregate does not verify: {e:?}"
            ))),
        }
    }

    /// The operator index at which every one of `keys` is a public share,
    /// mapping each key to its validator. Every key must be in the lock, at
    /// the same index.
    pub fn locate(&self, keys: &[[u8; 48]]) -> Result<Located, LockError> {
        let mut index: Option<usize> = None;
        let mut by_share = BTreeMap::new();
        for key in keys {
            let found = self.validators.iter().find_map(|v| {
                v.public_shares
                    .iter()
                    .position(|s| s == key)
                    .map(|i| (i, v))
            });
            let Some((i, v)) = found else {
                return Err(invalid(format!(
                    "key 0x{} is not a public share in the lock",
                    hex::encode(key)
                )));
            };
            match index {
                None => index = Some(i),
                Some(j) if j != i => {
                    return Err(invalid(format!(
                        "keys belong to different operators ({j} and {i})"
                    )));
                }
                _ => {}
            }
            by_share.insert(*key, v.clone());
        }
        Ok(Located {
            operator_index: index.ok_or_else(|| invalid("no keys to locate"))?,
            by_share,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Located {
    pub operator_index: usize,
    pub by_share: BTreeMap<[u8; 48], LockValidator>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2022-06-20T14:00:00Z"), Some(1655733600));
        assert_eq!(parse_rfc3339("2022-06-20T16:00:00+02:00"), Some(1655733600));
        assert_eq!(parse_rfc3339("2022-06-20T14:00:00.123Z"), Some(1655733600));
        assert_eq!(parse_rfc3339("2022-06-20 14:00:00Z"), None);
    }

    #[test]
    fn go_zero_time() {
        // time.Time{}.Unix()
        assert_eq!(unix_zero_time() as i64, -62135596800);
    }
}

#[cfg(test)]
mod vectors {
    use super::*;

    /// charon `cluster/testdata` locks (charon 67f664f7c): random contents,
    /// with the config, definition and lock hashes charon computed.
    fn check(json: &str) {
        let (_, hash) = parse_checked(json.as_bytes()).expect("hashes match");
        assert_ne!(hash, [0u8; 32]);
        // The test data is random, so the shape checks after the hashes fail.
        assert!(ClusterLock::parse(json.as_bytes()).is_err());
    }

    #[test]
    fn charon_v1_7() {
        check(include_str!(
            "../tests/vectors/cluster-lock/cluster_lock_v1_7_0.json"
        ));
    }
    #[test]
    fn charon_v1_8() {
        check(include_str!(
            "../tests/vectors/cluster-lock/cluster_lock_v1_8_0.json"
        ));
    }
    #[test]
    fn charon_v1_9() {
        check(include_str!(
            "../tests/vectors/cluster-lock/cluster_lock_v1_9_0.json"
        ));
    }
    #[test]
    fn charon_v1_10() {
        check(include_str!(
            "../tests/vectors/cluster-lock/cluster_lock_v1_10_0.json"
        ));
    }
    #[test]
    fn charon_v1_11() {
        check(include_str!(
            "../tests/vectors/cluster-lock/cluster_lock_v1_11_0.json"
        ));
    }

    /// A real lock from `charon create cluster` without `--deposit-amounts`,
    /// so `deposit_amounts` is `null`: it must parse in full and verify.
    #[test]
    fn charon_null_deposit_amounts() {
        let json =
            include_str!("../tests/vectors/cluster-lock/charon_create_null_deposit_amounts.json");
        assert!(json.contains("\"deposit_amounts\": null"));
        let lock = ClusterLock::parse(json.as_bytes()).expect("parses");
        lock.verify_aggregate().unwrap();
        assert_eq!(
            hex::encode(lock.lock_hash),
            "71ae536aca0d41a95cedde400a8f21ac4e9087c5e8072c2b6ec2fb2c8012c37f"
        );
    }
}

/// Builds valid v1.10 locks for tests: real hashes and a real aggregate.
#[cfg(test)]
pub(crate) mod testlock {
    use super::*;
    use crate::keystore::SecretKey;

    pub struct Spec {
        pub threshold: u64,
        /// Per validator: its fee recipient and the secret share of each
        /// operator.
        pub validators: Vec<([u8; 20], Vec<SecretKey>)>,
    }

    pub fn secret(seed: u8) -> SecretKey {
        let mut ikm = [seed; 32];
        ikm[0] = 0x5e;
        let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
        SecretKey::from_bytes(&sk.to_bytes()).unwrap()
    }

    fn hx(b: &[u8]) -> String {
        format!("0x{}", hex::encode(b))
    }

    pub fn build(spec: &Spec) -> Vec<u8> {
        build_with(spec, |_| {})
    }

    /// `edit` changes the JSON after the hashes are computed and before the
    /// aggregate is signed, e.g. to test what a tampered lock does.
    pub fn build_with(spec: &Spec, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let n = spec.validators[0].1.len();
        let operators: Vec<Value> = (0..n)
            .map(|i| {
                serde_json::json!({
                    "address": hx(&[i as u8 + 1; 20]),
                    "enr": format!("enr:-test-{i}"),
                    "config_signature": hx(&[7u8; 65]),
                    "enr_signature": hx(&[8u8; 65]),
                })
            })
            .collect();
        let validators: Vec<Value> = spec
            .validators
            .iter()
            .map(|(fr, _)| {
                serde_json::json!({
                    "fee_recipient_address": hx(fr),
                    "withdrawal_address": hx(&[0xaa; 20]),
                })
            })
            .collect();
        let mut def = serde_json::json!({
            "name": "test", "creator": {"address": hx(&[9u8; 20]), "config_signature": hx(&[6u8; 65])},
            "operators": operators, "uuid": "u", "version": "v1.10.0",
            "timestamp": "2026-11-26T00:00:00Z", "num_validators": spec.validators.len(),
            "threshold": spec.threshold, "validators": validators, "dkg_algorithm": "default",
            "fork_version": "0x10000910", "deposit_amounts": ["32000000000"],
            "consensus_protocol": "", "target_gas_limit": 60000000, "compounding": true,
            "config_hash": hx(&[0u8; 32]), "definition_hash": hx(&[0u8; 32]),
        });
        let d: DefinitionJson = serde_json::from_value(def.clone()).unwrap();
        def["config_hash"] = hx(&hash_definition(&d, Version::V1x10, true).unwrap()).into();
        let d: DefinitionJson = serde_json::from_value(def.clone()).unwrap();
        def["definition_hash"] = hx(&hash_definition(&d, Version::V1x10, false).unwrap()).into();

        let dvs: Vec<Value> = spec
            .validators
            .iter()
            .enumerate()
            .map(|(i, (fr, shares))| {
                let dv = [i as u8 + 0x30; 48];
                serde_json::json!({
                    "distributed_public_key": hx(&dv),
                    "public_shares": shares.iter().map(|s| hx(&s.public_key())).collect::<Vec<_>>(),
                    "builder_registration": {
                        "message": {"fee_recipient": hx(fr), "gas_limit": 60000000,
                                    "timestamp": 1764115200, "pubkey": hx(&dv)},
                        "signature": hx(&[1u8; 96]),
                    },
                    "partial_deposit_data": [],
                })
            })
            .collect();
        let mut lock = serde_json::json!({
            "cluster_definition": def, "distributed_validators": dvs,
            "signature_aggregate": "", "lock_hash": hx(&[0u8; 32]), "node_signatures": [],
        });
        let l: LockJson = serde_json::from_value(lock.clone()).unwrap();
        let lock_hash = hash_lock(&l, Version::V1x10).unwrap();
        lock["lock_hash"] = hx(&lock_hash).into();
        edit(&mut lock);

        let sigs: Vec<blst::min_pk::Signature> = spec
            .validators
            .iter()
            .flat_map(|(_, shares)| shares)
            .map(|s| blst::min_pk::Signature::from_bytes(&s.sign(&lock_hash)).unwrap())
            .collect();
        let refs: Vec<&blst::min_pk::Signature> = sigs.iter().collect();
        let agg = blst::min_pk::AggregateSignature::aggregate(&refs, true).unwrap();
        lock["signature_aggregate"] = hx(&agg.to_signature().to_bytes()).into();
        serde_json::to_vec_pretty(&lock).unwrap()
    }
}

#[cfg(test)]
mod checked {
    use super::testlock::*;
    use super::*;

    fn spec() -> Spec {
        Spec {
            threshold: 3,
            validators: vec![
                ([0x11; 20], (0..4).map(secret).collect()),
                ([0x22; 20], (10..14).map(secret).collect()),
            ],
        }
    }

    #[test]
    fn valid_lock() {
        let s = spec();
        let lock = ClusterLock::parse(&build(&s)).unwrap();
        lock.verify_aggregate().unwrap();
        assert_eq!(lock.validators[1].fee_recipient, [0x22; 20]);

        let keys = [
            s.validators[0].1[2].public_key(),
            s.validators[1].1[2].public_key(),
        ];
        let located = lock.locate(&keys).unwrap();
        assert_eq!(located.operator_index, 2);
        assert_eq!(located.by_share[&keys[1]].fee_recipient, [0x22; 20]);
    }

    #[test]
    fn keys_must_be_one_operators_shares() {
        let s = spec();
        let lock = ClusterLock::parse(&build(&s)).unwrap();
        let mixed = [
            s.validators[0].1[1].public_key(),
            s.validators[1].1[2].public_key(),
        ];
        assert!(lock.locate(&mixed).is_err());
        assert!(lock.locate(&[secret(99).public_key()]).is_err());
    }

    #[test]
    fn tampered_fee_recipient_breaks_the_hashes() {
        let s = spec();
        let json = build_with(&s, |l| {
            l["cluster_definition"]["validators"][0]["fee_recipient_address"] =
                format!("0x{}", hex::encode([0x66; 20])).into();
        });
        let e = ClusterLock::parse(&json).unwrap_err().to_string();
        assert!(e.contains("hash"), "{e}");
    }

    #[test]
    fn missing_share_signature_fails_the_aggregate() {
        let s = spec();
        let json = build(&s);
        let lock = ClusterLock::parse(&json).unwrap();
        // Every share but one signs the lock hash.
        let sigs: Vec<blst::min_pk::Signature> = s
            .validators
            .iter()
            .flat_map(|(_, shares)| shares)
            .skip(1)
            .map(|k| blst::min_pk::Signature::from_bytes(&k.sign(&lock.lock_hash)).unwrap())
            .collect();
        let refs: Vec<_> = sigs.iter().collect();
        let agg = blst::min_pk::AggregateSignature::aggregate(&refs, true).unwrap();
        let mut v: Value = serde_json::from_slice(&json).unwrap();
        v["signature_aggregate"] =
            format!("0x{}", hex::encode(agg.to_signature().to_bytes())).into();
        let lock = ClusterLock::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(lock.verify_aggregate().is_err());
    }

    #[test]
    fn registration_fee_recipient_must_match_definition() {
        let s = spec();
        let json = build(&s);
        // Change the registration and recompute the lock hash, so only the
        // consistency check can catch it.
        let mut v: Value = serde_json::from_slice(&json).unwrap();
        v["distributed_validators"][0]["builder_registration"]["message"]["fee_recipient"] =
            format!("0x{}", hex::encode([0x66; 20])).into();
        let l: LockJson = serde_json::from_value(v.clone()).unwrap();
        v["lock_hash"] =
            format!("0x{}", hex::encode(hash_lock(&l, Version::V1x10).unwrap())).into();
        let e = ClusterLock::parse(&serde_json::to_vec(&v).unwrap())
            .unwrap_err()
            .to_string();
        assert!(e.contains("builder registration fee recipient"), "{e}");
    }
}
