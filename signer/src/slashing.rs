//! Slashing protection with per-key low watermarks (the "minimal" strategy
//! from EIP-3076):
//!
//! - blocks: only sign `slot > last_slot` (or an identical re-sign).
//! - attestations: only sign `source >= last_source && target > last_target`
//!   (or an identical re-sign), which also rules out surround votes.
//!
//! The new watermark is fsynced to disk *before* the signature is produced.
//! One small JSON file per key keeps the format trivially auditable.
//!
//! Inside a TEE the disk is host-controlled storage: confidentiality and
//! integrity come from the encrypted, measured disk, but nothing here stops
//! the host from rolling the whole disk back to an older snapshot. See
//! `ROADMAP.md` for the planned anti-rollback measures.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::signing::{SlashingCheck, U64};
use crate::ssz::Root;

#[derive(Debug, thiserror::Error)]
pub enum SlashingError {
    #[error("slashing protection: {0}")]
    Violation(String),
    #[error("slashing protection database error: {0}")]
    Db(String),
}

impl From<std::io::Error> for SlashingError {
    fn from(e: std::io::Error) -> Self {
        SlashingError::Db(e.to_string())
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
struct BlockMark {
    slot: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_root: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
struct AttestationMark {
    source: u64,
    target: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_root: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
struct Record {
    block: Option<BlockMark>,
    attestation: Option<AttestationMark>,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    genesis_validators_root: String,
}

pub struct SlashingDb {
    dir: PathBuf,
    gvr: Root,
    locks: Mutex<HashMap<[u8; 48], Arc<Mutex<()>>>>,
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Writes `data` to `path` atomically and durably.
fn write_durable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

impl SlashingDb {
    /// Opens (or creates) the database, pinning it to one network.
    pub fn open(dir: &Path, gvr: Root) -> Result<Self, SlashingError> {
        fs::create_dir_all(dir)?;
        let meta_path = dir.join("metadata.json");
        if meta_path.exists() {
            let meta: Metadata = serde_json::from_slice(&fs::read(&meta_path)?)
                .map_err(|e| SlashingError::Db(format!("metadata: {e}")))?;
            if meta.genesis_validators_root != hex0x(&gvr) {
                return Err(SlashingError::Db(format!(
                    "database belongs to genesis_validators_root {}, not {}",
                    meta.genesis_validators_root,
                    hex0x(&gvr)
                )));
            }
        } else {
            let meta = Metadata {
                genesis_validators_root: hex0x(&gvr),
            };
            write_durable(
                &meta_path,
                &serde_json::to_vec_pretty(&meta).expect("serialize"),
            )?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            gvr,
            locks: Mutex::default(),
        })
    }

    fn path(&self, pubkey: &[u8; 48]) -> PathBuf {
        self.dir.join(format!("{}.json", hex::encode(pubkey)))
    }

    fn lock(&self, pubkey: &[u8; 48]) -> Arc<Mutex<()>> {
        self.locks
            .lock()
            .expect("lock poisoned")
            .entry(*pubkey)
            .or_default()
            .clone()
    }

    fn load(&self, pubkey: &[u8; 48]) -> Result<Record, SlashingError> {
        match fs::read(self.path(pubkey)) {
            Ok(b) => {
                serde_json::from_slice(&b).map_err(|e| SlashingError::Db(format!("record: {e}")))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Record::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn store(&self, pubkey: &[u8; 48], rec: &Record) -> Result<(), SlashingError> {
        write_durable(
            &self.path(pubkey),
            &serde_json::to_vec_pretty(rec).expect("serialize"),
        )?;
        Ok(())
    }

    /// Checks `check` against the key's watermark and durably records it.
    /// Returns `Ok` only if it is safe to sign `root`.
    pub fn check_and_record(
        &self,
        pubkey: &[u8; 48],
        check: SlashingCheck,
        root: &Root,
    ) -> Result<(), SlashingError> {
        let lock = self.lock(pubkey);
        let _guard = lock.lock().expect("lock poisoned");

        let mut rec = self.load(pubkey)?;
        let root_hex = Some(hex0x(root));

        match check {
            SlashingCheck::Block { slot } => {
                if let Some(last) = &rec.block {
                    if slot == last.slot && last.signing_root == root_hex {
                        return Ok(());
                    }
                    if slot <= last.slot {
                        return Err(SlashingError::Violation(format!(
                            "block at slot {slot} is not after last signed slot {}",
                            last.slot
                        )));
                    }
                }
                rec.block = Some(BlockMark {
                    slot,
                    signing_root: root_hex,
                });
            }
            SlashingCheck::Attestation { source, target } => {
                if let Some(last) = &rec.attestation {
                    if target == last.target && last.signing_root == root_hex {
                        return Ok(());
                    }
                    if source < last.source {
                        return Err(SlashingError::Violation(format!(
                            "attestation source epoch {source} is before last signed source {}",
                            last.source
                        )));
                    }
                    if target <= last.target {
                        return Err(SlashingError::Violation(format!(
                            "attestation target epoch {target} is not after last signed target {}",
                            last.target
                        )));
                    }
                }
                rec.attestation = Some(AttestationMark {
                    source,
                    target,
                    signing_root: root_hex,
                });
            }
        }

        self.store(pubkey, &rec)
    }

    /// Imports an EIP-3076 interchange file, raising watermarks (never
    /// lowering them).
    pub fn import(&self, json: &[u8]) -> Result<usize, SlashingError> {
        let ic: Interchange = serde_json::from_slice(json)
            .map_err(|e| SlashingError::Db(format!("interchange: {e}")))?;
        if ic.metadata.interchange_format_version != "5" {
            return Err(SlashingError::Db(format!(
                "unsupported interchange version {}",
                ic.metadata.interchange_format_version
            )));
        }
        if ic.metadata.genesis_validators_root.to_lowercase() != hex0x(&self.gvr) {
            return Err(SlashingError::Db(
                "interchange is for a different network".into(),
            ));
        }

        for entry in &ic.data {
            let pubkey: [u8; 48] = hex::decode(entry.pubkey.trim_start_matches("0x"))
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| SlashingError::Db(format!("bad pubkey {}", entry.pubkey)))?;

            let lock = self.lock(&pubkey);
            let _guard = lock.lock().expect("lock poisoned");
            let mut rec = self.load(&pubkey)?;

            if let Some(max) = entry.signed_blocks.iter().map(|b| b.slot.0).max() {
                let current = rec.block.as_ref().map(|b| b.slot);
                if current.is_none_or(|c| max > c) {
                    rec.block = Some(BlockMark {
                        slot: max,
                        signing_root: None,
                    });
                }
            }
            if !entry.signed_attestations.is_empty() {
                let max_source = entry
                    .signed_attestations
                    .iter()
                    .map(|a| a.source_epoch.0)
                    .max()
                    .unwrap_or(0);
                let max_target = entry
                    .signed_attestations
                    .iter()
                    .map(|a| a.target_epoch.0)
                    .max()
                    .unwrap_or(0);
                let (source, target) = match &rec.attestation {
                    Some(a) => (a.source.max(max_source), a.target.max(max_target)),
                    None => (max_source, max_target),
                };
                if rec
                    .attestation
                    .as_ref()
                    .is_none_or(|a| (a.source, a.target) != (source, target))
                {
                    rec.attestation = Some(AttestationMark {
                        source,
                        target,
                        signing_root: None,
                    });
                }
            }
            self.store(&pubkey, &rec)?;
        }
        Ok(ic.data.len())
    }

    /// Exports watermarks as a minimal EIP-3076 interchange file.
    pub fn export(&self) -> Result<serde_json::Value, SlashingError> {
        let mut data = Vec::new();
        let mut paths: Vec<_> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "json")
                    && p.file_stem().is_some_and(|s| s.len() == 96)
            })
            .collect();
        paths.sort();

        for path in paths {
            let rec: Record = serde_json::from_slice(&fs::read(&path)?)
                .map_err(|e| SlashingError::Db(format!("{}: {e}", path.display())))?;
            let stem = path.file_stem().expect("filtered").to_string_lossy();
            let blocks: Vec<_> = rec
                .block
                .iter()
                .map(|b| {
                    with_root(
                        serde_json::json!({"slot": b.slot.to_string()}),
                        &b.signing_root,
                    )
                })
                .collect();
            let atts: Vec<_> = rec
                .attestation
                .iter()
                .map(|a| {
                    let v = serde_json::json!({
                        "source_epoch": a.source.to_string(),
                        "target_epoch": a.target.to_string(),
                    });
                    with_root(v, &a.signing_root)
                })
                .collect();
            data.push(serde_json::json!({
                "pubkey": format!("0x{stem}"),
                "signed_blocks": blocks,
                "signed_attestations": atts,
            }));
        }

        Ok(serde_json::json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": hex0x(&self.gvr),
            },
            "data": data,
        }))
    }
}

/// EIP-3076 `signing_root` is optional; omit it rather than emit `null`.
fn with_root(mut v: serde_json::Value, root: &Option<String>) -> serde_json::Value {
    if let Some(r) = root {
        v["signing_root"] = serde_json::json!(r);
    }
    v
}

#[derive(Deserialize)]
struct Interchange {
    metadata: InterchangeMetadata,
    data: Vec<InterchangeEntry>,
}

#[derive(Deserialize)]
struct InterchangeMetadata {
    interchange_format_version: String,
    genesis_validators_root: String,
}

#[derive(Deserialize)]
struct InterchangeEntry {
    pubkey: String,
    #[serde(default)]
    signed_blocks: Vec<InterchangeBlock>,
    #[serde(default)]
    signed_attestations: Vec<InterchangeAttestation>,
}

#[derive(Deserialize)]
struct InterchangeBlock {
    slot: U64,
}

#[derive(Deserialize)]
struct InterchangeAttestation {
    source_epoch: U64,
    target_epoch: U64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: [u8; 48] = [7u8; 48];

    fn db() -> (tempfile::TempDir, SlashingDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = SlashingDb::open(dir.path(), [1u8; 32]).unwrap();
        (dir, db)
    }

    fn att(source: u64, target: u64) -> SlashingCheck {
        SlashingCheck::Attestation { source, target }
    }

    #[test]
    fn blocks() {
        let (_d, db) = db();
        let block = |slot| SlashingCheck::Block { slot };
        db.check_and_record(&PK, block(10), &[1; 32]).unwrap();
        // Identical re-sign is allowed, different root at same slot is not.
        db.check_and_record(&PK, block(10), &[1; 32]).unwrap();
        assert!(db.check_and_record(&PK, block(10), &[2; 32]).is_err());
        assert!(db.check_and_record(&PK, block(9), &[3; 32]).is_err());
        db.check_and_record(&PK, block(11), &[4; 32]).unwrap();
    }

    #[test]
    fn attestations() {
        let (_d, db) = db();
        db.check_and_record(&PK, att(5, 6), &[1; 32]).unwrap();
        db.check_and_record(&PK, att(5, 6), &[1; 32]).unwrap();
        // Double vote.
        assert!(db.check_and_record(&PK, att(5, 6), &[2; 32]).is_err());
        // Surrounding vote (source before last source).
        assert!(db.check_and_record(&PK, att(4, 7), &[3; 32]).is_err());
        // Surrounded vote / old target.
        assert!(db.check_and_record(&PK, att(5, 5), &[4; 32]).is_err());
        db.check_and_record(&PK, att(6, 8), &[5; 32]).unwrap();
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = SlashingDb::open(dir.path(), [1u8; 32]).unwrap();
            db.check_and_record(&PK, att(5, 6), &[1; 32]).unwrap();
        }
        let db = SlashingDb::open(dir.path(), [1u8; 32]).unwrap();
        assert!(db.check_and_record(&PK, att(5, 6), &[2; 32]).is_err());
        // A database for one network refuses to open for another.
        assert!(SlashingDb::open(dir.path(), [2u8; 32]).is_err());
    }

    #[test]
    fn import_raises_and_export_roundtrips() {
        let (_d, db) = db();
        db.check_and_record(&PK, att(5, 6), &[1; 32]).unwrap();
        let ic = serde_json::json!({
            "metadata": {"interchange_format_version": "5", "genesis_validators_root": hex0x(&[1u8; 32])},
            "data": [{
                "pubkey": hex0x(&PK),
                "signed_blocks": [{"slot": "100"}, {"slot": "90"}],
                "signed_attestations": [{"source_epoch": "3", "target_epoch": "9"}],
            }],
        });
        db.import(ic.to_string().as_bytes()).unwrap();
        assert!(
            db.check_and_record(&PK, SlashingCheck::Block { slot: 100 }, &[9; 32])
                .is_err()
        );
        assert!(db.check_and_record(&PK, att(5, 9), &[9; 32]).is_err());
        db.check_and_record(&PK, att(5, 10), &[9; 32]).unwrap();

        let out = db.export().unwrap();
        let entry = &out["data"][0];
        assert_eq!(entry["signed_blocks"][0]["slot"], "100");
        assert_eq!(entry["signed_attestations"][0]["source_epoch"], "5");
        assert_eq!(entry["signed_attestations"][0]["target_epoch"], "10");

        let (_d2, other) = self::db();
        other.import(out.to_string().as_bytes()).unwrap();
        assert!(other.check_and_record(&PK, att(5, 10), &[0; 32]).is_err());
    }
}
