//! Minimal SSZ `hash_tree_root` helpers.
//!
//! The signer only ever needs the hash tree roots of a handful of small
//! consensus containers, so this hand-rolled merkleization keeps the trusted
//! computing base small instead of pulling in a full consensus types library.
//! Every container root is cross-checked against go-eth2-client in
//! `tests/vectors`; the progressive types (EIP-7495, EIP-7916) follow
//! `eth-ssz-specs` 0.1.0 (the SSZ package consensus-specs v1.7.0 builds on)
//! and are checked against its vectors and the consensus spec tests in
//! `tests/spec_tests.rs`.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

pub type Root = [u8; 32];

/// Depth of the deepest tree we merkleize. A progressive list's level `n`
/// is a binary tree of `4^n` chunks (depth `2n`); depth 40 covers far more
/// data than a request body can carry.
const MAX_DEPTH: usize = 40;

pub fn hash(a: &[u8], b: &[u8]) -> Root {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn zero_hashes() -> &'static [Root; MAX_DEPTH + 1] {
    static ZERO: OnceLock<[Root; MAX_DEPTH + 1]> = OnceLock::new();
    ZERO.get_or_init(|| {
        let mut z = [[0u8; 32]; MAX_DEPTH + 1];
        for i in 1..=MAX_DEPTH {
            z[i] = hash(&z[i - 1], &z[i - 1]);
        }
        z
    })
}

/// `merkleize(chunks, limit)` from the SSZ spec.
///
/// Panics if `chunks` exceeds `limit` or the tree is deeper than
/// `MAX_DEPTH`; callers bound their inputs first.
pub fn merkleize(chunks: &[Root], limit: Option<usize>) -> Root {
    let limit = limit.unwrap_or(chunks.len());
    assert!(chunks.len() <= limit, "merkleize: more chunks than limit");
    let width = limit.max(1).next_power_of_two();
    let depth = width.trailing_zeros() as usize;
    assert!(depth <= MAX_DEPTH, "merkleize: tree too deep");

    let zeros = zero_hashes();
    if chunks.is_empty() {
        return zeros[depth];
    }

    let mut layer: Vec<Root> = chunks.to_vec();
    for zero in &zeros[..depth] {
        if layer.len() % 2 == 1 {
            layer.push(*zero);
        }
        layer = layer.chunks(2).map(|p| hash(&p[0], &p[1])).collect();
    }
    layer[0]
}

/// `merkleize_progressive(chunks)` from EIP-7916: a right-leaning spine whose
/// level `n` (from 0) is a binary tree of `4^n` chunks, terminated by a zero
/// chunk.
pub fn merkleize_progressive(chunks: &[Root]) -> Root {
    // Levels are collected top-down and hashed bottom-up (no recursion).
    let mut subtrees = Vec::new();
    let (mut rest, mut width) = (chunks, 1usize);
    while !rest.is_empty() {
        let n = width.min(rest.len());
        subtrees.push(merkleize(&rest[..n], Some(width)));
        rest = &rest[n..];
        width *= 4;
    }
    subtrees
        .iter()
        .rev()
        .fold([0u8; 32], |successor, subtree| hash(subtree, &successor))
}

pub fn mix_in_length(root: &Root, len: usize) -> Root {
    let mut l = [0u8; 32];
    l[..8].copy_from_slice(&(len as u64).to_le_bytes());
    hash(root, &l)
}

/// Packs bytes into 32-byte chunks, zero-padding the last chunk.
pub fn pack(bytes: &[u8]) -> Vec<Root> {
    bytes
        .chunks(32)
        .map(|c| {
            let mut r = [0u8; 32];
            r[..c.len()].copy_from_slice(c);
            r
        })
        .collect()
}

pub fn uint64(v: u64) -> Root {
    let mut r = [0u8; 32];
    r[..8].copy_from_slice(&v.to_le_bytes());
    r
}

pub fn boolean(v: bool) -> Root {
    let mut r = [0u8; 32];
    r[0] = v as u8;
    r
}

/// Root of a fixed-size byte vector (`Bytes4`, `Bytes20`, `Bytes32`,
/// `BLSPubkey`, `BLSSignature`, `ByteVector[256]`, ...).
pub fn bytes_vector(b: &[u8]) -> Root {
    merkleize(&pack(b), None)
}

pub fn container(fields: &[Root]) -> Root {
    merkleize(fields, None)
}

/// Root of a `ProgressiveContainer` (EIP-7495). `active_fields[i]` says
/// whether layout position `i` holds a field; `fields` are the roots of the
/// present fields in order. Gaps merkleize as zero chunks and the layout is
/// mixed in as a 256-bit little-endian bitfield.
pub fn progressive_container(active_fields: &[bool], fields: &[Root]) -> Root {
    assert!(
        (1..=256).contains(&active_fields.len()) && active_fields.last() == Some(&true),
        "progressive container: invalid active_fields"
    );
    assert_eq!(
        active_fields.iter().filter(|a| **a).count(),
        fields.len(),
        "progressive container: field count does not match active_fields"
    );
    let mut it = fields.iter();
    let chunks: Vec<Root> = active_fields
        .iter()
        .map(|&a| {
            if a {
                *it.next().expect("counted")
            } else {
                [0u8; 32]
            }
        })
        .collect();
    let mut word = [0u8; 32];
    for (i, _) in active_fields.iter().enumerate().filter(|(_, a)| **a) {
        word[i / 8] |= 1 << (i % 8);
    }
    hash(&merkleize_progressive(&chunks), &word)
}

/// `ProgressiveContainer` whose `active_fields` has no gaps
/// (`active_fields(width=fields.len())`), the only shape Gloas uses.
pub fn progressive_container_dense(fields: &[Root]) -> Root {
    progressive_container(&vec![true; fields.len()], fields)
}

/// Root of a `ProgressiveList` of basic elements given its SSZ serialization
/// and element count (`ProgressiveList[Byte]` has `len == serialized.len()`).
pub fn progressive_list_packed(serialized: &[u8], len: usize) -> Root {
    mix_in_length(&merkleize_progressive(&pack(serialized)), len)
}

/// Root of a `ProgressiveList` of composite elements given their roots.
pub fn progressive_list(roots: &[Root]) -> Root {
    mix_in_length(&merkleize_progressive(roots), roots.len())
}

/// Root of a `ByteList[max]`.
pub fn byte_list(b: &[u8], max: usize) -> Result<Root, String> {
    if b.len() > max {
        return Err(format!(
            "byte list of {} bytes exceeds limit {max}",
            b.len()
        ));
    }
    Ok(mix_in_length(
        &merkleize(&pack(b), Some(max.div_ceil(32))),
        b.len(),
    ))
}

/// Root of a `Bitvector[N]` given its SSZ serialization.
pub fn bitvector(serialized: &[u8], n: usize) -> Result<Root, String> {
    if serialized.len() != n.div_ceil(8) {
        return Err(format!(
            "bitvector[{n}] must be {} bytes, got {}",
            n.div_ceil(8),
            serialized.len()
        ));
    }
    if !n.is_multiple_of(8) {
        let last = serialized[serialized.len() - 1];
        if last >> (n % 8) != 0 {
            return Err(format!("bitvector[{n}] has bits set beyond its length"));
        }
    }
    Ok(merkleize(&pack(serialized), Some(n.div_ceil(256))))
}

/// Splits a bitlist serialization (with the trailing delimiter bit) into
/// its packed bits (delimiter removed) and bit length.
fn bitlist_bits(serialized: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let Some(&last) = serialized.last() else {
        return Err("bitlist is empty (missing delimiter bit)".into());
    };
    if last == 0 {
        return Err("bitlist last byte is zero (missing delimiter bit)".into());
    }
    let msb = 7 - last.leading_zeros() as usize;
    let len = (serialized.len() - 1) * 8 + msb;

    let mut bits = serialized.to_vec();
    let last_idx = bits.len() - 1;
    bits[last_idx] &= !(1u8 << msb);
    // Strip the byte that only held the delimiter.
    bits.truncate(len.div_ceil(8));
    Ok((bits, len))
}

/// Root of a `Bitlist[N]` given its SSZ serialization (with the trailing
/// delimiter bit).
pub fn bitlist(serialized: &[u8], max: usize) -> Result<Root, String> {
    let (bits, len) = bitlist_bits(serialized)?;
    if len > max {
        return Err(format!("bitlist length {len} exceeds limit {max}"));
    }
    let root = merkleize(&pack(&bits), Some(max.div_ceil(256)));
    Ok(mix_in_length(&root, len))
}

/// Root of a `ProgressiveBitList` (EIP-7916) given its SSZ serialization,
/// which is the same as a bounded bitlist's.
pub fn progressive_bitlist(serialized: &[u8]) -> Result<Root, String> {
    let (bits, len) = bitlist_bits(serialized)?;
    Ok(mix_in_length(&merkleize_progressive(&pack(&bits)), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkleize_matches_naive_padding() {
        let chunks: Vec<Root> = (0u8..5).map(|i| [i; 32]).collect();
        let mut padded = chunks.clone();
        padded.resize(8, [0u8; 32]);
        let l1: Vec<Root> = padded.chunks(2).map(|p| hash(&p[0], &p[1])).collect();
        let l2: Vec<Root> = l1.chunks(2).map(|p| hash(&p[0], &p[1])).collect();
        assert_eq!(merkleize(&chunks, None), hash(&l2[0], &l2[1]));
    }

    #[test]
    fn single_chunk_is_identity() {
        assert_eq!(merkleize(&[[7u8; 32]], None), [7u8; 32]);
    }

    #[test]
    fn bitlist_rejects_missing_delimiter() {
        assert!(bitlist(&[], 2048).is_err());
        assert!(bitlist(&[0x01, 0x00], 2048).is_err());
    }

    #[test]
    fn bitlist_rejects_over_limit() {
        // 9 bits + delimiter.
        assert!(bitlist(&[0xff, 0x03], 8).is_err());
        assert!(bitlist(&[0xff, 0x03], 9).is_ok());
    }
}
