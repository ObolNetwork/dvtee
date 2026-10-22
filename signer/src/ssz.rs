//! Minimal SSZ `hash_tree_root` helpers.
//!
//! The signer only ever needs the hash tree roots of a handful of small
//! consensus containers, so this hand-rolled merkleization keeps the trusted
//! computing base small instead of pulling in a full consensus types library.
//! Every container root is cross-checked against go-eth2-client in
//! `tests/vectors`.

use sha2::{Digest, Sha256};

pub type Root = [u8; 32];

/// Depth of the deepest tree we merkleize: Bitlist[131072] packs into 512
/// chunks, i.e. depth 9. Keep some headroom.
const MAX_DEPTH: usize = 16;

pub fn hash(a: &[u8], b: &[u8]) -> Root {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn zero_hashes() -> [Root; MAX_DEPTH + 1] {
    let mut z = [[0u8; 32]; MAX_DEPTH + 1];
    for i in 1..=MAX_DEPTH {
        z[i] = hash(&z[i - 1], &z[i - 1]);
    }
    z
}

/// `merkleize(chunks, limit)` from the SSZ spec.
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

/// Root of a fixed-size byte vector (`Bytes4`, `Bytes20`, `Bytes32`,
/// `BLSPubkey`, `BLSSignature`, ...).
pub fn bytes_vector(b: &[u8]) -> Root {
    merkleize(&pack(b), None)
}

pub fn container(fields: &[Root]) -> Root {
    merkleize(fields, None)
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

/// Root of a `Bitlist[N]` given its SSZ serialization (with the trailing
/// delimiter bit).
pub fn bitlist(serialized: &[u8], max: usize) -> Result<Root, String> {
    let Some(&last) = serialized.last() else {
        return Err("bitlist is empty (missing delimiter bit)".into());
    };
    if last == 0 {
        return Err("bitlist last byte is zero (missing delimiter bit)".into());
    }
    let msb = 7 - last.leading_zeros() as usize;
    let len = (serialized.len() - 1) * 8 + msb;
    if len > max {
        return Err(format!("bitlist length {len} exceeds limit {max}"));
    }

    let mut bits = serialized.to_vec();
    let last_idx = bits.len() - 1;
    bits[last_idx] &= !(1u8 << msb);
    // Strip the byte that only held the delimiter.
    bits.truncate(len.div_ceil(8));

    let root = merkleize(&pack(&bits), Some(max.div_ceil(256)));
    Ok(mix_in_length(&root, len))
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
