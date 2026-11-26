//! A small Roughtime client: signed, nonce-bound time from servers with
//! pinned Ed25519 keys (draft-ietf-ntp-roughtime).
//!
//! Live servers speak different drafts, so the request offers two versions
//! and the response is checked by the version the server picked:
//!
//! - `0x8000000c` (drafts 12 to 19, the same wire format): the version is
//!   inside the signed SREP, and the Merkle leaf is the whole request packet.
//! - `0x8000000b` (draft 11, still the only one Cloudflare serves): the
//!   version is a top-level tag, the leaf is the nonce, and the delegation
//!   context ends in `--`.
//!
//! Version 1 is not offered yet: it waits for the RFC, and for servers to
//! be checked against it.
//!
//! All of them use the `ROUGHTIM` framing, 32-byte nonces, SHA-512/256-bit
//! tree hashes and MIDP/RADI in seconds. Older drafts (Google's original
//! protocol, drafts up to 7) use other timestamp formats and are not supported.
//!
//! Only what a single measurement needs is here: no TCP, no chained nonces
//! for malfeasance reports. Each response is verified on its own; agreement
//! between servers is the caller's job (`anti_rollback`).

use std::collections::BTreeMap;

use ring::signature::{ED25519, UnparsedPublicKey};
use sha2::{Digest, Sha512};

/// Drafts 12 to 19, until the RFC assigns version 1.
pub const VERSION_DRAFT_12: u32 = 0x8000_000c;
/// Draft 11.
pub const VERSION_DRAFT_11: u32 = 0x8000_000b;
/// Ascending, as the request's VER tag requires.
const OFFERED_VERSIONS: [u32; 2] = [VERSION_DRAFT_11, VERSION_DRAFT_12];

/// Request packet size including the 12-byte framing. Draft-11 servers only
/// answer packets of exactly this size.
pub const REQUEST_SIZE: usize = 1024;

const MAGIC: &[u8; 8] = b"ROUGHTIM";
const MAX_TAGS: usize = 64;
const MAX_PATH: usize = 32;

const RESPONSE_CONTEXT: &[u8] = b"RoughTime v1 response signature\0";
const DELEGATION_CONTEXT: &[u8] = b"RoughTime v1 delegation signature\0";
const DELEGATION_CONTEXT_DRAFT_11: &[u8] = b"RoughTime v1 delegation signature--\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed response: {0}")]
    Malformed(&'static str),
    #[error("unsupported version {0:#x}")]
    Version(u32),
    #[error("invalid {0} signature")]
    Signature(&'static str),
    #[error("response is not for this request")]
    NotOurs,
    #[error("timestamp outside the delegation's validity")]
    Delegation,
}

const fn tag(s: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*s)
}

const VER: u32 = tag(b"VER\0");
const SRV: u32 = tag(b"SRV\0");
const NONC: u32 = tag(b"NONC");
const TYPE: u32 = tag(b"TYPE");
const ZZZZ: u32 = tag(b"ZZZZ");
const SIG: u32 = tag(b"SIG\0");
const SREP: u32 = tag(b"SREP");
const CERT: u32 = tag(b"CERT");
const DELE: u32 = tag(b"DELE");
const PUBK: u32 = tag(b"PUBK");
const MINT: u32 = tag(b"MINT");
const MAXT: u32 = tag(b"MAXT");
const ROOT: u32 = tag(b"ROOT");
const MIDP: u32 = tag(b"MIDP");
const RADI: u32 = tag(b"RADI");
const PATH: u32 = tag(b"PATH");
const INDX: u32 = tag(b"INDX");

/// SHA-512 truncated to 32 bytes.
fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha512::new();
    for p in parts {
        d.update(p);
    }
    d.finalize()[..32].try_into().expect("64-byte digest")
}

/// Encodes a message: tags sorted by their uint32 value, offsets implicit
/// for the first value.
pub fn encode(pairs: &BTreeMap<u32, Vec<u8>>) -> Vec<u8> {
    let n = pairs.len();
    let mut out = Vec::new();
    out.extend((n as u32).to_le_bytes());
    let mut offset = 0u32;
    for (i, v) in pairs.values().enumerate() {
        if i > 0 {
            out.extend(offset.to_le_bytes());
        }
        offset += v.len() as u32;
    }
    for t in pairs.keys() {
        out.extend(t.to_le_bytes());
    }
    for v in pairs.values() {
        out.extend(v);
    }
    out
}

/// Decodes a message into its tags. Rejects unsorted or repeated tags and
/// offsets that are unaligned, decreasing or out of range.
pub fn decode(msg: &[u8]) -> Result<BTreeMap<u32, &[u8]>, Error> {
    let u32_at = |i: usize| -> Result<u32, Error> {
        msg.get(i..i + 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
            .ok_or(Error::Malformed("truncated header"))
    };
    let n = u32_at(0)? as usize;
    if n == 0 || n > MAX_TAGS {
        return Err(Error::Malformed("tag count"));
    }
    let header = 8 * n;
    if msg.len() < header {
        return Err(Error::Malformed("truncated header"));
    }
    let values = &msg[header..];
    let mut offsets = vec![0usize];
    for i in 0..n - 1 {
        offsets.push(u32_at(4 + 4 * i)? as usize);
    }
    offsets.push(values.len());
    let mut out = BTreeMap::new();
    let mut last_tag = None;
    for i in 0..n {
        let t = u32_at(4 * n + 4 * i)?;
        if last_tag.is_some_and(|l| t <= l) {
            return Err(Error::Malformed("tags not in ascending order"));
        }
        last_tag = Some(t);
        let (start, end) = (offsets[i], offsets[i + 1]);
        if start % 4 != 0 || start > end || end > values.len() {
            return Err(Error::Malformed("offsets"));
        }
        out.insert(t, &values[start..end]);
    }
    Ok(out)
}

fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend((msg.len() as u32).to_le_bytes());
    out.extend(msg);
    out
}

fn unframe(packet: &[u8]) -> Result<&[u8], Error> {
    if packet.len() < 12 || &packet[..8] != MAGIC {
        return Err(Error::Malformed("missing ROUGHTIM framing"));
    }
    let len = u32::from_le_bytes(packet[8..12].try_into().expect("4 bytes")) as usize;
    if packet.len() - 12 != len {
        return Err(Error::Malformed("framing length"));
    }
    Ok(&packet[12..])
}

/// `SRV`: which long-term key the client expects.
pub fn srv(public_key: &[u8; 32]) -> [u8; 32] {
    h(&[&[0xff], public_key])
}

/// Builds a request packet of exactly `REQUEST_SIZE` bytes.
pub fn request(nonce: &[u8; 32], public_key: &[u8; 32]) -> Vec<u8> {
    let mut pairs = BTreeMap::new();
    pairs.insert(
        VER,
        OFFERED_VERSIONS
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect(),
    );
    pairs.insert(NONC, nonce.to_vec());
    pairs.insert(TYPE, 0u32.to_le_bytes().to_vec());
    pairs.insert(SRV, srv(public_key).to_vec());
    pairs.insert(ZZZZ, Vec::new());
    let pad = REQUEST_SIZE - frame(&encode(&pairs)).len();
    pairs.insert(ZZZZ, vec![0; pad]);
    let packet = frame(&encode(&pairs));
    debug_assert_eq!(packet.len(), REQUEST_SIZE);
    packet
}

/// A verified time reading: the server signed it at a moment within
/// `[midpoint - radius, midpoint + radius]` (Unix seconds), after it received
/// our request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub midpoint: u64,
    pub radius: u32,
    pub version: u32,
}

fn fixed<'a>(m: &BTreeMap<u32, &'a [u8]>, t: u32, len: usize) -> Result<&'a [u8], Error> {
    match m.get(&t) {
        Some(v) if v.len() == len => Ok(v),
        Some(_) => Err(Error::Malformed("tag has the wrong length")),
        None => Err(Error::Malformed("missing tag")),
    }
}

fn get_u32(m: &BTreeMap<u32, &[u8]>, t: u32) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(fixed(m, t, 4)?.try_into().expect("4")))
}

fn get_u64(m: &BTreeMap<u32, &[u8]>, t: u32) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(fixed(m, t, 8)?.try_into().expect("8")))
}

fn verify_sig(
    key: &[u8],
    context: &[u8],
    value: &[u8],
    sig: &[u8],
    what: &'static str,
) -> Result<(), Error> {
    let mut msg = context.to_vec();
    msg.extend(value);
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&msg, sig)
        .map_err(|_| Error::Signature(what))
}

/// Verifies `response` to `request` (as built by [`request`] with `nonce`)
/// against the server's long-term `public_key`.
pub fn verify(
    request: &[u8],
    nonce: &[u8; 32],
    response: &[u8],
    public_key: &[u8; 32],
) -> Result<Reading, Error> {
    let top = decode(unframe(response)?)?;
    if top.contains_key(&TYPE) && get_u32(&top, TYPE)? != 1 {
        return Err(Error::Malformed("TYPE is not a response"));
    }
    if let Some(n) = top.get(&NONC)
        && *n != nonce
    {
        return Err(Error::NotOurs);
    }

    let srep_bytes = *top.get(&SREP).ok_or(Error::Malformed("missing SREP"))?;
    let srep = decode(srep_bytes)?;
    // Draft 12 and later sign the version (in SREP); draft 11 does not.
    let version = if srep.contains_key(&VER) {
        get_u32(&srep, VER)?
    } else {
        get_u32(&top, VER)?
    };
    let draft_11 = match version {
        VERSION_DRAFT_12 if srep.contains_key(&VER) => false,
        VERSION_DRAFT_11 => true,
        v => return Err(Error::Version(v)),
    };

    // Long-term key -> delegated key.
    let cert = decode(top.get(&CERT).ok_or(Error::Malformed("missing CERT"))?)?;
    let dele_bytes = *cert.get(&DELE).ok_or(Error::Malformed("missing DELE"))?;
    let context = if draft_11 {
        DELEGATION_CONTEXT_DRAFT_11
    } else {
        DELEGATION_CONTEXT
    };
    verify_sig(
        public_key,
        context,
        dele_bytes,
        fixed(&cert, SIG, 64)?,
        "delegation",
    )?;
    let dele = decode(dele_bytes)?;
    let pubk = fixed(&dele, PUBK, 32)?;
    let (mint, maxt) = (get_u64(&dele, MINT)?, get_u64(&dele, MAXT)?);

    // Delegated key -> signed response.
    verify_sig(
        pubk,
        RESPONSE_CONTEXT,
        srep_bytes,
        fixed(&top, SIG, 64)?,
        "response",
    )?;
    let midpoint = get_u64(&srep, MIDP)?;
    let radius = get_u32(&srep, RADI)?;
    if radius == 0 {
        return Err(Error::Malformed("zero RADI"));
    }
    if midpoint < mint || midpoint > maxt {
        return Err(Error::Delegation);
    }

    // Our request is a leaf of the signed Merkle tree.
    let root = fixed(&srep, ROOT, 32)?;
    let path = top.get(&PATH).ok_or(Error::Malformed("missing PATH"))?;
    if path.len() % 32 != 0 || path.len() / 32 > MAX_PATH {
        return Err(Error::Malformed("PATH length"));
    }
    let mut index = get_u32(&top, INDX)?;
    let mut node = if draft_11 {
        h(&[&[0], nonce])
    } else {
        h(&[&[0], request])
    };
    for sibling in path.chunks(32) {
        node = if index & 1 == 0 {
            h(&[&[1], &node, sibling])
        } else {
            h(&[&[1], sibling, &node])
        };
        index >>= 1;
    }
    if index != 0 || node != root {
        return Err(Error::NotOurs);
    }

    Ok(Reading {
        midpoint,
        radius,
        version,
    })
}

/// A test server: signs responses with real keys, optionally with a wrong
/// time or a bad signature.
#[cfg(test)]
pub mod testing {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    pub struct Server {
        root: Ed25519KeyPair,
        online: Ed25519KeyPair,
        pub version: u32,
    }

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keygen");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key")
    }

    impl Server {
        pub fn new(version: u32) -> Self {
            Self {
                root: keypair(),
                online: keypair(),
                version,
            }
        }

        pub fn public_key(&self) -> [u8; 32] {
            self.root.public_key().as_ref().try_into().expect("32")
        }

        /// Answers `request` with time `midpoint ± radius`, in a batch of
        /// two requests (so PATH is not empty) at position `index`.
        pub fn respond(&self, request: &[u8], midpoint: u64, radius: u32, index: u32) -> Vec<u8> {
            let msg = decode(unframe(request).expect("framed")).expect("request");
            let nonce = msg[&NONC];
            let draft_11 = self.version == VERSION_DRAFT_11;
            let leaf = if draft_11 {
                h(&[&[0], nonce])
            } else {
                h(&[&[0], request])
            };
            let other = h(&[&[0], b"another request"]);
            let root = if index & 1 == 0 {
                h(&[&[1], &leaf, &other])
            } else {
                h(&[&[1], &other, &leaf])
            };

            let mut srep = BTreeMap::new();
            srep.insert(ROOT, root.to_vec());
            srep.insert(MIDP, midpoint.to_le_bytes().to_vec());
            srep.insert(RADI, radius.to_le_bytes().to_vec());
            if !draft_11 {
                srep.insert(VER, self.version.to_le_bytes().to_vec());
                srep.insert(VERS, self.version.to_le_bytes().to_vec());
            }
            let srep = encode(&srep);

            let mut dele = BTreeMap::new();
            dele.insert(PUBK, self.online.public_key().as_ref().to_vec());
            dele.insert(MINT, 0u64.to_le_bytes().to_vec());
            dele.insert(MAXT, u64::MAX.to_le_bytes().to_vec());
            let dele = encode(&dele);
            let context = if draft_11 {
                DELEGATION_CONTEXT_DRAFT_11
            } else {
                DELEGATION_CONTEXT
            };
            let mut cert = BTreeMap::new();
            cert.insert(DELE, dele.clone());
            cert.insert(
                SIG,
                self.root.sign(&[context, &dele].concat()).as_ref().to_vec(),
            );

            let mut top = BTreeMap::new();
            top.insert(
                SIG,
                self.online
                    .sign(&[RESPONSE_CONTEXT, &srep].concat())
                    .as_ref()
                    .to_vec(),
            );
            top.insert(SREP, srep);
            top.insert(CERT, encode(&cert));
            top.insert(PATH, other.to_vec());
            top.insert(INDX, index.to_le_bytes().to_vec());
            if draft_11 {
                top.insert(VER, self.version.to_le_bytes().to_vec());
            } else {
                top.insert(NONC, nonce.to_vec());
                top.insert(TYPE, 1u32.to_le_bytes().to_vec());
            }
            frame(&encode(&top))
        }
    }

    const VERS: u32 = tag(b"VERS");
}

#[cfg(test)]
mod tests {
    use super::testing::Server;
    use super::*;

    const NONCE: [u8; 32] = [9; 32];

    #[test]
    fn request_layout() {
        let req = request(&NONCE, &[1; 32]);
        assert_eq!(req.len(), REQUEST_SIZE);
        let msg = decode(unframe(&req).unwrap()).unwrap();
        assert_eq!(msg[&NONC], NONCE);
        assert_eq!(msg[&TYPE], 0u32.to_le_bytes());
        assert_eq!(msg[&SRV], srv(&[1; 32]));
        assert_eq!(
            msg[&VER],
            [0x8000_000bu32, 0x8000_000c]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>()
        );
        // Tags in the order the draft's NONC example implies.
        assert_eq!(&tag(b"NONC").to_le_bytes(), b"NONC");
        assert_eq!(tag(b"VER\0"), 0x0052_4556);
        assert_eq!(tag(b"NONC"), 0x434e_4f4e);
    }

    #[test]
    fn verifies_each_version() {
        for version in [VERSION_DRAFT_11, VERSION_DRAFT_12] {
            let s = Server::new(version);
            let req = request(&NONCE, &s.public_key());
            for index in [0, 1] {
                let resp = s.respond(&req, 1_800_000_000, 3, index);
                let r = verify(&req, &NONCE, &resp, &s.public_key()).unwrap();
                assert_eq!(
                    r,
                    Reading {
                        midpoint: 1_800_000_000,
                        radius: 3,
                        version
                    }
                );
            }
        }
    }

    #[test]
    fn rejects_forgeries() {
        let s = Server::new(VERSION_DRAFT_12);
        let other = Server::new(VERSION_DRAFT_12);
        let req = request(&NONCE, &s.public_key());
        let resp = s.respond(&req, 1_800_000_000, 3, 0);

        // Another server's key.
        assert_eq!(
            verify(&req, &NONCE, &resp, &other.public_key()),
            Err(Error::Signature("delegation"))
        );
        // A response to another request (replay).
        let req2 = request(&[8; 32], &s.public_key());
        assert!(verify(&req2, &[8; 32], &resp, &s.public_key()).is_err());
        // No flipped byte changes the time. A few are harmless: they rename
        // the NONC or TYPE tag, which draft-11 responses lack, to an unknown
        // tag, which must be ignored.
        let good = verify(&req, &NONCE, &resp, &s.public_key()).unwrap();
        let mut accepted = 0;
        for i in 0..resp.len() {
            let mut bad = resp.clone();
            bad[i] ^= 1;
            if let Ok(r) = verify(&req, &NONCE, &bad, &s.public_key()) {
                assert_eq!(r, good, "flipped byte {i} changed the reading");
                accepted += 1;
            }
        }
        assert!(accepted <= 8, "{accepted} flipped bytes accepted");
        // Truncated or unframed.
        assert!(verify(&req, &NONCE, &resp[..resp.len() - 4], &s.public_key()).is_err());
        assert!(verify(&req, &NONCE, &resp[12..], &s.public_key()).is_err());
    }

    #[test]
    fn decode_rejects_bad_headers() {
        let mut pairs = BTreeMap::new();
        pairs.insert(NONC, vec![0; 4]);
        pairs.insert(TYPE, vec![0; 4]);
        let mut msg = encode(&pairs);
        assert_eq!(decode(&msg).unwrap().len(), 2);
        // Unaligned offset.
        msg[4] = 2;
        assert!(decode(&msg).is_err());
        // Offset past the end.
        msg[4] = 40;
        assert!(decode(&msg).is_err());
        // Tags out of order.
        let mut msg = encode(&pairs);
        msg.swap(8, 12);
        msg.swap(9, 13);
        msg.swap(10, 14);
        msg.swap(11, 15);
        assert!(decode(&msg).is_err());
        assert!(decode(&[]).is_err());
        assert!(decode(&[0, 0, 0, 0]).is_err());
    }
}
