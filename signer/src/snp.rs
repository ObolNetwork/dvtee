//! Offline verification of AMD SEV-SNP evidence.
//!
//! Checks, all without network access:
//!
//! * the AMD certificate chain ARK → ASK → VCEK (or ARK → ASVK → VLEK),
//!   with the ARKs for Milan, Genoa and Turin embedded and pinned by SHA-256
//!   fingerprint ([`amd_anchors`]). CA certificates are RSA-PSS SHA-384;
//! * the report signature: ECDSA P-384 SHA-384 by the VCEK/VLEK over bytes
//!   `0x000..0x2A0` of the ATTESTATION_REPORT;
//! * that the VCEK was issued for the report's REPORTED_TCB and CHIP_ID
//!   (AMD's X.509 extensions under 1.3.6.1.4.1.3704.1);
//! * guest policy (debug and migration agent off, optional SMT), VMPL, a
//!   minimum TCB, the launch measurement and the REPORT_DATA binding.
//!
//! Layout: SEV-SNP Firmware ABI spec (AMD 56860), ATTESTATION_REPORT
//! structure, report versions 2 to 5. Offsets were cross-checked against
//! virtee/sev and snpguest. Not checked: revocation (AMD's CRL).

use std::fmt;
use std::time::SystemTime;

use ring::signature::{ECDSA_P384_SHA384_FIXED, RSA_PSS_2048_8192_SHA384, UnparsedPublicKey};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use x509_cert::Certificate;
use x509_cert::der::asn1::{AnyRef, ObjectIdentifier};
use x509_cert::der::{Decode, Encode, Reader, SliceReader, Tag, Tagged};
use x509_cert::spki::AlgorithmIdentifierRef;

pub const REPORT_LEN: usize = 0x4A0;
/// The signature covers the report up to the signature field.
const SIGNED_LEN: usize = 0x2A0;

const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// AMD VCEK/VLEK extensions (AMD 57230, "VCEK certificate").
const OID_PRODUCT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.2");
const OID_BL_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.1");
const OID_TEE_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.2");
const OID_SNP_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.3");
const OID_UCODE_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.8");
const OID_FMC_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.9");
const OID_HW_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.4");

/// Guest policy bits.
const POLICY_SMT: u64 = 1 << 16;
const POLICY_MIGRATE_MA: u64 = 1 << 18;
const POLICY_DEBUG: u64 = 1 << 19;
/// PLATFORM_INFO bit 0: SMT is enabled on the host.
const PLATFORM_SMT_EN: u64 = 1 << 0;

// ---------------------------------------------------------------------------
// Products and TCB

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Product {
    Milan,
    Genoa,
    Turin,
}

impl Product {
    pub fn name(self) -> &'static str {
        match self {
            Product::Milan => "Milan",
            Product::Genoa => "Genoa",
            Product::Turin => "Turin",
        }
    }

    /// From the CPUID family/model in v3+ reports.
    fn from_cpuid(family: u8, model: u8) -> Option<Self> {
        match (family, model) {
            (0x19, 0x00..=0x0F) => Some(Product::Milan),
            (0x19, 0x10..=0x1F | 0xA0..=0xAF) => Some(Product::Genoa),
            (0x1A, 0x00..=0x1F) => Some(Product::Turin),
            _ => None,
        }
    }
}

/// A TCB_VERSION split into its security patch levels. The byte layout of
/// the raw 64-bit value differs between generations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tcb {
    /// Turin and later only.
    pub fmc: Option<u8>,
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl Tcb {
    /// `raw` is the little-endian TCB_VERSION as a u64, the same form that
    /// `sealing-key --snp-min-tcb` takes.
    pub fn decode(raw: u64, product: Product) -> Self {
        let b = raw.to_le_bytes();
        match product {
            Product::Milan | Product::Genoa => Tcb {
                fmc: None,
                bootloader: b[0],
                tee: b[1],
                snp: b[6],
                microcode: b[7],
            },
            Product::Turin => Tcb {
                fmc: Some(b[0]),
                bootloader: b[1],
                tee: b[2],
                snp: b[3],
                microcode: b[7],
            },
        }
    }

    /// Every component is at least `min`'s. TCBs are not ordered as
    /// integers: each component is its own security patch level.
    pub fn at_least(&self, min: &Tcb) -> bool {
        self.fmc.unwrap_or(0) >= min.fmc.unwrap_or(0)
            && self.bootloader >= min.bootloader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
    }
}

impl fmt::Display for Tcb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(fmc) = self.fmc {
            write!(f, "fmc={fmc} ")?;
        }
        write!(
            f,
            "bl={} tee={} snp={} ucode={}",
            self.bootloader, self.tee, self.snp, self.microcode
        )
    }
}

// ---------------------------------------------------------------------------
// Report

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningKey {
    Vcek,
    Vlek,
}

/// A parsed ATTESTATION_REPORT (versions 2 to 5).
pub struct Report {
    bytes: Vec<u8>,
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub sig_algo: u32,
    pub current_tcb: u64,
    pub platform_info: u64,
    pub mask_chip_key: bool,
    /// 0 = VCEK, 1 = VLEK, 7 = unsigned.
    pub signing_key: u8,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: u64,
    /// CPUID family, model and stepping (v3+).
    pub cpuid: Option<(u8, u8, u8)>,
    pub chip_id: [u8; 64],
    pub committed_tcb: u64,
    /// Firmware (major, minor, build).
    pub current_fw: (u8, u8, u8),
    pub committed_fw: (u8, u8, u8),
    pub launch_tcb: u64,
    /// LAUNCH_MIT_VECTOR, CURRENT_MIT_VECTOR (v5+).
    pub mit_vectors: Option<(u64, u64)>,
}

fn arr<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
    b[off..off + N].try_into().expect("in bounds")
}
fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(arr(b, off))
}
fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(arr(b, off))
}

impl fmt::Display for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SigningKey::Vcek => "VCEK",
            SigningKey::Vlek => "VLEK",
        })
    }
}

impl Report {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != REPORT_LEN {
            return Err(format!(
                "report is {} bytes, expected {REPORT_LEN}",
                bytes.len()
            ));
        }
        let b = bytes;
        let version = le32(b, 0x00);
        if !(2..=5).contains(&version) {
            return Err(format!("unsupported report version {version} (2 to 5)"));
        }
        let key_info = le32(b, 0x48);
        let fw = |o: usize| (b[o + 2], b[o + 1], b[o]);
        Ok(Report {
            bytes: b.to_vec(),
            version,
            guest_svn: le32(b, 0x04),
            policy: le64(b, 0x08),
            family_id: arr(b, 0x10),
            image_id: arr(b, 0x20),
            vmpl: le32(b, 0x30),
            sig_algo: le32(b, 0x34),
            current_tcb: le64(b, 0x38),
            platform_info: le64(b, 0x40),
            mask_chip_key: key_info & (1 << 1) != 0,
            signing_key: ((key_info >> 2) & 0b111) as u8,
            report_data: arr(b, 0x50),
            measurement: arr(b, 0x90),
            host_data: arr(b, 0xC0),
            id_key_digest: arr(b, 0xE0),
            report_id_ma: arr(b, 0x160),
            reported_tcb: le64(b, 0x180),
            cpuid: (version >= 3).then(|| (b[0x188], b[0x189], b[0x18A])),
            chip_id: arr(b, 0x1A0),
            committed_tcb: le64(b, 0x1E0),
            current_fw: fw(0x1E8),
            committed_fw: fw(0x1EC),
            launch_tcb: le64(b, 0x1F0),
            mit_vectors: (version >= 5).then(|| (le64(b, 0x1F8), le64(b, 0x200))),
        })
    }

    pub fn signing_key(&self) -> Option<SigningKey> {
        match self.signing_key {
            0 => Some(SigningKey::Vcek),
            1 => Some(SigningKey::Vlek),
            _ => None,
        }
    }

    /// r and s are 72-byte little-endian fields; P-384 uses the low 48.
    fn signature_fixed(&self) -> Option<[u8; 96]> {
        let sig = &self.bytes[SIGNED_LEN..];
        let (r, s) = (&sig[0..72], &sig[72..144]);
        if r[48..].iter().chain(&s[48..]).any(|&x| x != 0) {
            return None;
        }
        let mut out = [0u8; 96];
        for i in 0..48 {
            out[i] = r[47 - i];
            out[48 + i] = s[47 - i];
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Trust anchors

/// One generation's AMD roots: the ARK and the two intermediates it signs.
pub struct ProductAnchors {
    pub product: Product,
    pub ark: Vec<u8>,
    pub ask: Vec<u8>,
    pub asvk: Vec<u8>,
}

pub struct Anchors(pub Vec<ProductAnchors>);

/// SHA-256 of the AMD Root Keys (DER), as served by
/// `https://kdsintf.amd.com/vcek/v1/{Milan,Genoa,Turin}/cert_chain` and
/// matching virtee/sev's built-in copies.
pub const ARK_SHA256: [(Product, &str); 3] = [
    (
        Product::Milan,
        "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
    ),
    (
        Product::Genoa,
        "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
    ),
    (
        Product::Turin,
        "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
    ),
];

const EMBEDDED: [(Product, &str, &str, &str); 3] = [
    (
        Product::Milan,
        include_str!("../certs/amd/milan/ark.pem"),
        include_str!("../certs/amd/milan/ask.pem"),
        include_str!("../certs/amd/milan/asvk.pem"),
    ),
    (
        Product::Genoa,
        include_str!("../certs/amd/genoa/ark.pem"),
        include_str!("../certs/amd/genoa/ask.pem"),
        include_str!("../certs/amd/genoa/asvk.pem"),
    ),
    (
        Product::Turin,
        include_str!("../certs/amd/turin/ark.pem"),
        include_str!("../certs/amd/turin/ask.pem"),
        include_str!("../certs/amd/turin/asvk.pem"),
    ),
];

pub fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    CertificateDer::from_pem_slice(pem)
        .ok()
        .map(|c| c.as_ref().to_vec())
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, b))
}

/// The embedded AMD roots. Panics if an embedded ARK does not match its
/// pinned fingerprint (a corrupted build, caught by the tests).
pub fn amd_anchors() -> Anchors {
    Anchors(
        EMBEDDED
            .iter()
            .map(|&(product, ark, ask, asvk)| {
                let der = |p: &str| pem_to_der(p.as_bytes()).expect("embedded AMD cert");
                let ark = der(ark);
                let pin = ARK_SHA256.iter().find(|(p, _)| *p == product).expect("pin");
                assert_eq!(sha256_hex(&ark), pin.1, "embedded {product:?} ARK");
                ProductAnchors {
                    product,
                    ark,
                    ask: der(ask),
                    asvk: der(asvk),
                }
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Certificates

fn parse_cert(der: &[u8]) -> Result<Certificate, String> {
    Certificate::from_der(der).map_err(|e| format!("bad certificate: {e}"))
}

/// The tbsCertificate exactly as encoded in `der`.
fn raw_tbs(der: &[u8]) -> Result<Vec<u8>, String> {
    let f = || -> x509_cert::der::Result<Vec<u8>> {
        let outer = AnyRef::from_der(der)?;
        let mut r = SliceReader::new(outer.value())?;
        AnyRef::decode(&mut r)?.to_der()
    };
    f().map_err(|e| format!("bad certificate: {e}"))
}

/// RSASSA-PSS parameters must be SHA-384, MGF1-SHA-384, salt 48 (AMD's).
fn check_pss_params(params: Option<&x509_cert::der::Any>) -> Result<(), String> {
    let bad = |m: &str| Err(format!("signature parameters: {m}"));
    let Some(p) = params else {
        return bad("missing");
    };
    if p.tag() != Tag::Sequence {
        return bad("not a sequence");
    }
    let sha384 = |a: &AlgorithmIdentifierRef<'_>| {
        a.oid == OID_SHA384 && a.parameters.is_none_or(|p| p.is_null())
    };
    let (mut hash, mut mgf, mut salt) = (false, false, false);
    let mut r = SliceReader::new(p.value()).map_err(|e| e.to_string())?;
    while !r.is_finished() {
        let field = AnyRef::decode(&mut r).map_err(|e| e.to_string())?;
        let Tag::ContextSpecific { number, .. } = field.tag() else {
            return bad("unexpected field");
        };
        let inner = field.value();
        match number.value() {
            0 => {
                let a = AlgorithmIdentifierRef::from_der(inner).map_err(|e| e.to_string())?;
                hash = sha384(&a);
            }
            1 => {
                let a = AlgorithmIdentifierRef::from_der(inner).map_err(|e| e.to_string())?;
                mgf = a.oid == OID_MGF1
                    && a.parameters
                        .and_then(|p| p.decode_as::<AlgorithmIdentifierRef<'_>>().ok())
                        .is_some_and(|h| sha384(&h));
            }
            2 => salt = u8::from_der(inner).map_err(|e| e.to_string())? == 48,
            3 => {
                if u8::from_der(inner).map_err(|e| e.to_string())? != 1 {
                    return bad("trailer field");
                }
            }
            _ => return bad("unexpected field"),
        }
    }
    if hash && mgf && salt {
        Ok(())
    } else {
        bad("not RSA-PSS SHA-384 / MGF1-SHA-384 / salt 48")
    }
}

/// Checks that `issuer` signed `cert` (RSA-PSS SHA-384) and that `cert` is
/// valid at `now`.
fn check_signed_by(
    what: &str,
    cert_der: &[u8],
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<(), String> {
    let cert = parse_cert(cert_der)?;
    let issuer = parse_cert(issuer_der)?;
    let tbs = cert.tbs_certificate();
    if tbs.issuer() != issuer.tbs_certificate().subject() {
        return Err(format!(
            "{what}: issuer {} is not {}",
            tbs.issuer(),
            issuer.tbs_certificate().subject()
        ));
    }
    let alg = cert.signature_algorithm();
    if alg.oid != OID_RSASSA_PSS || tbs.signature() != alg {
        return Err(format!("{what}: not signed with RSA-PSS"));
    }
    check_pss_params(alg.parameters.as_ref()).map_err(|e| format!("{what}: {e}"))?;
    let ikey = issuer.tbs_certificate().subject_public_key_info();
    if ikey.algorithm.oid != OID_RSA_ENCRYPTION && ikey.algorithm.oid != OID_RSASSA_PSS {
        return Err(format!("{what}: issuer key is not RSA"));
    }
    let sig = cert
        .signature()
        .as_bytes()
        .ok_or_else(|| format!("{what}: bad signature encoding"))?;
    UnparsedPublicKey::new(
        &RSA_PSS_2048_8192_SHA384,
        ikey.subject_public_key.raw_bytes(),
    )
    .verify(&raw_tbs(cert_der)?, sig)
    .map_err(|_| format!("{what}: bad signature"))?;
    let v = tbs.validity();
    let now = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    if now < v.not_before.to_unix_duration() || now > v.not_after.to_unix_duration() {
        return Err(format!(
            "{what}: not valid now ({} to {})",
            v.not_before, v.not_after
        ));
    }
    Ok(())
}

/// Verifies ARK (self-signed) → ASK/ASVK → leaf for the generation whose
/// intermediate issued `leaf_der`. Returns that generation.
fn verify_chain(
    anchors: &Anchors,
    key: SigningKey,
    leaf_der: &[u8],
    now: SystemTime,
) -> Result<Product, String> {
    let leaf = parse_cert(leaf_der)?;
    let issuer = leaf.tbs_certificate().issuer();
    let (leaf_name, ca_name) = match key {
        SigningKey::Vcek => ("VCEK", "ASK"),
        SigningKey::Vlek => ("VLEK", "ASVK"),
    };
    for pa in &anchors.0 {
        let ca = match key {
            SigningKey::Vcek => &pa.ask,
            SigningKey::Vlek => &pa.asvk,
        };
        if parse_cert(ca)?.tbs_certificate().subject() != issuer {
            continue;
        }
        let p = pa.product.name();
        check_signed_by(&format!("ARK-{p}"), &pa.ark, &pa.ark, now)?;
        check_signed_by(&format!("{ca_name}-{p}"), ca, &pa.ark, now)?;
        check_signed_by(leaf_name, leaf_der, ca, now)?;
        return Ok(pa.product);
    }
    Err(format!(
        "{leaf_name} issuer {issuer} is not a pinned AMD {ca_name}"
    ))
}

fn verify_report_signature(report: &Report, leaf_der: &[u8]) -> Result<(), String> {
    let leaf = parse_cert(leaf_der)?;
    let spki = leaf.tbs_certificate().subject_public_key_info();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY || curve != Some(OID_SECP384R1) {
        return Err("signing key is not ECDSA P-384".into());
    }
    let sig = report
        .signature_fixed()
        .ok_or("signature has non-zero padding")?;
    UnparsedPublicKey::new(
        &ECDSA_P384_SHA384_FIXED,
        spki.subject_public_key.raw_bytes(),
    )
    .verify(&report.bytes[..SIGNED_LEN], &sig)
    .map_err(|_| "bad signature".to_string())
}

/// AMD's VCEK/VLEK extensions that bind it to a chip and a TCB.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LeafInfo {
    pub product_name: Option<String>,
    pub fmc: Option<u8>,
    pub bootloader: Option<u8>,
    pub tee: Option<u8>,
    pub snp: Option<u8>,
    pub microcode: Option<u8>,
    /// 64 bytes (Milan, Genoa) or 8 (Turin). VLEKs have none.
    pub hw_id: Option<Vec<u8>>,
}

pub fn leaf_info(leaf_der: &[u8]) -> Result<LeafInfo, String> {
    let leaf = parse_cert(leaf_der)?;
    let mut info = LeafInfo::default();
    let int = |v: &[u8]| u8::from_der(v).map_err(|e| format!("bad TCB extension: {e}"));
    for ext in leaf.tbs_certificate().extensions().into_iter().flatten() {
        let v = ext.extn_value.as_bytes();
        match ext.extn_id {
            OID_PRODUCT_NAME => {
                info.product_name = AnyRef::from_der(v)
                    .ok()
                    .and_then(|a| std::str::from_utf8(a.value()).ok().map(str::to_string))
            }
            OID_FMC_SPL => info.fmc = Some(int(v)?),
            OID_BL_SPL => info.bootloader = Some(int(v)?),
            OID_TEE_SPL => info.tee = Some(int(v)?),
            OID_SNP_SPL => info.snp = Some(int(v)?),
            OID_UCODE_SPL => info.microcode = Some(int(v)?),
            OID_HW_ID => {
                // Raw bytes in AMD's certs; also accept an OCTET STRING.
                let id = match v.len() {
                    8 | 64 => v.to_vec(),
                    _ => match AnyRef::from_der(v) {
                        Ok(a)
                            if a.tag() == Tag::OctetString && matches!(a.value().len(), 8 | 64) =>
                        {
                            a.value().to_vec()
                        }
                        _ => return Err(format!("bad hwID extension ({} bytes)", v.len())),
                    },
                };
                info.hw_id = Some(id);
            }
            _ => {}
        }
    }
    Ok(info)
}

fn check_leaf_tcb(info: &LeafInfo, tcb: &Tcb) -> Result<(), String> {
    let mut want = vec![
        ("bl", info.bootloader, tcb.bootloader),
        ("tee", info.tee, tcb.tee),
        ("snp", info.snp, tcb.snp),
        ("ucode", info.microcode, tcb.microcode),
    ];
    if let Some(fmc) = tcb.fmc {
        want.insert(0, ("fmc", info.fmc, fmc));
    }
    for (name, cert, report) in want {
        match cert {
            None => return Err(format!("certificate has no {name} level")),
            Some(c) if c != report => {
                return Err(format!("{name}: certificate {c}, report {report}"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Certificate table (configfs-tsm auxblob / extended guest request)

const GUID_VCEK: &str = "63da758d-e664-4564-adc5-f4b93be8accd";
const GUID_VLEK: &str = "a8074bc2-a25a-483e-aae6-39c045a0b8a1";

/// GUID bytes in RFC 4122 order and in the mixed-endian EFI order; which
/// one the host tooling writes is to be confirmed on hardware.
fn guid_forms(s: &str) -> [[u8; 16]; 2] {
    let be: [u8; 16] = hex::decode(s.replace('-', ""))
        .expect("const")
        .try_into()
        .expect("16");
    let mut efi = be;
    efi[0..4].reverse();
    efi[4..6].reverse();
    efi[6..8].reverse();
    [be, efi]
}

/// Finds the VCEK or VLEK in a SEV-SNP certificate table: entries of
/// (GUID, offset u32, length u32) ended by an all-zero entry, with offsets
/// from the start of the table. The host fills this in, so every entry is
/// bounds checked; the certificate itself is only trusted after the chain
/// check.
pub fn leaf_from_cert_table(blob: &[u8], key: SigningKey) -> Result<Option<Vec<u8>>, String> {
    let guids = guid_forms(match key {
        SigningKey::Vcek => GUID_VCEK,
        SigningKey::Vlek => GUID_VLEK,
    });
    for i in 0..64 {
        let off = i * 24;
        let entry = blob
            .get(off..off + 24)
            .ok_or("certificate table is not terminated")?;
        let guid: [u8; 16] = arr(entry, 0);
        if guid == [0; 16] {
            return Ok(None);
        }
        if guids.contains(&guid) {
            let start = le32(entry, 16) as usize;
            let len = le32(entry, 20) as usize;
            let cert = start
                .checked_add(len)
                .and_then(|end| blob.get(start..end))
                .ok_or("certificate table entry out of bounds")?;
            return Ok(Some(cert.to_vec()));
        }
    }
    Err("certificate table has too many entries".into())
}

/// The AMD KDS URL of the VCEK for this report's chip and REPORTED_TCB.
pub fn kds_vcek_url(product: Product, chip_id: &[u8; 64], tcb: &Tcb) -> String {
    let base = format!("https://kdsintf.amd.com/vcek/v1/{}", product.name());
    match tcb.fmc {
        Some(fmc) => format!(
            "{base}/{}?fmcSPL={fmc:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            hex::encode(&chip_id[..8]),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        ),
        None => format!(
            "{base}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            hex::encode(chip_id),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        ),
    }
}

/// The generation of a report, from its CPUID (v3+). v2 reports don't say.
pub fn report_product(report: &Report) -> Option<Product> {
    report
        .cpuid
        .and_then(|(family, model, _)| Product::from_cpuid(family, model))
}

// ---------------------------------------------------------------------------
// Verification

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Fail,
    Info,
}

pub struct Line {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

#[derive(Default)]
pub struct Outcome {
    pub lines: Vec<Line>,
    /// Set once the chain and signature check out.
    pub product: Option<Product>,
}

impl Outcome {
    fn push(&mut self, name: &'static str, status: Status, detail: impl Into<String>) {
        self.lines.push(Line {
            name,
            status,
            detail: detail.into(),
        });
    }
    fn check(&mut self, name: &'static str, r: Result<String, String>) -> bool {
        let ok = r.is_ok();
        match r {
            Ok(d) => self.push(name, Status::Ok, d),
            Err(d) => self.push(name, Status::Fail, d),
        }
        ok
    }
    pub fn ok(&self) -> bool {
        !self.lines.is_empty() && self.lines.iter().all(|l| l.status != Status::Fail)
    }
    pub fn failed(&self) -> Vec<&'static str> {
        self.lines
            .iter()
            .filter(|l| l.status == Status::Fail)
            .map(|l| l.name)
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct Expect {
    /// REPORT_DATA the verifier computed (nonce, TLS cert, BLS keys).
    pub report_data: Option<[u8; 64]>,
    pub measurement: Option<[u8; 48]>,
    /// Raw TCB_VERSION, as for `sealing-key --snp-min-tcb`.
    pub min_tcb: Option<u64>,
    pub vmpl: u32,
    /// Fail if SMT is enabled on the host.
    pub deny_smt: bool,
    /// Certificate validity is checked at this time.
    pub now: SystemTime,
}

impl Default for Expect {
    fn default() -> Self {
        Expect {
            report_data: None,
            measurement: None,
            min_tcb: None,
            vmpl: 0,
            deny_smt: false,
            now: SystemTime::now(),
        }
    }
}

fn ok(d: impl Into<String>) -> Result<String, String> {
    Ok(d.into())
}

/// Verifies an SNP report against `anchors` (always [`amd_anchors`] outside
/// tests). `leaf_der` is the VCEK or VLEK; without it the hardware checks
/// fail. Every check is reported; [`Outcome::ok`] is the verdict.
pub fn verify(
    report: &[u8],
    leaf_der: Option<&[u8]>,
    anchors: &Anchors,
    expect: &Expect,
) -> Outcome {
    let mut out = Outcome::default();
    let r = match Report::parse(report) {
        Ok(r) => r,
        Err(e) => {
            out.push("report", Status::Fail, e);
            return out;
        }
    };
    out.push("report version", Status::Info, r.version.to_string());

    // Which key signed, and with what.
    let key = r.signing_key();
    let signed = out.check(
        "signing key",
        match (key, r.sig_algo, r.mask_chip_key) {
            (_, _, true) => Err("MASK_CHIP_KEY set: report is unsigned".into()),
            (None, _, _) => Err(format!("SIGNING_KEY {}: report is unsigned", r.signing_key)),
            (_, algo, _) if algo != 1 => {
                Err(format!("SIGNATURE_ALGO {algo}, expected 1 (ECDSA P-384)"))
            }
            (Some(k), _, _) => ok(k.to_string()),
        },
    );

    // Chain and signature.
    let cpu = report_product(&r);
    if r.version >= 3 && cpu.is_none() {
        let (f, m, _) = r.cpuid.unwrap_or_default();
        out.push(
            "product",
            Status::Fail,
            format!("unknown CPUID family {f:#x} model {m:#x}"),
        );
    }
    let mut product = None;
    let leaf = match (leaf_der, key) {
        (Some(l), Some(k)) if signed => Some((l, k)),
        (None, _) if signed => {
            out.push(
                "amd chain",
                Status::Fail,
                "no VCEK: not in the evidence; pass --vcek or --fetch-vcek",
            );
            None
        }
        _ => None,
    };
    if let Some((leaf, k)) = leaf {
        match verify_chain(anchors, k, leaf, expect.now) {
            Ok(p) => {
                out.push(
                    "amd chain",
                    Status::Ok,
                    format!(
                        "ARK-{0} → {1}-{0} → {k}",
                        p.name(),
                        if k == SigningKey::Vcek { "ASK" } else { "ASVK" }
                    ),
                );
                if out.check(
                    "report signature",
                    verify_report_signature(&r, leaf).map(|()| "ECDSA P-384".to_string()),
                ) {
                    product = Some(p);
                }
            }
            Err(e) => out.push("amd chain", Status::Fail, e),
        }
    }
    if let (Some(p), Some(c)) = (product, cpu)
        && p != c
    {
        out.push(
            "product",
            Status::Fail,
            format!("chain is {}, report CPUID is {}", p.name(), c.name()),
        );
    }
    out.product = product;

    // The VCEK must be for this report's chip and TCB.
    if let (Some(p), Some((leaf, k))) = (product, leaf) {
        match leaf_info(leaf) {
            Err(e) => {
                out.push("vcek tcb", Status::Fail, e);
            }
            Ok(info) => {
                let name_ok = info
                    .product_name
                    .as_deref()
                    .is_some_and(|n| n.starts_with(p.name()));
                if !name_ok {
                    out.push(
                        "product",
                        Status::Fail,
                        format!(
                            "certificate product {:?}, chain {}",
                            info.product_name,
                            p.name()
                        ),
                    );
                }
                let tcb = Tcb::decode(r.reported_tcb, p);
                out.check(
                    "vcek tcb",
                    check_leaf_tcb(&info, &tcb).map(|()| format!("matches reported TCB ({tcb})")),
                );
                if k == SigningKey::Vcek {
                    out.check(
                        "chip id",
                        match &info.hw_id {
                            _ if r.chip_id == [0; 64] => {
                                ok("masked in report (MASK_CHIP_ID), not compared")
                            }
                            Some(id)
                                if r.chip_id.starts_with(id)
                                    && (id.len() == 64 || r.chip_id[8..] == [0; 56]) =>
                            {
                                ok("matches VCEK")
                            }
                            Some(_) => Err("does not match the VCEK's hwID".into()),
                            None => Err("VCEK has no hwID".into()),
                        },
                    );
                }
            }
        }
    }

    // TCB levels and the minimum.
    if let Some(p) = product.or(cpu) {
        for (name, raw) in [
            ("reported tcb", r.reported_tcb),
            ("committed tcb", r.committed_tcb),
            ("current tcb", r.current_tcb),
            ("launch tcb", r.launch_tcb),
        ] {
            out.push(
                name,
                Status::Info,
                format!("{} ({raw:#018x})", Tcb::decode(raw, p)),
            );
        }
        if let Some(min_raw) = expect.min_tcb {
            let min = Tcb::decode(min_raw, p);
            let reported = Tcb::decode(r.reported_tcb, p);
            let committed = Tcb::decode(r.committed_tcb, p);
            out.check("min tcb", if !reported.at_least(&min) {
                Err(format!("reported TCB {reported} is below {min}"))
            } else if !committed.at_least(&min) {
                Err(format!("committed TCB {committed} is below {min}: the sealing key cannot be derived"))
            } else {
                ok(format!("reported and committed TCB >= {min}"))
            });
        }
    } else if expect.min_tcb.is_some() {
        out.push(
            "min tcb",
            Status::Fail,
            "generation unknown, cannot decode TCB",
        );
    }
    let (maj, min, build) = r.current_fw;
    out.push(
        "firmware",
        Status::Info,
        format!("{maj}.{min} build {build}"),
    );

    // Guest policy and platform.
    out.check(
        "debug policy",
        if r.policy & POLICY_DEBUG != 0 {
            Err("guest is debuggable; host can read its memory".into())
        } else {
            ok("debug disabled")
        },
    );
    out.check(
        "migration agent",
        if r.policy & POLICY_MIGRATE_MA != 0 {
            Err("policy allows a migration agent".into())
        } else if r.report_id_ma != [0xFF; 32] {
            Err("guest is bound to a migration agent".into())
        } else {
            ok("none")
        },
    );
    let smt_on = r.platform_info & PLATFORM_SMT_EN != 0;
    let smt = format!(
        "host SMT {}, guest policy {}",
        if smt_on { "enabled" } else { "disabled" },
        if r.policy & POLICY_SMT != 0 {
            "allows SMT"
        } else {
            "requires SMT off"
        }
    );
    if expect.deny_smt && smt_on {
        out.push("smt", Status::Fail, smt);
    } else {
        out.push("smt", Status::Info, smt);
    }
    out.check(
        "vmpl",
        if r.vmpl == expect.vmpl {
            ok(r.vmpl.to_string())
        } else {
            Err(format!("{}, expected {}", r.vmpl, expect.vmpl))
        },
    );
    out.push("guest svn", Status::Info, r.guest_svn.to_string());
    out.push("family id", Status::Info, hex::encode(r.family_id));
    out.push("image id", Status::Info, hex::encode(r.image_id));
    out.push("host data", Status::Info, hex::encode(r.host_data));
    if r.id_key_digest != [0; 48] {
        out.push("id key digest", Status::Info, hex::encode(r.id_key_digest));
    }
    if let Some((launch, current)) = r.mit_vectors {
        out.push(
            "mitigations",
            Status::Info,
            format!("launch {launch:#x}, current {current:#x}"),
        );
    }

    // Binding and measurement.
    if let Some(rd) = expect.report_data {
        out.check(
            "report_data binding",
            if r.report_data == rd {
                ok("")
            } else {
                Err("MISMATCH".into())
            },
        );
    }
    let m = hex::encode(r.measurement);
    match expect.measurement {
        Some(exp) if exp == r.measurement => {
            out.push("measurement", Status::Ok, m);
        }
        Some(exp) => out.push(
            "measurement",
            Status::Fail,
            format!("{m}, expected {}", hex::encode(exp)),
        ),
        None => out.push("measurement", Status::Info, format!("{m} (not checked)")),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair};
    use std::time::Duration;

    const VIRTEE_REPORT: &str = include_str!("../tests/fixtures/snp/virtee/report_milan.hex");
    const VIRTEE_VCEK_MILAN: &[u8] = include_bytes!("../tests/fixtures/snp/virtee/vcek_milan.der");
    const VIRTEE_VCEK_TURIN: &[u8] = include_bytes!("../tests/fixtures/snp/virtee/vcek_turin.der");

    fn at(unix: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix)
    }
    /// 2027-01-01: inside every fixture certificate's validity.
    fn now() -> SystemTime {
        at(1_798_761_600)
    }

    fn real_report() -> Vec<u8> {
        hex::decode(VIRTEE_REPORT.trim()).unwrap()
    }

    fn status(o: &Outcome, name: &str) -> Status {
        o.lines
            .iter()
            .find(|l| l.name == name)
            .unwrap_or_else(|| panic!("no {name} line"))
            .status
    }

    #[test]
    fn embedded_arks_match_pins() {
        let a = amd_anchors();
        assert_eq!(a.0.len(), 3);
        for pa in &a.0 {
            // Each intermediate verifies under its ARK.
            check_signed_by("ARK", &pa.ark, &pa.ark, now()).unwrap();
            check_signed_by("ASK", &pa.ask, &pa.ark, now()).unwrap();
            check_signed_by("ASVK", &pa.asvk, &pa.ark, now()).unwrap();
        }
    }

    #[test]
    fn report_offsets() {
        let r = Report::parse(&real_report()).unwrap();
        assert_eq!(r.version, 2);
        assert_eq!(r.policy, 0x30000);
        assert_eq!(r.vmpl, 0);
        assert_eq!(r.sig_algo, 1);
        assert_eq!(r.signing_key(), Some(SigningKey::Vcek));
        assert_eq!(r.reported_tcb, 0x7308_0000_0000_0003);
        assert_eq!(r.cpuid, None);
        assert_eq!(r.current_fw, (1, 52, 4));
        assert_eq!(r.report_id_ma, [0xFF; 32]);
        assert_eq!(hex::encode(&r.chip_id[..4]), "d49554ec");
        assert_eq!(hex::encode(&r.measurement[..4]), "7a1e5c26");
    }

    // Real evidence: virtee/sev's Milan report with the VCEK AMD issued for it.
    #[test]
    fn real_milan_report_verifies() {
        let o = verify(
            &real_report(),
            Some(VIRTEE_VCEK_MILAN),
            &amd_anchors(),
            &Expect {
                now: now(),
                ..Default::default()
            },
        );
        assert!(o.ok(), "{:?}", o.failed());
        assert_eq!(o.product, Some(Product::Milan));
        for name in [
            "signing key",
            "amd chain",
            "report signature",
            "vcek tcb",
            "chip id",
            "debug policy",
            "migration agent",
            "vmpl",
        ] {
            assert_eq!(status(&o, name), Status::Ok, "{name}");
        }
    }

    #[test]
    fn real_report_tampered_fails_signature() {
        let mut rep = real_report();
        rep[0x90] ^= 1; // measurement
        let o = verify(
            &rep,
            Some(VIRTEE_VCEK_MILAN),
            &amd_anchors(),
            &Expect {
                now: now(),
                ..Default::default()
            },
        );
        assert_eq!(o.failed(), ["report signature"]);
    }

    #[test]
    fn real_report_needs_a_vcek() {
        let o = verify(
            &real_report(),
            None,
            &amd_anchors(),
            &Expect {
                now: now(),
                ..Default::default()
            },
        );
        assert_eq!(o.failed(), ["amd chain"]);
    }

    #[test]
    fn expired_vcek_fails() {
        // virtee's Milan VCEK is valid 2023-04-03 to 2030-04-03.
        let o = verify(
            &real_report(),
            Some(VIRTEE_VCEK_MILAN),
            &amd_anchors(),
            &Expect {
                now: at(2_000_000_000),
                ..Default::default()
            },
        );
        assert_eq!(o.failed(), ["amd chain"]);
    }

    #[test]
    fn real_turin_vcek_chain_and_extensions() {
        let a = amd_anchors();
        assert_eq!(
            verify_chain(&a, SigningKey::Vcek, VIRTEE_VCEK_TURIN, now()),
            Ok(Product::Turin)
        );
        let info = leaf_info(VIRTEE_VCEK_TURIN).unwrap();
        assert_eq!(info.product_name.as_deref(), Some("Turin"));
        assert_eq!(info.hw_id.as_deref().map(<[u8]>::len), Some(8));
        assert_eq!(
            (info.fmc, info.bootloader, info.microcode),
            (Some(0), Some(0), Some(9))
        );
        // A Turin VCEK does not chain to Milan's ASK.
        assert!(verify_chain(&a, SigningKey::Vlek, VIRTEE_VCEK_TURIN, now()).is_err());
    }

    #[test]
    fn tcb_layouts() {
        let t = Tcb::decode(0x7308_0000_0000_0003, Product::Milan);
        assert_eq!(
            (t.bootloader, t.tee, t.snp, t.microcode, t.fmc),
            (3, 0, 8, 0x73, None)
        );
        // Turin: fmc, bl, tee, snp in bytes 0-3, microcode in byte 7.
        let t = Tcb::decode(0x4800_0000_0501_0302, Product::Turin);
        assert_eq!(
            (t.fmc, t.bootloader, t.tee, t.snp, t.microcode),
            (Some(2), 3, 1, 5, 72)
        );
        // Per component, not as an integer.
        let min = Tcb::decode(0x7308_0000_0000_0003, Product::Milan);
        let lower_ucode_higher_bl = Tcb::decode(0x7208_0000_0000_0009, Product::Milan);
        assert!(!lower_ucode_higher_bl.at_least(&min));
        assert!(min.at_least(&min));
    }

    #[test]
    fn kds_url() {
        let r = Report::parse(&real_report()).unwrap();
        let url = kds_vcek_url(
            Product::Milan,
            &r.chip_id,
            &Tcb::decode(r.reported_tcb, Product::Milan),
        );
        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Milan/d49554ec"));
        assert!(url.ends_with("?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115"));
        let mut chip = [0u8; 64];
        chip[..8].copy_from_slice(&[0xa1; 8]);
        let url = kds_vcek_url(
            Product::Turin,
            &chip,
            &Tcb::decode(0x4800_0000_0501_0302, Product::Turin),
        );
        assert_eq!(
            url,
            "https://kdsintf.amd.com/vcek/v1/Turin/a1a1a1a1a1a1a1a1?fmcSPL=02&blSPL=03&teeSPL=01&snpSPL=05&ucodeSPL=72"
        );
    }

    // ---- fake chain (tests/fixtures/snp/fake, generated by gen.sh) ----

    struct Fake {
        anchors: Anchors,
        leaf: Vec<u8>,
        key: &'static [u8],
        product: Product,
    }

    fn fake(product: Product, key: SigningKey) -> Fake {
        macro_rules! f {
            ($n:literal) => {
                include_bytes!(concat!("../tests/fixtures/snp/fake/", $n))
            };
        }
        let der = |p: &[u8]| pem_to_der(p).unwrap();
        match (product, key) {
            (Product::Milan, _) => Fake {
                anchors: Anchors(vec![ProductAnchors {
                    product,
                    ark: der(f!("milan-ark.pem")),
                    ask: der(f!("milan-ask.pem")),
                    asvk: der(f!("milan-asvk.pem")),
                }]),
                leaf: der(if key == SigningKey::Vcek {
                    f!("milan-vcek.pem")
                } else {
                    f!("milan-vlek.pem")
                }),
                key: if key == SigningKey::Vcek {
                    f!("milan-vcek.pk8")
                } else {
                    f!("milan-vlek.pk8")
                },
                product,
            },
            (Product::Turin, SigningKey::Vcek) => Fake {
                anchors: Anchors(vec![ProductAnchors {
                    product,
                    ark: der(f!("turin-ark.pem")),
                    ask: der(f!("turin-ask.pem")),
                    asvk: der(f!("turin-ask.pem")),
                }]),
                leaf: der(f!("turin-vcek.pem")),
                key: f!("turin-vcek.pk8"),
                product,
            },
            _ => unreachable!(),
        }
    }

    /// A v3 report matching the fake VCEK: what a healthy guest returns.
    fn fake_report(f: &Fake, key: SigningKey) -> Vec<u8> {
        let mut r = vec![0u8; REPORT_LEN];
        r[0..4].copy_from_slice(&3u32.to_le_bytes());
        r[0x08..0x10].copy_from_slice(&0x30000u64.to_le_bytes());
        r[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        r[0x48..0x4C].copy_from_slice(&((key as u32) << 2).to_le_bytes());
        r[0x50..0x90].copy_from_slice(&[0x11; 64]);
        r[0x90..0xC0].copy_from_slice(&[0x22; 48]);
        r[0x160..0x180].copy_from_slice(&[0xFF; 32]);
        let (tcb, family, model): (u64, u8, u8) = match f.product {
            // bl=4 tee=1 snp=22 ucode=213, as in gen.sh
            Product::Milan | Product::Genoa => (0xD516_0000_0000_0104, 0x19, 0x01),
            // fmc=2 bl=3 tee=1 snp=5 ucode=72
            Product::Turin => (0x4800_0000_0501_0302, 0x1A, 0x02),
        };
        for off in [0x38, 0x180, 0x1E0, 0x1F0] {
            r[off..off + 8].copy_from_slice(&tcb.to_le_bytes());
        }
        r[0x188] = family;
        r[0x189] = model;
        match f.product {
            Product::Turin => {
                r[0x1A0..0x1A8].copy_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8])
            }
            _ => {
                for (i, b) in r[0x1A0..0x1E0].iter_mut().enumerate() {
                    *b = i as u8 + 1;
                }
            }
        }
        sign(f, &mut r);
        r
    }

    fn sign(f: &Fake, r: &mut [u8]) {
        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, f.key, &rng).unwrap();
        let sig = kp.sign(&rng, &r[..SIGNED_LEN]).unwrap();
        let sig = sig.as_ref();
        r[SIGNED_LEN..].fill(0);
        for i in 0..48 {
            r[SIGNED_LEN + i] = sig[47 - i];
            r[SIGNED_LEN + 72 + i] = sig[95 - i];
        }
    }

    fn expect() -> Expect {
        Expect {
            report_data: Some([0x11; 64]),
            measurement: Some([0x22; 48]),
            now: now(),
            ..Default::default()
        }
    }

    /// Changes one thing in a good fake report, re-signs, and returns the
    /// names of the checks that failed.
    fn fails_with(product: Product, edit: impl Fn(&mut Vec<u8>), exp: Expect) -> Vec<&'static str> {
        let f = fake(product, SigningKey::Vcek);
        let mut r = fake_report(&f, SigningKey::Vcek);
        edit(&mut r);
        sign(&f, &mut r);
        verify(&r, Some(&f.leaf), &f.anchors, &exp).failed()
    }

    #[test]
    fn fake_chain_positive() {
        for (p, k) in [
            (Product::Milan, SigningKey::Vcek),
            (Product::Milan, SigningKey::Vlek),
            (Product::Turin, SigningKey::Vcek),
        ] {
            let f = fake(p, k);
            let o = verify(&fake_report(&f, k), Some(&f.leaf), &f.anchors, &expect());
            assert!(
                o.ok(),
                "{p:?} {k:?}: {:?}",
                o.lines
                    .iter()
                    .filter(|l| l.status == Status::Fail)
                    .map(|l| (l.name, l.detail.clone()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(o.product, Some(p));
        }
    }

    #[test]
    fn fake_chain_is_not_amd() {
        let f = fake(Product::Milan, SigningKey::Vcek);
        let o = verify(
            &fake_report(&f, SigningKey::Vcek),
            Some(&f.leaf),
            &amd_anchors(),
            &expect(),
        );
        assert_eq!(o.failed(), ["amd chain"]);
    }

    #[test]
    fn wrong_root() {
        // Milan leaf, Turin anchors.
        let f = fake(Product::Milan, SigningKey::Vcek);
        let t = fake(Product::Turin, SigningKey::Vcek);
        let o = verify(
            &fake_report(&f, SigningKey::Vcek),
            Some(&f.leaf),
            &t.anchors,
            &expect(),
        );
        assert_eq!(o.failed(), ["amd chain"]);
        // Same subject names, different ARK key.
        let mut a = fake(Product::Milan, SigningKey::Vcek).anchors;
        a.0[0].ark = t.anchors.0[0].ark.clone();
        let o = verify(
            &fake_report(&f, SigningKey::Vcek),
            Some(&f.leaf),
            &a,
            &expect(),
        );
        assert_eq!(o.failed(), ["amd chain"]);
    }

    #[test]
    fn bad_signature() {
        let f = fake(Product::Milan, SigningKey::Vcek);
        let mut r = fake_report(&f, SigningKey::Vcek);
        r[0x50] ^= 1;
        let o = verify(&r, Some(&f.leaf), &f.anchors, &expect());
        assert_eq!(o.failed(), ["report signature", "report_data binding"]);
        // Signed by a different key.
        let other = fake(Product::Milan, SigningKey::Vlek);
        let mut r = fake_report(&f, SigningKey::Vcek);
        sign(&other, &mut r);
        assert_eq!(
            verify(&r, Some(&f.leaf), &f.anchors, &expect()).failed(),
            ["report signature"]
        );
    }

    #[test]
    fn vlek_report_needs_vlek_chain() {
        // Report says VLEK, but the leaf is a VCEK (issued by the ASK).
        let f = fake(Product::Milan, SigningKey::Vcek);
        let mut r = fake_report(&f, SigningKey::Vcek);
        r[0x48] = 1 << 2;
        sign(&f, &mut r);
        assert_eq!(
            verify(&r, Some(&f.leaf), &f.anchors, &expect()).failed(),
            ["amd chain"]
        );
    }

    #[test]
    fn tcb_mismatch() {
        // Reported TCB microcode 214, VCEK issued for 213.
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x187] = 214, expect()),
            ["vcek tcb"]
        );
        // Turin fmc.
        assert_eq!(
            fails_with(Product::Turin, |r| r[0x180] = 9, expect()),
            ["vcek tcb"]
        );
    }

    #[test]
    fn chip_id_mismatch() {
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x1A0] ^= 1, expect()),
            ["chip id"]
        );
        assert_eq!(
            fails_with(Product::Turin, |r| r[0x1A7] ^= 1, expect()),
            ["chip id"]
        );
        // Turin's 8-byte hwID must not match a chip id with more bytes set.
        assert_eq!(
            fails_with(Product::Turin, |r| r[0x1B0] = 1, expect()),
            ["chip id"]
        );
    }

    #[test]
    fn product_mismatch() {
        // Milan chain, Turin CPUID.
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x188] = 0x1A, expect()),
            ["product"]
        );
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x188] = 0x17, expect()),
            ["product"]
        );
    }

    #[test]
    fn min_tcb() {
        let with_min = |min: u64| Expect {
            min_tcb: Some(min),
            ..expect()
        };
        // Reported bl=4 tee=1 snp=22 ucode=213.
        assert!(fails_with(Product::Milan, |_| {}, with_min(0xD516_0000_0000_0104)).is_empty());
        assert!(fails_with(Product::Milan, |_| {}, with_min(0x0300_0000_0000_0000)).is_empty());
        assert_eq!(
            fails_with(Product::Milan, |_| {}, with_min(0xD517_0000_0000_0104)),
            ["min tcb"]
        );
        assert_eq!(
            fails_with(Product::Milan, |_| {}, with_min(0xD616_0000_0000_0000)),
            ["min tcb"]
        );
        // Committed below the minimum: the sealing key could not be derived.
        assert_eq!(
            fails_with(
                Product::Milan,
                |r| r[0x1E7] = 200,
                with_min(0xD516_0000_0000_0104)
            ),
            ["min tcb"]
        );
        // Turin layout: fmc in byte 0.
        assert_eq!(
            fails_with(Product::Turin, |_| {}, with_min(0x0000_0000_0000_0003)),
            ["min tcb"]
        );
        assert!(fails_with(Product::Turin, |_| {}, with_min(0x0000_0000_0000_0002)).is_empty());
    }

    #[test]
    fn policy_checks() {
        let set = |off: usize, v: u64| {
            move |r: &mut Vec<u8>| {
                let cur = le64(r, off);
                r[off..off + 8].copy_from_slice(&(cur | v).to_le_bytes());
            }
        };
        assert_eq!(
            fails_with(Product::Milan, set(0x08, POLICY_DEBUG), expect()),
            ["debug policy"]
        );
        assert_eq!(
            fails_with(Product::Milan, set(0x08, POLICY_MIGRATE_MA), expect()),
            ["migration agent"]
        );
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x160] = 0, expect()),
            ["migration agent"]
        );
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x30] = 1, expect()),
            ["vmpl"]
        );
        assert!(
            fails_with(
                Product::Milan,
                |r| r[0x30] = 1,
                Expect {
                    vmpl: 1,
                    ..expect()
                }
            )
            .is_empty()
        );
        let deny = Expect {
            deny_smt: true,
            ..expect()
        };
        assert!(fails_with(Product::Milan, |_| {}, deny.clone()).is_empty());
        assert_eq!(
            fails_with(Product::Milan, set(0x40, PLATFORM_SMT_EN), deny),
            ["smt"]
        );
        assert!(fails_with(Product::Milan, set(0x40, PLATFORM_SMT_EN), expect()).is_empty());
    }

    #[test]
    fn binding_and_measurement() {
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x8F] ^= 1, expect()),
            ["report_data binding"]
        );
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x90] ^= 1, expect()),
            ["measurement"]
        );
    }

    #[test]
    fn unsigned_or_odd_reports() {
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x48] = 7 << 2, expect()),
            ["signing key"]
        );
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x48] = 1 << 1, expect()),
            ["signing key"]
        );
        assert_eq!(
            fails_with(Product::Milan, |r| r[0x34] = 2, expect()),
            ["signing key"]
        );
        for v in [1u8, 6] {
            assert_eq!(
                fails_with(Product::Milan, |r| r[0] = v, expect()),
                ["report"]
            );
        }
        let f = fake(Product::Milan, SigningKey::Vcek);
        let r = fake_report(&f, SigningKey::Vcek);
        assert_eq!(
            verify(&r[..0x49F], Some(&f.leaf), &f.anchors, &expect()).failed(),
            ["report"]
        );
    }

    #[test]
    fn report_v5_fields() {
        let f = fake(Product::Milan, SigningKey::Vcek);
        let mut r = fake_report(&f, SigningKey::Vcek);
        r[0] = 5;
        r[0x1F8] = 3;
        r[0x200] = 1;
        sign(&f, &mut r);
        let o = verify(&r, Some(&f.leaf), &f.anchors, &expect());
        assert!(o.ok());
        let mit = o.lines.iter().find(|l| l.name == "mitigations").unwrap();
        assert_eq!(mit.detail, "launch 0x3, current 0x1");
    }

    #[test]
    fn cert_table() {
        let f = fake(Product::Milan, SigningKey::Vcek);
        for guid in guid_forms(GUID_VCEK) {
            let mut t = Vec::new();
            // ASK entry first, then the VCEK, then the terminator.
            t.extend_from_slice(&guid_forms("4ab7b379-bbac-4fe4-a02f-05aef327c782")[0]);
            t.extend_from_slice(&72u32.to_le_bytes());
            t.extend_from_slice(&0u32.to_le_bytes());
            t.extend_from_slice(&guid);
            t.extend_from_slice(&72u32.to_le_bytes());
            t.extend_from_slice(&(f.leaf.len() as u32).to_le_bytes());
            t.extend_from_slice(&[0; 24]);
            t.extend_from_slice(&f.leaf);
            assert_eq!(
                leaf_from_cert_table(&t, SigningKey::Vcek).unwrap(),
                Some(f.leaf.clone())
            );
            assert_eq!(leaf_from_cert_table(&t, SigningKey::Vlek).unwrap(), None);
            // Out of bounds length.
            let mut bad = t.clone();
            bad[24 + 20..24 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(leaf_from_cert_table(&bad, SigningKey::Vcek).is_err());
        }
        assert!(leaf_from_cert_table(&[1; 30], SigningKey::Vcek).is_err());
        assert_eq!(
            leaf_from_cert_table(&[0; 24], SigningKey::Vcek).unwrap(),
            None
        );
    }

    #[test]
    fn pss_params_must_be_sha384() {
        // AMD's encoding, with the explicit trailer field.
        let amd = parse_cert(&amd_anchors().0[0].ark).unwrap();
        check_pss_params(amd.signature_algorithm().parameters.as_ref()).unwrap();
        // OpenSSL's, without it.
        let fake = parse_cert(&fake(Product::Milan, SigningKey::Vcek).leaf).unwrap();
        check_pss_params(fake.signature_algorithm().parameters.as_ref()).unwrap();
        assert!(check_pss_params(None).is_err());
        let sha256 = x509_cert::der::Any::from_der(&hex::decode(
            "3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
        ).unwrap()).unwrap();
        assert!(check_pss_params(Some(&sha256)).is_err());
    }
}
