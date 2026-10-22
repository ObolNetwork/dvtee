//! TLS termination inside the guest.
//!
//! The server key is generated on first start and kept in the data directory
//! (the encrypted, measured disk in a TEE deployment), so it never exists
//! outside the guest. Its certificate is bound into attestation evidence; see
//! `tee.rs`.
//!
//! Optional mutual TLS pins client certificates by SHA-256 fingerprint,
//! the same model as Web3Signer's `knownClients` file.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

pub struct Material {
    pub config: Arc<ServerConfig>,
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Loads `cert.pem`/`key.pem` from `dir`, generating a self-signed pair for
/// `sans` on first use.
pub fn load_or_generate(
    dir: &Path,
    sans: &[String],
    known_clients: Option<&Path>,
) -> anyhow::Result<Material> {
    std::fs::create_dir_all(dir)?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if !cert_path.exists() {
        let ck = rcgen::generate_simple_self_signed(sans.to_vec())
            .context("generating TLS certificate")?;
        let key_pem = ck.signing_key.serialize_pem();
        write_private(&key_path, key_pem.as_bytes())?;
        std::fs::write(&cert_path, ck.cert.pem())?;
        tracing::info!(path = %cert_path.display(), ?sans, "generated self-signed TLS certificate");
    }

    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes()).context("parsing cert.pem")?;
    let key = PrivateKeyDer::from_pem_file(&key_path).context("parsing key.pem")?;

    let builder =
        ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let builder = match known_clients {
        Some(path) => builder.with_client_cert_verifier(Arc::new(PinnedClients::load(path)?)),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_single_cert(vec![cert.clone()], key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Material {
        config: Arc::new(config),
        cert_der: cert.to_vec(),
        cert_pem,
    })
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Accepts exactly the client certificates whose SHA-256 DER fingerprint is
/// listed (one per line, hex, `:` separators and a leading name allowed, so
/// Web3Signer `knownClients` files work as-is).
#[derive(Debug)]
struct PinnedClients {
    fingerprints: Vec<[u8; 32]>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedClients {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut fingerprints = Vec::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let fp = line
                .split_whitespace()
                .last()
                .unwrap_or_default()
                .replace(':', "");
            let bytes: [u8; 32] = hex::decode(&fp)
                .ok()
                .and_then(|v| v.try_into().ok())
                .with_context(|| format!("bad SHA-256 fingerprint {line:?}"))?;
            fingerprints.push(bytes);
        }
        anyhow::ensure!(
            !fingerprints.is_empty(),
            "{} lists no client fingerprints",
            path.display()
        );
        Ok(Self {
            fingerprints,
            algs: provider().signature_verification_algorithms,
        })
    }
}

impl ClientCertVerifier for PinnedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.fingerprints.contains(&fp) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "client certificate not in known clients".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
