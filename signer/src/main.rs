use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use tee_signer::api::{self, AppState};
use tee_signer::network::Network;
use tee_signer::signing::Policy;
use tee_signer::slashing::SlashingDb;
use tee_signer::{keystore, tee, tls};

/// Web3Signer-compatible BLS remote signer designed to run inside a
/// confidential VM (AMD SEV-SNP today; Intel TDX / Arm CCA via configfs-tsm).
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the signing API.
    Serve(ServeArgs),
    /// Print the slashing protection database as EIP-3076 interchange JSON.
    SlashingExport {
        #[arg(
            long,
            env = "TEE_SIGNER_DATA_DIR",
            default_value = "/var/lib/tee-signer"
        )]
        data_dir: PathBuf,
        #[arg(long, env = "TEE_SIGNER_NETWORK")]
        network: Network,
    },
    /// Offline check of evidence fetched from /api/v1/tee/attestation: the
    /// REPORT_DATA binding and debug policy. Does NOT verify the hardware
    /// signature; use `snpguest verify attestation` (SEV-SNP) or DCAP (TDX).
    VerifyEvidence {
        /// JSON response saved from /api/v1/tee/attestation.
        #[arg(long)]
        evidence: PathBuf,
        /// The nonce you sent, hex.
        #[arg(long)]
        nonce: String,
        /// Expected launch measurement, hex (from sev-snp-measure / MRTD).
        #[arg(long)]
        expected_measurement: Option<String>,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, env = "TEE_SIGNER_LISTEN", default_value = "127.0.0.1:9000")]
    listen: SocketAddr,
    /// Holds the slashing protection database and TLS key. Must be on the
    /// encrypted, measured disk in a TEE deployment.
    #[arg(
        long,
        env = "TEE_SIGNER_DATA_DIR",
        default_value = "/var/lib/tee-signer"
    )]
    data_dir: PathBuf,
    /// EIP-2335 keystores with sibling .txt password files (charon's
    /// validator_keys layout).
    #[arg(long, env = "TEE_SIGNER_KEYSTORES_DIR")]
    keystores_dir: PathBuf,
    /// mainnet, hoodi, sepolia, or custom:<gvr>:<genesis_fork>:<capella_fork>.
    #[arg(long, env = "TEE_SIGNER_NETWORK")]
    network: Network,
    /// Serve plain HTTP. Only for development: TLS must terminate inside the
    /// TEE for attestation to mean anything.
    #[arg(long, env = "TEE_SIGNER_INSECURE_HTTP")]
    insecure_http: bool,
    /// Subject alternative names for the generated TLS certificate.
    #[arg(long = "tls-san", env = "TEE_SIGNER_TLS_SANS", value_delimiter = ',', default_values_t = ["localhost".to_string(), "127.0.0.1".to_string()])]
    tls_sans: Vec<String>,
    /// Require client certificates whose SHA-256 fingerprints are listed in
    /// this file (Web3Signer knownClients format).
    #[arg(long, env = "TEE_SIGNER_TLS_KNOWN_CLIENTS")]
    tls_known_clients: Option<PathBuf>,
    #[arg(long, env = "TEE_SIGNER_ALLOW_VOLUNTARY_EXITS", default_value_t = true, action = clap::ArgAction::Set)]
    allow_voluntary_exits: bool,
    #[arg(long, env = "TEE_SIGNER_ALLOW_DEPOSITS", default_value_t = false, action = clap::ArgAction::Set)]
    allow_deposits: bool,
    /// EIP-3076 interchange file to import before serving.
    #[arg(long, env = "TEE_SIGNER_SLASHING_PROTECTION_IMPORT")]
    slashing_protection_import: Option<PathBuf>,
    #[arg(long, env = "TEE_SIGNER_LOG_JSON")]
    log_json: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve(args) => {
            init_logging(args.log_json);
            tokio::runtime::Runtime::new()?.block_on(serve(args))
        }
        Cmd::SlashingExport { data_dir, network } => {
            let db = SlashingDb::open(&data_dir.join("slashing"), network.genesis_validators_root)?;
            println!("{}", serde_json::to_string_pretty(&db.export()?)?);
            Ok(())
        }
        Cmd::VerifyEvidence {
            evidence,
            nonce,
            expected_measurement,
        } => verify_evidence(&evidence, &nonce, expected_measurement.as_deref()),
    }
}

fn init_logging(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        fmt.json().init();
    } else {
        fmt.init();
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let keys = keystore::load_dir(&args.keystores_dir)?;
    if keys.is_empty() {
        bail!("no keystores found in {}", args.keystores_dir.display());
    }

    let db = SlashingDb::open(
        &args.data_dir.join("slashing"),
        args.network.genesis_validators_root,
    )?;
    if let Some(path) = &args.slashing_protection_import {
        let n = db.import(&std::fs::read(path)?)?;
        tracing::info!(entries = n, path = %path.display(), "imported slashing protection");
    }

    let tls = if args.insecure_http {
        tracing::warn!("serving plain HTTP: attestation is disabled and traffic is unprotected");
        None
    } else {
        Some(tls::load_or_generate(
            &args.data_dir.join("tls"),
            &args.tls_sans,
            args.tls_known_clients.as_deref(),
        )?)
    };

    let state = Arc::new(AppState {
        keys,
        db,
        network: args.network.clone(),
        policy: Policy {
            allow_voluntary_exits: args.allow_voluntary_exits,
            allow_deposits: args.allow_deposits,
        },
        tls_cert: tls
            .as_ref()
            .map(|m| (m.cert_der.clone(), m.cert_pem.clone())),
    });
    let app = api::router(state.clone()).layer(tower_http::trace::TraceLayer::new_for_http());

    tracing::info!(
        listen = %args.listen,
        network = %args.network.name,
        keys = state.keys.len(),
        tls = tls.is_some(),
        mtls = args.tls_known_clients.is_some(),
        "tee-signer serving"
    );

    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        h.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    });

    match tls {
        Some(m) => {
            axum_server::bind_rustls(
                args.listen,
                axum_server::tls_rustls::RustlsConfig::from_config(m.config),
            )
            .handle(handle)
            .serve(app.into_make_service())
            .await?
        }
        None => {
            axum_server::bind(args.listen)
                .handle(handle)
                .serve(app.into_make_service())
                .await?
        }
    }
    Ok(())
}

fn verify_evidence(
    path: &std::path::Path,
    nonce: &str,
    expected: Option<&str>,
) -> anyhow::Result<()> {
    use rustls::pki_types::pem::PemObject;

    let ev: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let field = |k: &str| {
        ev[k]
            .as_str()
            .with_context(|| format!("evidence is missing {k}"))
    };
    let unhex = |s: &str| hex::decode(s.trim_start_matches("0x")).context("bad hex");

    let provider = field("provider")?;
    let report = unhex(field("report")?)?;
    let nonce: [u8; 32] = unhex(nonce)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be 32 bytes"))?;
    let cert =
        rustls::pki_types::CertificateDer::from_pem_slice(field("tls_certificate")?.as_bytes())?;
    let pubkeys: Vec<[u8; 48]> = ev["pubkeys"]
        .as_array()
        .context("evidence is missing pubkeys")?
        .iter()
        .map(|v| {
            let b = unhex(v.as_str().unwrap_or_default())?;
            b.try_into().map_err(|_| anyhow::anyhow!("bad pubkey"))
        })
        .collect::<anyhow::Result<_>>()?;

    let layout =
        tee::layout(provider).with_context(|| format!("unsupported provider {provider}"))?;
    let expected_rd = tee::report_data(&nonce, &cert, &pubkeys);
    let actual_rd = report
        .get(layout.report_data..layout.report_data + 64)
        .context("report too short")?;
    let (m_off, m_len) = layout.measurement;
    let measurement = hex::encode(
        report
            .get(m_off..m_off + m_len)
            .context("report too short")?,
    );

    println!("provider:            {provider}");
    println!(
        "tls cert sha256:     {}",
        hex::encode(Sha256::digest(&cert))
    );
    println!("bls pubkeys:         {}", pubkeys.len());
    println!(
        "{:<20} {measurement}",
        format!("{}:", layout.measurement_name)
    );

    let mut ok = true;
    if actual_rd == expected_rd {
        println!("report_data binding: OK");
    } else {
        println!("report_data binding: MISMATCH");
        ok = false;
    }
    let debug = match provider {
        "sev_guest" => tee::snp_debug_allowed(&report),
        "tdx_guest" => tee::tdx_debug(&report),
        _ => None,
    };
    match debug {
        Some(false) => println!("debug policy:        OK (debug disabled)"),
        Some(true) => {
            println!("debug policy:        FAIL (guest is debuggable; host can read its memory)");
            ok = false;
        }
        None => println!("debug policy:        unknown"),
    }
    if let Some(exp) = expected {
        if exp
            .trim_start_matches("0x")
            .eq_ignore_ascii_case(&measurement)
        {
            println!("measurement:         OK");
        } else {
            println!("measurement:         MISMATCH (expected {exp})");
            ok = false;
        }
    } else {
        println!("measurement:         not checked (pass --expected-measurement)");
    }
    println!(
        "\nNOTE: the report's hardware signature is NOT verified here. Verify it with\n\
         `snpguest verify attestation` (SEV-SNP) or Intel DCAP (TDX) before trusting it."
    );
    if !ok {
        bail!("evidence verification failed");
    }
    Ok(())
}
