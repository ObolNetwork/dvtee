use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use sev_signer::api::{self, AppState};
use sev_signer::network::{self, Network};
use sev_signer::platform::{PlatformArgs, SnpKeyParams};
use sev_signer::signing::Policy;
use sev_signer::slashing::SlashingDb;
use sev_signer::{keystore, tee, tls};

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
            env = "SEV_SIGNER_DATA_DIR",
            default_value = "/var/lib/sev-signer"
        )]
        data_dir: PathBuf,
        #[command(flatten)]
        network: NetworkArgs,
    },
    /// Write a 32-byte sealing key for PURPOSE to stdout, e.g. for
    /// `cryptsetup open --key-file=-`. On SEV-SNP it is derived from the
    /// chip's VCEK, the launch measurement, the guest policy and a pinned
    /// minimum TCB, so only the same measured image on the same chip gets it.
    SealingKey {
        #[arg(long, default_value = "data-disk")]
        purpose: String,
        /// Minimum TCB_VERSION mixed into the SNP key, as the raw 64-bit hex
        /// value from an attestation report (its encoding varies by CPU
        /// generation). Required for --platform tee.
        #[arg(long, env = "SEV_SIGNER_SNP_MIN_TCB", value_parser = parse_hex_u64)]
        snp_min_tcb: Option<u64>,
        /// VMPL mixed into the SNP key; must be >= the guest's own VMPL.
        #[arg(long, env = "SEV_SIGNER_SNP_VMPL", default_value_t = 0)]
        snp_vmpl: u32,
        #[command(flatten)]
        platform: PlatformArgs,
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
        /// Accept `insecure_dev` evidence (development and e2e tests only).
        #[arg(long)]
        allow_insecure_dev: bool,
    },
}

#[derive(clap::Args)]
struct NetworkArgs {
    /// mainnet, hoodi, sepolia, or custom:<gvr>:<genesis_fork>:<capella_fork>
    /// (no fork schedule: Gloas request types are refused).
    #[arg(
        long,
        env = "SEV_SIGNER_NETWORK",
        required_unless_present = "network_config",
        conflicts_with = "network_config"
    )]
    network: Option<Network>,
    /// Consensus-layer config.yaml (e.g. a devnet's network-configs/config.yaml)
    /// with the fork schedule. Requires --genesis-validators-root.
    #[arg(
        long,
        env = "SEV_SIGNER_NETWORK_CONFIG",
        requires = "genesis_validators_root"
    )]
    network_config: Option<PathBuf>,
    /// Genesis validators root for --network-config, hex.
    #[arg(
        long,
        env = "SEV_SIGNER_GENESIS_VALIDATORS_ROOT",
        requires = "network_config"
    )]
    genesis_validators_root: Option<String>,
}

impl NetworkArgs {
    fn resolve(&self) -> anyhow::Result<Network> {
        match (
            &self.network,
            &self.network_config,
            &self.genesis_validators_root,
        ) {
            (Some(n), None, None) => Ok(n.clone()),
            (None, Some(path), Some(gvr)) => {
                let gvr = network::parse_root(gvr).map_err(anyhow::Error::msg)?;
                let cfg = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                Network::from_config_yaml(&cfg, gvr)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
            }
            _ => bail!("use either --network or --network-config with --genesis-validators-root"),
        }
    }
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, env = "SEV_SIGNER_LISTEN", default_value = "127.0.0.1:9000")]
    listen: SocketAddr,
    /// Holds the slashing protection database and TLS key. Must be on the
    /// encrypted, measured disk in a TEE deployment.
    #[arg(
        long,
        env = "SEV_SIGNER_DATA_DIR",
        default_value = "/var/lib/sev-signer"
    )]
    data_dir: PathBuf,
    /// EIP-2335 keystores with sibling .txt password files (charon's
    /// validator_keys layout).
    #[arg(long, env = "SEV_SIGNER_KEYSTORES_DIR")]
    keystores_dir: PathBuf,
    #[command(flatten)]
    network: NetworkArgs,
    /// Serve plain HTTP. Only for development: TLS must terminate inside the
    /// TEE for attestation to mean anything.
    #[arg(long, env = "SEV_SIGNER_INSECURE_HTTP")]
    insecure_http: bool,
    /// Subject alternative names for the generated TLS certificate.
    #[arg(long = "tls-san", env = "SEV_SIGNER_TLS_SANS", value_delimiter = ',', default_values_t = ["localhost".to_string(), "127.0.0.1".to_string()])]
    tls_sans: Vec<String>,
    /// Require client certificates whose SHA-256 fingerprints are listed in
    /// this file (Web3Signer knownClients format).
    #[arg(long, env = "SEV_SIGNER_TLS_KNOWN_CLIENTS")]
    tls_known_clients: Option<PathBuf>,
    /// Second TLS listener serving only /upcheck, /healthcheck and
    /// /api/v1/tee/attestation, without client certificates, so peers and
    /// monitoring can fetch evidence while signing stays behind mTLS.
    #[arg(long, env = "SEV_SIGNER_PUBLIC_LISTEN")]
    public_listen: Option<SocketAddr>,
    #[arg(long, env = "SEV_SIGNER_ALLOW_VOLUNTARY_EXITS", default_value_t = true, action = clap::ArgAction::Set)]
    allow_voluntary_exits: bool,
    #[arg(long, env = "SEV_SIGNER_ALLOW_DEPOSITS", default_value_t = false, action = clap::ArgAction::Set)]
    allow_deposits: bool,
    /// EIP-3076 interchange file to import before serving.
    #[arg(long, env = "SEV_SIGNER_SLASHING_PROTECTION_IMPORT")]
    slashing_protection_import: Option<PathBuf>,
    #[arg(long, env = "SEV_SIGNER_LOG_JSON")]
    log_json: bool,
    #[command(flatten)]
    platform: PlatformArgs,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve(args) => {
            init_logging(args.log_json);
            tokio::runtime::Runtime::new()?.block_on(serve(args))
        }
        Cmd::SlashingExport { data_dir, network } => {
            let network = network.resolve()?;
            let db = SlashingDb::open(&data_dir.join("slashing"), network.genesis_validators_root)?;
            println!("{}", serde_json::to_string_pretty(&db.export()?)?);
            Ok(())
        }
        Cmd::SealingKey {
            purpose,
            snp_min_tcb,
            snp_vmpl,
            platform,
        } => {
            use std::io::{IsTerminal, Write};
            let platform = platform.build()?;
            let snp = snp_min_tcb.map(|min_tcb| SnpKeyParams {
                min_tcb,
                vmpl: snp_vmpl,
            });
            let key = platform.sealing_key(&purpose, snp)?;
            let mut out = std::io::stdout();
            if out.is_terminal() {
                bail!("refusing to write a raw key to a terminal; pipe it to cryptsetup");
            }
            out.write_all(key.as_ref())?;
            Ok(())
        }
        Cmd::VerifyEvidence {
            evidence,
            nonce,
            expected_measurement,
            allow_insecure_dev,
        } => verify_evidence(
            &evidence,
            &nonce,
            expected_measurement.as_deref(),
            allow_insecure_dev,
        ),
    }
}

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn init_logging(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        fmt.json().init();
    } else {
        use std::io::IsTerminal;
        fmt.with_ansi(std::io::stdout().is_terminal()).init();
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let network = args.network.resolve()?;
    let platform = args.platform.build()?;
    if platform.is_insecure() {
        refuse_mainnet(&network)?;
        tracing::warn!(
            "INSECURE-DEV PLATFORM: no TEE, keys are readable by the host, evidence is unsigned. \
             Development and testing only."
        );
    }

    let keys = keystore::load_dir(&args.keystores_dir)?;
    if keys.is_empty() {
        bail!("no keystores found in {}", args.keystores_dir.display());
    }

    let db = SlashingDb::open(
        &args.data_dir.join("slashing"),
        network.genesis_validators_root,
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
        network: network.clone(),
        policy: Policy {
            allow_voluntary_exits: args.allow_voluntary_exits,
            allow_deposits: args.allow_deposits,
        },
        tls_cert: tls
            .as_ref()
            .map(|m| (m.cert_der.clone(), m.cert_pem.clone())),
        platform,
    });
    let app = api::router(state.clone()).layer(tower_http::trace::TraceLayer::new_for_http());

    tracing::info!(
        listen = %args.listen,
        network = %network.name,
        gloas_epoch = ?network
            .forks
            .iter()
            .find(|f| f.name == network::ForkName::Gloas && f.epoch != network::FAR_FUTURE_EPOCH)
            .map(|f| f.epoch),
        keys = state.keys.len(),
        tls = tls.is_some(),
        mtls = args.tls_known_clients.is_some(),
        "sev-signer serving"
    );

    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        h.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    });

    if args.public_listen.is_some() && tls.is_none() {
        bail!("--public-listen requires TLS (it serves attestation evidence bound to the TLS key)");
    }
    match tls {
        Some(m) => {
            if let Some(addr) = args.public_listen {
                let public = api::public_router(state.clone())
                    .layer(tower_http::trace::TraceLayer::new_for_http());
                let cfg = axum_server::tls_rustls::RustlsConfig::from_config(m.public_config);
                let h = handle.clone();
                tracing::info!(listen = %addr, "public listener (health, attestation)");
                tokio::spawn(async move {
                    if let Err(e) = axum_server::bind_rustls(addr, cfg)
                        .handle(h)
                        .serve(public.into_make_service())
                        .await
                    {
                        tracing::error!(error = %e, "public listener failed");
                    }
                });
            }
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

/// SIGINT or SIGTERM. Containers send SIGTERM, and as PID 1 the signer gets
/// no default handler for it.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => tracing::warn!(error = %e, "cannot listen for SIGTERM"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The insecure platform must never hold mainnet keys. Checked by genesis
/// validators root and fork version, so `custom:` cannot get around it.
fn refuse_mainnet(network: &Network) -> anyhow::Result<()> {
    let mainnet = Network::presets()
        .into_iter()
        .find(|n| n.name == "mainnet")
        .expect("mainnet preset");
    if network.genesis_validators_root == mainnet.genesis_validators_root
        || network.genesis_fork_version == mainnet.genesis_fork_version
    {
        bail!("the insecure-dev platform refuses to run on mainnet");
    }
    Ok(())
}

fn verify_evidence(
    path: &std::path::Path,
    nonce: &str,
    expected: Option<&str>,
    allow_insecure_dev: bool,
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
    if provider == "insecure_dev" {
        if allow_insecure_dev {
            println!("platform:            INSECURE DEV (accepted by --allow-insecure-dev)");
        } else {
            println!("platform:            FAIL (insecure_dev evidence: no TEE, unsigned)");
            ok = false;
        }
    } else {
        match debug {
            Some(false) => println!("debug policy:        OK (debug disabled)"),
            Some(true) => {
                println!(
                    "debug policy:        FAIL (guest is debuggable; host can read its memory)"
                );
                ok = false;
            }
            None => println!("debug policy:        unknown"),
        }
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
