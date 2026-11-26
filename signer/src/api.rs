//! Web3Signer-compatible eth2 HTTP API, plus a TEE attestation endpoint.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::keystore::SecretKey;
use crate::network::Network;
use crate::pins::Pins;
use crate::platform::{Platform, PlatformError};
use crate::signing::{self, Policy, PrepareError, SignBody, SignRequest};
use crate::slashing::{SlashingDb, SlashingError};
use crate::tee;
use crate::tls::{ClientFingerprint, KnownRoles, Role};

pub struct AppState {
    pub keys: BTreeMap<[u8; 48], SecretKey>,
    pub db: SlashingDb,
    pub network: Network,
    pub policy: Policy,
    /// DER of the TLS certificate the API is served with, if any.
    pub tls_cert: Option<(Vec<u8>, String)>,
    /// Source of attestation evidence.
    pub platform: Platform,
    /// Settings pinned from the cluster lock, if any.
    pub pins: Option<Pins>,
    /// Roles of the pinned client certificates, when mutual TLS is on.
    pub roles: Option<KnownRoles>,
}

/// The role a request needs.
fn required_role(body: &SignBody) -> Role {
    match body {
        SignBody::VoluntaryExit { .. } => Role::Exit,
        SignBody::Deposit { .. } => Role::Deposit,
        _ => Role::Duties,
    }
}

/// Sign requests carry at most a Gloas execution payload envelope: a full
/// execution payload, hex-encoded. EIP-7934 caps the RLP block at 10 MiB,
/// which is ~20 MiB as JSON hex, plus the block access list.
const SIGN_BODY_LIMIT: usize = 32 * 1024 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/upcheck", get(|| async { "OK" }))
        .route(
            "/healthcheck",
            get(|| async { Json(json!({"status": "UP"})) }),
        )
        .route("/api/v1/eth2/publicKeys", get(public_keys))
        .route(
            "/api/v1/eth2/sign/{identifier}",
            post(sign).layer(DefaultBodyLimit::max(SIGN_BODY_LIMIT)),
        )
        .route("/api/v1/tee/attestation", get(attestation))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

/// Health and attestation only, for a listener without client
/// authentication: evidence is meant to be fetched by anyone (e.g. charon
/// peers), and it reveals nothing beyond the public keys and certificate.
pub fn public_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/upcheck", get(|| async { "OK" }))
        .route(
            "/healthcheck",
            get(|| async { Json(json!({"status": "UP"})) }),
        )
        .route("/api/v1/tee/attestation", get(attestation))
        .with_state(state)
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

async fn public_keys(State(st): State<Arc<AppState>>) -> Json<Vec<String>> {
    Json(
        st.keys
            .keys()
            .map(|k| format!("0x{}", hex::encode(k)))
            .collect(),
    )
}

fn parse_pubkey(s: &str) -> Option<[u8; 48]> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .ok()?
        .try_into()
        .ok()
}

async fn sign(
    State(st): State<Arc<AppState>>,
    Path(identifier): Path<String>,
    client: Option<Extension<ClientFingerprint>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(pubkey) = parse_pubkey(&identifier) else {
        return error(
            StatusCode::BAD_REQUEST,
            "identifier must be a 0x-prefixed BLS public key",
        );
    };
    if !st.keys.contains_key(&pubkey) {
        return error(StatusCode::NOT_FOUND, "public key not found");
    }

    let req: SignRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("invalid request body: {e}");
            tracing::warn!(pubkey = %identifier, error = %msg, "rejected sign request");
            return error(StatusCode::BAD_REQUEST, msg);
        }
    };

    if let Some(roles) = &st.roles {
        let role = required_role(&req.body);
        let allowed = client
            .and_then(|Extension(ClientFingerprint(fp))| fp)
            .is_some_and(|fp| roles.allows(&fp, role));
        if !allowed {
            let msg = format!(
                "client certificate lacks the {:?} role for this request",
                role.name()
            );
            tracing::warn!(pubkey = %identifier, error = %msg, "rejected sign request");
            return error(StatusCode::FORBIDDEN, msg);
        }
    }

    if let Some(pins) = &st.pins
        && let Err(e) = pins.check(&pubkey, &req.body)
    {
        tracing::warn!(pubkey = %identifier, status = %StatusCode::FORBIDDEN, error = %e, "rejected sign request");
        return error(StatusCode::FORBIDDEN, e.to_string());
    }

    let prepared = match signing::prepare(&req, &st.network, &st.policy) {
        Ok(p) => p,
        Err(e) => {
            let status = match e {
                PrepareError::Forbidden(_) | PrepareError::Refused(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_REQUEST,
            };
            tracing::warn!(pubkey = %identifier, %status, error = %e, "rejected sign request");
            return error(status, e.to_string());
        }
    };

    // Slashing check, durable record and BLS signing are blocking work.
    let st2 = st.clone();
    let result = tokio::task::spawn_blocking(move || {
        if let Some(check) = prepared.slashing {
            st2.db
                .check_and_record(&pubkey, check, &prepared.signing_root)?;
        }
        let sk = st2.keys.get(&pubkey).expect("checked above");
        Ok::<_, SlashingError>((prepared.kind, sk.sign(&prepared.signing_root)))
    })
    .await;

    let (kind, signature) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e @ SlashingError::Violation(_))) => {
            tracing::warn!(pubkey = %identifier, error = %e, "refused to sign");
            return error(StatusCode::PRECONDITION_FAILED, e.to_string());
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "slashing protection database failure");
            return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    tracing::debug!(pubkey = %identifier, kind, "signed");
    let sig = format!("0x{}", hex::encode(signature));
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"));
    if wants_json {
        Json(json!({"signature": sig})).into_response()
    } else {
        ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], sig).into_response()
    }
}

#[derive(Deserialize)]
struct AttestationQuery {
    nonce: String,
}

async fn attestation(
    State(st): State<Arc<AppState>>,
    Query(q): Query<AttestationQuery>,
) -> Response {
    let Some(nonce) = hex::decode(q.nonce.trim_start_matches("0x"))
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    else {
        return error(StatusCode::BAD_REQUEST, "nonce must be 32 bytes of hex");
    };
    let Some((cert_der, cert_pem)) = st.tls_cert.clone() else {
        return error(
            StatusCode::CONFLICT,
            "attestation requires TLS: evidence is bound to the TLS certificate",
        );
    };

    let pubkeys: Vec<[u8; 48]> = st.keys.keys().copied().collect();
    let lock_hash = st.pins.as_ref().map(|p| p.lock_hash);
    let report_data = tee::report_data(&nonce, &cert_der, &pubkeys, lock_hash.as_ref());

    let st2 = st.clone();
    match tokio::task::spawn_blocking(move || st2.platform.evidence(&report_data)).await {
        Ok(Ok(ev)) => Json(json!({
            "provider": ev.provider,
            "report": format!("0x{}", hex::encode(&ev.report)),
            "auxblob": ev.auxblob.map(|b| format!("0x{}", hex::encode(b))),
            "report_data": format!("0x{}", hex::encode(report_data)),
            "tls_certificate": cert_pem,
            "pubkeys": pubkeys.iter().map(|k| format!("0x{}", hex::encode(k))).collect::<Vec<_>>(),
            "cluster_lock_hash": lock_hash.map(|h| format!("0x{}", hex::encode(h))),
        }))
        .into_response(),
        Ok(Err(e @ PlatformError::Tee(tee::TeeError::Unavailable))) => {
            error(StatusCode::NOT_IMPLEMENTED, e.to_string())
        }
        Ok(Err(e)) => error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
