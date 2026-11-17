//! Cross-implementation tests against vectors produced by `tests/vecgen`
//! (go-eth2-client SSZ, herumi BLS and the wealdtech EIP-2335 encryptor, the
//! same stack charon uses).

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde::Deserialize;
use sev_signer::api::{AppState, router};
use sev_signer::keystore::{self, SecretKey};
use sev_signer::network::Network;
use sev_signer::signing::{self, Policy, SignRequest};
use sev_signer::slashing::SlashingDb;
use tower::ServiceExt;

#[derive(Deserialize)]
struct Vectors {
    secret_key: String,
    public_key: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    request: serde_json::Value,
    signing_root: String,
    signature: String,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn vectors() -> Vectors {
    serde_json::from_slice(&std::fs::read(dir().join("signing_vectors.json")).unwrap()).unwrap()
}

fn hoodi() -> Network {
    "hoodi".parse().unwrap()
}

fn allow_all() -> Policy {
    Policy {
        allow_voluntary_exits: true,
        allow_deposits: true,
    }
}

fn secret(v: &Vectors) -> SecretKey {
    SecretKey::from_bytes(&hex::decode(v.secret_key.trim_start_matches("0x")).unwrap()).unwrap()
}

#[test]
fn signing_roots_and_signatures_match_go() {
    let v = vectors();
    let sk = secret(&v);
    assert_eq!(format!("0x{}", hex::encode(sk.public_key())), v.public_key);
    assert_eq!(v.vectors.len(), 13);

    for vec in &v.vectors {
        let req: SignRequest = serde_json::from_value(vec.request.clone())
            .unwrap_or_else(|e| panic!("{}: parse: {e}", vec.name));
        let p = signing::prepare(&req, &hoodi(), &allow_all())
            .unwrap_or_else(|e| panic!("{}: prepare: {e}", vec.name));
        assert_eq!(
            format!("0x{}", hex::encode(p.signing_root)),
            vec.signing_root,
            "{}",
            vec.name
        );
        assert_eq!(
            format!("0x{}", hex::encode(sk.sign(&p.signing_root))),
            vec.signature,
            "{}",
            vec.name
        );
    }
}

#[test]
fn roots_are_computed_not_trusted() {
    let v = vectors();
    for vec in &v.vectors {
        // Without signingRoot the computed root is still produced...
        let mut body = vec.request.clone();
        body.as_object_mut().unwrap().remove("signingRoot");
        let req: SignRequest = serde_json::from_value(body).unwrap();
        let p = signing::prepare(&req, &hoodi(), &allow_all()).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(p.signing_root)),
            vec.signing_root,
            "{}",
            vec.name
        );

        // ...and a mismatching signingRoot is rejected.
        let mut body = vec.request.clone();
        body["signingRoot"] = serde_json::json!(format!("0x{}", "11".repeat(32)));
        let req: SignRequest = serde_json::from_value(body).unwrap();
        assert!(
            signing::prepare(&req, &hoodi(), &allow_all()).is_err(),
            "{}",
            vec.name
        );
    }
}

#[test]
fn other_network_is_rejected() {
    let v = vectors();
    let req: SignRequest = serde_json::from_value(v.vectors[0].request.clone()).unwrap();
    assert!(signing::prepare(&req, &"mainnet".parse().unwrap(), &allow_all()).is_err());
}

#[test]
fn charon_keystores_decrypt() {
    let v = vectors();
    let keys = keystore::load_dir(&dir().join("keystores")).unwrap();
    assert_eq!(keys.len(), 1, "both keystores hold the same key");
    let pk = keys.keys().next().unwrap();
    assert_eq!(format!("0x{}", hex::encode(pk)), v.public_key);
}

fn app(data: &std::path::Path, policy: Policy) -> axum::Router {
    let net = hoodi();
    let state = AppState {
        keys: keystore::load_dir(&dir().join("keystores")).unwrap(),
        db: SlashingDb::open(&data.join("slashing"), net.genesis_validators_root).unwrap(),
        network: net,
        policy,
        tls_cert: None,
        platform: sev_signer::platform::Platform::Tee,
    };
    router(Arc::new(state))
}

async fn post(
    app: &axum::Router,
    pubkey: &str,
    body: &serde_json::Value,
    json: bool,
) -> (StatusCode, String) {
    let mut req = Request::post(format!("/api/v1/eth2/sign/{pubkey}"))
        .header("content-type", "application/json");
    if json {
        req = req.header("accept", "application/json");
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn http_api() {
    let v = vectors();
    let get = |name: &str| v.vectors.iter().find(|x| x.name == name).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let app = app(
        tmp.path(),
        Policy {
            allow_voluntary_exits: true,
            allow_deposits: false,
        },
    );
    let pk = &v.public_key;

    // publicKeys
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/eth2/publicKeys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Vec<String>>(&body).unwrap(),
        vec![pk.clone()]
    );

    // Plain-text and JSON responses.
    let att = get("attestation");
    let (s, b) = post(&app, pk, &att.request, false).await;
    assert_eq!((s, b.as_str()), (StatusCode::OK, att.signature.as_str()));
    let (s, b) = post(&app, pk, &att.request, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&b).unwrap()["signature"],
        att.signature
    );

    // Older attestation after a newer one is refused by slashing protection.
    let (s, _) = post(&app, pk, &get("attestation_previous_fork").request, false).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);

    // Block: first sign ok, conflicting block at the same slot refused.
    let block = get("block_v2_fulu");
    assert_eq!(
        post(&app, pk, &block.request, false).await.0,
        StatusCode::OK
    );
    let mut conflicting = block.request.clone();
    conflicting["beacon_block"]["block_header"]["state_root"] =
        serde_json::json!(format!("0x{}", "ee".repeat(32)));
    conflicting.as_object_mut().unwrap().remove("signingRoot");
    assert_eq!(
        post(&app, pk, &conflicting, false).await.0,
        StatusCode::PRECONDITION_FAILED
    );

    // Policy, unknown key, malformed input.
    assert_eq!(
        post(&app, pk, &get("deposit").request, false).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(&app, pk, &get("voluntary_exit").request, false)
            .await
            .0,
        StatusCode::OK
    );
    let other = format!("0x{}", "aa".repeat(48));
    assert_eq!(
        post(&app, &other, &att.request, false).await.0,
        StatusCode::NOT_FOUND
    );
    let mut bad = att.request.clone();
    bad["type"] = serde_json::json!("BLOCK");
    assert_eq!(post(&app, pk, &bad, false).await.0, StatusCode::BAD_REQUEST);

    // Slashing protection survives a restart.
    drop(app);
    let app = self::app(tmp.path(), allow_all());
    assert_eq!(
        post(&app, pk, &conflicting, false).await.0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        post(&app, pk, &block.request, false).await.0,
        StatusCode::OK,
        "identical re-sign"
    );
}
