use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use axum_macros::debug_handler;
use axum_server::tls_rustls::RustlsConfig;
use base58::ToBase58;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bitcoin::PrivateKey;
use bitcoin::hashes::{Hash, ripemd160, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use config::Config as ConfigBuilder;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::json;
use tokio::net::UnixStream;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;

const API_KEY_ENV: &str = "API_KEY";

#[derive(Debug, Clone, Deserialize, Default)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PathsConfig {
    cert: String,
    key: String,
    wallet_dir: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct ElectrumConfig {
    data_dir: String,
    rpc_socket: String,
    rpc_user: String,
    rpc_password: String,
}

#[derive(Debug, Clone, Default)]
struct AppConfig {
    server: ServerConfig,
    paths: PathsConfig,
    electrum: ElectrumConfig,
}

#[derive(Clone)]
struct AppState {
    api_key: String,
    rpc_socket: PathBuf,
    rpc_auth: String,
    wallet_dir: PathBuf,
}

impl AppState {
    fn wallet_path(&self, name: &str) -> PathBuf {
        self.wallet_dir.join(name)
    }
}

fn home_dir() -> PathBuf {
    dirs::home_dir().expect("Failed to resolve home directory")
}

fn env_value(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.is_empty())
}

fn load_config() -> AppConfig {
    let config_path = env_value("CONFIG_PATH").unwrap_or_else(|| "config.toml".into());
    let settings = ConfigBuilder::builder()
        .add_source(config::File::with_name(&config_path).required(false))
        .set_default("server.host", "0.0.0.0")
        .unwrap()
        .set_default("server.port", 8080)
        .unwrap()
        .set_default("paths.cert", "certs/cert.crt")
        .unwrap()
        .set_default("paths.key", "certs/cert.key")
        .unwrap()
        .set_default("paths.wallet_dir", "")
        .unwrap()
        .set_default("electrum.data_dir", "")
        .unwrap()
        .set_default("electrum.rpc_socket", "")
        .unwrap()
        .set_default("electrum.rpc_user", "")
        .unwrap()
        .set_default("electrum.rpc_password", "")
        .unwrap()
        .build()
        .expect("Failed to load configuration");

    AppConfig {
        server: ServerConfig {
            host: settings
                .get_string("server.host")
                .unwrap_or_else(|_| "0.0.0.0".into()),
            port: settings.get_int("server.port").unwrap_or(8080) as u16,
        },
        paths: PathsConfig {
            cert: settings.get_string("paths.cert").unwrap_or_default(),
            key: settings.get_string("paths.key").unwrap_or_default(),
            wallet_dir: settings
                .get_string("paths.wallet_dir")
                .ok()
                .filter(|v| !v.is_empty()),
        },
        electrum: ElectrumConfig {
            data_dir: settings.get_string("electrum.data_dir").unwrap_or_default(),
            rpc_socket: settings
                .get_string("electrum.rpc_socket")
                .unwrap_or_default(),
            rpc_user: settings.get_string("electrum.rpc_user").unwrap_or_default(),
            rpc_password: settings
                .get_string("electrum.rpc_password")
                .unwrap_or_default(),
        },
    }
}

fn electrum_data_dir(config: &ElectrumConfig) -> PathBuf {
    env_value("ELECTRUM_DATA")
        .or_else(|| take_nonempty(&config.data_dir))
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".electrum-ltc"))
}

fn rpc_socket_path(config: &ElectrumConfig) -> PathBuf {
    env_value("ELECTRUM_RPC_SOCKET")
        .or_else(|| take_nonempty(&config.rpc_socket))
        .map(PathBuf::from)
        .unwrap_or_else(|| electrum_data_dir(config).join("daemon_rpc_socket"))
}

fn rpc_basic_auth(config: &ElectrumConfig) -> String {
    let config_json = fs::read_to_string(electrum_data_dir(config).join("config"))
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .unwrap_or_default();

    let stored_user = config_json
        .get("rpcuser")
        .and_then(|user| user.as_str())
        .unwrap_or("user")
        .to_string();
    let stored_password = config_json
        .get("rpcpassword")
        .and_then(|password| password.as_str())
        .map(str::to_string)
        .unwrap_or_default();

    let user = env_value("ELECTRUM_RPC_USER")
        .or_else(|| take_nonempty(&config.rpc_user))
        .unwrap_or(stored_user);
    let password = env_value("ELECTRUM_RPC_PASSWORD")
        .or_else(|| take_nonempty(&config.rpc_password))
        .unwrap_or(stored_password);

    BASE64.encode(format!("{user}:{password}"))
}

fn wallets_path(config: &PathsConfig) -> PathBuf {
    env_value("WALLET_DIR")
        .or_else(|| config.wallet_dir.clone())
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".electrum-ltc").join("wallets"))
}

fn take_nonempty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

async fn rpc(
    state: &AppState,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let payload =
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let stream = UnixStream::connect(&state.rpc_socket).await.map_err(|e| {
        format!(
            "cannot reach electrum daemon at {}: {}",
            state.rpc_socket.display(),
            e
        )
    })?;
    let (mut sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("electrum rpc handshake failed: {}", e))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri("http://localhost/")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("authorization", format!("Basic {}", state.rpc_auth))
        .body(Full::new(Bytes::from(payload)))
        .map_err(|e| e.to_string())?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| e.to_string())?;
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid response from electrum daemon: {}", e))?;

    if let Some(error) = value.get("error").and_then(|error| error.get("message")) {
        return Err(error.as_str().unwrap_or("unknown daemon error").to_string());
    }
    Ok(value
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    amount: String,
}

#[derive(Deserialize)]
struct RestoreWalletRequest {
    name: String,
    wif: String,
}

async fn require_api_key(
    state: &AppState,
    headers: axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let user_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if user_key != state.api_key.trim() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Invalid API key" })),
        ));
    }
    Ok(())
}

#[debug_handler]
async fn create_wallet(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid wallet name provided" })),
        );
    }

    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let mut data = [0u8; 32];
    rng.fill_bytes(&mut data);

    let secret_key = SecretKey::from_slice(&data).unwrap();
    let public_key = PrivateKey::new(secret_key, bitcoin::Network::Bitcoin).public_key(&secp);

    let pubkey_bytes = public_key.to_bytes();
    let hash160 = ripemd160::Hash::hash(sha256::Hash::hash(&pubkey_bytes).as_ref());

    let mut address_bytes = Vec::with_capacity(25);
    address_bytes.push(0x30);
    address_bytes.extend_from_slice(hash160.as_ref());
    let checksum = sha256::Hash::hash(sha256::Hash::hash(&address_bytes).as_ref());
    address_bytes.extend(&checksum[..4]);
    let address = address_bytes.to_base58();

    let mut wif_bytes = Vec::new();
    wif_bytes.push(0xB0);
    wif_bytes.extend(&data);
    wif_bytes.push(0x01);
    let wif_checksum = sha256::Hash::hash(sha256::Hash::hash(&wif_bytes).as_ref());
    wif_bytes.extend(&wif_checksum[..4]);
    let wif = wif_bytes.to_base58();

    let wallet_path = state.wallet_path(&name);
    let wallet_dir = wallet_path.parent().expect("invalid wallet path");
    if let Err(e) = fs::create_dir_all(wallet_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Create wallet dir failed: {}", e) })),
        );
    }

    if let Err(e) = rpc(
        &state,
        "restore",
        json!({"text": wif, "wallet_path": wallet_path}),
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Restore failed: {} {}", e, wif) })),
        );
    }
    if let Err(e) = rpc(&state, "load_wallet", json!({"wallet_path": wallet_path})).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Load failed: {}", e) })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "wallet": name,
            "address": address,
            "wif": wif
        })),
    )
}

#[debug_handler]
async fn get_balance(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }
    let wallet_path = state.wallet_path(&name);
    match rpc(&state, "getbalance", json!({"wallet": wallet_path})).await {
        Ok(balance) => (StatusCode::OK, Json(balance)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to get balance", "details": e })),
        ),
    }
}

#[debug_handler]
async fn get_address(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }
    let wallet_path = state.wallet_path(&name);
    match rpc(&state, "getunusedaddress", json!({"wallet": wallet_path})).await {
        Ok(address) => (
            StatusCode::OK,
            Json(json!({ "address": address.as_str().unwrap_or_default() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        ),
    }
}

#[debug_handler]
async fn get_transactions(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }
    let wallet_path = state.wallet_path(&name);
    match rpc(&state, "onchain_history", json!({"wallet": wallet_path})).await {
        Ok(result) => {
            let transactions = result["transactions"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter(|tx| tx["incoming"].as_bool() == Some(true))
                .map(|tx| json!({
                    "txid": tx["txid"],
                    "amount": tx["bc_value"].as_str().and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0),
                    "confirmations": tx["confirmations"],
                    "timestamp": tx["timestamp"]
                }))
                .collect::<Vec<_>>();
            (
                StatusCode::OK,
                Json(json!({ "success": true, "transactions": transactions })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e })),
        ),
    }
}

#[debug_handler]
async fn send(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
    Json(body): Json<SendRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }

    let SendRequest { to, amount } = body;

    if to.is_empty() || amount.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing \"to\" or \"amount\"" })),
        );
    }

    let amount_f: f64 = match amount.parse() {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid amount" })),
            );
        }
    };

    let wallet_path = state.wallet_path(&name);

    let input_count = (amount_f / 0.05).ceil() as usize;
    let tx_size = 10.0 + (input_count as f64 * 148.0) + (2.0 * 34.0);
    let fee = (tx_size * 10000.0) / 1000.0 / 1e8;
    let adjusted_amount = amount_f - fee;

    if adjusted_amount <= 0.0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Amount too small to cover estimated fee ({fee:.8} LTC)")
            })),
        );
    }

    let raw_tx = match rpc(
        &state,
        "payto",
        json!({
            "destination": to,
            "amount": format!("{adjusted_amount:.8}"),
            "fee": format!("{fee:.8}"),
            "wallet": wallet_path
        }),
    )
    .await
    {
        Ok(transaction) => transaction
            .as_str()
            .map(|tx| tx.trim().to_string())
            .unwrap_or_default(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("payto error: {}", e) })),
            );
        }
    };

    let signed_tx = match rpc(
        &state,
        "signtransaction",
        json!({"tx": raw_tx, "wallet": wallet_path}),
    )
    .await
    {
        Ok(transaction) => transaction
            .as_str()
            .map(|tx| tx.trim().to_string())
            .unwrap_or_default(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("signtransaction error: {}", e) })),
            );
        }
    };

    let txid = match rpc(&state, "broadcast", json!({"tx": signed_tx})).await {
        Ok(id) => id
            .as_str()
            .map(|id| id.trim().to_string())
            .unwrap_or_default(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("broadcast error: {}", e) })),
            );
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "txid": txid,
            "feeLTC": format!("{fee:.8}"),
            "adjustedAmount": format!("{adjusted_amount:.8}"),
        })),
    )
}

#[debug_handler]
async fn delete_wallet(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid wallet name" })),
        );
    }
    let wallet_path = state.wallet_path(&name);

    let _ = rpc(&state, "close_wallet", json!({"wallet_path": wallet_path})).await;

    if wallet_path.exists() {
        match fs::remove_file(&wallet_path) {
            Ok(_) => (
                StatusCode::OK,
                Json(json!({ "success": true, "deleted": name })),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": e.to_string() })),
            ),
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Wallet not found" })),
        )
    }
}

#[debug_handler]
async fn restore_wallet(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(_): AxumPath<String>,
    Json(body): Json<RestoreWalletRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }
    let RestoreWalletRequest { name, wif } = body;
    if name.is_empty() || wif.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing or invalid name/wif" })),
        );
    }
    let wallet_path = state.wallet_path(&name);

    let secret_key = match PrivateKey::from_wif(&wif) {
        Ok(private_key) => private_key.inner,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Invalid WIF: {}", e) })),
            );
        }
    };
    let secret_key_hex = hex::encode(secret_key.as_ref());

    if let Err(e) = rpc(
        &state,
        "restore",
        json!({"text": secret_key_hex, "wallet_path": wallet_path}),
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Restore failed: {}", e) })),
        );
    }
    if let Err(e) = rpc(&state, "load_wallet", json!({"wallet_path": wallet_path})).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({ "success": true, "restored": name })),
    )
}

#[debug_handler]
async fn reload_wallets(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(&state, headers).await {
        return e;
    }

    let mut status = vec!["Waiting for daemon initialization...".to_string()];
    let mut ready = false;
    for _ in 0..60 {
        if rpc(&state, "getinfo", json!({})).await.is_ok() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    status.push(if ready {
        "Daemon is running".to_string()
    } else {
        "Daemon did not become ready in time".to_string()
    });

    status.push("Loading wallets...".to_string());
    let mut load_promises = vec![];

    if let Ok(wallets) = fs::read_dir(&state.wallet_dir) {
        for wallet in wallets.flatten() {
            let wallet_path = wallet.path();
            let wallet_name = wallet_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_string();
            let state = state.clone();
            load_promises.push(async move {
                match rpc(&state, "load_wallet", json!({"wallet_path": wallet_path})).await {
                    Ok(_) => format!("Wallet {} loaded successfully", wallet_name),
                    Err(e) => format!("Wallet {} load failed: {}", wallet_name, e),
                }
            });
        }
    }
    status.extend(futures::future::join_all(load_promises).await);
    status.push("All wallet operations completed".to_string());

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "status": "Daemon and wallets reloaded",
            "details": status
        })),
    )
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let config = load_config();
    let api_key = env_value(API_KEY_ENV)
        .unwrap_or_default()
        .trim()
        .to_string();
    let state = Arc::new(AppState {
        api_key,
        rpc_socket: rpc_socket_path(&config.electrum),
        rpc_auth: rpc_basic_auth(&config.electrum),
        wallet_dir: wallets_path(&config.paths),
    });

    let app = Router::new()
        .route("/wallet/create/:name", post(create_wallet))
        .route("/wallet/balance/:name", get(get_balance))
        .route("/wallet/address/:name", get(get_address))
        .route("/wallet/transactions/:name", get(get_transactions))
        .route("/wallet/send/:name", post(send))
        .route("/wallet/delete/:name", post(delete_wallet))
        .route("/wallet/restore/:any", post(restore_wallet))
        .route("/wallet/reload", post(reload_wallets))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid server address");

    let cert_path = Path::new(&config.paths.cert);
    let key_path = Path::new(&config.paths.key);

    let tls = if cert_path.exists() && key_path.exists() {
        match RustlsConfig::from_pem_file(&config.paths.cert, &config.paths.key).await {
            Ok(tls) => Some(tls),
            Err(e) => {
                eprintln!(
                    "warning: failed to load TLS certificates, falling back to plain http: {e}"
                );
                None
            }
        }
    } else {
        None
    };

    if let Some(tls) = tls {
        println!(
            "Litecoin API listening on https://{}:{}",
            config.server.host, config.server.port
        );
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        println!(
            "Litecoin API listening on http://{}:{}",
            config.server.host, config.server.port
        );
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }
}
