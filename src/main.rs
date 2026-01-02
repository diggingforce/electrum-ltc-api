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
use bitcoin::PrivateKey;
use bitcoin::hashes::{Hash, ripemd160, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use config::Config as ConfigBuilder;
use hex;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::json;
use tokio::process::Command;
use tokio::time::sleep;
use tower_http::trace::TraceLayer;

const API_KEY_ENV: &str = "API_KEY";
const DEFAULT_CONFIG_PATH: &str = "config.toml";

#[derive(Debug, Clone, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Deserialize)]
struct PathsConfig {
    cert: String,
    key: String,
    wallet_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ElectrumConfig {
    command: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AppConfig {
    server: ServerConfig,
    paths: PathsConfig,
    electrum: ElectrumConfig,
}

fn home_dir() -> PathBuf {
    dirs::home_dir().expect("Failed to get home directory")
}

fn load_config() -> AppConfig {
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
    
    let settings = ConfigBuilder::builder()
        .add_source(config::File::with_name(&config_path).required(false))
        .set_default("server.host", "0.0.0.0").unwrap()
        .set_default("server.port", 8080).unwrap()
        .set_default("paths.cert", "certs/cert.crt").unwrap()
        .set_default("paths.key", "certs/cert.key").unwrap()
        .set_default("electrum.command", "electrum-ltc").unwrap()
        .build()
        .expect("Failed to load configuration");
    
    settings.try_deserialize().expect("Failed to parse configuration")
}

fn default_wallets_path() -> PathBuf {
    home_dir().join(".electrum-ltc").join("wallets")
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

#[derive(Clone)]
struct AppState {
    api_key: String,
    config: AppConfig,
}

impl AppState {
    fn wallets_path(&self) -> PathBuf {
        if let Some(ref custom_path) = self.config.paths.wallet_dir {
            PathBuf::from(custom_path)
        } else {
            default_wallets_path()
        }
    }
    
    fn get_wallet_path(&self, name: &str) -> PathBuf {
        self.wallets_path().join(name)
    }
}

async fn require_api_key(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    for (k, v) in headers.iter() {
        println!("Header: {}: {:?}", k, v);
    }
    let user_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if user_key.trim() != state.api_key.trim() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Invalid API key" })),
        ));
    }
    Ok(())
}

async fn run_command(electrum_cmd: &str, command: &str, wallet_path: Option<&Path>) -> std::io::Result<String> {
    let mut args = command
        .split_whitespace()
        .map(String::from)
        .collect::<Vec<_>>();
    if let Some(wallet_path) = wallet_path {
        args.push("-w".into());
        args.push(wallet_path.display().to_string());
    }
    let output = Command::new(electrum_cmd).args(args).output().await?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

#[debug_handler]
async fn create_wallet(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(State(state.clone()), headers).await {
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

    let priv_key = PrivateKey::new(secret_key, bitcoin::Network::Bitcoin);
    let pubkey = priv_key.public_key(&secp);

    let pubkey_bytes = pubkey.to_bytes();
    let sha = sha256::Hash::hash(&pubkey_bytes);
    let hash160 = ripemd160::Hash::hash(sha.as_ref());

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

    let wallet_path = state.get_wallet_path(&name);
    let wallet_dir = wallet_path.parent().expect("invalid wallet path");
    if !wallet_dir.exists() {
        if let Err(e) = fs::create_dir_all(wallet_dir) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Create wallet dir failed: {}", e) })),
            );
        }
    }

    if let Err(e) = run_command(&state.config.electrum.command, &format!("restore {}", wif), Some(&wallet_path)).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Restore failed: {} {}", e, wif) })),
        );
    }
    if let Err(e) = run_command(&state.config.electrum.command, "load_wallet", Some(&wallet_path)).await {
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
    if let Err(e) = require_api_key(state.clone(), headers).await {
        return e;
    }
    let wallet_path = state.get_wallet_path(&name);
    match run_command(&state.config.electrum.command, "getbalance", Some(&wallet_path)).await {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(val) => (StatusCode::OK, Json(val)),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Invalid balance response"})),
            ),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to get balance", "details": e.to_string() })),
        ),
    }
}

#[debug_handler]
async fn get_address(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(state.clone(), headers).await {
        return e;
    }
    let wallet_path = state.get_wallet_path(&name);
    match run_command(&state.config.electrum.command, "getunusedaddress", Some(&wallet_path)).await {
        Ok(address) => (StatusCode::OK, Json(json!({ "address": address }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

#[debug_handler]
async fn get_transactions(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(e) = require_api_key(state.clone(), headers).await {
        return e;
    }
    let wallet_path = state.get_wallet_path(&name);
    match run_command(&state.config.electrum.command, "onchain_history", Some(&wallet_path)).await {
        Ok(output) => match serde_json::from_str::<serde_json::Value>(&output) {
            Ok(data) => {
                let txs = data["transactions"]
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
                    Json(json!({ "success": true, "transactions": txs })),
                )
            }
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "error": "Invalid tx response" })),
            ),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "success": false, "error": e.to_string() })),
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
    if let Err(e) = require_api_key(state.clone(), headers).await {
        return e;
    }

    let SendRequest { to, amount } = body;

    if to.is_empty() || amount.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing \"to\" or \"amount\"" })),
        );
    }

    let wallet_path = state.get_wallet_path(&name);

    let amount_f: f64 = match amount.parse() {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid amount" })),
            );
        }
    };

    let input_count = (amount_f / 0.05).ceil() as usize;
    let output_count = 2;
    let fee_rate_per_kb = 10000f64;
    let tx_size = 10.0 + (input_count as f64 * 148.0) + (output_count as f64 * 34.0);
    let fee = (tx_size * fee_rate_per_kb) / 1000.0 / 1e8;
    let adjusted_amount = amount_f - fee;

    if adjusted_amount <= 0.0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Amount too small to cover estimated fee ({fee:.8} LTC)")
            })),
        );
    }

    let payto_cmd = format!(
        "payto -f {fee} {to} {adjusted_amount:.8}",
        fee = fee,
        to = to,
        adjusted_amount = adjusted_amount
    );

    let raw_tx = match run_command(&state.config.electrum.command, &payto_cmd, Some(&wallet_path)).await {
        Ok(val) => val.trim().to_string(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("payto error: {}", e) })),
            );
        }
    };

    let sign_cmd = format!("signtransaction {}", raw_tx);
    let signed_tx = match run_command(&state.config.electrum.command, &sign_cmd, Some(&wallet_path)).await {
        Ok(val) => val.trim().to_string(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("signtransaction error: {}", e) })),
            );
        }
    };

    let broadcast_cmd = format!("broadcast {}", signed_tx);
    let txid = match run_command(&state.config.electrum.command, &broadcast_cmd, None).await {
        Ok(val) => val.trim().to_string(),
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
    if let Err(e) = require_api_key(state.clone(), headers).await {
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
    let wallet_path = state.get_wallet_path(&name);

    let _ = run_command(&state.config.electrum.command, "close_wallet", Some(&wallet_path)).await;

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
    if let Err(e) = require_api_key(state.clone(), headers).await {
        return e;
    }
    let RestoreWalletRequest { name, wif } = body;
    if name.is_empty() || wif.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing or invalid name/wif" })),
        );
    }
    let wallet_path = state.get_wallet_path(&name);

    let secret_key = match bitcoin::PrivateKey::from_wif(&wif) {
        Ok(priv_key) => priv_key.inner,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Invalid WIF: {}", e) })),
            );
        }
    };
    let secret_key_hex = hex::encode(secret_key.as_ref());

    if let Err(e) = run_command(&state.config.electrum.command, &format!("restore {}", secret_key_hex), Some(&wallet_path)).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Restore failed: {}", e) })),
        );
    }
    if let Err(e) = run_command(&state.config.electrum.command, "load_wallet", Some(&wallet_path)).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
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
    if let Err(e) = require_api_key(state.clone(), headers).await {
        return e;
    }
    let mut status = vec![];

    match run_command(&state.config.electrum.command, "stop", None).await {
        Ok(_) => status.push("Daemon stopped successfully".to_owned()),
        Err(e) => status.push(format!("Daemon stop attempt: {}", e)),
    }
    match run_command(&state.config.electrum.command, "daemon -d", None).await {
        Ok(_) => status.push("Daemon started successfully".to_owned()),
        Err(e) => {
            status.push(format!("Daemon start failed: {}", e));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "error": e.to_string(),
                    "status": "Reload failed",
                    "details": status
                })),
            );
        }
    }

    status.push("Waiting for daemon initialization...".to_owned());
    sleep(Duration::from_secs(2)).await;
    status.push("Daemon initialization complete".to_owned());

    status.push("Loading wallets...".to_owned());
    let mut load_promises = vec![];

    if let Ok(wallets) = fs::read_dir(state.wallets_path()) {
        for w in wallets.flatten() {
            let wallet = w.path();
            let wallet_name = wallet
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let wallet_path = wallet.clone();
            let electrum_cmd = state.config.electrum.command.clone();
            let stat = async move {
                match run_command(&electrum_cmd, "load_wallet", Some(&wallet_path)).await {
                    Ok(_) => {
                        format!("Wallet {} loaded successfully", wallet_name)
                    }
                    Err(e) => {
                        format!("Wallet {} load failed: {}", wallet_name, e)
                    }
                }
            };
            load_promises.push(stat);
        }
    }
    let results = futures::future::join_all(load_promises).await;
    status.extend(results);

    status.push("All wallet operations completed".to_owned());
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
    
    let app_config = load_config();
    let api_key = env::var(API_KEY_ENV).unwrap_or_default().trim().to_string();
    let state = Arc::new(AppState { 
        api_key,
        config: app_config.clone(),
    });

    let path = env::var_os("PATH").unwrap_or_default();
    let local_bin = home_dir().join(".local/bin");
    let mut paths = env::split_paths(&path).collect::<Vec<_>>();
    if !paths.contains(&local_bin) {
        paths.push(local_bin);
        unsafe {
            env::set_var("PATH", env::join_paths(paths).unwrap());
        }
    }

    let rustls_config = RustlsConfig::from_pem_file(&app_config.paths.cert, &app_config.paths.key)
        .await
        .expect("Failed to load TLS certificates");

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

    let addr = format!("{}:{}", app_config.server.host, app_config.server.port)
        .parse()
        .expect("Invalid server address");
    
    println!("[] Litecoin API Loaded on https://{}:{}", app_config.server.host, app_config.server.port);
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
