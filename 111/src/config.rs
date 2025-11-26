use anyhow::{Context, Result, bail};
use config::Config as ConfigCrate;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use clap::{Parser, ArgAction};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use once_cell::sync::Lazy;
use secrecy::Secret;
use deadpool_rocksdb;
use hex;
use ring::rand::{SecureRandom, SystemRandom};
use tracing::{info, warn};
use crate::utils::secure_load_file;
#[derive(Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub struct AppConfig {
    pub mainnet: bool,
    pub coinbase_sk: Zeroizing<String>,
    pub db_path: String,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub max_peers: usize,
    pub max_mempool_size: usize,
    pub seed_nodes: Vec<String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub ca_cert: String,
    pub reorg_max_depth: usize,
    pub backup_signing_key: String,
    pub signing_key_path: String,
    pub tx_expiration_ms: u128,
    pub log_level: String,
    pub max_threads: usize,
    pub num_randomx_threads: usize,
    pub enable_huge_pages: bool,
    pub rpc_jwt_secret: String,
    #[zeroize(skip)]
    pub coinbase_sk_bytes: Box<Zeroizing<[u8; 32]>>,
    #[zeroize(skip)]
    pub checkpoint_hashes: HashMap<usize, [u8;32]>,
    #[serde(default)]
    pub checkpoints: HashMap<usize, String>,
}
impl AppConfig {
    pub fn load() -> Result<Self> {
        let mut config = ConfigCrate::builder()
            .add_source(config::File::with_name("lyrion.toml").required(false))
            .add_source(config::Environment::with_prefix("LYRION"))
            .build()?
            .try_deserialize::<Self>()?;
        // Secure loading of coinbase key
        let decoded = STANDARD.decode(&config.coinbase_sk).context("Invalid base64 coinbase_sk")?;
        if decoded.len() != 32 { bail!("coinbase_sk must be 32 bytes"); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        config.coinbase_sk_bytes = Box::new(Zeroizing::new(arr));
        // Loading dynamic checkpoints
        let mut checkpoint_hashes = HashMap::new();
        for (&height, hex_str) in &config.checkpoints {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(hex_str, &mut bytes).context(format!("Invalid checkpoint hash at height {height}"))?;
            checkpoint_hashes.insert(height, bytes);
        }
        config.checkpoint_hashes = checkpoint_hashes;
        // Automatic generation of JWT secret if absent
        if config.rpc_jwt_secret.is_empty() {
            let rng = SystemRandom::new();
            let mut secret = [0u8; 64];
            rng.fill(&mut secret).expect("RNG failed");
            config.rpc_jwt_secret = STANDARD.encode(secret);
            info!("RPC JWT secret generated automatically"); // ← we no longer display the value
        }
        // Warning if checkpoints enabled on mainnet
        if config.mainnet && !config.checkpoint_hashes.is_empty() {
            warn!("⚠️ SECURITY: Checkpoints are ENABLED on Mainnet. This is acceptable for launch phase but should be removed later.");
        }
        // Validations
        if config.p2p_port == 0 || config.rpc_port == 0 { bail!("Ports must be > 0"); }
        if config.rpc_jwt_secret.is_empty() { bail!("RPC JWT secret required"); }
        if config.num_randomx_threads == 0 {
            config.num_randomx_threads = num_cpus::get_physical().min(64);
        }
        if config.seed_nodes.is_empty() { bail!("At least one seed node required"); }
        if config.enable_huge_pages {
            crate::utils::init_huge_pages().context("Huge pages init failed")?;
        }
        Ok(config)
    }
}
