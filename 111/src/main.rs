use anyhow::{Context, Result};
use clap::{Parser, ArgAction};
use tracing::Level;
use tracing_subscriber::prelude::*;
use lyrion::chain::Chain;
use lyrion::config::AppConfig;
use lyrion::db::create_db_pool;
use lyrion::mempool::Mempool;
use lyrion::miner::miner_task;
use lyrion::net::PeerManager;
use lyrion::tx::{create_genesis_block, Block, BlockHeader, Transaction, TXInput, TXOutput, p2pkh_script, validate_transaction};
use lyrion::utils::{now_ms, pubkey_to_address, SECP, PowEngine, u256_from_hash, secure_load_file, secure_save_secret, pubkey_to_anon_address, address_to_anon_pubkey, create_coinbase};
use secp256k1::{PublicKey, SecretKey};
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, timeout};
use backtrace::Backtrace;
use zeroize::Zeroize;
use zeroize::Zeroizing;
use tracing::{info, warn, error};
use actix_web::{get, web, App, HttpResponse, HttpRequest};
use prometheus::{Encoder, TextEncoder};
use jsonwebtoken::{decode, Validation, DecodingKey, encode, EncodingKey, Header};
use serde_json::json;
use tokio_rustls::TlsAcceptor as ActixTlsAcceptor;
use rustls::{ServerConfig, Certificate, PrivateKey};
use governor::{RateLimiter, Jitter, clock::ReasonablyAccurate, state::keyed::DefaultKeyedStateStore, middleware::NoOpMiddleware};
use mimalloc::MiMalloc;
use bip39::{Mnemonic, Language, Seed};
use bitcoin::bip32::{ExtendedPrivKey, DerivationPath};
use bitcoin::Network;
use bitcoin::bip32::ChildNumber;
use bitcoin::bip32::ExtendedPrivKey;
use std::str::FromStr;
use std::path::PathBuf;
use dirs;
use rocksdb::{IteratorMode, Direction};
use hex;
use reqwest;
use rand::{rngs::OsRng};
use rand::seq::SliceRandom;
use rand::RngCore;
use monero_serai::keys::{PrivateKey as AnonPrivateKey, PublicKey as AnonPublicKey};
use monero_serai::ringct::Clsag;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{PedersenGens, BulletproofGens, RangeProof};
use bincode::serialize;
use bincode::deserialize;
use crate::wallet::Wallet;
#[cfg(feature = "gui")]
use lyrion::gui::run_gui;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
#[derive(Parser)]
struct Cli {
    command: Commands,
    #[arg(long, hide = true)]
    db_encryption_key_b64: Option<String>,
}
#[derive(Subcommand)]
enum Commands {
    InitDb,
    RunNode,
    Status,
    Peers,
    Wallet(WalletSubcommand),
    Explorer(ExplorerSubcommand),
    Admin(AdminSubcommand),
    #[cfg(feature = "gui")]
    Gui,
}
#[derive(Subcommand)]
enum WalletSubcommand {
    New { #[arg(short, long)] show_mnemonic: bool },
    Restore { mnemonic: String, #[arg(short, long)] passphrase: Option<String> },
    Balance { #[arg(short, long)] address: Option<String> },
    Utxos { #[arg(short, long)] address: Option<String>, #[arg(long)] spendable_only: bool },
    History { #[arg(short, long)] address: Option<String>, #[arg(long, default_value = "50")] limit: u32 },
    DumpPrivkey { address: String, #[arg(long)] confirm_danger: bool },
    AnonNew,
    GetAnonAddress,
    GetAnonBalance,
    Send {
        to: String,
        amount: u64,
        #[arg(short, long)] fee_rate: Option<u64>,
        #[arg(short, long)] change_address: Option<String>,
        #[arg(long)] anonymous: bool,
        #[arg(long, default_value = "20")] ring_size: usize,
    },
    CreateMultisig {
        #[arg(num_args = 2..)] pubkeys: Vec<String>,
        required: usize,
    },
}
#[derive(Subcommand)]
enum ExplorerSubcommand {
    Block { height_or_hash: String },
    Tx { hash: String },
    Address { address: String, #[arg(default_value = "1")] page: usize, #[arg(default_value = "25")] page_size: usize },
    RichList { #[arg(default_value = "1")] page: usize, [arg(default_value = "100")] page_size: usize },
}
#[derive(Subcommand)]
enum AdminSubcommand {
    BackupNow,
}
fn wallet_path() -> PathBuf {
    dirs::home_dir().unwrap().join(".lyrion/wallet.dat")
}
async fn load_chain_readonly() -> Result<(Arc<tokio::sync::RwLock<Chain>>, Pool, Arc<PowEngine>, Arc<AppConfig>)> {
    let config = Arc::new(AppConfig::load().context("Unable to load lyrion.toml. Check if the file exists in the current directory.")?);
    let db_pool = create_db_pool(&config.db_path).context("Unable to open the database. Has the node been initialized with 'lyrion InitDb'?") ? ;
    let pow_engine = Arc::new(PowEngine::new(&config).context("Unable to initialize the PoW engine (RandomX)")?);
    let dummy_mempool = Arc::new(tokio::sync::RwLock::new(Mempool::new(1)));
    let chain = Chain::load_from_db(db_pool.clone(), pow_engine.clone(), config.clone(), dummy_mempool).await
        .context("Unable to load the blockchain. First run 'lyrion InitDb' or check if the node is synchronized.")?;
    Ok((Arc::new(tokio::sync::RwLock::new(chain)), db_pool, pow_engine, config))
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    std::panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::new();
        error!("CRITICAL PANIC : {:?}\nBacktrace: {:?}", panic_info, backtrace);
    }));
    match cli.command {
        Commands::InitDb => {
            let config = AppConfig::load().context("Unable to load lyrion.toml")?;
            init_logger(&config.log_level);
            info!("Initializing Lyrion database...");
            let pool = create_db_pool(&config.db_path)?;
            let conn = pool.get().context("Unable to access the database")?;
            let pow_engine = PowEngine::new(&config)?;
            let sk = SecretKey::new(&mut rand::thread_rng());
            let pk = PublicKey::from_secret_key(&SECP, &sk);
            let genesis = create_genesis_block(&pk, &Arc::new(pow_engine)).expect("Genesis failed");
            conn.put("genesis_hash", genesis.header_hash(&Arc::new(pow_engine))?)?;
            info!("Database initialized successfully – genesis hash : {}", hex::encode(genesis.header_hash(&Arc::new(pow_engine))?));
            println!("Generated coinbase key (to add in lyrion.toml) :\ncoinbase_sk = \"{}\"", base64::engine::general_purpose::STANDARD.encode(sk.secret_bytes()));
        }
        Commands::RunNode => {
            info!("Preventive initialization of RandomX (Allocation ~2.5 GB)...");
            if let Err(e) = lyrion::utils::RANDOMX_DATASET.as_ref() {
                error!("Critical RandomX allocation failure: {}. Check if you have 4GB+ of RAM.", e);
                return Ok(());
            }
            std::env::set_var("LYRION_DB_ENCRYPTION_KEY_B64", cli.db_encryption_key_b64.unwrap_or_default());
            let config = Arc::new(AppConfig::load()?);
            init_logger(&config.log_level);
            let mut sk = Zeroizing::new(SecretKey::from_slice(&**config.coinbase_sk_bytes).context("Invalid secret key")?);
            let pk = PublicKey::from_secret_key(&SECP, &sk);
            info!("Coinbase address: {}", pubkey_to_address(&pk));
            let db_pool = create_db_pool(&config.db_path)?;
            let pow_engine = Arc::new(PowEngine::new(&config)?);
            let genesis = create_genesis_block(&pubkey, &pow_engine)?;
            let mempool = Arc::new(tokio::sync::RwLock::new(Mempool::new(config.max_mempool_size)));
            let chain = Arc::new(tokio::sync::RwLock::new(
                Chain::load_from_db(db_pool.clone(), pow_engine, config.clone(), mempool.clone()).await.unwrap_or_else(|_| Chain::new(db_pool.clone(), genesis, pow_engine, config.clone(), mempool.clone()).await.unwrap()),
            ));
            let node_keypair = load_keypair(&config.signing_key_path)?;
            let (inv_tx, mut inv_rx) = mpsc::channel(1000);
            let (block_tx, _) = broadcast::channel(100);
            let (tip_change_tx, tip_change_rx) = broadcast::channel(100);
            let (shutdown_tx, _) = broadcast::channel(1);
            let peer_manager = Arc::new(PeerManager::new(node_keypair, inv_tx.clone(), block_tx.clone(), tip_change_tx.clone(), config.clone(), db_pool.clone(), chain.clone(), mempool.clone()).await?);
            peer_manager.connect_to_seeds(&config.seed_nodes).await;
            let listener = TcpListener::bind(format!("[::]:{}", config.p2p_port)).await.context("Failed to bind to P2P port")?;
            let manager_clone = peer_manager.clone();
            let shutdown_rx_listener = shutdown_tx.subscribe();
            let listener_handle = tokio::spawn(async move {
                tokio::select! {
                    _ = async {
                        while let Ok((tcp, addr)) = listener.accept().await {
                            if let Ok(stream) = manager_clone.acceptor.accept(tcp).await {
                                manager_clone.add_peer(stream, addr.ip()).await;
                            }
                        }
                    } => {}
                    _ = shutdown_rx_listener.recv() => {}
                }
            });
            let chain_clone = chain.clone();
            let mempool_clone = mempool.clone();
            let inv_tx_clone = inv_tx.clone();
            let inv_handle = tokio::spawn(async move {
                while let Some((typ, hash)) = inv_rx.recv().await {
                    trace!("Received inventory: type={}, hash={:x?}", typ, hash);
                    let mut c = chain_clone.write().await;
                    let mut m = mempool_clone.write().await;
                    if typ == 1 {
                        if !m.txs.contains_key(&hash) && !c.state.read().await.hash_to_height.contains_key(&hash) {
                            let mut msg = MSG_GETDATA.to_le_bytes().to_vec();
                            msg.extend_from_slice(&1u32.to_le_bytes());
                            msg.extend_from_slice(&hash);
                        }
                    } else if typ == 2 {
                        if !c.state.read().await.hash_to_height.contains_key(&hash) {
                            let mut msg = MSG_GETDATA.to_le_bytes().to_vec();
                            msg.extend_from_slice(&2u32.to_le_bytes());
                            msg.extend_from_slice(&hash);
                        }
                    }
                }
            });
            let tip_change_tx_clone = tip_change_tx.clone();
            let miner_handle = tokio::spawn(miner_task(chain.clone(), mempool.clone(), block_tx, tip_change_rx, tip_change_tx_clone, pubkey, config.max_threads, &config, &pow_engine));
            let metrics_handle = tokio::spawn(start_metrics_server());
            let health_handle = tokio::spawn(start_health_server(chain.clone(), mempool.clone(), peer_manager.clone()));
            let db_pool_clone = db_pool.clone();
            let config_clone_backup = config.clone();
            let shutdown_rx_backup = shutdown_tx.subscribe();
            let maintenance_lock = Arc::new(tokio::sync::Mutex::new(()));
            let backup_handle = tokio::spawn(async move {
                loop {
                    let _guard = maintenance_lock.clone().lock().await;
                    if let Err(e) = secure_backup_db(&db_pool_clone, &config_clone_backup, maintenance_lock.clone()).await {
                        error!("Backup error: {}", e);
                    }
                    sleep(Duration::from_hours(1)).await;
                }
            });
            let mempool_clone_clean = mempool.clone();
            let config_clone = config.clone();
            let shutdown_rx_clean = shutdown_tx.subscribe();
            let clean_handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = async {
                            let mut m = mempool_clone_clean.write().await;
                            if let Err(e) = m.clean_expired(config_clone.tx_expiration_ms).await {
                                error!("Mempool clean error: {}", e);
                            }
                        } => {}
                        _ = shutdown_rx_clean.recv() => break,
                    }
                    sleep(Duration::from_secs(300)).await;
                }
            });
            let rpc_handle = tokio::spawn(start_rpc_server(chain.clone(), config.rpc_port, config.rpc_jwt_secret.clone(), config.clone()));
            signal::ctrl_c().await.context("Failed to capture signal")?;
            info!("Shutting down node...");
            let _ = shutdown_tx.send(());
            for handle in vec![listener_handle, inv_handle, miner_handle, metrics_handle, backup_handle, clean_handle, rpc_handle] {
                if let Err(e) = timeout(Duration::from_secs(30), handle).await {
                    error!("Task did not shutdown in time: {}", e);
                    handle.abort();
                }
            }
            let chain_guard = chain.read().await;
            if let Some(best_block) = chain_guard.state.read().await.blocks.get(&chain_guard.best_height) {
                chain_guard.save_block(chain_guard.best_height, best_block).await?;
            }
            let conn = db_pool.get()?;
            conn.flush_wal(true)?;
            sk.zeroize();
        }
        Commands::Status => {
            let (chain_arc, _, _, _) = load_chain_readonly().await?;
            let chain = chain_arc.read().await;
            println!("Height: {}", chain.best_height);
            println!("Best block : {}", hex::encode(chain.best_tip));
            println!("Sync: {}", if chain.best_height > 10 { "synchronized" } else { "synchronization in progress" });
            println!("Peers: see http://127.0.0.1:9000/metrics (gauge lyrion_peers_connected)");
        }
        Commands::Peers => {
            println!("List of connected peers available only when the node is running.");
            println!("Use Prometheus on http://127.0.0.1:9000/metrics → lyrion_peers_connected");
            println!("Or use a metrics explorer (Grafana/PromLens/etc).");
        }
        Commands::Wallet(wallet_cmd) => {
            let (chain_arc, db_pool, _, _) = load_chain_readonly().await?;
            let chain = chain_arc.read().await;
            let conn = db_pool.get()?;
            match wallet_cmd {
                WalletSubcommand::New { show_mnemonic } => {
                    let mnemonic = Mnemonic::generate_in(Language::English, 24)?;
                    let wallet = Wallet::from_mnemonic(&mnemonic.to_string(), &config)?;
                    fs::create_dir_all(wallet_path().parent().unwrap())?;
                    fs::write(&wallet_path(), mnemonic.to_string())?;
                    println!("Wallet created successfully.");
                    println!("Coinbase address (first address): {}", wallet.get_receive_address(0)?);
                    if show_mnemonic {
                        println!("\n=== RECOVERY PHRASE (24 words) ===");
                        println!("{}", mnemonic);
                        println!("=== KEEP IT OFFLINE ===");
                    } else {
                        println!("\nUse --show-mnemonic to display the phrase.");
                    }
                }
                WalletSubcommand::Restore { mnemonic, passphrase } => {
                    let mn = Mnemonic::parse_in(Language::English, &mnemonic)?;
                    let wallet = Wallet::from_mnemonic(&mn.to_string(), &config)?;
                    fs::create_dir_all(wallet_path().parent().unwrap())?;
                    fs::write(&wallet_path(), mn.to_string())?;
                    println!("Wallet restored successfully.");
                }
                WalletSubcommand::Balance { address } => {
                    if let Some(addr) = address {
                        let pubkey_hash = address_to_pubkey_hash(&addr)?;
                        let cf = conn.cf_handle("addr_index").context("CF addr_index missing")?;
                        let mut prefix = b"addr:".to_vec();
                        prefix.extend_from_slice(&pubkey_hash);
                        let mut balance = 0u64;
                        let iter = conn.iterator_cf(&cf, rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward));
                        for item in iter {
                            let (key, value) = item?;
                            if !key.starts_with(&prefix) { break; }
                            balance = balance.checked_add(u64::from_be_bytes(value.try_into()?)).unwrap();
                        }
                        println!("Balance {} : {} LYRION", addr, balance as f64 / 1e9);
                    } else {
                        let mnemonic_str = fs::read_to_string(wallet_path())?;
                        let wallet = Wallet::from_mnemonic(&mnemonic_str, &config)?;
                        let (balance, pending) = wallet.get_balance()?;
                        println!("Confirmed balance: {} LYRION", balance as f64 / 1e9);
                        println!("Pending: {} LYRION", pending as f64 / 1e9);
                    }
                }
                WalletSubcommand::Utxos { address, spendable_only } => {
                    let wallet = Wallet::from_mnemonic(&fs::read_to_string(wallet_path())?, &config)?;
                    let utxos = wallet.get_utxos(spendable_only)?;
                    for u in utxos {
                        println!("TXID: {} vout {} : {} LYRION (conf: {})", hex::encode(u.txid), u.vout, u.value as f64 / 1e9, u.confirmations);
                    }
                }
                WalletSubcommand::History { address, limit } => {
                    let wallet = Wallet::from_mnemonic(&fs::read_to_string(wallet_path())?, &config)?;
                    let history = wallet.get_history(limit as usize)?;
                    for entry in history {
                        println!("TXID: {} – {} LYRION ({} conf)", entry.txid, entry.net_amount as f64 / 1e9, entry.confirmations);
                    }
                }
                WalletSubcommand::DumpPrivkey { address, confirm_danger } => {
                    if !confirm_danger {
                        bail!("Option --confirm-danger required to export a private key");
                    }
                    let wallet = Wallet::from_mnemonic(&fs::read_to_string(wallet_path())?, &config)?;
                    let privkey = wallet.get_privkey_for_address(&address)?;
                    println!("Private key (WIF): {}", bitcoin::PrivateKey::new(privkey, if config.mainnet { Network::Bitcoin } else { Network::Testnet }).to_wif());
                }
                WalletSubcommand::AnonNew => {
                    let anon_priv = AnonPrivateKey::new(&mut OsRng);
                    let anon_pub = anon_priv.public_key();
                    secure_save_secret(".lyrion/anon_spend.dat", &anon_priv.to_bytes())?;
                    println!("Anonymous key generated successfully.");
                    println!("Anonymous address: {}", pubkey_to_anon_address(&anon_pub));
                    println!("SAVE THE PRIVATE KEY IMMEDIATELY – IT IS NOT RECOVERABLE BY THE TRANSPARENT MNEMONIC");
                }
                WalletSubcommand::GetAnonAddress => {
                    let bytes = secure_load_file(".lyrion/anon_spend.dat")?.expose_secret().clone();
                    if bytes.len() != 32 { bail!("anon_spend.dat file corrupted"); }
                    let anon_priv = AnonPrivateKey::from_bytes(&bytes)?;
                    let anon_pub = anon_priv.public_key();
                    println!("Anonymous address: {}", pubkey_to_anon_address(&anon_pub));
                }
                WalletSubcommand::GetAnonBalance => {
                    println!("Anonymous balance not supported in CLI v0.2.4. Use the graphical interface with manual scan or wait for v0.3.0 for full support.");
                },
                WalletSubcommand::Send {
                    to,
                    amount,
                    fee_rate,
                    change_address,
                    anonymous,
                    ring_size,
                } => {
                    let mnemonic_str = fs::read_to_string(wallet_path())?;
                    let wallet = Wallet::from_mnemonic(&mnemonic_str, &config)?;
                    if anonymous {
                        bail!("Anonymous transactions are not yet supported in the CLI wallet to avoid any loss of funds. Full support (scanning + signing) planned in v0.3.0. Use raw transactions via RPC for advanced users.");
                    }
                    let (tx, txid) = wallet.create_tx(&to, amount, fee_rate.unwrap_or(MIN_FEE_PER_BYTE), change_address.as_deref())?;
                    let raw_hex = hex::encode(bincode::serialize(&tx)?);
                    println!("Transaction created (txid = {})", hex::encode(txid));
                    // Broadcast
                    let client = reqwest::Client::new();
                    let res = client.post(format!("http://127.0.0.1:{}/send_tx", config.rpc_port))
                        .header("Authorization", format!("Bearer {}", config.rpc_jwt_secret))
                        .json(&json!({"tx": raw_hex}))
                        .send().await?;
                    if res.status().is_success() {
                        println!("Transaction broadcasted successfully");
                    } else {
                        bail!("Broadcast failure: {}", res.text().await?);
                    }
                }
                WalletSubcommand::CreateMultisig { pubkeys, required } => {
                    let pubs: Vec<PublicKey> = pubkeys.iter().map(|s| PublicKey::from_str(s).unwrap()).collect();
                    let script = Builder::new()
                        .push_int(required as i64)
                        .push_slice(pubs.iter().map(|p| p.serialize().as_slice()).collect::<Vec<_>>())
                        .push_int(pubs.len() as i64)
                        .push_opcode(OP_CHECKMULTISIG)
                        .into_script();
                    let script_hash = hash160(&script);
                    let address = check_encode(&[0], &script_hash);
                    println!("Multisig address {}-of-{} created:", required, pubkeys.len());
                    println!("{}", address);
                    println!("Redeem script (hex): {}", hex::encode(script));
                },
            }
        }
        Commands::Explorer(explorer_cmd) => {
            let (chain_arc, db_pool, pow_engine, _) = load_chain_readonly().await?;
            let chain = chain_arc.read().await;
            let conn = db_pool.get()?;
            match explorer_cmd {
                ExplorerSubcommand::Block { height_or_hash } => {
                    let block = if height_or_hash.len() == 64 {
                        let hash_vec = hex::decode(&height_or_hash)?;
                        let hash: [u8; 32] = hash_vec.try_into().context("Invalid hash length")?;
                        let height_opt = chain.state.read().await.hash_to_height.get(&hash).cloned();
                        if let Some(h) = height_opt {
                            chain.load_block_from_db(h).await?
                        } else {
                            bail!("Block not found");
                        }
                    } else {
                        let height: usize = height_or_hash.parse()?;
                        chain.load_block_from_db(height).await?
                    };
                    let height = chain.state.read().await.hash_to_height.get(&block.header_hash(&pow_engine)?).cloned().unwrap_or(0);
                    println!("Block {}", height);
                    println!("Hash: {}", hex::encode(block.header_hash(&pow_engine)?));
                    println!("Height: {}", height);
                    println!("Timestamp: {}", block.header.timestamp);
                    println!("Tx count: {}", block.txs.len());
                    println!("Size: {} bytes", block.size());
                }
                ExplorerSubcommand::Tx { hash } => {
                    let tx_hash_vec = hex::decode(&hash)?;
                    let txid: [u8; 32] = tx_hash_vec.try_into().context("Invalid hash length")?;
                    if let Some(cf_tx) = conn.cf_handle("tx_index") {
                        if let Some(data) = conn.get_cf(&cf_tx, txid)? {
                            let (height, tx_index) = deserialize::<(usize, usize)>(&data)?;
                            let block = chain.load_block_from_db(height).await?;
                            let tx = &block.txs[tx_index];
                            println!("Transaction {}", hash);
                            println!("Block: {}", height);
                            println!("Confirmations: {}", chain.best_height - height + 1);
                            println!("Inputs: {}", tx.inputs.len());
                            println!("Outputs: {}", tx.outputs.len());
                            println!("Fee: {} LYRION", /* calculated */);
                            return Ok(());
                        }
                    }
                    for h in (chain.best_height.saturating_sub(10_000)..=chain.best_height).rev() {
                        let block = chain.load_block_from_db(h).await?;
                        for (idx, tx) in block.txs.iter().enumerate() {
                            if tx.hash() == txid {
                                return Ok(());
                            }
                        }
                    }
                }
                ExplorerSubcommand::Address { address, page, page_size } => {
                    let pubkey_hash = address_to_pubkey_hash(&address)?;
                    let cf = conn.cf_handle("addr_index").unwrap();
                    let mut prefix = b"addr:".to_vec();
                    prefix.extend_from_slice(&pubkey_hash);
                    let mut txs = vec![];
                    let iter = conn.iterator_cf(&cf, IteratorMode::From(&prefix, Direction::Forward));
                    for item in iter {
                        let (key, value) = item?;
                        if !key.starts_with(&prefix) { break; }
                        let txid: [u8;32] = key[5..37].try_into()?;
                        let vout = u32::from_be_bytes(key[37..41].try_into()?);
                        let value = u64::from_be_bytes(value.try_into()?);
                        txs.push((txid, vout, value));
                    }
                    println!("Address {} – {} transactions", address, txs.len());
                    let start = (page - 1) * page_size;
                    let end = start + page_size;
                    let page_txs = if start < txs.len() { &txs[start..end.min(txs.len())] } else { &[] };
                    for (txid, vout, value) in page_txs {
                        println!("TXID: {}, Vout: {}, Value: {}", txid, vout, value);
                    }
                },
                ExplorerSubcommand::RichList { page, page_size } => {
                    use itertools::Itertools;
                    let cf_addr = conn.cf_handle("addr_index").unwrap();
                    let iter = conn.iterator_cf(&cf_addr, IteratorMode::Start);
                    let mut balances: DashMap<[u8;20], u64> = DashMap::new();
                    for item in iter {
                        let (key, value) = item?;
                        if key.starts_with(b"addr:") {
                            let pkh: [u8;20] = key[5..25].try_into()?;
                            let val = u64::from_be_bytes(value.try_into()?);
                            balances.entry(pkh).or_insert(0).add_assign(val);
                        }
                    }
                    let mut sorted: Vec<_> = balances.into_iter().collect();
                    sorted.sort_by(|a, b| b.1.cmp(a.1));
                    let start = (page - 1) * page_size;
                    for (rank, (pkh, bal)) in sorted.iter().skip(start).take(page_size).enumerate() {
                        let mut payload = vec![0];
                        payload.extend_from_slice(&pkh);
                        let addr = payload.to_base58check();
                        println!("{:<4} {:<44} {:>15.9} LYRION", rank + start + 1, addr, *bal as f64 / 1e9);
                    }
                },
            }
        }
        Commands::Admin(admin_cmd) => {
            match admin_cmd {
                AdminSubcommand::BackupNow => {
                    let config = AppConfig::load()?;
                    let db_pool = create_db_pool(&config.db_path)?;
                    let maintenance_lock = Arc::new(tokio::sync::Mutex::new(()));
                    secure_backup_db(&db_pool, &config, maintenance_lock).await?;
                    println!("Immediate backup completed.");
                }
            }
        }
        #[cfg(feature = "gui")]
        Commands::Gui => {
            let config = Arc::new(AppConfig::load()?);
            run_gui(config);
        }
    }
    Ok(())
}
fn init_logger(level: &str) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_level(true))
        .with(tracing_subscriber::EnvFilter::new(level))
        .init();
}
async fn start_metrics_server() -> Result<()> {
    let encoder = TextEncoder::new();
    HttpServer::new(move || {
        App::new().service(web::resource("/metrics").to(move || async move {
            let mut buffer = vec![];
            if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
                return HttpResponse::InternalServerError().body(e.to_string());
            }
            HttpResponse::Ok().body(buffer)
        }))
    })
    .bind(("[::]", 9000))?
    .run()
    .await
    .context("Metrics server failed")
}
async fn start_health_server(chain: Arc<tokio::sync::RwLock<Chain>>, mempool: Arc<tokio::sync::RwLock<Mempool>>, peer_manager: Arc<PeerManager>) -> Result<()> {
    #[get("/health")]
    async fn health() -> HttpResponse { HttpResponse::Ok().body("OK") }
    HttpServer::new(move || App::new().service(health))
        .bind(("[::]", 8080))?
        .run()
        .await
        .context("Health server failed")
}
async fn start_rpc_server(chain: Arc<tokio::sync::RwLock<Chain>>, port: u16, jwt_secret: String, config: Arc<AppConfig>) -> Result<()> {
    fn validate_jwt(token: &str, secret: &str) -> Result<bool> {
        let validation = Validation::default();
        let token_data = decode::<HashMap<String, String>>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation).map_err(|_| anyhow!("Invalid JWT"))?;
        let exp = token_data.claims.get("exp").and_then(|exp| exp.parse::<u64>().ok()).unwrap_or(0);
        if exp > SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn refresh_jwt(token: &str, secret: &str) -> Result<String> {
        let mut claims = decode::<HashMap<String, String>>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())?.claims;
        claims.insert("exp".to_string(), (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600).to_string());
        encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(|_| anyhow!("Refresh failed"))
    }
    let rpc_rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_second(nonzero!(10u32))));
    #[get("/height")]
    async fn get_height(chain: web::Data<Arc<tokio::sync::RwLock<Chain>>>, req: HttpRequest, secret: web::Data<String>, limiter: web::Data<Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, ReasonablyAccurate, NoOpMiddleware>>>) -> HttpResponse {
        let ip = req.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4([0,0,0,0].into()));
        limiter.until_key_ready_with_jitter(&ip, Jitter::up_to(Duration::from_millis(100))).await;
        if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(token) = auth.to_str() {
                if validate_jwt(token.trim_start_matches("Bearer "), &secret).is_ok() {
                    let c = chain.read().await;
                    return HttpResponse::Ok().body(format!("{}", c.best_height));
                }
            }
        }
        HttpResponse::Unauthorized().body("Invalid or missing JWT")
    }
    #[get("/balance/{address}")]
    async fn get_balance(chain: web::Data<Arc<tokio::sync::RwLock<Chain>>>, path: web::Path<String>, req: HttpRequest, secret: web::Data<String>, limiter: web::Data<Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, ReasonablyAccurate, NoOpMiddleware>>>) -> HttpResponse {
        let ip = req.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4([0,0,0,0].into()));
        limiter.until_key_ready_with_jitter(&ip, Jitter::up_to(Duration::from_millis(100))).await;
        if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(token) = auth.to_str() {
                if validate_jwt(token.trim_start_matches("Bearer "), &secret).is_ok() {
                    let address = path.into_inner();
                    let pubkey_hash = match crate::utils::address_to_pubkey_hash(&address) {
                        Ok(h) => h,
                        Err(_) => return HttpResponse::BadRequest().body("Invalid address"),
                    };
                    let conn = chain.db_pool.get().map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?;
                    let cf_addr_index = conn.cf_handle("addr_index").map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?;
                    let mut balance = 0u64;
                    let mut prefix = b"addr:".to_vec();
                    prefix.extend_from_slice(&pubkey_hash);
                    let mut iter = conn.iterator_cf(cf_addr_index, rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward));
                    while let Some((key, value)) = iter.next() {
                        if !key.starts_with(&prefix) { break; }
                        let Ok(val_bytes) = value.try_into() else { continue; };
                        balance = balance.checked_add(u64::from_be_bytes(val_bytes)).unwrap_or(balance);
                    }
                    return HttpResponse::Ok().body(format!("{}", balance));
                }
            }
        }
        HttpResponse::Unauthorized().body("Invalid or missing JWT")
    }
    #[get("/block")]
    async fn get_block(chain: web::Data<Arc<tokio::sync::RwLock<Chain>>>, req: HttpRequest, secret: web::Data<String>, limiter: web::Data<Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, ReasonablyAccurate, NoOpMiddleware>>>) -> HttpResponse {
        let ip = req.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4([0,0,0,0].into()));
        limiter.until_key_ready_with_jitter(&ip, Jitter::up_to(Duration::from_millis(100))).await;
        if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(token) = auth.to_str() {
                if validate_jwt(token.trim_start_matches("Bearer "), &secret).is_ok() {
                    let c = chain.read().await;
                    if let Some(block) = c.state.read().await.blocks.get(&c.best_height) {
                        let mut block_data = 1u32.to_be_bytes().to_vec();
                        block_data.extend_from_slice(&serialize(&block).map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?);
                        return HttpResponse::Ok().body(block_data);
                    } else {
                        return HttpResponse::NotFound().body("No block at tip");
                    }
                }
            }
        }
        HttpResponse::Unauthorized().body("Invalid or missing JWT")
    }
    #[get("/mempool")]
    async fn get_mempool(mempool: web::Data<Arc<tokio::sync::RwLock<Mempool>>>, req: HttpRequest, secret: web::Data<String>, limiter: web::Data<Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, ReasonablyAccurate, NoOpMiddleware>>>) -> HttpResponse {
        let ip = req.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4([0,0,0,0].into()));
        limiter.until_key_ready_with_jitter(&ip, Jitter::up_to(Duration::from_millis(100))).await;
        if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(token) = auth.to_str() {
                if validate_jwt(token.trim_start_matches("Bearer "), &secret).is_ok() {
                    let m = mempool.read().await;
                    let txs: Vec<Transaction> = m.txs.iter().map(|e| (*e.value().tx).clone()).collect();
                    let mut mempool_data = 1u32.to_be_bytes().to_vec();
                    mempool_data.extend_from_slice(&serialize(&txs).map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?);
                    return HttpResponse::Ok().body(mempool_data);
                }
            }
        }
        HttpResponse::Unauthorized().body("Invalid or missing JWT")
    }
    #[post("/send_tx")]
    async fn send_tx(mempool: web::Data<Arc<tokio::sync::RwLock<Mempool>>>, chain: web::Data<Arc<tokio::sync::RwLock<Chain>>>, data: web::Json<serde_json::Value>, req: HttpRequest, secret: web::Data<String>, limiter: web::Data<Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, ReasonablyAccurate, NoOpMiddleware>>>) -> HttpResponse {
        let ip = req.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::V4([0,0,0,0].into()));
        limiter.until_key_ready_with_jitter(&ip, Jitter::up_to(Duration::from_millis(100))).await;
        if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(token) = auth.to_str() {
                if validate_jwt(token.trim_start_matches("Bearer "), &secret).is_ok() {
                    let raw_hex = data.get("tx").and_then(|v| v.as_str()).unwrap_or("");
                    let raw = match hex::decode(raw_hex) {
                        Ok(r) => r,
                        Err(_) => return HttpResponse::BadRequest().body("Invalid hex"),
                    };
                    let tx: Transaction = match deserialize(&raw) {
                        Ok(t) => t,
                        Err(_) => return HttpResponse::BadRequest().body("Invalid TX"),
                    };
                    let mut m = mempool.write().await;
                    let c = chain.read().await;
                    if let Ok(true) = m.insert(tx, &c).await {
                        return HttpResponse::Ok().body("TX sent");
                    } else {
                        return HttpResponse::BadRequest().body("Invalid TX");
                    }
                }
            }
        }
        HttpResponse::Unauthorized().body("Invalid or missing JWT")
    }
    let cert_bytes = secure_load_file(&config.tls_cert)?.expose_secret().clone();
    let key_bytes = secure_load_file(&config.tls_key)?.expose_secret().clone();
    let cert = Certificate(cert_bytes);
    let key = PrivateKey(key_bytes);
    let root_store = RootCertStore::empty();
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_single_cert(vec![cert], key)
        .context("Invalid RPC TLS config")?;
    let acceptor = ActixTlsAcceptor::from(Arc::new(server_config));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(chain.clone()))
            .app_data(web::Data::new(mempool.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .app_data(web::Data::new(rpc_rate_limiter.clone()))
            .service(get_height)
            .service(get_balance)
            .service(get_block)
            .service(get_mempool)
            .service(send_tx)
    })
    .bind_rustls(("[::]", port), acceptor)?
    .run()
    .await
    .context("RPC server failed")
}
struct Utxo {
    txid: [u8; 32],
    vout: u32,
    value: u64,
    confirmations: usize,
    script_pubkey: Vec<u8>,
    height: usize,
    derivation_path: String,
    is_confirmed: bool, // Added to distinguish mempool/confirmed
}
#[derive(Serialize, Deserialize, Clone)]
struct TxHistoryEntry {
    txid: String,
    timestamp: u32,
    net_amount: i64,
    confirmations: usize,
    is_receive: bool,
}
#[derive(PartialEq)]
enum AppState {
    SetupPassword,
    CreateWallet,
    RestoreWallet,
    Main,
}
fn get_block_timestamp(db: &DB, height: usize) -> AnyResult<u32> {
    let mut key = b"h:".to_vec();
    key.extend_from_slice(&(height as u64).to_be_bytes());
    let hash_bytes = db.get(&key)?.ok_or_else(|| anyhow::anyhow!("Block hash not found"))?;
    let mut block_key = b"b:".to_vec();
    block_key.extend_from_slice(&hash_bytes);
    let block_bytes = db.get(block_key)?.ok_or_else(|| anyhow::anyhow!("Block not found"))?;
    let block: Block = bincode::deserialize(&block_bytes)?;
    Ok(block.header.timestamp)
}
fn height_from_txid(db: &DB, txid: &[u8; 32]) -> AnyResult<usize> {
    let cf_tx = db.cf_handle("tx_index").ok_or_else(|| anyhow::anyhow!("tx_index CF missing"))?;
    let data = db.get_cf(&cf_tx, txid)?.ok_or_else(|| anyhow::anyhow!("Tx not found in index"))?;
    let (height, _): (usize, usize) = bincode::deserialize(&data)?;
    Ok(height)
}
fn query_addr_index(db: &DB, pkh: &[u8; 20]) -> AnyResult<Vec<([u8; 32], u32, u64)>> {
    let cf = db.cf_handle("addr_index").unwrap();
    let mut prefix = b"addr:".to_vec();
    prefix.extend_from_slice(pkh);
    let mut res = Vec::new();
    let iter = db.iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));
    for item in iter {
        let (key, value) = item?;
        if !key.starts_with(&prefix) { break; }
        let txid: [u8;32] = key[5..37].try_into()?;
        let vout = u32::from_be_bytes(key[37..41].try_into()?);
        let val = u64::from_be_bytes(value.try_into()?);
        res.push((txid, vout, val));
    }
    Ok(res)
}
fn scan_chain(seed: &Secret<[u8; 64]>, db: &Arc<DB>, chain_num: u32, gap_limit: usize, current_height: usize) -> AnyResult<(Vec<Utxo>, u64, Vec<String>, u32)> {
    let cf_utxo = db.cf_handle("utxo").unwrap();
    let secp = Secp256k1::new();
    let master = ExtendedPrivKey::new_master(Network::Bitcoin, seed.expose_secret())?;
    let base_path = "m/44'/1987'/0'/".parse::<DerivationPath>()?;
    let chain_path = base_path.extend([ChildNumber::from_hardened_idx(chain_num)?]);
    let mut utxos = Vec::new();
    let mut addresses = Vec::new();
    let mut index = 0u32;
    let mut gap = 0;
    while gap < gap_limit {
        let path = chain_path.extend([ChildNumber::from_normal_idx(index)?]);
        let child = master.derive_priv(&secp, &path)?;
        let sk = SecretKey::from_slice(&child.private_key.secret_bytes())?;
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let address = pubkey_to_address(&pk);
        let pkh = hash160(&pk.serialize());
        let entries = query_addr_index(db, &pkh)?;
        let mut has_activity = false;
        for (txid, vout, value) in entries {
            has_activity = true;
            let mut utxo_key = b"u:".to_vec();
            utxo_key.extend_from_slice(&txid);
            utxo_key.extend_from_slice(&vout.to_be_bytes());
            if let Some(raw) = db.get_cf(cf_utxo, utxo_key)? {
                let out: TXOutput = bincode::deserialize(&raw)?;
                let height = height_from_txid(db, &txid)?;
                utxos.push(Utxo {
                    txid,
                    vout,
                    value,
                    confirmations: current_height.saturating_sub(height) + 1,
                    script_pubkey: out.script_pubkey,
                    height,
                    derivation_path: path.to_string(),
                    is_confirmed: true,
                });
            }
        }
        if has_activity {
            addresses.push(address);
            gap = 0;
        } else {
            gap += 1;
        }
        index += 1;
    }
    let balance: u64 = utxos.iter().map(|u| u.value).sum();
    Ok((utxos, balance, addresses, index))
}
async fn scan_wallet_task(db: Arc<DB>, seed: Secret<[u8;64]>, current_height: usize, mempool_txs: Vec<Transaction>) -> AnyResult<(Vec<Utxo>, u64, Vec<TxHistoryEntry>, Vec<String>, Vec<String>, u32, u32)> {
    let (receive_utxos, receive_bal, receive_addrs, recv_idx) = scan_chain(&seed, &db, 0, 20, current_height)?;
    let (change_utxos, change_bal, change_addrs, chg_idx) = scan_chain(&seed, &db, 1, 20, current_height)?;
    let mut all_utxos = receive_utxos;
    all_utxos.extend(change_utxos);
    let all_bal = receive_bal + change_bal;
    let mem_utxos = scan_mempool(&mempool_txs, &receive_addrs.iter().chain(&change_addrs).cloned().collect::<Vec<_>>());
    all_utxos.extend(mem_utxos);
    let history = build_history_task(&db, &receive_addrs, &change_addrs, current_height)?;
    Ok((all_utxos, all_bal, history, receive_addrs, change_addrs, recv_idx, chg_idx))
}
fn build_history_task(db: &DB, receive_addrs: &[String], change_addrs: &[String], current_height: usize) -> AnyResult<Vec<TxHistoryEntry>> {
    let mut history_map: HashMap<[u8; 32], i64> = HashMap::new();
    let cf_utxo = db.cf_handle("utxo").unwrap();
    let all_addrs = receive_addrs.iter().chain(change_addrs.iter()).cloned().collect::<Vec<_>>();
    for addr in all_addrs {
        let pkh = address_to_pubkey_hash(&addr)?;
        let entries = query_addr_index(db, &pkh)?;
        for (txid, vout, value) in entries {
            let mut utxo_key = b"u:".to_vec();
            utxo_key.extend_from_slice(&txid);
            utxo_key.extend_from_slice(&vout.to_be_bytes());
            let is_spent = db.get_cf(cf_utxo, utxo_key)?.is_none();
            let entry = history_map.entry(txid).or_insert(0);
            *entry += if is_spent { -(value as i64) } else { value as i64 };
        }
    }
    let mut history: Vec<TxHistoryEntry> = history_map.into_iter().filter(|(_, net)| *net != 0).map(|(txid, net)| TxHistoryEntry {
        txid: hex::encode(txid),
        timestamp: get_block_timestamp(db, height_from_txid(db, &txid)?).unwrap_or(0),
        net_amount: net,
        confirmations: current_height.saturating_sub(height_from_txid(db, &txid)?) + 1,
        is_receive: net > 0,
    }).collect();
    history.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
    Ok(history)
}
pub struct LyrionWalletApp {
    temp_password_input: String,
    temp_password_confirm: String,
    password: SecretString,
    mnemonic: Option<Secret<String>>,
    seed: Option<Secret<[u8; 64]>>,
    utxos: Vec<Utxo>,
    balance: u64,
    pending_balance: u64,
    receive_addresses: Vec<String>,
    change_addresses: Vec<String>,
    current_receive_index: u32,
    current_change_index: u32,
    config: Arc<AppConfig>,
    db: Arc<DB>,
    current_height: usize,
    status: String,
    error: Option<String>,
    to_address: String,
    amount_str: String,
    fee_rate_str: String,
    tx_hex: String,
    qr_texture: Option<TextureHandle>,
    history: Vec<TxHistoryEntry>,
    anon_spend_key: Option<SecretVec<u8>>,
    anon_address: String,
    scan_promise: Option<Promise<AnyResult<(Vec<Utxo>, u64, Vec<TxHistoryEntry>, Vec<String>, Vec<String>, u32, u32)>>>,
    send_promise: Option<Promise<AnyResult<(String, bool)>>>,
    state: AppState,
    jwt_visible: bool,
    selected_tab: Option<String>,
}
impl LyrionWalletApp {
    fn new(cc: &eframe::CreationContext<'_>, config: Arc<AppConfig>) -> Self {
        let mut app = Self {
            temp_password_input: String::new(),
            temp_password_confirm: String::new(),
            password: SecretString::new(String::new()),
            mnemonic: None,
            seed: None,
            utxos: Vec::new(),
            balance: 0,
            pending_balance: 0,
            receive_addresses: Vec::new(),
            change_addresses: Vec::new(),
            current_receive_index: 0,
            current_change_index: 0,
            config,
            db: {
                let path = PathBuf::from(&config.db_path);
                let mut opts = Options::default();
                opts.create_if_missing(true);
                opts.set_allow_mmap_reads(true);
                opts.set_max_open_files(1000);
                Arc::new(DB::open_as_secondary(&opts, &path, &path.join("secondary")).unwrap_or_else(|_| {
                    DB::open_for_read_only(&opts, &path, false).unwrap()
                }))
            },
            current_height: 0,
            status: "Initializing...".to_string(),
            error: None,
            to_address: String::new(),
            amount_str: String::new(),
            fee_rate_str: "10".to_string(),
            tx_hex: String::new(),
            qr_texture: None,
            history: vec![],
            anon_spend_key: None,
            anon_address: String::new(),
            scan_promise: None,
            send_promise: None,
            state: AppState::SetupPassword,
            jwt_visible: false,
            selected_tab: None,
        };
        if std::fs::read(home_dir().unwrap().join(WALLET_FILE)).is_ok() {
            app.state = AppState::SetupPassword;
        } else {
            app.state = AppState::CreateWallet;
        }
        if let Ok(bytes) = std::fs::read(home_dir().unwrap().join(".lyrion").join("anon_spend.dat")) {
            if bytes.len() == 32 {
                app.anon_spend_key = Some(SecretVec::new(bytes));
                let priv_key = AnonPrivateKey::from_bytes(&app.anon_spend_key.as_ref().unwrap().expose_secret()).unwrap();
                let pub_key = priv_key.public_key();
                app.anon_address = pubkey_to_anon_address(&pub_key);
            }
        }
        app.load_current_height();
        app
    }
    fn load_current_height(&mut self) {
        if let Ok(bytes) = self.db.get(DB_KEY_HEIGHT) {
            if let Ok(h) = bytes {
                self.current_height = u32::from_be_bytes((&h[..4]).try_into().unwrap_or([0;4])) as usize;
            }
        }
    }
    fn encrypt_wallet(&self, password: &str) -> AnyResult<Vec<u8>> {
        let mut salt = [0u8; 32];
        thread_rng().fill_bytes(&mut salt);
        let mut key = [0u8; 32];
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, ArgonConfig::default())
            .hash_password_into(password.as_bytes(), &salt, &mut key)?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, self.seed.as_ref().unwrap().expose_secret().as_ref())?;
        let mut data = salt.to_vec();
        data.extend_from_slice(&nonce_bytes);
        data.extend_from_slice(&ciphertext);
        Ok(data)
    }
    fn decrypt_wallet(&mut self, password: &str, data: &[u8]) -> AnyResult<()> {
        if data.len() < 44 { bail!("Corrupted wallet file"); }
        let salt = &data[0..32];
        let nonce = Nonce::from_slice(&data[32..44]);
        let ciphertext = &data[44..];
        let mut key = [0u8; 32];
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, ArgonConfig::default())
            .hash_password_into(password.as_bytes(), salt, &mut key)?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let plaintext = cipher.decrypt(nonce, ciphertext)?;
        let mut seed_arr = [0u8; 64];
        seed_arr.copy_from_slice(&plaintext);
        self.seed = Some(Secret::new(seed_arr));
        Ok(())
    }
}
impl App for LyrionWalletApp {
    fn save(&mut self, storage: &mut dyn Storage) {
        if let Ok(data) = self.encrypt_wallet(self.password.expose_secret()) {
            std::fs::create_dir_all(home_dir().unwrap().join(".lyrion"))?;
            std::fs::write(home_dir().unwrap().join(WALLET_FILE), data)?;
        }
    }
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("Wallet", |ui| {
                    if ui.button("New receive address").clicked() { self.current_receive_index += 1; }
                    if ui.button("Lock").clicked() { self.state = AppState::SetupPassword; self.password = SecretString::new(String::new()); }
                    if ui.button("Quit").clicked() { _frame.close(); }
                });
            });
        });
        match self.state {
            AppState::SetupPassword => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Lyrion Wallet - Password");
                    ui.add(egui::TextEdit::singleline(&mut self.temp_password_input).password(true));
                    if ui.button("Unlock").clicked() {
                        let secret_pw = SecretString::new(self.temp_password_input.clone());
                        self.temp_password_input.zeroize();
                        if let Ok(data) = std::fs::read(home_dir().unwrap().join(WALLET_FILE)) {
                            if self.decrypt_wallet(secret_pw.expose_secret(), &data).is_ok() {
                                self.password = secret_pw;
                                self.load_current_height();
                                let db = self.db.clone();
                                let seed = self.seed.clone().unwrap();
                                let height = self.current_height;
                                // Add mempool via RPC
                                let client = Client::new();
                                let mempool_res = client.get(format!("http://127.0.0.1:{}/mempool", self.config.rpc_port))
                                    .header("Authorization", format!("Bearer {}", self.config.rpc_jwt_secret))
                                    .send().await;
                                let mempool_txs = if let Ok(res) = mempool_res {
                                    if let Ok(body) = res.bytes().await {
                                        deserialize::<Vec<Transaction>>(&body[4..]).unwrap_or_default()
                                    } else { vec![] }
                                } else { vec![] };
                                self.scan_promise = Some(Promise::spawn_async(async move { scan_wallet_task(db, seed, height, mempool_txs) }));
                                self.state = AppState::Main;
                            } else {
                                self.error = Some("Incorrect password".to_string());
                            }
                        }
                    }
                    if let Some(err) = &self.error {
                        ui.colored_label(Color32::RED, err);
                    }
                });
            }
            AppState::CreateWallet | AppState::RestoreWallet => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading(if self.state == AppState::CreateWallet { "Wallet Creation" } else { "Restore Wallet" });
                    let mnemonic_str = if self.state == AppState::CreateWallet {
                        let m = Mnemonic::generate_in(Language::English, 24)?;
                        self.mnemonic = Some(Secret::new(m.to_string()));
                        m.to_string()
                    } else {
                        self.mnemonic.as_ref().map(|s| s.expose_secret().clone()).unwrap_or_default()
                    };
                    if self.state == AppState::CreateWallet {
                        ui.label("Recovery phrase (24 words) – KEEP OFFLINE");
                        ui.label(RichText::new(&mnemonic_str).monospace().background_color(Color32::BLACK));
                    } else {
                        let mut mn = self.mnemonic.as_ref().map(|s| s.expose_secret().clone()).unwrap_or_default();
                        ui.text_edit_singleline(&mut mn);
                        self.mnemonic = Some(Secret::new(mn));
                    }
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.temp_password_input).password(true));
                    ui.label("Confirmation:");
                    ui.add(egui::TextEdit::singleline(&mut self.temp_password_confirm).password(true));
                    if ui.button("Confirm").clicked() && self.temp_password_input == self.temp_password_confirm && !self.temp_password_input.is_empty() {
                        let secret_pw = SecretString::new(self.temp_password_input.clone());
                        self.temp_password_input.zeroize();
                        self.temp_password_confirm.zeroize();
                        self.password = secret_pw;
                        if let Some(m) = &self.mnemonic {
                            let seed = Seed::new(&Mnemonic::parse_in(Language::English, m.expose_secret())?, "");
                            let mut seed_arr = [0u8; 64];
                            seed_arr.copy_from_slice(seed.as_bytes());
                            self.seed = Some(Secret::new(seed_arr));
                            self.load_current_height();
                            let db = self.db.clone();
                            let seed = self.seed.clone().unwrap();
                            let height = self.current_height;
                            let client = Client::new();
                            let mempool_res = client.get(format!("http://127.0.0.1:{}/mempool", self.config.rpc_port))
                                .header("Authorization", format!("Bearer {}", self.config.rpc_jwt_secret))
                                .send().await;
                            let mempool_txs = if let Ok(res) = mempool_res {
                                if let Ok(body) = res.bytes().await {
                                    deserialize::<Vec<Transaction>>(&body[4..]).unwrap_or_default()
                                } else { vec![] }
                            } else { vec![] };
                            self.scan_promise = Some(Promise::spawn_async(async move { scan_wallet_task(db, seed, height, mempool_txs) }));
                            self.state = AppState::Main;
                        }
                    }
                });
            }
            AppState::Main => {
                egui::SidePanel::left("side_panel").show(ctx, |ui| {
                    ui.heading("Lyrion Wallet");
                    ui.label(RichText::new(format!("Confirmed balance: {:.9} LYRION", self.balance as f64 / 1e9)).strong());
                    ui.label(RichText::new(format!("Pending: {:.9} LYRION", self.pending_balance as f64 / 1e9)).strong());
                    if !self.anon_address.is_empty() {
                        ui.label(format!("Anon address: {}", self.anon_address));
                    }
                    ui.separator();
                    if ui.button(" Receive ").clicked() { self.selected_tab = Some("receive".to_string()); }
                    if ui.button(" Send ").clicked() { self.selected_tab = Some("send".to_string()); }
                    if ui.button(" History ").clicked() { self.selected_tab = Some("history".to_string()); }
                    if ui.button("Refresh").clicked() {
                        self.load_current_height();
                        let db = self.db.clone();
                        let seed = self.seed.clone().unwrap();
                        let height = self.current_height;
                        let client = Client::new();
                        let mempool_res = client.get(format!("http://127.0.0.1:{}/mempool", self.config.rpc_port))
                            .header("Authorization", format!("Bearer {}", self.config.rpc_jwt_secret))
                            .send().await;
                        let mempool_txs = if let Ok(res) = mempool_res {
                            if let Ok(body) = res.bytes().await {
                                deserialize::<Vec<Transaction>>(&body[4..]).unwrap_or_default()
                            } else { vec![] }
                        } else { vec![] };
                        self.scan_promise = Some(Promise::spawn_async(async move { scan_wallet_task(db, seed, height, mempool_txs) }));
                    }
                });
                egui::CentralPanel::default().show(ctx, |ui| {
                    if ui.button("Force DB reconnection + rescan").clicked() {
                        let path = PathBuf::from(&self.config.db_path);
                        let mut opts = Options::default();
                        opts.create_if_missing(true);
                        opts.set_allow_mmap_reads(true);
                        opts.set_max_open_files(1000);
                        self.db = Arc::new(DB::open_as_secondary(&opts, &path, &path.join("secondary")).unwrap());
                        self.load_current_height();
                        let db = self.db.clone();
                        let seed = self.seed.clone().unwrap();
                        let height = self.current_height;
                        let client = Client::new();
                        let mempool_res = client.get(format!("http://127.0.0.1:{}/mempool", self.config.rpc_port))
                            .header("Authorization", format!("Bearer {}", self.config.rpc_jwt_secret))
                            .send().await;
                        let mempool_txs = if let Ok(res) = mempool_res {
                            if let Ok(body) = res.bytes().await {
                                deserialize::<Vec<Transaction>>(&body[4..]).unwrap_or_default()
                            } else { vec![] }
                        } else { vec![] };
                        self.scan_promise = Some(Promise::spawn_async(async move { scan_wallet_task(db, seed, height, mempool_txs) }));
                    }
                    if let Some(promise) = &mut self.scan_promise {
                        if let Some(res) = promise.ready_mut() {
                            match res {
                                Ok((utxos, bal, hist, recv_addrs, chg_addrs, recv_idx, chg_idx)) => {
                                    self.utxos = utxos.clone();
                                    self.balance = utxos.iter().filter(|u| u.is_confirmed).map(|u| u.value).sum();
                                    self.pending_balance = utxos.iter().filter(|u| !u.is_confirmed).map(|u| u.value).sum();
                                    self.history = hist.clone();
                                    self.receive_addresses = recv_addrs.clone();
                                    self.change_addresses = chg_addrs.clone();
                                    self.current_receive_index = *recv_idx;
                                    self.current_change_index = *chg_idx;
                                    self.status = format!("Scan completed – {} LYRION (pending: {})", self.balance as f64 / 1e9, self.pending_balance as f64 / 1e9);
                                }
                                Err(e) => {
                                    self.error = Some(e.to_string());
                                }
                            }
                        } else {
                            ui.spinner();
                            ui.label("Scanning...");
                        }
                    }
                    match self.selected_tab.as_deref() {
                        Some("receive") | None => {
                            ui.heading("Receive");
                            ui.label(RichText::new("To protect your privacy, use a new address for each receipt.").color(Color32::YELLOW));
                            if ui.button("New receive address").clicked() {
                                self.current_receive_index +=1;
                            }
                            let addr = self.receive_addresses.last().cloned().unwrap_or_default();
                            ui.horizontal(|ui| {
                                ui.label("Address:");
                                let mut temp_addr = addr.clone();
                                ui.text_edit_singleline(&mut temp_addr);
                                if ui.button("Copy").clicked() { ctx.copy_text(addr.clone()); }
                            });
                            let code = QrCode::new(addr.as_bytes()).unwrap();
                            let image = image::ImageBuffer::from_fn(code.width() as u32, code.width() as u32, |x, y| {
                                if code[(x as usize, y as usize)] == qrcode::Color::Dark { Luma([0u8]) } else { Luma([255u8]) }
                            });
                            let texture = ctx.load_texture("qr", egui::ColorImage::from_rgba_unmultiplied([256, 256], &image.to_rgba8()), egui::TextureOptions::linear());
                            self.qr_texture = Some(texture);
                            if let Some(tex) = &self.qr_texture {
                                ui.image(tex, [300.0, 300.0]);
                            }
                        }
                        Some("send") => {
                            ui.heading("Send");
                            ui.label("Recipient address:");
                            ui.text_edit_singleline(&mut self.to_address);
                            ui.label("Amount (LYRION):");
                            ui.text_edit_singleline(&mut self.amount_str);
                            ui.label("Fee rate (sat/vB):");
                            ui.text_edit_singleline(&mut self.fee_rate_str);
                            if ui.button("Send").clicked() && let (Ok(amount), Ok(fee)) = (self.amount_str.parse::<u64>(), self.fee_rate_str.parse::<u64>()) {
                                let seed = self.seed.clone().expect("Wallet locked");
                                let config = self.config.clone();
                                let utxos = self.utxos.clone();
                                let to = self.to_address.clone();
                                let idx = self.current_change_index;
                                self.send_promise = Some(Promise::spawn_async(async move {
                                    send_transaction_task(seed, config, utxos, to, amount, fee, idx).await
                                }));
                            } else {
                                self.error = Some("Invalid amount or fees".to_string());
                            }
                            if let Some(promise) = &mut self.send_promise {
                                if let Some(res) = promise.ready_mut() {
                                    match res {
                                        Ok((txid, used)) => {
                                            ui.label(RichText::new(txid).color(Color32::GREEN));
                                            if *used {
                                                self.current_change_index +=1;
                                            }
                                            self.to_address.clear();
                                            self.amount_str.clear();
                                            let db = self.db.clone();
                                            let seed = self.seed.clone().unwrap();
                                            let height = self.current_height;
                                            let client = Client::new();
                                            let mempool_res = client.get(format!("http://127.0.0.1:{}/mempool", self.config.rpc_port))
                                                .header("Authorization", format!("Bearer {}", self.config.rpc_jwt_secret))
                                                .send().await;
                                            let mempool_txs = if let Ok(res) = mempool_res {
                                                if let Ok(body) = res.bytes().await {
                                                    deserialize::<Vec<Transaction>>(&body[4..]).unwrap_or_default()
                                                } else { vec![] }
                                            } else { vec![] };
                                            self.scan_promise = Some(Promise::spawn_async(async move { scan_wallet_task(db, seed, height, mempool_txs) }));
                                        }
                                        Err(e) => {
                                            ui.label(RichText::new(e.to_string()).color(Color32::RED));
                                        }
                                    }
                                } else {
                                    ui.spinner();
                                    ui.label("Sending in progress...");
                                }
                            }
                        }
                        Some("history") => {
                            ui.heading("History");
                            ScrollArea::vertical().show(ui, |ui| {
                                for entry in &self.history {
                                    ui.horizontal(|ui| {
                                        ui.label(format!("TXID: {}", &entry.txid[..10]));
                                        ui.label(format!("{} LYRION", entry.net_amount as f64 / 1e9));
                                        ui.label(if entry.is_receive { "Received" } else { "Sent" });
                                        ui.label(format!("Confs: {}", entry.confirmations));
                                    });
                                }
                            });
                        }
                        _ => {}
                    }
                    if let Some(err) = &self.error {
                        ui.colored_label(Color32::RED, err);
                    }
                    ui.label(&self.status);
                });
            }
        }
    }
}
pub fn run_gui(config: Arc<AppConfig>) {
    eframe::run_native(
        "Lyrion Wallet",
        eframe::NativeOptions::default(),
        Box::new(|cc| Ok(Box::new(LyrionWalletApp::new(cc, config)))),
    );
}
fn p2pkh_script_from_pkh(pkh: &[u8; 20]) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(pkh);
    script.extend_from_slice(&[0x88, 0xAC]);
    script
}
pub mod wallet {
    use super::*;
    #[derive(Clone)]
    pub struct Wallet {
        master: ExtendedPrivKey,
        config: Arc<AppConfig>,
    }
    impl Wallet {
        pub fn from_mnemonic(mnemonic: &str, config: &AppConfig) -> Result<Self> {
            let mn = Mnemonic::parse_in(Language::English, mnemonic)?;
            let seed = Seed::new(&mn, "");
            let network = if config.mainnet { bitcoin::Network::Bitcoin } else { bitcoin::Network::Testnet };
            let master = ExtendedPrivKey::new_master(network, seed.as_bytes())?;
            Ok(Self { master, config: config.clone() })
        }
        pub fn get_receive_address(&self, index: u32) -> Result<String> {
            let path: DerivationPath = format!("m/44'/1987'/0'/0/{}", index).parse()?;
            let child = self.master.derive_priv(&SECP, &path)?;
            let sk = SecretKey::from_slice(&child.private_key.to_bytes())?;
            let pk = PublicKey::from_secret_key(&SECP, &sk);
            Ok(pubkey_to_address(&pk))
        }
        pub fn get_balance(&self) -> Result<(u64, u64)> {
            let db_pool = create_db_pool(&self.config.db_path)?;
            let conn = db_pool.get()?;
            let cf_addr = conn.cf_handle("addr_index").ok_or(anyhow!("addr_index missing"))?;
            let cf_utxo = conn.cf_handle("utxo").ok_or(anyhow!("utxo missing"))?;
            let cf_tx_index = conn.cf_handle("tx_index").ok_or(anyhow!("tx_index missing"))?;
            let current_height = load_current_height(&conn)?;
            let mut confirmed = 0u64;
            let mut pending = 0u64;
            for chain in 0..2 { // receive & change
                for i in 0..100 {
                    let path: DerivationPath = format!("m/44'/1987'/0'/{}/{}", chain, i).parse()?;
                    let child = self.master.derive_priv(&SECP, &path)?;
                    let sk = SecretKey::from_slice(&child.private_key.to_bytes())?;
                    let pk = PublicKey::from_secret_key(&SECP, &sk);
                    let pkh = hash160(&pk.serialize());
                    let mut prefix = b"addr:".to_vec();
                    prefix.extend_from_slice(&pkh);
                    let iter = conn.iterator_cf(cf_addr, IteratorMode::From(&prefix, Direction::Forward));
                    for item in iter {
                        let (key, value) = item?;
                        if !key.starts_with(&prefix) { break; }
                        let txid: [u8;32] = key[25..57].try_into()?;
                        let vout = u32::from_be_bytes(key[57..61].try_into()?);
                        let value = u64::from_be_bytes(value.try_into()?);
                        let mut utxo_key = b"u:".to_vec();
                        utxo_key.extend_from_slice(&txid);
                        utxo_key.extend_from_slice(&vout.to_be_bytes());
                        if conn.get_cf(cf_utxo, &utxo_key)?.is_some() {
                            if let Some(tx_data) = conn.get_cf(cf_tx_index, txid)? {
                                let (height, _) = deserialize::<(usize, usize)>(&tx_data)?;
                                if current_height.saturating_sub(height) >= 1 {
                                    confirmed += value;
                                } else {
                                    pending += value;
                                }
                            } else {
                                pending += value;
                            }
                        }
                    }
                }
            }
            Ok((confirmed, pending))
        }
        pub fn get_utxos(&self, spendable_only: bool) -> Result<Vec<Utxo>> {
            let db_pool = create_db_pool(&self.config.db_path)?;
            let conn = db_pool.get()?;
            let cf_addr = conn.cf_handle("addr_index").ok_or(anyhow!("addr_index missing"))?;
            let cf_utxo = conn.cf_handle("utxo").ok_or(anyhow!("utxo missing"))?;
            let cf_tx_index = conn.cf_handle("tx_index").ok_or(anyhow!("tx_index missing"))?;
            let current_height = load_current_height(&conn)?;
            let mut utxos = Vec::new();
            for chain in 0..2 {
                for i in 0..100 {
                    let path: DerivationPath = format!("m/44'/1987'/0'/{}/{}", chain, i).parse()?;
                    let child = self.master.derive_priv(&SECP, &path)?;
                    let sk = SecretKey::from_slice(&child.private_key.secret_bytes())?;
                    let pk = PublicKey::from_secret_key(&SECP, &sk);
                    let pkh = hash160(&pk.serialize());
                    let mut prefix = b"addr:".to_vec();
                    prefix.extend_from_slice(&pkh);
                    let iter = conn.iterator_cf(cf_addr, IteratorMode::From(&prefix, Direction::Forward));
                    for item in iter {
                        let (key, value) = item?;
                        if !key.starts_with(&prefix) { break; }
                        let txid: [u8;32] = key[25..57].try_into()?;
                        let vout = u32::from_be_bytes(key[57..61].try_into()?);
                        let value = u64::from_be_bytes(value.try_into()?);
                        let mut utxo_key = b"u:".to_vec();
                        utxo_key.extend_from_slice(&txid);
                        utxo_key.extend_from_slice(&vout.to_be_bytes());
                        if let Some(raw) = conn.get_cf(cf_utxo, &utxo_key)? {
                            let out: TXOutput = bincode::deserialize(&raw)?;
                            let confs = if let Some(tx_data) = conn.get_cf(cf_tx_index, txid)? {
                                let (height, _) = deserialize::<(usize, usize)>(&tx_data)?;
                                current_height.saturating_sub(height) + 1
                            } else { 0 };
                            if !spendable_only || confs >= COINBASE_MATURITY {
                                utxos.push(Utxo { txid, vout, value, confirmations: confs, script_pubkey: out.script_pubkey, height: 0, derivation_path: path.to_string(), is_confirmed: confs > 0 });
                            }
                        }
                    }
                }
            }
            Ok(utxos)
        }
        pub fn get_history(&self, limit: usize) -> Result<Vec<TxHistoryEntry>> {
            let db_pool = create_db_pool(&self.config.db_path)?;
            let conn = db_pool.get()?;
            let cf_addr = conn.cf_handle("addr_index").ok_or(anyhow!("addr_index missing"))?;
            let cf_utxo = conn.cf_handle("utxo").ok_or(anyhow!("utxo missing"))?;
            let current_height = load_current_height(&conn)?;
            let mut history_map: HashMap<[u8;32], i64> = HashMap::new();
            let mut receive_addrs = Vec::new();
            let mut change_addrs = Vec::new();
            for chain in 0..2 {
                let mut addrs = if chain == 0 { &mut receive_addrs } else { &mut change_addrs };
                for i in 0..100 {
                    let path: DerivationPath = format!("m/44'/1987'/0'/{}/{}", chain, i).parse()?;
                    let child = self.master.derive_priv(&SECP, &path)?;
                    let sk = SecretKey::from_slice(&child.private_key.secret_bytes())?;
                    let pk = PublicKey::from_secret_key(&SECP, &sk);
                    addrs.push(pubkey_to_address(&pk));
                    let pkh = hash160(&pk.serialize());
                    let entries = query_addr_index(&conn, &pkh)?;
                    for (txid, vout, value) in entries {
                        let mut utxo_key = b"u:".to_vec();
                        utxo_key.extend_from_slice(&txid);
                        utxo_key.extend_from_slice(&vout.to_be_bytes());
                        let is_receive = if chain == 0 { value as i64 } else { -(value as i64) };
                        *history_map.entry(txid).or_insert(0) += if conn.get_cf(cf_utxo, &utxo_key)?.is_some() { is_receive } else { -is_receive };
                    }
                }
            }
            let mut history: Vec<TxHistoryEntry> = history_map.into_iter().map(|(txid, net)| TxHistoryEntry {
                txid: hex::encode(txid),
                timestamp: get_block_timestamp(&conn, height_from_txid(&conn, &txid)?).unwrap_or(0),
                net_amount: net,
                confirmations: current_height.saturating_sub(height_from_txid(&conn, &txid)?) + 1,
                is_receive: net > 0,
            }).collect();
            history.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
            history.truncate(limit);
            Ok(history)
        }
        pub fn get_privkey_for_address(&self, address: &str) -> Result<SecretKey> {
            let pkh = address_to_pubkey_hash(address)?;
            for chain in 0..2 {
                for i in 0..100 {
                    let path: DerivationPath = format!("m/44'/1987'/0'/{}/{}", chain, i).parse()?;
                    let child = self.master.derive_priv(&SECP, &path)?;
                    let sk = SecretKey::from_slice(&child.private_key.secret_bytes())?;
                    let pk = PublicKey::from_secret_key(&SECP, &sk);
                    if hash160(&pk.serialize()) == pkh {
                        return Ok(sk);
                    }
                }
            }
            bail!("Address not found in the wallet");
        }
        pub fn create_tx(&self, to: &str, amount: u64, fee_rate: u64, change_addr: Option<&str>) -> Result<(Transaction, [u8;32])> {
            let utxos = self.get_utxos(true)?;
            let mut selected = utxos.clone();
            selected.sort_by_key(|u| std::cmp::Reverse(u.value));
            let mut input_sum = 0u64;
            let mut inputs = Vec::new();
            for u in selected {
                inputs.push(u.clone());
                input_sum += u.value;
                if input_sum >= amount + 100_000 { break; }
            }
            if input_sum < amount { bail!("Insufficient funds"); }
            let dust = 1000u64;
            let dummy_sig_size = 106usize;
            let overhead = 10 + 4 + 4 + 4 + 4;
            let mut fee = (inputs.len() * dummy_sig_size + overhead + 34) as u64 * fee_rate;
            let mut change: u64;
            for _ in 0..20 {
                change = input_sum - amount - fee;
                let outputs_count = if change > dust { 2 } else { 1 };
                let size = overhead + inputs.len() * dummy_sig_size + outputs_count * 34 + inputs.len() * 4;
                let new_fee = (size as u64) * fee_rate;
                if (new_fee as i64 - fee as i64).abs() < 20 { break; }
                fee = new_fee;
            }
            change = input_sum - amount - fee;
            if input_sum < amount + fee { bail!("Insufficient funds (fees included)"); }
            let to_pkh = address_to_pubkey_hash(to)?;
            let mut outputs = vec![TXOutput {
                value: amount,
                script_pubkey: p2pkh_script_from_pkh(&to_pkh),
                commitment: None,
            }];
            let mut change_used = false;
            if change > dust {
                change_used = true;
                let path = DerivationPath::from_str(&format!("m/44'/1987'/0'/1/{}", self.current_change_index))?;
                let child = self.master.derive_priv(&SECP, &path)?;
                let pk = PublicKey::from_secret_key(&SECP, &SecretKey::from_slice(&child.private_key.secret_bytes())?);
                outputs.push(TXOutput { value: change, script_pubkey: p2pkh_script(&pk), commitment: None });
            } else if let Some(ch) = change_addr {
                let ch_pkh = address_to_pubkey_hash(ch)?;
                outputs.push(TXOutput { value: change, script_pubkey: p2pkh_script_from_pkh(&ch_pkh), commitment: None });
            }
            let mut tx = Transaction {
                version: 1,
                is_anonymous: false,
                inputs: inputs.iter().map(|u| TXInput {
                    txid: u.txid,
                    vout: u.vout,
                    script_sig: vec![],
                    sequence: 0xffffffff,
                }).collect(),
                outputs,
                lock_time: 0,
                range_proofs: vec![],
            };
            for (i, utxo) in inputs.iter().enumerate() {
                let path: DerivationPath = utxo.derivation_path.parse()?;
                let child = self.master.derive_priv(&SECP, &path)?;
                let sk = SecretKey::from_slice(&child.private_key.secret_bytes())?;
                let sighash = tx.sighash(i, &utxo.script_pubkey, 0x01);
                let msg = secp256k1::Message::from_slice(&sighash)?;
                let sig = SECP.sign_ecdsa(&msg, &sk);
                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(0x01); // SIGHASH_ALL
                tx.inputs[i].script_sig = sig_bytes;
                tx.inputs[i].script_sig.extend_from_slice(&PublicKey::from_secret_key(&SECP, &sk).serialize());
            }
            Ok((tx, tx.hash()))
        }
    }
}
