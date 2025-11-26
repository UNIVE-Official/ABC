use anyhow::Result;
use num_cpus;
use prometheus::IntGauge;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use tokio::time::sleep;
use crate::chain::Chain;
use crate::mempool::Mempool;
use crate::tx::{Block, BlockHeader, create_coinbase, BlockHeader, Transaction};
use crate::utils::{compact_to_target, now_ms, subsidy, TWO_POW_256, TARGET_BLOCK_TIME, u256_from_hash, PowEngine};
use secp256k1::PublicKey;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{info, debug};
use ring::rand::{SecureRandom, SystemRandom};
use rayon::ThreadPoolBuilder;
use bincode::serialize;
use crate::config::AppConfig;
use rand::Rng;
use tokio_metrics::RuntimeMonitor;
const NONCE_CHUNK_SIZE: u32 = 1_000_000;
#[derive(Serialize, Deserialize)]
struct HeaderWithoutNonce {
    version: u32,
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: u32,
    bits: u32,
}
pub async fn miner_task(
    chain_arc: Arc<RwLock<Chain>>,
    mempool_arc: Arc<RwLock<Mempool>>,
    block_tx: broadcast::Sender<Block>,
    mut tip_change_rx: broadcast::Receiver<[u8; 32]>,
    tip_change_tx: broadcast::Sender<[u8; 32]>,
    pubkey: PublicKey,
    max_threads: usize,
    config: &AppConfig,
    pow_engine: &Arc<PowEngine>,
) -> Result<()> {
    let mut readonly_attempts = 0u8;
    let monitor = RuntimeMonitor::new(&tokio::runtime::Handle::current());
    let mut current_num_threads = num_cpus::get_physical().min(max_threads).max(4).min(64);
    let pool = ThreadPoolBuilder::new().num_threads(current_num_threads).thread_name(|i| format!("miner-{}", i)).build()?;
    let interrupt = Arc::new(AtomicBool::new(false));
    let interrupt_clone = interrupt.clone();
    tokio::spawn(async move {
        while tip_change_rx.recv().await.is_ok() {
            interrupt_clone.store(true, Ordering::Relaxed);
        }
    });
    let hash_rate_gauge = IntGauge::new("hash_rate", "Hashes per second").unwrap_or_else(|_| IntGauge::new("hash_rate_fallback", "Fallback").unwrap());
    let rng = SystemRandom::new();
    loop {
        interrupt.store(false, Ordering::Relaxed);
        let chain_read = chain_arc.read().await;
        if chain_read.read_only_mode.load(Ordering::Relaxed) {
            readonly_attempts += 1;
            if readonly_attempts > 30 {
                error!("Chain stuck in read_only_mode > 5 minutes – possible attack or disk corruption");
                return Err(anyhow::anyhow!("Persistent read_only_mode"));
            }
            warn!("Chain in read_only_mode, waiting 10s before retry (attempt {}/{})", readonly_attempts, 30);
            drop(chain_read);
            sleep(Duration::from_secs(10)).await;
            continue;
        }
        readonly_attempts = 0;
        let (prev_hash, height, bits, selected_txs, fees) = {
            let height = chain_read.best_height + 1;
            let bits = calculate_next_bits(&*chain_read, height).await;
            let mempool = mempool_arc.read().await;
            let selected = mempool.select_txs(crate::utils::MAX_BLOCK_SIZE - 1000);
            let fees: u64 = selected.iter().map(|tx| tx.fee(&HashMap::new())).try_fold(0u64, u64::checked_add).expect("Fee overflow");
            (chain_read.best_tip, height, bits, selected, fees)
        };
        let mut extra = [0u8; 8];
        rng.fill(&mut extra);
        let mut coinbase = create_coinbase(height, &extra, &pubkey);
        coinbase.outputs[0].value = subsidy(height).checked_add(fees).context("Subsidy overflow")?;
        if let Ok(custom_dest) = config.coinbase_sk.parse::<PublicKey>() {
            coinbase.outputs[0].script_pubkey = crate::tx::p2pkh_script(&custom_dest);
        }
        let mut txs = vec![coinbase];
        txs.extend(selected_txs);
        let merkle_root = Block::compute_merkle_root(&txs);
        let target = compact_to_target(bits);
        let found = Arc::new(AtomicBool::new(false));
        let interrupt_inner = interrupt.clone();
        let header_base = {
            let current_time = (now_ms()? / 1000) as u32;
            if current_time % 1000 != 0 {
                warn!("Timestamp drift detected: {} ms. Adjusting to nearest second.", current_time % 1000);
            }
            let h = HeaderWithoutNonce {
                version: 1,
                prev_hash,
                merkle_root,
                timestamp: current_time,
                bits,
            };
            serialize(&h)?
        };
        let start_time = Instant::now();
        let hash_count = AtomicU64::new(0);
        let found_nonce = Arc::new(AtomicU64::new(0));
        let current_tip = {
            let chain = chain_arc.read().await;
            chain.best_tip
        };
        let current_load = monitor.instrumented_tasks() as f64 / current_num_threads as f64;
        let adjusted_threads = if current_load > 0.9 {
            current_num_threads.saturating_sub(8).max(4)
        } else if current_load < 0.6 {
            (current_num_threads + 8).min(64)
        } else {
            current_num_threads
        };
        if adjusted_threads != current_num_threads {
            current_num_threads = adjusted_threads;
            pool.set_num_threads(current_num_threads);
        }
        pool.install(|| {
            let mut nonce_start = 0u64;
            loop {
                if found.load(Ordering::Relaxed) || interrupt_inner.load(Ordering::Relaxed) { break; }
                (nonce_start..nonce_start + NONCE_CHUNK_SIZE as u64).into_par_iter().find_any(|&nonce| {
                    if interrupt_inner.load(Ordering::Relaxed) { return false; }
                    let mut input = header_base.clone();
                    input.extend_from_slice(&nonce.to_le_bytes());
                    let hash = pow_engine.hash(&input).unwrap_or([0; 32]);
                    hash_count.fetch_add(1, Ordering::Relaxed);
                    if u256_from_hash(hash) <= target {
                        found.store(true, Ordering::Relaxed);
                        found_nonce.store(nonce, Ordering::Relaxed);
                        true
                    } else { false; }
                });
                nonce_start = nonce_start.wrapping_add(NONCE_CHUNK_SIZE as u64);
            }
        });
        let elapsed = start_time.elapsed().as_secs_f64().max(1.0);
        let hash_rate = hash_count.load(Ordering::Relaxed) as f64 / elapsed;
        hash_rate_gauge.set(hash_rate as i64);
        debug!("Hash rate: {} H/s", hash_rate);
        if found.load(Ordering::Relaxed) {
            let nonce = found_nonce.load(Ordering::Relaxed);
            let block = Block { header: BlockHeader { version: 1, prev_hash, merkle_root, timestamp: (now_ms()? / 1000) as u32, bits, nonce }, txs };
            let mut chain = chain_arc.write().await;
            let template_prev_hash = block.header.prev_hash;
            if template_prev_hash == current_tip && chain.add_block(block.clone()).await? {
                let _ = block_tx.send(block.clone());
                let _ = tip_change_tx.send(block.header_hash(&pow_engine)?);
                info!("Block mined at height {} with hash {:x?}", height, block.header_hash(&pow_engine)?);
            } else {
                debug!("Block already known or invalid, or tip changed during mining");
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
}
