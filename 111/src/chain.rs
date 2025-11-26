use anyhow::{bail, Context, Result};
use bincode::{deserialize, serialize};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use rocksdb::{DB, WriteBatch, ColumnFamily, WriteOptions, IteratorMode, Snapshot as RocksSnapshot};
use std::collections::{BTreeMap, HashMap, VecDeque, HashSet};
use std::sync::Arc;
use std::time::{Instant, Duration};
use crate::errors::ChainError;
use crate::mempool::Mempool;
use crate::tx::{Block, BlockHeader, Transaction, TXInput, TXOutput, validate_block, validate_transaction};
use crate::utils::{compact_to_target, target_to_compact, now_ms, subsidy, TWO_POW_256, DIFFICULTY_ADJUST_INTERVAL, TARGET_BLOCK_TIME, u256_from_hash, pow_hash, LRU_CACHE_SIZE, PowEngine, u256_from_be, ASSUME_VALID_DEPTH, sha256d};
use tokio::sync::RwLock as TokioRwLock;
use rayon::prelude::*;
use monero_serai::ringct::KeyImage;
use lru::LruCache;
use tracing::{info, warn, error, debug};
use deadpool_rocksdb::{Pool};
use prometheus::{IntCounter, Histogram};
use retry::retry;
use tokio::time::sleep;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use curve25519_dalek::scalar::Scalar;
use crate::tx::PedersenGens;
use quota::Quota;
use serde::{Serialize, Deserialize};
macro_rules! lazy_metric {
    ($name:literal, $desc:literal) => {
        Lazy::new(|| {
            IntCounter::new($name, $desc).unwrap_or_else(|_| IntCounter::new(concat!($name, "_fallback"), concat!("Fallback counter for ", $desc)).unwrap())
        });
    };
}
static METRIC_ORPHANS: Lazy<IntCounter> = lazy_metric!("lyrion_orphans", "Number of orphan blocks");
static METRIC_VALIDATION_TIME: Lazy<Histogram> = Lazy::new(|| {
    Histogram::new("lyrion_validation_time", "Block validation time in seconds").unwrap_or_else(|_| Histogram::new("lyrion_validation_time_fallback", "Fallback").unwrap())
});
static METRIC_CONSENSUS_ERRORS: Lazy<IntCounter> = lazy_metric!("lyrion_consensus_errors", "Consensus errors count");
static METRIC_ROLLBACK_FAILURE: Lazy<IntCounter> = lazy_metric!("lyrion_rollback_failure", "Rollback failure count");
static DB_KEY_TIP: &str = "tip";
static DB_KEY_HEIGHT: &str = "height";
static DB_KEY_GENESIS_HASH: &str = "genesis_hash";
static DB_KEY_UTXO_SET_HASH: &str = "utxo_set_hash";
static DB_KEY_TOTAL_SUPPLY: &str = "total_supply";
static DB_KEY_STATE_TOTAL_SUPPLY: &[u8] = b"state:total_supply";
#[derive(Serialize, Deserialize, Clone)]
struct ReorgJournal {
    journal_id: String,
    old_tip_height: usize,
    old_tip_hash: [u8; 32],
    disconnect_depth: usize,
    new_block: Block,
}
fn start_reorg_journal(conn: &DB, journal_id: &str, journal: &ReorgJournal) -> Result<()> {
    let key = format!("reorg:pending:{}", journal_id);
    let data = bincode::serialize(journal)?;
    conn.put(key.as_bytes(), &data)?;
    Ok(())
}
fn commit_reorg_batch(conn: &DB, batch: WriteBatch, journal_id: &str) -> Result<()> {
    let mut write_opts = WriteOptions::default();
    write_opts.set_sync(true);
    conn.write_opt(&batch, &write_opts)?;
    let key = format!("reorg:pending:{}", journal_id);
    conn.delete(key.as_bytes())?;
    Ok(())
}
fn recover_pending_reorgs(conn: &DB, pow_engine: &Arc<PowEngine>) -> Result<()> {
    let iter = conn.iterator(IteratorMode::From(b"reorg:pending:", Direction::Forward));
    for item in iter {
        let (k, v) = item?;
        if !k.starts_with(b"reorg:pending:") { break; }
        let journal: ReorgJournal = bincode::deserialize(&v)?;
        let current_height = load_current_height(conn)?;
        let current_tip = load_current_tip(conn)?;
        if current_height == journal.old_tip_height && current_tip == journal.old_tip_hash {
            let mut batch = WriteBatch::default();
            let mut h = current_height;
            for _ in 0..journal.disconnect_depth {
                let blk = load_block_by_height(conn, h)?;
                build_block_ops(&blk, h, &BigUint::zero(), BlockAction::Disconnect, &mut batch, conn, pow_engine)?;
                h -= 1;
            }
            build_block_ops(&journal.new_block, h + 1, &BigUint::zero(), BlockAction::Connect, &mut batch, conn, pow_engine)?;
            let mut write_opts = WriteOptions::default();
            write_opts.set_sync(true);
            conn.write_opt(&batch, &write_opts)?;
            conn.delete(&k)?;
            info!("Recovered pending reorg from journal {}", journal.journal_id);
        } else {
            warn!("Pending reorg journal {} stale, discarding", journal.journal_id);
            conn.delete(&k)?;
        }
    }
    Ok(())
}
fn load_current_height(conn: &DB) -> Result<usize> {
    let height_bytes = conn.get(DB_KEY_HEIGHT)?.context("Missing height")?;
    Ok(u32::from_be_bytes(height_bytes.try_into()?) as usize)
}
fn load_current_tip(conn: &DB) -> Result<[u8; 32]> {
    let tip = conn.get(DB_KEY_TIP)?.context("Missing tip")?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&tip);
    Ok(arr)
}
fn load_block_by_height(conn: &DB, height: usize) -> Result<Block> {
    let mut key = b"h:".to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    let hash_bytes = conn.get(&key)?.context("Missing hash")?;
    let mut block_key = b"b:".to_vec();
    block_key.extend_from_slice(&hash_bytes);
    let block_bytes = conn.get(&block_key)?.context("Missing block")?;
    bincode::deserialize(&block_bytes).context("Deserialize block failed")
}
fn hash_utxo_entry(txid: &[u8; 32], vout: u32, output: &TXOutput) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 4 + 8 + output.script_pubkey.len());
    data.extend_from_slice(txid);
    data.extend_from_slice(&vout.to_be_bytes());
    data.extend_from_slice(&output.value.to_be_bytes());
    data.extend_from_slice(&output.script_pubkey);
    if let Some(comm) = &output.commitment {
        data.extend_from_slice(comm);
    }
    sha256d(&data)
}
fn xor_hash(a: &mut [u8; 32], b: &[u8; 32]) {
    for i in 0..32 {
        a[i] ^= b[i];
    }
}
#[derive(Clone)]
pub struct ChainState {
    pub blocks: BTreeMap<usize, Block>,
    pub height_to_hash: BTreeMap<usize, [u8; 32]>,
    pub hash_to_height: HashMap<[u8; 32], usize>,
    pub cumulative_work: BTreeMap<usize, BigUint>,
    pub timestamps: VecDeque<u32>,
    pub utxo_set_hash: [u8; 32],
    pub total_supply: u64,
}
#[derive(Default)]
struct StateChanges {
    new_blocks: HashMap<usize, Block>,
    new_height_to_hash: HashMap<usize, [u8; 32]>,
    new_hash_to_height: HashMap<[u8; 32], usize>,
    new_cumulative_work: HashMap<usize, BigUint>,
    timestamp_change: Option<u32>, // Some(ts) for push, None for pop
    utxo_set_hash: [u8; 32],
    total_supply: u64,
    new_hdr: Option<(usize, BlockHeader)>,
    new_tx_index: Vec<([u8; 32], (usize, usize))>,
    deleted_tx_index: Vec<[u8; 32]>,
}
#[derive(Clone)]
pub struct Chain {
    pub db_pool: Pool,
    pub state: Arc<TokioRwLock<ChainState>>,
    pub best_tip: [u8; 32],
    pub best_height: usize,
    pub orphan_blocks: HashMap<[u8; 32], (Block, Instant)>,
    target_cache: TokioRwLock<LruCache<u32, BigUint>>,
    genesis_hash: [u8; 32],
    batch_pending: Arc<AtomicBool>,
    work_cache: TokioRwLock<LruCache<usize, BigUint>>,
    read_only_mode: Arc<AtomicBool>,
    pow_engine: Arc<PowEngine>,
    state_lock: tokio::sync::Mutex<()>,
    config: Arc<AppConfig>,
    cache_quota: Quota,
    mempool: Arc<TokioRwLock<Mempool>>,
}
impl Chain {
    pub async fn new(db_pool: Pool, genesis: Block, pow_engine: Arc<PowEngine>, config: Arc<AppConfig>, mempool: Arc<TokioRwLock<Mempool>>) -> Result<Self> {
        let genesis_hash = genesis.header_hash(&pow_engine)?;
        let mut chain = Self {
            db_pool,
            state: Arc::new(TokioRwLock::new(ChainState {
                blocks: BTreeMap::new(),
                height_to_hash: BTreeMap::new(),
                hash_to_height: HashMap::with_capacity(10000),
                cumulative_work: BTreeMap::new(),
                timestamps: VecDeque::with_capacity(11),
                utxo_set_hash: [0u8; 32],
                total_supply: 0,
            })),
            best_tip: [0; 32],
            best_height: 0,
            orphan_blocks: HashMap::with_capacity(500),
            target_cache: TokioRwLock::new(LruCache::new(LRU_CACHE_SIZE)),
            genesis_hash,
            batch_pending: Arc::new(AtomicBool::new(false)),
            work_cache: TokioRwLock::new(LruCache::new(LRU_CACHE_SIZE * 2)),
            read_only_mode: Arc::new(AtomicBool::new(false)),
            pow_engine,
            state_lock: tokio::sync::Mutex::new(()),
            config,
            cache_quota: Quota::per_hour(nonzero!(1000000u32)).allow_burst(nonzero!(1000u32)),
            mempool,
        };
        chain.init_genesis_async(&genesis).await?;
        info!("LYRION chain initialized with genesis block");
        Ok(chain)
    }
    async fn init_genesis_async(&mut self, genesis: &Block) -> Result<()> {
        let target = compact_to_target(genesis.header.bits);
        let work = TWO_POW_256.clone() / (target + BigUint::from(1u32));
        let mut batch = WriteBatch::default();
        self.apply_block_action(genesis, 0, BlockAction::Connect, true, work, &mut batch).await?;
        Ok(())
    }
    pub async fn load_from_db(db_pool: Pool, pow_engine: Arc<PowEngine>, config: Arc<AppConfig>, mempool: Arc<TokioRwLock<Mempool>>) -> Result<Self> {
        let conn = db_pool.get()?;
        recover_pending_reorgs(&conn, &pow_engine)?;
        let tip = conn.get(DB_KEY_TIP)?.context("Missing tip")?;
        let mut best_tip = [0u8; 32];
        best_tip.copy_from_slice(&tip);
        let height_bytes = conn.get(DB_KEY_HEIGHT)?.context("Missing height")?;
        let best_height = u32::from_be_bytes(height_bytes.try_into().context("Invalid height bytes")? ) as usize;
        let genesis_hash_bytes = conn.get(DB_KEY_GENESIS_HASH)?.context("Missing genesis_hash")?;
        let mut genesis_hash = [0u8; 32];
        genesis_hash.copy_from_slice(&genesis_hash_bytes);
        let mut chain = Chain {
            db_pool: db_pool.clone(),
            state: Arc::new(TokioRwLock::new(ChainState {
                blocks: BTreeMap::new(),
                height_to_hash: BTreeMap::new(),
                hash_to_height: HashMap::with_capacity(best_height + 1),
                cumulative_work: BTreeMap::new(),
                timestamps: VecDeque::new(),
                utxo_set_hash: [0u8; 32],
                total_supply: 0,
            })),
            best_tip,
            best_height,
            orphan_blocks: HashMap::new(),
            target_cache: TokioRwLock::new(LruCache::new(LRU_CACHE_SIZE)),
            genesis_hash,
            batch_pending: Arc::new(AtomicBool::new(false)),
            work_cache: TokioRwLock::new(LruCache::new(LRU_CACHE_SIZE * 2)),
            read_only_mode: Arc::new(AtomicBool::new(false)),
            pow_engine,
            state_lock: tokio::sync::Mutex::new(()),
            config,
            cache_quota: Quota::per_hour(nonzero!(1000000u32)).allow_burst(nonzero!(1000u32)),
            mempool,
        };
        let prune_start = best_height.saturating_sub(PRUNE_DEPTH);
        let mut cum_work = BigUint::zero();
        let snapshot = RocksSnapshot::new(&conn);
        for h in 0..=best_height {
            let mut key = b"h:".to_vec();
            key.extend_from_slice(&h.to_be_bytes());
            let hash_bytes = snapshot.get(&key)?.context("Missing hash")?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            let header = if h >= prune_start {
                let full = chain.load_block_from_db(h).await?;
                let mut state = chain.state.write().await;
                state.blocks.insert(h, full.clone());
                state.timestamps.push_back(full.header.timestamp);
                if state.timestamps.len() > 11 { state.timestamps.pop_front(); }
                drop(state);
                full.header
            } else {
                chain.load_header(h).await?
            };
            let target = compact_to_target(header.bits);
            cum_work += TWO_POW_256.clone() / (target + BigUint::from(1u32));
            let mut state = chain.state.write().await;
            state.height_to_hash.insert(h, hash);
            state.hash_to_height.insert(hash, h);
            state.cumulative_work.insert(h, cum_work.clone());
            drop(state);
            chain.work_cache.write().await.put(h, cum_work.clone());
        }
        if chain.state.read().await.cumulative_work.get(&best_height) != Some(&cum_work) {
            bail!(ChainError::InvalidBlock("Chain work mismatch".into()));
        }
        chain.validate_state().await?;
        chain.validate_supply_smart().await?;
        info!("LYRION chain loaded from DB at height {} – supply validated", best_height);
        Ok(chain)
    }
    pub async fn load_block_from_db(&self, height: usize) -> Result<Block> {
        let conn = self.db_pool.get()?;
        let mut key = b"h:".to_vec();
        key.extend_from_slice(&height.to_be_bytes());
        let hash_bytes = conn.get(key)?.context("Missing hash")?;
        let mut block_key = b"b:".to_vec();
        block_key.extend_from_slice(&hash_bytes);
        let block_bytes = conn.get(block_key)?.context("Missing block")?;
        let block: Block = deserialize(&block_bytes).context("Deserialize block failed")?;
        Ok(block)
    }
    pub async fn load_header(&self, height: usize) -> Result<BlockHeader> {
        let conn = self.db_pool.get()?;
        let mut key = b"hdr:".to_vec();
        key.extend_from_slice(&height.to_be_bytes());
        if let Some(bytes) = conn.get(&key)? {
            return Ok(deserialize(&bytes)?);
        }
        // fallback if very old node without hdr:
        let block = self.load_block_from_db(height).await?;
        Ok(block.header)
    }
    pub async fn save_block(&self, height: usize, block: &Block) -> Result<()> {
        let conn = self.db_pool.get()?;
        let mut batch = WriteBatch::default();
        let hash = block.header_hash(&self.pow_engine)?;
        let mut block_key = b"b:".to_vec();
        block_key.extend_from_slice(&hash);
        let block_bytes = serialize(block).context("Serialize block failed")?;
        batch.put(block_key, block_bytes);
        let mut height_key = b"h:".to_vec();
        height_key.extend_from_slice(&height.to_be_bytes());
        batch.put(height_key, hash);
        batch.put(DB_KEY_TIP, hash);
        batch.put(DB_KEY_HEIGHT, (height as u32).to_be_bytes());
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        retry(|| conn.write_opt(&batch, &write_opts)).context("Write error")?;
        info!("Block saved at height {}", height);
        Ok(())
    }
    pub async fn get_headers(&self, locator: [u8; 32], stop: [u8; 32]) -> Result<Vec<BlockHeader>> {
        let mut headers = Vec::new();
        let state = self.state.read().await;
        let start_height = match state.hash_to_height.get(&locator) {
            Some(&h) => h + 1,
            None => return Ok(vec![]),
        };
        drop(state);
        let max_headers = 2000;
        for height in start_height..=self.best_height {
            if headers.len() >= max_headers {
                break;
            }
            let header = self.load_header(height).await?;
            let hash = header.hash(&self.pow_engine)?;
            headers.push(header);
            if hash == stop {
                break;
            }
        }
        Ok(headers)
    }
    enum BlockAction {
        Connect,
        Disconnect,
    }
    async fn apply_block_action(&mut self, block: &Block, height: usize, action: BlockAction, is_best: bool, work: BigUint, batch: &mut WriteBatch) -> Result<()> {
        let _lock = self.state_lock.lock().await;
        if self.batch_pending.load(Ordering::Relaxed) {
            bail!("Batch pending, cannot apply action");
        }
        if self.read_only_mode.load(Ordering::Relaxed) && matches!(action, BlockAction::Connect) {
            bail!("Chain in read-only mode due to previous failure");
        }
        self.batch_pending.store(true, Ordering::Relaxed);
        let start_time = Instant::now();
        let conn = self.db_pool.get()?;
        let snapshot = RocksSnapshot::new(&conn);
        let cf_utxo = conn.cf_handle("utxo").context("UTXO CF missing")?;
        let cf_anonymous = conn.cf_handle("anonymous").context("Anonymous CF missing")?;
        let cf_key_images = conn.cf_handle("key_images").context("Key images CF missing")?;
        let cf_coinbase = conn.cf_handle("coinbase").context("Coinbase CF missing")?;
        let cf_addr_index = conn.cf_handle("addr_index").context("ADDR INDEX CF missing")?;
        let cf_tx_index = conn.cf_handle("tx_index").context("TX INDEX CF missing")?;
        let hash = block.header_hash(&self.pow_engine)?;
        let mut rollback_ops = Vec::new();
        let mut changes = StateChanges::default();
        self.apply_utxo_changes(block, height, &work, batch, &snapshot, cf_utxo, cf_anonymous, cf_key_images, cf_coinbase, cf_addr_index, &mut rollback_ops, &mut changes, matches!(action, BlockAction::Connect)).await?;
        changes.new_blocks.insert(height, block.clone());
        changes.new_height_to_hash.insert(height, hash);
        changes.new_hash_to_height.insert(hash, height);
        if let Some(prev_work) = self.state.read().await.cumulative_work.get(&(height - 1)).cloned() {
            changes.new_cumulative_work.insert(height, prev_work + work.clone());
        } else {
            changes.new_cumulative_work.insert(height, work.clone());
        }
        match action {
            BlockAction::Connect => {
                changes.timestamp_change = Some(block.header.timestamp);
                if changes.timestamps.len() > 11 {
                    changes.timestamps.pop_front();
                }
                let mut hdr_key = b"hdr:".to_vec();
                hdr_key.extend_from_slice(&height.to_be_bytes());
                batch.put(hdr_key, serialize(&block.header)?);
                changes.new_hdr = Some((height, block.header.clone()));
                for (idx, tx) in block.txs.iter().enumerate() {
                    let txid = tx.hash();
                    batch.put_cf(cf_tx_index, txid, serialize(&(height, idx))?);
                    changes.new_tx_index.push((txid, (height, idx)));
                }
                let current_supply = load_supply_from_db(&conn)?;
                let new_supply = current_supply + subsidy(height);
                batch.put(DB_KEY_STATE_TOTAL_SUPPLY, new_supply.to_le_bytes());
                changes.total_supply = new_supply;
            }
            BlockAction::Disconnect => {
                changes.timestamp_change = None;
                for tx in &block.txs {
                    let txid = tx.hash();
                    batch.delete_cf(cf_tx_index, txid);
                    changes.deleted_tx_index.push(txid);
                }
                let current_supply = load_supply_from_db(&conn)?;
                let new_supply = current_supply - subsidy(height);
                batch.put(DB_KEY_STATE_TOTAL_SUPPLY, new_supply.to_le_bytes());
                changes.total_supply = new_supply;
            }
        }
        let mut write_opts = WriteOptions::default();
        let res = retry(|| conn.write_opt(batch, &write_opts)).context("Write error");
        if res.is_err() {
            error!("Write failed: {}. Attempting rollback.", res.as_ref().unwrap_err());
            let mut rollback_batch = WriteBatch::default();
            for (cf, key, value) in rollback_ops.into_iter().rev() {
                if let Some(v) = value {
                    rollback_batch.put_cf(cf, key, v);
                } else {
                    rollback_batch.delete_cf(cf, key);
                }
            }
            let mut rollback_attempts = 0;
            while rollback_attempts < 3 {
                if conn.write_opt(&rollback_batch, &write_opts).is_ok() {
                    return res;
                }
                rollback_attempts += 1;
            }
            error!("Rollback failed after 3 attempts. Entering safe read-only mode.");
            METRIC_ROLLBACK_FAILURE.inc();
            self.read_only_mode.store(true, Ordering::Relaxed);
            return res;
        }
        {
            let mut state = self.state.write().await;
            for (h, b) in changes.new_blocks {
                state.blocks.insert(h, b);
            }
            for (h, hash) in changes.new_height_to_hash {
                state.height_to_hash.insert(h, hash);
            }
            for (hash, h) in changes.new_hash_to_height {
                state.hash_to_height.insert(hash, h);
            }
            for (h, w) in changes.new_cumulative_work {
                state.cumulative_work.insert(h, w);
            }
            if let Some(ts) = changes.timestamp_change {
                state.timestamps.push_back(ts);
                if state.timestamps.len() > 11 {
                    state.timestamps.pop_front();
                }
            } else {
                state.timestamps.pop_back();
            }
            state.utxo_set_hash = changes.utxo_set_hash;
            state.total_supply = changes.total_supply;
        }
        if matches!(action, BlockAction::Connect) && is_best {
            self.best_tip = hash;
            self.best_height = height;
            if height > PRUNE_DEPTH {
                let mut state = self.state.write().await;
                self.prune(height - PRUNE_DEPTH, batch, &conn, cf_addr_index, &mut state).await?;
            }
        }
        METRIC_VALIDATION_TIME.observe(start_time.elapsed().as_secs_f64());
        info!("Block action applied at height {}: {:?}", height, action);
        self.batch_pending.store(false, Ordering::Relaxed);
        if height % 5000 == 0 {
            conn.compact_range(None::<&[u8]>, None::<&[u8]>);
        }
        Ok(())
    }
    enum Action {
        Connect,
        Disconnect,
    }
    async fn handle_utxo_action(
        &self,
        cf: &ColumnFamily,
        is_anonymous: bool,
        tx: &Transaction,
        snapshot: &RocksSnapshot<'_>,
        batch: &mut WriteBatch,
        rollback_ops: &mut Vec<(&ColumnFamily, Vec<u8>, Option<Vec<u8>>)>,
        current_set_hash: &mut [u8; 32],
        current_supply: &mut u64,
        action: Action,
        cf_addr_index: &ColumnFamily,
    ) -> Result<()> {
        let is_connect = matches!(action, Action::Connect);
        if tx.is_coinbase() {
            let cf_coinbase = self.conn.cf_handle("coinbase").unwrap();
            let txid = tx.hash();
            if is_connect {
                batch.put_cf(cf_coinbase, txid, height.to_be_bytes());
                rollback_ops.push((cf_coinbase, txid.to_vec(), None));
            } else {
                if let Some(prev) = snapshot.get_cf(cf_coinbase, txid)? {
                    rollback_ops.push((cf_coinbase, txid.to_vec(), Some(prev)));
                }
                batch.delete_cf(cf_coinbase, txid);
            }
            return Ok(());
        }
        if is_anonymous {
            for vin in &tx.inputs {
                if vin.script_sig.len() < 32 { bail!(ChainError::InvalidScript); }
                let key_image = KeyImage::from_slice(&vin.script_sig[0..32]).context(ChainError::InvalidKeyImage)?;
                let exists = snapshot.get_cf(cf_key_images, key_image.as_bytes())?.is_some();
                if exists && is_connect { METRIC_CONSENSUS_ERRORS.inc(); bail!(ChainError::DoubleSpend); }
                if is_connect {
                    batch.put_cf(cf_key_images, key_image.as_bytes(), height.to_be_bytes());
                    rollback_ops.push((cf_key_images, key_image.as_bytes().to_vec(), None));
                } else {
                    if let Some(prev) = snapshot.get_cf(cf_key_images, key_image.as_bytes())? {
                        rollback_ops.push((cf_key_images, key_image.as_bytes().to_vec(), Some(prev)));
                    }
                    batch.delete_cf(cf_key_images, key_image.as_bytes());
                }
                let mut key = b"a:".to_vec();
                key.extend_from_slice(&vin.txid);
                key.extend_from_slice(&vin.vout.to_be_bytes());
                if let Some(prev) = snapshot.get_cf(cf, &key)? {
                    let prev_out: TXOutput = deserialize(&prev).context("Deserialize prev_out failed")?;
                    let element_hash = hash_utxo_entry(&vin.txid, vin.vout, &prev_out);
                    if is_connect {
                        xor_hash(current_set_hash, &element_hash);
                        *current_supply = current_supply.checked_sub(prev_out.value).ok_or(ChainError::ValueOverflow)?;
                        rollback_ops.push((cf, key.clone(), Some(prev.clone())));
                        batch.delete_cf(cf, key);
                    } else {
                        xor_hash(current_set_hash, &element_hash);
                        *current_supply = current_supply.checked_add(prev_out.value).ok_or(ChainError::ValueOverflow)?;
                        batch.put_cf(cf, &key, prev.clone());
                        rollback_ops.push((cf, key, None));
                    }
                } else {
                    bail!(ChainError::MissingUTXO);
                }
            }
        } else {
            for vin in &tx.inputs {
                let mut key = b"u:".to_vec();
                key.extend_from_slice(&vin.txid);
                key.extend_from_slice(&vin.vout.to_be_bytes());
                if let Some(prev) = snapshot.get_cf(cf, &key)? {
                    let prev_out: TXOutput = deserialize(&prev).context("Deserialize prev_out failed")?;
                    let element_hash = hash_utxo_entry(&vin.txid, vin.vout, &prev_out);
                    if is_connect {
                        xor_hash(current_set_hash, &element_hash);
                        *current_supply = current_supply.checked_sub(prev_out.value).ok_or(ChainError::ValueOverflow)?;
                        rollback_ops.push((cf, key.clone(), Some(prev.clone())));
                        batch.delete_cf(cf, key);
                    } else {
                        xor_hash(current_set_hash, &element_hash);
                        *current_supply = current_supply.checked_add(prev_out.value).ok_or(ChainError::ValueOverflow)?;
                        batch.put_cf(cf, &key, prev.clone());
                        rollback_ops.push((cf, key, None));
                    }
                } else {
                    bail!(ChainError::MissingUTXO);
                }
            }
        }
        let outputs_iter = if is_connect { tx.outputs.iter().enumerate() } else { tx.outputs.iter().rev().enumerate() };
        for (vout, out) in outputs_iter {
            let mut key = if is_anonymous { b"a:".to_vec() } else { b"u:".to_vec() };
            key.extend_from_slice(&tx.hash());
            key.extend_from_slice(&(vout as u32).to_be_bytes());
            let element_hash = hash_utxo_entry(&tx.hash(), vout as u32, out);
            if is_connect {
                xor_hash(current_set_hash, &element_hash);
                *current_supply = current_supply.checked_add(out.value).ok_or(ChainError::ValueOverflow)?;
                let serialized_out = serialize(out).context("Serialize out failed")?;
                batch.put_cf(cf, &key, serialized_out);
                rollback_ops.push((cf, key.clone(), None));
            } else {
                xor_hash(current_set_hash, &element_hash);
                *current_supply = current_supply.checked_sub(out.value).ok_or(ChainError::ValueOverflow)?;
                if let Some(prev) = snapshot.get_cf(cf, &key)? {
                    rollback_ops.push((cf, key.clone(), Some(prev.clone())));
                }
                batch.delete_cf(cf, key);
            }
            if is_anonymous { continue; }
            let mut addr_key = b"addr:".to_vec();
            addr_key.extend_from_slice(&hash160(&out.script_pubkey));
            addr_key.extend_from_slice(&tx.hash());
            addr_key.extend_from_slice(&(vout as u32).to_be_bytes());
            if is_connect {
                batch.put_cf(cf_addr_index, &addr_key, &out.value.to_be_bytes());
                rollback_ops.push((cf_addr_index, addr_key.clone(), None));
            } else {
                if let Some(prev) = snapshot.get_cf(cf_addr_index, &addr_key)? {
                    rollback_ops.push((cf_addr_index, addr_key.clone(), Some(prev)));
                }
                batch.delete_cf(cf_addr_index, &addr_key);
            }
        }
        Ok(())
    }
    async fn apply_utxo_changes(&self, block: &Block, height: usize, work: &BigUint, batch: &mut WriteBatch, snapshot: &RocksSnapshot<'_>, cf_utxo: &ColumnFamily, cf_anonymous: &ColumnFamily, cf_key_images: &ColumnFamily, cf_coinbase: &ColumnFamily, cf_addr_index: &ColumnFamily, rollback_ops: &mut Vec<(&ColumnFamily, Vec<u8>, Option<Vec<u8>>)>, changes: &mut StateChanges, is_connect: bool) -> Result<()> {
        let mut current_set_hash = self.state.read().await.utxo_set_hash;
        let mut current_supply = self.state.read().await.total_supply;
        let action = if is_connect { Action::Connect } else { Action::Disconnect };
        for tx in &block.txs {
            let cf = if tx.is_anonymous { cf_anonymous } else { cf_utxo };
            self.handle_utxo_action(cf, tx.is_anonymous, tx, snapshot, batch, rollback_ops, &mut current_set_hash, &mut current_supply, action, cf_addr_index)?;
        }
        changes.utxo_set_hash = current_set_hash;
        changes.total_supply = current_supply;
        batch.put(DB_KEY_UTXO_SET_HASH, current_set_hash);
        batch.put(DB_KEY_TOTAL_SUPPLY, current_supply.to_be_bytes());
        Ok(())
    }
    async fn prune(&mut self, height: usize, batch: &mut WriteBatch, conn: &DB, cf_addr_index: &ColumnFamily, state: &mut ChainState) -> Result<()> {
        let _lock = self.state_lock.lock().await;
        if let Some(block) = state.blocks.remove(&height) {
            let hash = block.header_hash(&self.pow_engine)?;
            // Removal of the block and height only
            let mut block_key = b"b:".to_vec();
            block_key.extend_from_slice(&hash);
            batch.delete(block_key);
            // we keep height_to_hash and hash_to_height → locators work on pruned node
            // state.height_to_hash and hash_to_height remain in memory for recent blocks + loaded via h:
            // Update address indexes for outputs of the pruned block
            for tx in &block.txs {
                if tx.is_anonymous { continue; }
                let txid = tx.hash();
                for vout in 0..tx.outputs.len() as u32 {
                    let out = &tx.outputs[vout as usize];
                    let mut addr_key = b"addr:".to_vec();
                    addr_key.extend_from_slice(&hash160(&out.script_pubkey));
                    addr_key.extend_from_slice(&txid);
                    addr_key.extend_from_slice(&vout.to_be_bytes());
                    batch.delete_cf(cf_addr_index, &addr_key);
                }
            }
        }
        Ok(())
    }
    pub async fn add_block(&mut self, block: Block, _mempool_unused: &mut Mempool) -> Result<bool> {
        let _lock = self.state_lock.lock().await;
        let hash = block.header_hash(&self.pow_engine)?;
        let state_read = self.state.read().await;
        if state_read.hash_to_height.contains_key(&hash) { return Ok(false); }
        drop(state_read);
        let prev_hash = block.header.prev_hash;
        let prev_height = match self.state.read().await.hash_to_height.get(&prev_hash) {
            Some(&h) => h,
            None => {
                self.orphan_blocks.insert(hash, (block, Instant::now()));
                METRIC_ORPHANS.inc();
                if self.orphan_blocks.len() > 500 {
                    let oldest = self.orphan_blocks.iter().min_by_key(|_, (_, time)| *time).expect("Oldest missing").0.clone();
                    self.orphan_blocks.remove(&oldest);
                }
                return Ok(false);
            }
        };
        let height = prev_height + 1;
        let val_start = Instant::now();
        let block_clone = block.clone();
        let chain_clone = self.clone();
        tokio::task::spawn_blocking(move || {
            Chain::validate_block(&block_clone, &chain_clone, height)
        }).await.context("Validation panic")??;
        METRIC_VALIDATION_TIME.observe(val_start.elapsed().as_secs_f64());
        let bits = block.header.bits;
        let mut cache_guard = self.target_cache.write().await;
        let target = cache_guard.get_or_insert(bits, || compact_to_target(bits)).clone();
        drop(cache_guard);
        let block_work = TWO_POW_256.clone() / (target + BigUint::from(1u32));
        let prev_work = self.state.read().await.cumulative_work.get(&prev_height).cloned().unwrap_or_default();
        let new_work = prev_work + block_work;
        let current_work = self.state.read().await.cumulative_work.get(&self.best_height).cloned().unwrap_or_default();
        let mut batch = WriteBatch::default();
        let mut reorg = false;
        if new_work > current_work {
            if self.best_height.saturating_sub(prev_height) > REORG_MAX_DEPTH {
                warn!("Reorg too deep (>100), alerting for potential fork attack");
                bail!(ChainError::ReorgTooDeep);
            }
            let mut current_chain_work = current_work.clone();
            let mut new_chain_work = new_work.clone();
            if new_chain_work <= current_chain_work * BigUint::from(99u32) / BigUint::from(100u32) {
                warn!("New chain work too low, possible attack");
                bail!(ChainError::ReorgTooDeep);
            }
            // Journal
            let journal_id = now_ms()?.to_string();
            let disconnect_depth = self.best_height - prev_height;
            let journal = ReorgJournal {
                journal_id: journal_id.clone(),
                old_tip_height: self.best_height,
                old_tip_hash: self.best_tip,
                disconnect_depth,
                new_block: block.clone(),
            };
            let conn = self.db_pool.get()?;
            start_reorg_journal(&conn, &journal_id, &journal)?;
            // 1. Disconnect the old chain (Rollback)
            let mut current_h = self.best_height;
            while current_h > prev_height {
                let blk = self.load_block_from_db(current_h).await?;
                self.build_block_ops(&blk, current_h, &BigUint::zero(), BlockAction::Disconnect, &mut batch)?;
                current_h -= 1;
            }
            // 2. Connect the new chain (Roll forward)
            self.build_block_ops(&block, height, &block_work, BlockAction::Connect, &mut batch)?;
            // 3. Atomic Commit
            commit_reorg_batch(&conn, batch, &journal_id)?;
            // 4. Update memory state only after DB success
            self.best_height = height;
            reorg = true;
            warn!("Reorganization performed at height {}", height);
        } else {
            self.apply_block_action(&block, height, BlockAction::Connect, reorg, block_work, &mut batch).await?;
        }
        self.save_block(height, &block).await?;
        let mut m = self.mempool.write().await;
        for tx in &block.txs { m.remove(&tx.hash()); }
        drop(m);
        self.process_orphans().await?;
        if reorg { warn!("Reorganization performed at height {}", height); }
        if height % 1000 == 0 {
            self.validate_state().await?;
        }
        if height % 5000 == 0 {
            let conn = self.db_pool.get()?;
            conn.compact_range(None::<&[u8]>, None::<&[u8]>);
        }
        Ok(reorg)
    }
    fn build_block_ops(
        &self,
        block: &Block,
        height: usize,
        work: &BigUint,
        action: BlockAction,
        batch: &mut WriteBatch
    ) -> Result<()> {
        let start_time = Instant::now();
        let conn = self.db_pool.get()?;
        let snapshot = RocksSnapshot::new(&conn);
        let cf_utxo = conn.cf_handle("utxo").context("UTXO CF missing")?;
        let cf_anonymous = conn.cf_handle("anonymous").context("Anonymous CF missing")?;
        let cf_key_images = conn.cf_handle("key_images").context("Key images CF missing")?;
        let cf_coinbase = conn.cf_handle("coinbase").context("Coinbase CF missing")?;
        let cf_addr_index = conn.cf_handle("addr_index").context("ADDR INDEX CF missing")?;
        let cf_tx_index = conn.cf_handle("tx_index").context("TX INDEX CF missing")?;
        let hash = block.header_hash(&self.pow_engine)?;
        let mut rollback_ops = Vec::new();
        let mut changes = StateChanges::default();
        self.apply_utxo_changes(block, height, work, batch, &snapshot, cf_utxo, cf_anonymous, cf_key_images, cf_coinbase, cf_addr_index, &mut rollback_ops, &mut changes, matches!(action, BlockAction::Connect)).await?;
        changes.new_blocks.insert(height, block.clone());
        changes.new_height_to_hash.insert(height, hash);
        changes.new_hash_to_height.insert(hash, height);
        if let Some(prev_work) = self.state.read().await.cumulative_work.get(&(height - 1)).cloned() {
            changes.new_cumulative_work.insert(height, prev_work + work.clone());
        } else {
            changes.new_cumulative_work.insert(height, work.clone());
        }
        match action {
            BlockAction::Connect => {
                changes.timestamp_change = Some(block.header.timestamp);
                if changes.timestamps.len() > 11 {
                    changes.timestamps.pop_front();
                }
                let mut hdr_key = b"hdr:".to_vec();
                hdr_key.extend_from_slice(&height.to_be_bytes());
                batch.put(hdr_key, serialize(&block.header)?);
                changes.new_hdr = Some((height, block.header.clone()));
                for (idx, tx) in block.txs.iter().enumerate() {
                    let txid = tx.hash();
                    batch.put_cf(cf_tx_index, txid, serialize(&(height, idx))?);
                    changes.new_tx_index.push((txid, (height, idx)));
                }
            }
            BlockAction::Disconnect => {
                changes.timestamp_change = None;
                for tx in &block.txs {
                    let txid = tx.hash();
                    batch.delete_cf(cf_tx_index, txid);
                    changes.deleted_tx_index.push(txid);
                }
            }
        }
        batch.put(DB_KEY_UTXO_SET_HASH, current_set_hash);
        batch.put(DB_KEY_TOTAL_SUPPLY, current_supply.to_be_bytes());
        Ok(())
    }
    pub async fn process_orphans(&mut self) -> Result<()> {
        let now = Instant::now();
        self.orphan_blocks.retain(|_, (_, time)| now.duration_since(*time) < ORPHAN_TTL);
        if self.orphan_blocks.len() > 500 {
            let oldest = self.orphan_blocks.iter().min_by_key(|(_, (_, time))| *time).expect("Oldest missing").0.clone();
            self.orphan_blocks.remove(&oldest);
        }
        let mut to_process: Vec<([u8; 32], Block)> = self.orphan_blocks.drain().map(|(h, (b, _))| (h, b)).collect();
        let mut depth = 0;
        while !to_process.is_empty() && depth < 500 {
            depth += 1;
            let mut added = false;
            let mut next = Vec::new();
            for (hash, block) in to_process {
                if self.add_block(block).await? { added = true; } else { next.push((hash, block)); }
            }
            if !added { break; }
            to_process = next;
        }
        for (h, b) in to_process { self.orphan_blocks.insert(h, (b, Instant::now())); }
        METRIC_ORPHANS.set(self.orphan_blocks.len() as i64);
        Ok(())
    }
    pub fn get_genesis_hash(&self) -> [u8; 32] { self.genesis_hash }
    pub async fn validate_state(&self) -> Result<()> {
        let conn = self.db_pool.get()?;
        let stored_supply_bytes = conn.get(DB_KEY_TOTAL_SUPPLY)?;
        let state_supply = self.state.read().await.total_supply;
        if let Some(bytes) = stored_supply_bytes {
            let db_val = u64::from_be_bytes(bytes.try_into()?);
            if db_val != state_supply {
                error!("CRITICAL: In-memory supply ({}) differs from DB supply ({})", state_supply, db_val);
                bail!(ChainError::SupplyMismatch);
            }
        }
        Ok(())
    }
    pub async fn validate_state_full(&self) -> Result<()> {
    let conn = self.db_pool.get()?;
    let cf_utxo = conn.cf_handle("utxo").context("UTXO CF missing")?;
    let cf_anonymous = conn.cf_handle("anonymous").context("Anonymous CF missing")?;
    let (utxo_res, anon_res) = tokio::join!(
        tokio::task::spawn_blocking(move || compute_cf_supply(&conn, cf_utxo)),
        tokio::task::spawn_blocking(move || compute_cf_supply(&conn, cf_anonymous)),
    );
    let full_supply = utxo_res?? + anon_res??;
    let mut total_supply = 0u64;
    for h in 0..=self.best_height {
        total_supply = total_supply.checked_add(subsidy(h)).ok_or(ChainError::ValueOverflow)?;
    }
    if full_supply != total_supply {
        bail!(ChainError::InvalidBlock("Supply mismatch".into()));
    }
    Ok(())
    }
    pub async fn validate_supply_full(&self) -> Result<()> {
    let conn = self.db_pool.get()?;
    let cf_utxo = conn.cf_handle("utxo").context("UTXO CF missing")?;
    let cf_anonymous = conn.cf_handle("anonymous").context("Anonymous CF missing")?;
    let (utxo_res, anon_res) = tokio::join!(
        tokio::task::spawn_blocking(move || compute_cf_supply(&conn, cf_utxo)),
        tokio::task::spawn_blocking(move || compute_cf_supply(&conn, cf_anonymous)),
    );
    let utxo_supply = utxo_res??;
    let anon_supply = anon_res??;
    let mut calculated_supply = 0u64;
    for height in 0..=self.best_height {
        calculated_supply = calculated_supply.checked_add(subsidy(height)).ok_or(ChainError::ValueOverflow)?;
    }
    if utxo_supply + anon_supply != calculated_supply {
        bail!(ChainError::SupplyMismatch);
    }
    Ok(())
}
    pub async fn validate_supply_smart(&self) -> Result<()> {
        let conn = self.db_pool.get()?;
        let saved_hash = conn.get(DB_KEY_UTXO_SET_HASH)?;
        let saved_supply = conn.get(DB_KEY_TOTAL_SUPPLY)?;
        if let (Some(hash_bytes), Some(supply_bytes)) = (saved_hash, saved_supply) {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            let supply = u64::from_be_bytes(supply_bytes.try_into()?);
            let mut calculated_supply = 0u128;
            for height in 0..=self.best_height {
                calculated_supply += subsidy(height) as u128;
            }
            if calculated_supply != supply as u128 {
                bail!(ChainError::SupplyMismatch);
            } else {
                info!("Fast Validation: Supply matches theoretical value ({} LYRION). UTXO Set Hash: {:x?}", supply as f64 / 1e9, hash);
                let mut state = self.state.write().await;
                state.total_supply = supply;
                state.utxo_set_hash = hash;
                return Ok(());
            }
        }
        self.validate_supply_full().await
    }
    pub async fn validate_block(block: &Block, chain: &Chain, height: usize) -> Result<()> {
        if block.size() > MAX_BLOCK_SIZE { bail!(ChainError::InvalidBlock("Block too large".into())); }
        let hash = block.header_hash(&chain.pow_engine)?;
        let target = compact_to_target(block.header.bits);
        if u256_from_be(&hash) > target { bail!(ChainError::InsufficientPoW); }
        if block.header.bits != calculate_next_bits(chain, height).await {
            bail!(ChainError::InvalidBlock("Invalid bits".into()));
        }
        if block.header.merkle_root != Block::compute_merkle_root(&block.txs) {
            bail!(ChainError::InvalidBlock("Invalid Merkle root".into()));
        }
        if block.txs.is_empty() || !block.txs[0].is_coinbase() {
            bail!(ChainError::InvalidBlock("No coinbase".into()));
        }
        let conn = chain.db_pool.get()?;
        let cf_utxo = conn.cf_handle("utxo")?;
        let cf_anonymous = conn.cf_handle("anonymous")?;
        let mut utxos = HashMap::new();
        let mut anon_outputs = HashMap::new();
        for tx in block.txs.iter().skip(1) {
            for vin in &tx.inputs {
                let mut key = if tx.is_anonymous { b"a:".to_vec() } else { b"u:".to_vec() };
                key.extend_from_slice(&vin.txid);
                key.extend_from_slice(&vin.vout.to_be_bytes());
                let cf = if tx.is_anonymous { cf_anonymous } else { cf_utxo };
                if let Some(value) = conn.get_cf(cf, &key)? {
                    let output: TXOutput = deserialize(&value).context("Deserialize output failed")?;
                    if tx.is_anonymous {
                        anon_outputs.insert((vin.txid, vin.vout), output);
                    } else {
                        utxos.insert((vin.txid, vin.vout), output);
                    }
                }
            }
        }
        for tx in &block.txs[1..] {
            validate_transaction(tx, chain, height).await?;
        }
        let total_fees: u64 = block.txs[1..].iter().map(|tx| tx.fee(if tx.is_anonymous { &anon_outputs } else { &utxos })).try_fold(0u64, u64::checked_add).ok_or(ChainError::InvalidCoinbaseFee)?;
        let expected = subsidy(height).checked_add(total_fees).ok_or(ChainError::InvalidCoinbaseFee)?;
        if block.txs[0].outputs.is_empty() || block.txs[0].outputs[0].value != expected {
            bail!(ChainError::InvalidCoinbaseFee);
        }
        let pc = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut batch_verifier = BatchVerifier::new();
        let mut block_input_commitments = Vec::new();
        let mut block_output_commitments = Vec::new();
        for tx in &block.txs {
            if tx.is_anonymous {
                for vin in &tx.inputs {
                    if let Some(out) = anon_outputs.get(&(vin.txid, vin.vout)) {
                        if let Some(comm) = &out.commitment {
                            let comm = CompressedRistretto::from_slice(comm).decompress().ok_or(ChainError::InvalidCommitment)?;
                            block_input_commitments.push(comm);
                        }
                    }
                }
                for out in &tx.outputs {
                    if let Some(comm) = &out.commitment {
                        let comm = CompressedRistretto::from_slice(comm).decompress().ok_or(ChainError::InvalidCommitment)?;
                        block_output_commitments.push(comm);
                    }
                }
                for (out, proof_bytes) in tx.outputs.iter().zip(&tx.range_proofs) {
                    let proof: RangeProof = deserialize(proof_bytes).context("Deserialize proof error")?;
                    let comm_bytes = out.commitment.as_ref().ok_or(ChainError::InvalidCommitment)?;
                    let comm = CompressedRistretto::from_slice(comm_bytes).decompress().ok_or(ChainError::InvalidCommitment)?;
                    batch_verifier.queue(&proof, &comm, out.value, &bp_gens);
                }
            }
        }
        if !batch_verifier.verify(&bp_gens).is_ok() {
            bail!(ChainError::InvalidRangeProof);
        }
        let sum_block_inputs = block_input_commitments.iter().fold(pc.commit(Scalar::zero(), Scalar::zero()), |acc, comm| acc + *comm);
        let sum_block_outputs = block_output_commitments.iter().fold(pc.commit(Scalar::zero(), Scalar::zero()), |acc, comm| acc + *comm);
        let fee_commit = pc.commit(Scalar::from(total_fees), Scalar::zero());
        if sum_block_inputs != sum_block_outputs + fee_commit {
            bail!(ChainError::InvalidCommitment);
        }
        let median_time = get_median_timestamp(chain, height - 1);
        let current_time = (now_ms()? / 1000) as u32;
        if block.header.timestamp <= median_time || block.header.timestamp > current_time + 7200 {
            bail!(ChainError::InvalidTimestamp);
        }
        if let Some(&expected_hash) = chain.config.checkpoint_hashes.get(&height) {
            if hash != expected_hash {
                bail!(ChainError::AttackDetected);
            }
        }
        Ok(())
    }
}
pub async fn calculate_next_bits(chain: &Chain, height: usize) -> u32 {
    if height % DIFFICULTY_ADJUST_INTERVAL != 0 {
        chain.load_header(height - 1).await.unwrap().bits
    } else {
        let start_height = height - DIFFICULTY_ADJUST_INTERVAL;
        let start_header = chain.load_header(start_height).await.unwrap();
        let end_header = chain.load_header(height - 1).await.unwrap();
        let actual_time = (end_header.timestamp - start_header.timestamp) as u128;
        let actual_time = actual_time.clamp(EXPECTED_TIME / 4, EXPECTED_TIME * 4);
        let old_target = compact_to_target(end_header.bits);
        let mut new_target = old_target * BigUint::from(actual_time) / BigUint::from(EXPECTED_TIME);
        let max_target = old_target.clone() * BigUint::from(4u32);
        let min_target = old_target / BigUint::from(4u32);
        if new_target > max_target { new_target = max_target; }
        if new_target < min_target { new_target = min_target; }
        let genesis_target = compact_to_target(0x1d00ffff);
        if new_target > genesis_target { new_target = genesis_target; }
        let median_time = get_median_timestamp(chain, height - 1);
        if end_header.timestamp <= median_time {
            new_target = old_target;
        }
        target_to_compact(new_target)
    }
}
pub fn get_median_timestamp(chain: &Chain, height: usize) -> u32 {
    let mut times = Vec::with_capacity(11);
    let conn = chain.db_pool.get().expect("DB get failed");
    for i in (height.saturating_sub(10)..=height).rev() {
        let mut key = b"h:".to_vec();
        key.extend_from_slice(&i.to_be_bytes());
        if let Some(hash_bytes) = conn.get(&key).expect("Get failed") {
            let mut block_key = b"b:".to_vec();
            block_key.extend_from_slice(&hash_bytes);
            if let Some(block_bytes) = conn.get(block_key).expect("Get block failed") {
                let block: Block = deserialize(&block_bytes).expect("Deserialize failed");
                times.push(block.header.timestamp);
            }
        }
    }
    times.sort_unstable();
    if times.is_empty() { 0 } else { times[times.len() / 2] }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use tempdir::TempDir;
    use std::fs::File;
    use std::io::Write;
    use secp256k1::{PublicKey, SecretKey};
    use rand::thread_rng;
    use crate::tx::TXOutput;
    #[tokio::test]
    async fn test_compact_target_vectors() {
        assert_eq!(compact_to_target(0x1d00ffff), BigUint::from(0xffffu32) << (8 * (0x1d - 3)));
        assert_eq!(target_to_compact(compact_to_target(0x1d00ffff)), 0x1d00ffff);
        let max_target = BigUint::from(1u32) << 256;
        assert_eq!(target_to_compact(max_target), 0x1d00ffff);
        assert_eq!(target_to_compact(BigUint::zero()), 0x1d00ffff);
        assert_eq!(compact_to_target(0), BigUint::zero());
    }
    #[tokio::test]
    async fn test_chain_init() {
        let db_pool = create_db_pool("test_db").expect("Pool failed");
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = sk.public_key(&SECP);
        let genesis = create_genesis_block(&pk, &Arc::new(PowEngine::new(&AppConfig::load().expect("Config failed")).expect("Pow failed"))).expect("Genesis failed");
        let pow_engine = Arc::new(PowEngine::new(&AppConfig::load().expect("Config failed")).expect("Pow failed"));
        let config = Arc::new(AppConfig::load().expect("Config failed"));
        let mempool = Arc::new(TokioRwLock::new(Mempool::new(100_000_000)));
        let chain = Chain::new(db_pool, genesis, pow_engine, config, mempool).await.expect("Chain failed");
        assert_eq!(chain.best_height, 0);
    }
    #[tokio::test]
    async fn test_chain_fork() {
        let db_pool = create_db_pool("test_fork_db").expect("Pool failed");
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = sk.public_key(&SECP);
        let genesis = create_genesis_block(&pk, &Arc::new(PowEngine::new(&AppConfig::load().expect("Config failed")).expect("Pow failed"))).expect("Genesis failed");
        let pow_engine = Arc::new(PowEngine::new(&AppConfig::load().expect("Config failed")).expect("Pow failed"));
        let config = Arc::new(AppConfig::load().expect("Config failed"));
        let mempool = Arc::new(TokioRwLock::new(Mempool::new(100_000_000)));
        let mut chain = Chain::new(db_pool, genesis.clone(), pow_engine, config, mempool).await.expect("Chain failed");
        let mut block1 = genesis.clone();
        block1.header.prev_hash = chain.best_tip;
        chain.add_block(block1).await.expect("Add failed");
        let mut block_fork = genesis.clone();
        block_fork.header.prev_hash = genesis.header_hash(&pow_engine).expect("Hash failed");
        block_fork.header.bits = 0x1d00ffff;
        chain.add_block(block_fork).await.expect("Add failed");
        assert_eq!(chain.best_height, 1);
    }
}
