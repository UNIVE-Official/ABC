use anyhow::{Context, Result};
use dashmap::DashMap;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::chain::Chain;
use crate::errors::ChainError;
use crate::tx::{TXOutput, Transaction, validate_transaction};
use crate::utils::{MIN_FEE_PER_BYTE, now_ms, LRU_CACHE_SIZE, MAX_PACKAGE_DEPTH, MAX_PACKAGE_SIZE};
use once_cell::sync::Lazy;
use prometheus::IntGauge;
use quota::Quota;
static FEE_CACHE: Lazy<DashMap<[u8; 32], u64>> = Lazy::new(|| DashMap::with_capacity_and_hasher_and_shard_amount(50000, RandomState::default(), 256, AhashHasher::default()));
static METRIC_MEMPOOL_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("lyrion_mempool_size", "Mempool size in bytes").unwrap_or_else(|_| IntGauge::new("lyrion_mempool_size_fallback", "Fallback").unwrap())
});
static METRIC_MEMPOOL_TX_COUNT: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("lyrion_mempool_tx_count", "Number of TXs in mempool").unwrap_or_else(|_| IntGauge::new("lyrion_mempool_tx_count_fallback", "Fallback").unwrap())
});
#[derive(Clone, Eq)]
pub struct MempoolEntry {
    pub tx: Arc<Transaction>,
    pub fee_per_byte: u64,
    pub time: u128,
    pub depends_on: HashSet<[u8; 32]>,
    pub fee: u64,
}
impl Ord for MempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.fee_per_byte.cmp(&self.fee_per_byte).then_with(|| self.time.cmp(&other.time))
    }
}
impl PartialOrd for MempoolEntry { fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) } }
impl PartialEq for MempoolEntry { fn eq(&self, other: &Self) -> bool { self.tx.hash() == other.tx.hash() } }
pub struct Mempool {
    pub txs: DashMap<[u8; 32], MempoolEntry>,
    heap: RwLock<BinaryHeap<MempoolEntry>>,
    total_bytes: AtomicUsize,
    by_parent: DashMap<[u8; 32], Vec<[u8; 32]>>,
    fee_index: DashMap<u64, BTreeSet<[u8; 32]>>,
    ttl_heap: RwLock<BinaryHeap<(u128, [u8; 32])>>,
    lru: RwLock<lru::LruCache<[u8; 32], ()>>,
    max_size: RwLock<usize>,
    expiration_index: DashMap<u128, Vec<[u8; 32]>>,
    avg_fee: Mutex<u64>,
    pub key_images: DashMap<[u8; 32], [u8; 32]>, // KeyImage -> TxID
}
impl Mempool {
    pub fn new(max_size: usize) -> Self {
        let instance = Self {
            txs: DashMap::with_capacity_and_hasher_and_shard_amount(50000, RandomState::default(), 256, AhashHasher::default()),
            heap: RwLock::new(BinaryHeap::with_capacity(50000)),
            total_bytes: AtomicUsize::new(0),
            by_parent: DashMap::with_capacity_and_hasher_and_shard_amount(10000, RandomState::default(), 256, AhashHasher::default()),
            fee_index: DashMap::with_capacity_and_hasher_and_shard_amount(1000, RandomState::default(), 256, AhashHasher::default()),
            ttl_heap: RwLock::new(BinaryHeap::new()),
            lru: RwLock::new(lru::LruCache::new(LRU_CACHE_SIZE)),
            max_size: RwLock::new(max_size),
            expiration_index: DashMap::with_capacity_and_hasher_and_shard_amount(10000, RandomState::default(), 256, AhashHasher::default()),
            avg_fee: Mutex::new(0),
            key_images: DashMap::new(),
        };
        METRIC_MEMPOOL_SIZE.set(0);
        METRIC_MEMPOOL_TX_COUNT.set(0);
        instance
    }
    pub async fn update_max_size(&self, new_max: usize) {
        let mut max = self.max_size.write().await;
        *max = new_max.min(256 * 1024 * 1024);
    }
    pub async fn insert(&self, tx: Transaction, chain: &Chain) -> Result<bool> {
        let txid = tx.hash();
        if self.txs.contains_key(&txid) { return Ok(false); }
        let size = tx.size();
        if size == 0 || size > 500_000 { bail!(ChainError::InvalidTx("Invalid size".into())); }
        let conn = chain.db_pool.get()?;
        let cf_utxo = conn.cf_handle("utxo")?;
        let cf_anonymous = conn.cf_handle("anonymous")?;
        let mut input_sum = 0u64;
        let mut depends_on = HashSet::with_capacity(tx.inputs.len());
        let mut depth = 0;
        let mut stack: Vec<[u8; 32]> = tx.inputs.iter().map(|vin| vin.txid).filter(|&id| self.txs.contains_key(&id)).collect();
        while !stack.is_empty() && depth < MAX_PACKAGE_DEPTH {
            depth += 1;
            let parent = stack.pop().unwrap();
            if depends_on.contains(&parent) { bail!("Cycle detected in dependencies"); }
            depends_on.insert(parent);
            if let Some(entry) = self.txs.get(&parent) {
                stack.extend(&entry.depends_on);
            }
        }
        if depth >= MAX_PACKAGE_DEPTH { bail!(ChainError::PackageDepthExceeded); }
        let mut package_size = size;
        for dep in &depends_on {
            if let Some(entry) = self.txs.get(dep) {
                package_size += entry.tx.size();
            }
            if package_size > MAX_PACKAGE_SIZE { bail!("Package size exceeded"); }
        }
        let mut outputs = HashMap::new();
        for vin in &tx.inputs {
            let mut key = if tx.is_anonymous { b"a:".to_vec() } else { b"u:".to_vec() };
            key.extend_from_slice(&vin.txid);
            key.extend_from_slice(&vin.vout.to_be_bytes());
            let cf = if tx.is_anonymous { cf_anonymous } else { cf_utxo };
            if let Some(value) = conn.get_cf(cf, &key)? {
                let output: TXOutput = deserialize(&value).context("Deserialize output failed")?;
                input_sum = input_sum.checked_add(output.value).ok_or(ChainError::ValueOverflow)?;
                outputs.insert((vin.txid, vin.vout), output);
            } else if self.txs.contains_key(&vin.txid) {
                depends_on.insert(vin.txid);
            } else {
                bail!(ChainError::MissingUTXO);
            }
        }
        let output_sum: u64 = tx.outputs.iter().map(|o| o.value).try_fold(0u64, u64::checked_add).ok_or(ChainError::ValueOverflow)?;
        let fee = input_sum.checked_sub(output_sum).ok_or(ChainError::ValueOverflow)?;
        let fee_per_byte = fee / size as u64;
        if let Some((_, old_entry)) = self.txs.get(&txid) {
            let old_fee = old_entry.fee;
            if fee < old_fee + (MIN_FEE_PER_BYTE * 2) * size as u64 { bail!(ChainError::InsufficientFee); }
        }
        if tx.is_anonymous {
            for vin in &tx.inputs {
                if vin.script_sig.len() < 32 { bail!(ChainError::InvalidScript); }
                let key_image_bytes: [u8; 32] = vin.script_sig[0..32].try_into().unwrap_or([0;32]);
                if self.key_images.contains_key(&key_image_bytes) {
                    bail!(ChainError::DoubleSpend); // Immediate rejection if already in mempool
                }
            }
        }
        let time = now_ms()?;
        let tx_arc = Arc::new(tx);
        let entry = MempoolEntry { tx: tx_arc.clone(), fee_per_byte, time, depends_on, fee };
        if tx.is_anonymous {
            for vin in &tx.inputs {
                if vin.script_sig.len() >= 32 {
                    let ki: [u8; 32] = vin.script_sig[0..32].try_into().unwrap();
                    self.key_images.insert(ki, txid);
                }
            }
        }
        self.txs.insert(txid, entry.clone());
        self.heap.write().await.push(entry.clone());
        self.ttl_heap.write().await.push((time, txid));
        self.expiration_index.entry(time).or_insert_with(|| Vec::with_capacity(10)).push(txid);
        self.total_bytes.fetch_add(size, AtomicOrdering::Relaxed);
        METRIC_MEMPOOL_SIZE.set(self.total_bytes.load(AtomicOrdering::Relaxed) as i64);
        METRIC_MEMPOOL_TX_COUNT.inc();
        for dep in &entry.depends_on {
            self.by_parent.entry(*dep).or_insert_with(|| Vec::with_capacity(5)).push(txid);
        }
        self.fee_index.entry(fee_per_byte).or_insert_with(BTreeSet::new).insert(txid);
        FEE_CACHE.insert(txid, fee);
        let mut lru = self.lru.write().await;
        lru.put(txid, ());
        let mut avg = self.avg_fee.lock().await;
        *avg = (*avg * (self.txs.len() as u64 - 1) + fee_per_byte) / self.txs.len() as u64;
        let max = *self.max_size.read().await;
        while self.total_bytes.load(AtomicOrdering::Relaxed) > max || self.txs.len() > 50000 {
            self.evict_low_fee_package().await;
        }
        self.remove_orphaned_txs().await;
        Ok(true)
    }
    async fn remove_orphaned_txs(&self) {
        let mut to_remove = Vec::new();
        for entry in self.txs.iter() {
            let deps = &entry.depends_on;
            for dep in deps {
                if !self.txs.contains_key(dep) {
                    to_remove.push(*entry.key());
                    break;
                }
            }
        }
        for txid in to_remove {
            self.remove(&txid);
        }
    }
    pub fn remove(&self, txid: &[u8; 32]) {
        if let Some((_, entry)) = self.txs.remove(txid) {
            if entry.tx.is_anonymous {
                for vin in &entry.tx.inputs {
                     if vin.script_sig.len() >= 32 {
                         let ki: [u8; 32] = vin.script_sig[0..32].try_into().unwrap();
                         self.key_images.remove(&ki);
                     }
                }
            }
            self.total_bytes.fetch_sub(entry.tx.size(), AtomicOrdering::Relaxed);
            METRIC_MEMPOOL_SIZE.set(self.total_bytes.load(AtomicOrdering::Relaxed) as i64);
            METRIC_MEMPOOL_TX_COUNT.dec();
            FEE_CACHE.remove(txid);
            if let Some((_, children)) = self.by_parent.remove(txid) {
                for child in children { self.remove(&child); }
            }
            if let Some(mut set) = self.fee_index.get_mut(&entry.fee_per_byte) {
                set.remove(txid);
            }
            if let Some(mut exp_list) = self.expiration_index.get_mut(&entry.time) {
                if let Some(pos) = exp_list.iter().position(|id| id == txid) { exp_list.remove(pos); }
            }
            let mut avg = self.avg_fee.lock().await;
            *avg = (*avg * (self.txs.len() as u64 + 1) - entry.fee_per_byte) / self.txs.len() as u64;
        }
    }
    pub async fn evict_low_fee_package(&self) {
        let avg_fee = *self.avg_fee.lock().await;
        let mut heap = self.heap.write().await;
        if let Some(low) = heap.pop() {
            if low.fee_per_byte < avg_fee / 2 {
                drop(heap);
                self.remove(&low.tx.hash());
                if let Some(children) = self.by_parent.get(&low.tx.hash()) {
                    for child in children.value() {
                        self.remove(child);
                    }
                }
            }
        }
    }
    pub fn select_txs(&self, max_size: usize) -> Vec<Transaction> {
        let mut selected = Vec::new();
        let mut size = 0;
        let mut included = HashSet::new();
        let mut visited_packages = HashSet::new();
        let mut fee_rates: Vec<u64> = self.fee_index.iter().map(|e| *e.key()).collect();
        fee_rates.sort_by(|a, b| b.cmp(a));
        for fee_rate in fee_rates {
            if size >= max_size { break; }
            if let Some(set) = self.fee_index.get(&fee_rate) {
                for txid in set.iter() {
                    if included.contains(txid) || visited_packages.contains(txid) { continue; }
                    if let Some(entry) = self.txs.get(txid) {
                        let mut package = vec![(*entry.tx).clone()];
                        let mut package_size = entry.tx.size();
                        let mut to_include = vec![*txid];
                        let mut stack: Vec<[u8; 32]> = entry.depends_on.iter().cloned().collect();
                        let mut visited = HashSet::new();
                        let mut depth = 0;
                        while let Some(parent) = stack.pop() {
                            depth += 1;
                            if depth > MAX_PACKAGE_DEPTH { break; }
                            if visited.contains(&parent) { continue; }
                            visited.insert(parent);
                            visited_packages.insert(parent);
                            if let Some(parent_entry) = self.txs.get(&parent) {
                                package.insert(0, (*parent_entry.tx).clone());
                                package_size += parent_entry.tx.size();
                                to_include.push(parent);
                                stack.extend(&parent_entry.depends_on);
                            }
                        }
                        if package_size <= max_size - size && package_size <= MAX_PACKAGE_SIZE {
                            selected.extend(package);
                            size += package_size;
                            for id in to_include { included.insert(id); }
                        }
                    }
                }
            }
        }
        selected
    }
    pub async fn clean_expired(&mut self, expiration_ms: u128) -> Result<()> {
        let now = now_ms()?;
        let mut to_remove = Vec::new();
        let ttl_heap = self.ttl_heap.read().await;
        for &(time, txid) in ttl_heap.iter() {
            if now.saturating_sub(time) > expiration_ms {
                to_remove.push(txid);
            } else {
                break;
            }
        }
        drop(ttl_heap);
        for txid in to_remove {
            self.remove(&txid);
            let mut ttl_heap = self.ttl_heap.write().await;
            ttl_heap.pop();
        }
        let mut exp_to_remove = Vec::new();
        for entry in self.expiration_index.iter() {
            if now.saturating_sub(*entry.key()) > expiration_ms {
                exp_to_remove.push(*entry.key());
            }
        }
        for key in exp_to_remove {
            self.expiration_index.remove(&key);
        }
        Ok(())
    }
}
