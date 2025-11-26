use anyhow::{bail, Context, Result};
use digest::Digest;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use parking_lot::Mutex as ParkingMutex;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
use secp256k1::Secp256k1;
use sha2::Sha256;
use ripemd::Ripemd160;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use base58check::ToBase58Check;
use num_cpus;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use crate::errors::ChainError;
use ed25519_dalek::Keypair;
use nix::unistd::Uid;
use nix::sys::stat::{fstat, Mode};
use nix::sys::mman::{mlock, munmap, mprotect, ProtFlags, MapFlags};
use tracing::{error, warn, info};
use prometheus::IntCounter;
use rayon::prelude::*;
use tokio::sync::Mutex;
use crate::config::AppConfig;
use byteorder::{BigEndian, ReadBytesExt};
use std::ptr;
use std::alloc::{alloc, Layout};
use scopeguard::defer;
use std::sync::atomic::{AtomicUsize, Ordering};
use secrecy::ExposeSecret;
use secrecy::SecretVec<u8>;
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::path::Path;
pub const MAX_BLOCK_SIZE: usize = 4_000_000;
pub const COINBASE_MATURITY: usize = 100;
pub const HALVING_INTERVAL: usize = 2_100_000;
pub const DIFFICULTY_ADJUST_INTERVAL: usize = 2016;
pub const TARGET_BLOCK_TIME: u128 = 60;
pub const EXPECTED_TIME: u128 = (TARGET_BLOCK_TIME as u128) * (DIFFICULTY_ADJUST_INTERVAL as u128);
pub const PRUNE_DEPTH: usize = 10080;
pub const REORG_MAX_DEPTH: usize = 2016;
pub const VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);
pub const PEER_TIMEOUT: Duration = Duration::from_secs(20);
pub const ORPHAN_TTL: Duration = Duration::from_secs(3600);
pub const MIN_FEE_PER_BYTE: u64 = 10;
pub const MAX_RING_SIZE: usize = 20;
pub const MSG_RATE_LIMIT: u32 = 10;
pub const LRU_CACHE_SIZE: usize = 500_000;
pub const MAX_MSG_DECOMPRESSED: usize = 16 * 1024 * 1024;
pub const MAX_PACKAGE_DEPTH: usize = 50;
pub const MAX_COMPRESSED_SIZE: usize = MAX_MSG_DECOMPRESSED / 4;
pub const MAX_PACKAGE_SIZE: usize = 1_000_000;
pub const ASSUME_VALID_DEPTH: usize = 10080;
pub const BATCH_SIZE: usize = 10_000;
pub const GENESIS_TIMESTAMP: u32 = 1732060800; // 2025-11-20 00:00:00 UTC
pub const INITIAL_SUBSIDY: u64 = 10_000_000_000; // 10.00000000 LYRION
pub const TAIL_SUBSIDY: u64 = 500_000_000; // 0.500000000 LYRION
pub const MAX_SUBSIDY_HALVINGS: usize = 64;
pub const ANON_FEE_MULTIPLIER_NUMERATOR: u128 = 3;
pub const ANON_FEE_MULTIPLIER_DENOMINATOR: u128 = 2;
pub static SECP: Lazy<Secp256k1<secp256k1::All>> = Lazy::new(|| Secp256k1::new());
pub static TWO_POW_256: Lazy<BigUint> = Lazy::new(|| BigUint::from(1u32) << 256);
pub static RANDOMX_FLAGS: Lazy<RandomXFlag> = Lazy::new(|| {
    let flags_large = RandomXFlag::FLAG_DEFAULT | RandomXFlag::FLAG_LARGE_PAGES | RandomXFlag::FLAG_HARD_AES;
    if RandomXCache::new(flags_large).is_ok() {
        flags_large
    } else {
        warn!("Huge pages unavailable, falling back to default flags");
        RandomXFlag::FLAG_DEFAULT
    }
});
pub static RANDOMX_CACHE: Lazy<Result<RandomXCache>> = Lazy::new(|| RandomXCache::new(*RANDOMX_FLAGS).context("RandomX cache init failed"));
pub static RANDOMX_DATASET: Lazy<Result<Arc<RandomXDataset>>> = Lazy::new(|| {
    let cache = RANDOMX_CACHE.as_ref()?;
    RandomXDataset::new(*RANDOMX_FLAGS, cache).context("RandomX dataset init failed").map(Arc::new)
});
macro_rules! lazy_metric {
    ($name:literal, $desc:literal) => {
        Lazy::new(|| {
            IntCounter::new($name, $desc).unwrap_or_else(|_| IntCounter::new(concat!($name, "_fallback"), concat!("Fallback counter for ", $desc)).unwrap())
        });
    };
}
pub static METRIC_CLOCK_DRIFT: Lazy<IntCounter> = lazy_metric!("lyrion_clock_drift", "Number of clock drift incidents");
pub static METRIC_RANDOMX_ERRORS: Lazy<IntCounter> = lazy_metric!("lyrion_randomx_errors", "RandomX initialization errors");
/// Compute supply from a single column family (UTXO or Anonymous)
fn compute_cf_supply(db: &rocksdb::DB, cf: &rocksdb::ColumnFamily) -> Result<u64> {
    let snapshot = rocksdb::Snapshot::new(db);
    let mut sum = 0u64;
    let iter = snapshot.iterator_cf(cf, rocksdb::IteratorMode::Start);
    for item in iter {
        let (_, v) = item?;
        let out: TXOutput = bincode::deserialize(&v).context("Deserialize failed in supply validation")?;
        sum = sum.checked_add(out.value).ok_or(ChainError::ValueOverflow)?;
    }
    Ok(sum)
}
pub struct PowEngine {
    pub pool: Vec<ParkingMutex<RandomXVM>>,
    idx: AtomicUsize,
}
impl PowEngine {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let num_threads = config.num_randomx_threads.max(1).min(64);
        let mut pool = Vec::with_capacity(num_threads as usize);
        let dataset = RANDOMX_DATASET.as_ref()?.clone();
        let cache = RANDOMX_CACHE.as_ref()?.clone();
        for _ in 0..num_threads {
            let vm = RandomXVM::new(*RANDOMX_FLAGS, cache.clone(), Some(&dataset)).map_err(|e| {
                METRIC_RANDOMX_ERRORS.inc();
                anyhow::Error::from(e)
            })?;
            pool.push(ParkingMutex::new(vm));
        }
        Ok(Self { pool, idx: AtomicUsize::new(0) })
    }
    pub fn hash(&self, data: &[u8]) -> Result<[u8; 32]> {
        if self.pool.is_empty() {
            bail!("RandomX pool empty");
        }
        let idx = self.idx.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        let mut vm = self.pool[idx].lock();
        let mut hash = [0u8; 32];
        vm.calculate_hash(data, &mut hash).context("RandomX hash failed")?;
        Ok(hash)
    }
}
pub fn pow_hash(header: &[u8], engine: &PowEngine) -> Result<[u8; 32]> {
    engine.hash(header)
}
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let h1 = hasher.finalize();
    hasher = Sha256::new();
    hasher.update(&h1);
    let h2 = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha = hasher.finalize();
    hash_ripemd160(&sha)
}
pub fn hash_ripemd160(data: &[u8]) -> [u8; 20] {
    let mut ripemd = Ripemd160::new();
    ripemd.update(data);
    let ripe = ripemd.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}
pub fn u256_from_hash(hash: [u8; 32]) -> BigUint {
    BigUint::from_bytes_be(&hash)
}
pub fn u256_from_be(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}
pub fn compact_to_target(bits: u32) -> BigUint {
    if bits == 0 { return BigUint::zero(); }
    let exp = (bits >> 24) as usize;
    if exp > 80 { bail!(ChainError::InvalidBlock("target exponent too large")); } // ← protection DoS
    let mut mant = BigUint::from(bits & 0x007fffff);
    if bits & 0x00800000 != 0 {
        mant += BigUint::from(1u32) << 23;
    }
    if exp > 3 {
        mant <<= 8 * (exp - 3);
    } else if exp < 3 {
        mant >>= 8 * (3 - exp);
    }
    mant
}
pub fn target_to_compact(mut target: BigUint) -> u32 {
    if target.is_zero() { return 0x1d00ffff; }
    let size = (target.bits() + 7) / 8;
    if size > 80 { return 0x1d00ffff; } // ← additional protection
    let mut compact = 0u32;
    if size <= 3 {
        let mant = target.to_u32_digits().get(0).cloned().unwrap_or(0).min(0x007fffff);
        compact = mant << (8 * (3 - size as u32));
    } else {
        target >>= 8 * (size - 3);
        let mant = target.to_u32_digits().get(0).cloned().unwrap_or(0).min(0x007fffff);
        compact = mant;
    }
    let exp = if compact & 0x00800000 != 0 {
        compact >>= 8;
        (size + 1) as u32
    } else {
        size as u32
    };
    compact |= exp << 24;
    compact
}
pub fn now_ms() -> Result<u128> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .map_err(|e| {
            error!("System time error: {}. Recommending NTP sync.", e);
            METRIC_CLOCK_DRIFT.inc();
            ChainError::InvalidTimestamp.into()
        })
}
pub fn subsidy(height: usize) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= MAX_SUBSIDY_HALVINGS {
        TAIL_SUBSIDY
    } else {
        INITIAL_SUBSIDY.checked_shr(halvings as u32).unwrap_or(0)
    }
}
pub fn pubkey_to_address(pubkey: &secp256k1::PublicKey) -> String {
    let mut payload = vec![0];
    payload.extend_from_slice(&hash160(&pubkey.serialize()));
    payload.to_base58check()
}
pub fn secure_load_file(path: &str) -> Result<SecretVec<u8>> {
    let file = OpenOptions::new().read(true).open(path).context("Unable to open the secret file")?;
    let meta_fd = fstat(file.as_raw_fd()).context("Unable to get fstat on FD")?;
    if meta_fd.st_uid != Uid::effective().as_raw() {
        bail!(ChainError::FilePermissionError("Wrong owner".into()));
    }
    let mode = Mode::from_bits_truncate(meta_fd.st_mode);
    if mode.intersects(Mode::from_bits_truncate(0o077)) {
        bail!(ChainError::FilePermissionError("Permissions too broad".into()));
    }
    if meta_fd.st_size > 4096 {
        bail!(ChainError::FilePermissionError("Key file too large".into()));
    }
    let mut buf = vec![0u8; meta_fd.st_size as usize];
    file.read_exact(&mut buf).context("Reading secret file")?;
    let secret = SecretVec::new(buf);
    Ok(secret)
}
pub fn load_keypair(path: &str) -> Result<ed25519_dalek::Keypair> {
    let bytes = secure_load_file(path).context("Load file failed")?;
    if bytes.expose_secret().len() != 32 {
        bail!(ChainError::InvalidEncryptionKey);
    }
    let secret = ed25519_dalek::SecretKey::from_bytes(bytes.expose_secret()).context("Invalid secret key bytes")?;
    let public = ed25519_dalek::PublicKey::from(&secret);
    Ok(ed25519_dalek::Keypair { secret, public })
}
#[cfg(target_os = "linux")]
pub fn init_huge_pages() -> Result<()> {
    let size = 2 * 1024 * 1024 * 1024;
    let ptr = unsafe { nix::sys::mman::mmap(
        std::ptr::null_mut(),
        size,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_HUGETLB,
        -1,
        0,
    ).context("Mmap failed")? };
    if ptr.is_null() {
        warn!("Failed to init huge pages; falling back to standard allocation.");
        return Ok(());
    }
    unsafe { munmap(ptr, size).context("Munmap failed")?; }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub fn init_huge_pages() -> Result<()> {
    warn!("Huge pages not supported on this OS; using standard allocation.");
    Ok(())
}
pub fn secure_save_secret(path: &str, data: &[u8]) -> Result<()> {
    let tmp_path = format!("{}.tmp", path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .context("Failed to create temporary key file")?;
    file.write_all(data)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use nix::unistd::fchown;
        use nix::unistd::Uid;
        let uid = Uid::effective();
        fchown(file.as_raw_fd(), Some(uid), None)?;
    }
    fs::rename(&tmp_path, path).context("Atomic rename failed")?;
    if let Some(parent_dir) = Path::new(path).parent() {
        let dir_file = OpenOptions::new()
            .read(true)
            .open(parent_dir)
            .context("Unable to open parent directory for fsync")?;
        dir_file.sync_all().context("Failed to fsync parent directory")?;
    }
    Ok(())
}
pub fn header_hash(header: &BlockHeader, engine: &PowEngine) -> Result<[u8; 32]> {
    let serialized = bincode::serialize(header)?;
    engine.hash(&serialized)
}
pub fn address_to_pubkey_hash(address: &str) -> Result<[u8; 20]> {
    let (_version, payload) = base58check::from_check(address)?;
    Ok(payload.try_into().map_err(|_| anyhow::anyhow!("Invalid payload length"))?)
}
pub fn pubkey_to_anon_address(pubkey: &monero_serai::keys::PublicKey) -> String {
    let mut payload = vec![1u8]; // version 1 = anonymous address
    payload.extend_from_slice(&pubkey.to_bytes());
    payload.to_base58check()
}
pub fn address_to_anon_pubkey(addr: &str) -> Result<monero_serai::keys::PublicKey> {
    let (version, payload) = base58check::from_check(addr)?;
    if version != 1 || payload.len() != 32 {
        bail!("Not a valid anonymous address");
    }
    Ok(monero_serai::keys::PublicKey::from_bytes(&payload)?)
}
