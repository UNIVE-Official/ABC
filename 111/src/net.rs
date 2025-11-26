use anyhow::{bail, Context, Result};
use governor::{RateLimiter, Rate, Jitter, clock::ReasonablyAccurate, state::keyed::DefaultKeyedStateStore, middleware::NoOpMiddleware};
use tracing::{error, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, broadcast};
use tokio::task::{self, JoinSet};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use rustls::{ClientConfig, ServerConfig, RootCertStore, Certificate, PrivateKey};
use webpki_roots::TLS_SERVER_ROOTS;
use crate::config::AppConfig;
use crate::utils::{hash160, PEER_TIMEOUT, MSG_RATE_LIMIT, secure_load_file, now_ms, load_keypair, MAX_MSG_DECOMPRESSED, ChainError, MAX_COMPRESSED_SIZE};
use deadpool_rocksdb::Pool;
use bincode::deserialize;
use bincode::serialize;
use nonzero_ext::nonzero;
use rand::seq::SliceRandom;
use rand::thread_rng;
use crate::tx::Block;
use crate::tx::BlockHeader;
use tokio::sync::RwLock;
use tracing::trace;
use ed25519_dalek::PublicKey;
use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use libp2p::PeerId;
use prometheus::IntGauge;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use snappy;
use ring::rand::SystemRandom;
use dashmap::DashMap;
use zeroize::ZeroizeMut;
use crate::tx::Block;
use crate::tx::BlockHeader;
use governor::Quota;
use once_cell::sync::Lazy;
use lazy_static::lazy_static;
use tokio::sync::Semaphore;
lazy_static! {
    static ref BLOCKING_SEMAPHORE: Semaphore = Semaphore::new(32);
}
static METRIC_TIME_DRIFT: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("lyrion_time_drift", "Peer time drift in seconds").unwrap_or_else(|_| IntGauge::new("lyrion_time_drift_fallback", "Fallback").unwrap())
});
static METRIC_PEERS_CONNECTED: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("lyrion_peers_connected", "Number of connected peers").unwrap_or_else(|_| IntGauge::new("lyrion_peers_connected_fallback", "Fallback").unwrap())
});
const VERSION: u32 = 1;
const MIN_VERSION: u32 = 1;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300);
const SIGNATURE_CACHE_TTL_MS: u128 = 3600_000;
const MAX_PEERS_PER_SUBNET: usize = 2; // hardened against eclipse
const CONN_TIMEOUT: Duration = Duration::from_secs(10);
const MSG_GETADDR: u32 = 9;
const MSG_ADDR: u32 = 10;
const MSG_PING: u32 = 11;
const MSG_PONG: u32 = 12;
const MSG_GETHEADERS: u32 = 4;
const MSG_HEADERS: u32 = 8;
const MSG_GETDATA: u32 = 3; // used for TX and BLOCK depending on inv type
const MSG_TX: u32 = 5;
const MSG_BLOCK: u32 = 6;
#[derive(Clone)]
pub struct Peer {
    stream: TokioRwLock<TlsStream<TcpStream>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    reputation: i8,
    version: u32,
    height: usize,
    peer_id: PeerId,
    score: AtomicI32, // Behavior score (starts at 100)
}
impl Peer {
    pub fn penalize(&self, cost: i32) {
        let new_score = self.score.fetch_sub(cost, Ordering::Relaxed);
        if new_score <= 0 {
            self.ban();
        }
    }
    fn ban(&self) {
        warn!("Banning peer {} for malicious behavior", self.peer_id);
        // Close connection and add IP to blacklist in DB
    }
}
pub struct PeerManager {
    peers: TokioRwLock<HashMap<IpAddr, Vec<Arc<Peer>>>>,
    peers_by_id: TokioRwLock<HashMap<PeerId, (IpAddr, Arc<Peer>)>>,
    bans: TokioRwLock<HashMap<IpAddr, Instant>>,
    bans_persistent: TokioRwLock<HashMap<IpAddr, Instant>>,
    inv_tx: mpsc::Sender<(u32, [u8; 32])>,
    block_tx: broadcast::Sender<Block>,
    tip_change_tx: broadcast::Sender<[u8; 32]>,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    rate_limiter_ip: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, ReasonablyAccurate, NoOpMiddleware>>,
    rate_limiter_peer: Arc<RateLimiter<PeerId, DefaultKeyedStateStore<PeerId>, ReasonablyAccurate, NoOpMiddleware>>,
    db_pool: Pool,
    shutdown_tx: broadcast::Sender<()>,
    chain: Arc<RwLock<Chain>>,
    mempool: Arc<RwLock<Mempool>>,
    config: Arc<AppConfig>,
    signature_cache: DashMap<PeerId, (PublicKey, u128)>,
    rpc_rate_limiter: Arc::new(RateLimiter::keyed(Quota::per_second(nonzero!(10)))),
    known_peers: TokioRwLock<Vec<String>>, // "ip:port"
    pending_inv: DashMap<PeerId, usize>, // anti-flood
    node_keypair: ed25519_dalek::Keypair,
}
impl PeerManager {
    pub async fn new(node_keypair: ed25519_dalek::Keypair) -> Result<Arc<Self>> {
        let pm = Arc::new(Self {
            peers: TokioRwLock::new(HashMap::new()),
            peers_by_id: TokioRwLock::new(HashMap::new()),
            bans: TokioRwLock::new(HashMap::new()),
            bans_persistent: TokioRwLock::new(HashMap::new()),
            inv_tx: mpsc::Sender<(u32, [u8; 32])>,
            block_tx: broadcast::Sender<Block>,
            tip_change_tx: broadcast::Sender<[u8; 32]>,
            acceptor: TlsAcceptor,
            connector: TlsConnector,
            rate_limiter_ip: Arc::new(RateLimiter::keyed(Quota::per_second(Quota::per_second(nonzero!(MSG_RATE_LIMIT)))),
            rate_limiter_peer: Arc::new(RateLimiter::keyed(Quota::per_second(nonzero!(MSG_RATE_LIMIT)))),
            db_pool: Pool,
            shutdown_tx: broadcast::Sender<()>,
            chain: Arc<RwLock<Chain>>,
            mempool: Arc<RwLock<Mempool>>,
            config: Arc<AppConfig>,
            signature_cache: DashMap::new(),
            rpc_rate_limiter: Arc::new(RateLimiter::keyed(Quota::per_second(nonzero!(10)))),
            known_peers: TokioRwLock::new(vec![]),
            pending_inv: DashMap::new(),
            node_keypair,
        });
        // Add seeds to known_peers
        let mut kp = pm.known_peers.write().await;
        kp.extend(config.seed_nodes.iter().cloned());
        drop(kp);
        // Automatic reconnection task
        let pm_clone = pm.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(30)).await;
                let peer_count = pm_clone.peers.read().await.len();
                if peer_count < pm_clone.config.max_peers / 2 {
                    let known = pm_clone.known_peers.read().await.clone();
                    for addr in known.choose_multiple(&mut thread_rng(), 10) {
                        if let Ok(tcp) = timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                            if let Ok(tcp) = tcp {
                                pm_clone.add_peer(stream, ip).await;
                            }
                        }
                    }
                }
            }
        });
        Ok(pm)
    }
    pub async fn add_peer(&self, mut stream: TlsStream<TcpStream>, ip: IpAddr) {
        if self.is_banned(ip).await {
            return;
        }
        let peers_guard = self.peers.read().await;
        let conns = peers_guard.get(&ip).map(|v| v.len()).unwrap_or(0);
        if conns >= self.config.max_peers / 10 || peers_guard.len() >= self.config.max_peers {
            drop(peers_guard);
            return;
        }
        let subnet = match ip {
            IpAddr::V4(ip4) => IpAddr::V4(ip4.octets()[0..3].iter().cloned().chain([0]).collect::<Vec<u8>>().try_into().unwrap()),
            IpAddr::V6(ip6) => IpAddr::V6(ip6.octets()[0..14].iter().cloned().chain([0, 0]).collect::<Vec<u8>>().try_into().unwrap()),
        };
        let subnet_conns = peers_guard.get(&subnet).map(|v| v.len()).unwrap_or(0);
        if subnet_conns >= MAX_PEERS_PER_SUBNET {
            warn!("Too many peers from subnet {}", subnet);
            return;
        }
        drop(peers_guard);
        let our_keypair = self.node_keypair.clone();
        let our_pub = our_keypair.public.to_bytes();
        let peer_id = PeerId::from_bytes(&our_pub).context("PeerId from bytes failed")?;
        let peer = Arc::new(Peer {
            stream: TokioRwLock::new(stream),
            write_tx: mpsc::channel(100).0,
            reputation: 0,
            version: 0,
            height: 0,
            peer_id,
            score: AtomicI32::new(100),
        });
        if self.handshake(&peer).await.is_err() {
            self.decrease_reputation(&peer, ip).await;
            return;
        }
        let peer_addr = format!("{}:{}", ip, self.config.p2p_port);
        self.known_peers.write().await.push(peer_addr.clone());
        // Broadcast Addr of the new peer
        let msg = serialize(&(MSG_ADDR, now_ms()?, vec![peer_addr.clone()]))?;
        self.broadcast(msg).await;
        // Request GetAddr to the new peer
        peer.write_tx.send(serialize(&MSG_GETADDR).unwrap()).await.ok();
        let mut peers_write = self.peers.write().await;
        peers_write.entry(ip).or_insert_with(Vec::new).push(peer.clone());
        METRIC_PEERS_CONNECTED.set(peers_write.len() as i64);
        drop(peers_write);
        let mut peers_by_id = self.peers_by_id.write().await;
        peers_by_id.insert(peer.peer_id, (ip, peer.clone()));
        drop(peers_by_id);
        let shutdown_rx = self.shutdown_tx.subscribe();
        let inv_tx_clone = self.inv_tx.clone();
        let block_tx_clone = self.block_tx.clone();
        let tip_change_tx_clone = self.tip_change_tx.clone();
        let chain_clone = self.chain.clone();
        let mempool_clone = self.mempool.clone();
        let peer_clone_write = peer.clone();
        let mut join_set = JoinSet::new();
        join_set.spawn(async move {
            while let Some(mut msg) = peer_clone_write.write_tx.recv().await {
                if msg.len() > 1024 {
                    let compressed = snappy::compress(&msg).map_err(|_| ChainError::DecompressionFailed)?;
                    msg = compressed;
                    msg.insert(0, 1);
                } else {
                    msg.insert(0, 0);
                }
                let mut stream = peer_clone_write.stream.write().await;
                if let Ok(()) = stream.write_tx.try_send(msg) {
                    if let Err(e) = stream.flush().await {
                        return;
                    }
                } else {
                    warn!("Peer channel full, dropping {}", ip);
                    return;
                }
            }
        });
        let peer_clone_heartbeat = peer.clone();
        join_set.spawn(async move {
            let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
            loop {
                interval.tick().await;
                if peer_clone_heartbeat.write_tx.send(vec![0; 1]).await.is_err() {
                    break;
                }
            }
        });
        join_set.spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let mut buf = vec![0u8; MAX_MESSAGE_SIZE + 1];
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    res = timeout(PEER_TIMEOUT, peer.stream.read().await.read(&mut buf)) => {
                        match res {
                            Ok(Ok(len)) if len > 0 && len <= MAX_MESSAGE_SIZE => {
                                let is_compressed = buf[0] == 1;
                                let mut data = buf[1..len].to_vec();
                                // MOVE TO A DEDICATED THREAD
                                let permit = BLOCKING_SEMAPHORE.acquire().await.unwrap();
                                let processed_data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                                    if is_compressed {
                                        if data.len() > MAX_COMPRESSED_SIZE { bail!(ChainError::AttackDetected); }
                                        let decomp = snappy::uncompress(&data).map_err(|_| ChainError::DecompressionFailed)?;
                                        if decomp.len() > MAX_MSG_DECOMPRESSED { bail!(ChainError::AttackDetected); }
                                        Ok(decomp)
                                    } else {
                                        Ok(data)
                                    }
                                }).await??; // Double ? for join error and internal error
                                drop(permit);
                                // Message processing with decompressed data
                                if data.len() < 4 { bail!(ChainError::InvalidBlock("Message too short".into())); }
                                if let Err(e) = self.handle_message(&processed_data, &peer, ip, inv_tx_clone.clone(), block_tx_clone.clone(), tip_change_tx_clone.clone(), chain_clone.clone(), mempool_clone.clone()).await {
                                    error!("Peer message error {}: {}", ip, e);
                                    self.decrease_reputation(&peer, ip).await;
                                }
                            }
                            Ok(Ok(len)) if len > MAX_MESSAGE_SIZE => {
                                warn!("Oversized message from {}", ip);
                                self.decrease_reputation(&peer, ip).await;
                            }
                            _ => {
                                warn!("Peer timeout or disconnection {}", ip);
                                break;
                            }
                        }
                    }
                }
            }
            self.remove_peer(ip, &peer).await;
        });
        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                error!("Peer task error: {}", e);
            }
        }
    }
    async fn is_banned(&self, ip: IpAddr) -> bool {
        let mut bans = self.bans.write().await;
        bans.retain(|_, expiry| Instant::now() < *expiry);
        let mut persistent = self.bans_persistent.write().await;
        persistent.retain(|_, expiry| Instant::now() < *expiry);
        bans.contains_key(&ip) || persistent.contains_key(&ip)
    }
    async fn handshake(&self, peer: &Arc<Peer>) -> Result<()> {
        let chain = self.chain.read().await;
        let genesis_hash = chain.get_genesis_hash();
        drop(chain);
        let timestamp = now_ms()? / 1000;
        let mut nonce = [0u8; 12];
        SystemRandom::new().fill(&mut nonce).context("Nonce generation error")?;
        let mut msg = serialize(&VERSION).context("Serialize version error")?;
        msg.extend_from_slice(&genesis_hash);
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg.extend_from_slice(&nonce);
        let our_keypair = self.node_keypair.clone();
        let our_pub = our_keypair.public.to_bytes();
        let mut to_sign = msg.clone();
        to_sign.extend_from_slice(&our_pub);
        let our_sig = our_keypair.sign(&to_sign);
        let mut handshake_msg = to_sign;
        handshake_msg.extend_from_slice(&our_sig.to_bytes());
        peer.write_tx.send(handshake_msg).await.context("Send handshake error")?;
        let mut buf = vec![0u8; 0 + msg.len() + 32 + 64 + 4];
        let mut stream_read = peer.stream.read().await;
        timeout(HANDSHAKE_TIMEOUT, stream_read.read_exact(&mut buf)).await.context("Handshake timeout")??;
        if buf.len() != msg.len() + 32 + 64 { bail!(ChainError::InvalidHandshake); }
        let msg_len = msg.len();
        let recv_pub_bytes: [u8; 32] = buf[msg_len..msg_len + 32].try_into().context("Invalid pub")?;
        let mut recv_pub = PublicKey::from_bytes(&recv_pub_bytes).context("Invalid public key")?;
        let peer_id = PeerId::from_bytes(&recv_pub_bytes).context("PeerId from bytes failed")?;
        if let Some((cached_pub, cache_time)) = self.signature_cache.get(&peer_id) {
            if recv_pub == cached_pub && now_ms()? - cache_time < SIGNATURE_CACHE_TTL_MS {
                recv_pub_bytes.zeroize();
                return Ok(());
            }
        }
        let peer_sig = Signature::from_bytes(&buf[msg_len + 32..msg_len + 96])?.context("Invalid signature")?;
        let verify_data = [&buf[..msg_len], &recv_pub_bytes].concat();
        recv_pub.verify(&verify_data, &peer_sig).context("Signature verification failed")?;
        let recv_version = u32::from_le_bytes(buf[0..4].try_into()?);
        if recv_version < MIN_VERSION { bail!(ChainError::InvalidHandshake); }
        if buf[4..36] != genesis_hash {
            bail!(ChainError::InvalidHandshake);
        }
        let recv_timestamp = u64::from_le_bytes(buf[36..44].try_into().try_into()?);
        let recv_nonce = &buf[44..56];
        recv_nonce.zeroize_mut();
        if recv_nonce == [0; 12] { bail!(ChainError::InvalidHandshake); }
        let time_diff = (recv_timestamp as i64 - timestamp as i64).abs();
        METRIC_TIME_DRIFT.set(time_diff);
        if time_diff > 300 {
            bail!(ChainError::InvalidHandshake);
        }
        if time_diff > 60 {
            warn!("Handshake time drift: {}s from peer {}", time_diff, peer.peer_id);
        }
        self.signature_cache.insert(peer_id, (recv_pub, now_ms()?));
        peer.version = recv_version;
        recv_pub_bytes.zeroize();
        Ok(())
    }
    async fn handle_message(
        &self,
        data: &[u8],
        peer: &Arc<Peer>,
        ip: IpAddr,
        inv_tx: mpsc::Sender<(u32, [u8; 32])>,
        block_tx: broadcast::Sender<Block>,
        tip_change_tx: broadcast::Sender<[u8; 32]>,
        chain: Arc<RwLock<Chain>>,
        mempool: Arc<RwLock<Mempool>>,
    ) -> Result<()> {
        self.rate_limiter_ip.until_key_ready_with_jitter(&ip, Jitter::up_to(Duration::from_millis(100))).await;
        self.rate_limiter_peer.until_key_ready_with_jitter(&peer.peer_id, Jitter::up_to(Duration::from_millis(100))).await;
        if data.len() < 4 { bail!(ChainError::InvalidBlock("Message too short".into())); }
        let msg_type = u32::from_le_bytes(data[0..4].try_into().context("Invalid msg type")?);
        trace!("Received message of type {}", msg_type);
        // Anti INV flood
        if msg_type == 1 || msg_type == 2 {
            let count = self.pending_inv.entry(peer.peer_id).or_insert(0);
            *count += 1;
            if *count > 1000 {
                self.decrease_reputation(peer, ip).await;
                return Ok(());
            }
        }
        match msg_type {
            1 => {
                let hash: [u8; 32] = data[4..36].try_into().context("Invalid hash")?;
                let _ = inv_tx.send((1, hash)).await;
            }
            2 => {
                let hash: [u8; 32] = data[4..36].try_into().context("Invalid hash")?;
                let _ = inv_tx.send((2, hash)).await;
            }
            3 => {
                let inv_type = u32::from_le_bytes(data[4..8].try_into()?);
                let hash = [u8;32]::try_from(&data[8..40])?;
                if inv_type == 1 { // TX
                    if let Some(entry) = mempool.read().await.txs.get(&hash) {
                        let tx_data = serialize(&*entry.tx).context("Serialize tx failed")?;
                        let mut msg = MSG_TX.to_le_bytes().to_vec();
                        msg.extend_from_slice(&tx_data);
                        peer.write_tx.send(msg).await.ok();
                    }
                } else if inv_type == 2 { // BLOCK
                    let chain = self.chain.read().await;
                    let block = chain.load_block_from_db(chain.hash_to_height[&hash]).await?;
                    let payload = serialize(&block)?;
                    let mut msg = MSG_BLOCK.to_le_bytes().to_vec();
                    msg.extend_from_slice(&payload);
                    peer.write_tx.send(msg).await.ok();
                }
            }
            4 => {
                if data.len() < 40 { bail!(ChainError::InvalidBlock("GETHEADERS too short".into())); }
                let locator = <[u8;32]>::try_from(&data[4..36])?;
                let stop = if data.len() >= 72 { <[u8;32]>::try_from(&data[36..68])? } else { [0u8;32] };
                let headers = self.chain.read().await.get_headers(locator, stop).await?;
                let payload = serialize(&headers)?;
                let mut msg = MSG_HEADERS.to_le_bytes().to_vec();
                msg.extend(payload);
                peer.write_tx.send(msg).await.ok();
            }
            5 => {
                let tx: Transaction = deserialize(&data[4..])?;
                let mut mempool = self.mempool.write().await;
                let chain = self.chain.read().await;
                if let Ok(true) = mempool.insert(tx, &chain).await {
                    // Broadcast INV TX
                    let mut inv_msg = 1u32.to_le_bytes().to_vec();
                    inv_msg.extend_from_slice(&tx.hash());
                    self.broadcast(inv_msg).await;
                }
            }
            6 => {
                let block: Block = deserialize(&data[4..])?;
                let mut chain = self.chain.write().await;
                let mut mempool = self.mempool.write().await;
                if chain.add_block(block.clone()).await? {
                    // Broadcast INV BLOCK
                    let mut inv_msg = 2u32.to_le_bytes().to_vec();
                    inv_msg.extend_from_slice(&block.header_hash(&chain.pow_engine)?);
                    self.broadcast(inv_msg).await;
                }
            }
            8 => {
                let headers: Vec<BlockHeader> = deserialize(&data[4..]).context("Deserialize headers failed")?;
                if headers.is_empty() { return Ok(()); }
                let mut prev_hash = headers[0].prev_hash;
                let mut chain_write = self.chain.write().await;
                for header in headers {
                    let hash = header.hash(&chain_write.pow_engine)?;
                    if header.prev_hash != prev_hash {
                        bail!(ChainError::InvalidBlock("Discontinuous headers".into()));
                    }
                    prev_hash = hash;
                    let light_block = Block {
                        header: header.clone(),
                        txs: vec![],
                    };
                    let _ = chain_write.add_block(light_block).await;
                }
            }
            9 => {
                // GetAddr
                let addrs = self.known_peers.read().await.clone();
                let payload = serialize(&addrs)?;
                let mut msg = MSG_ADDR.to_le_bytes().to_vec();
                msg.extend(&payload);
                peer.write_tx.send(msg).await.ok();
            }
            10 => {
                // Addr
                let addrs: Vec<String> = deserialize(&data[4..])?;
                let mut known = self.known_peers.write().await;
                for addr in addrs {
                    if !known.contains(&addr) {
                        known.push(addr);
                    }
                }
            }
            11 => { // ping
                let nonce = data[4..12].try_into()?;
                let pong = [MSG_PONG.to_le_bytes(), nonce].concat();
                peer.write_tx.send(pong).await.ok();
            }
            12 => { /* update last_pong */ }
            _ => bail!("Unknown message type"),
        }
        Ok(())
    }
    async fn broadcast(&self, msg: Vec<u8>) {
        for (_, peers) in self.peers.read().await.iter() {
            for p in peers {
                p.write_tx.send(msg.clone()).await.ok();
            }
        }
    }
    async fn decrease_reputation(&self, peer: &Arc<Peer>, ip: IpAddr) {
        peer.reputation -= 10;
        if peer.reputation <= -50 {
            self.ban_ip(ip, Duration::from_hours(72)).await;
        }
    }
    async fn ban_ip(&self, ip: IpAddr, duration: Duration) {
        let mut bans = self.bans.write().await;
        bans.insert(ip, Instant::now() + duration);
        drop(bans);
        let mut persistent = self.bans_persistent.write().await;
        let expiry = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + duration.as_secs();
        persistent.insert(ip, Instant::now() + duration);
        drop(persistent);
        let conn = self.db_pool.get().ok();
        if let Some(conn) = conn {
            let _ = conn.put(format!("ban:{}", ip), expiry.to_be_bytes());
            conn.flush_wal(true).ok();
        }
        info!("Peer banned: {}", ip);
        self.remove_peers(ip).await;
    }
    async fn remove_peer(&self, ip: IpAddr, peer: &Arc<Peer>) {
        let mut peers = self.peers.write().await;
        if let Some(vec) = peers.get_mut(&ip) {
            vec.retain(|p| !Arc::ptr_eq(p, peer));
            if vec.is_empty() {
                peers.remove(&ip);
            }
        }
        let mut peers_by_id = self.peers_by_id.write().await;
        peers_by_id.remove(&peer.peer_id);
        let peers_read = self.peers.read().await;
        METRIC_PEERS_CONNECTED.set(peers_read.len() as i64);
    }
    async fn remove_peers(&self, ip: IpAddr) {
        let mut peers = self.peers.write().await;
        peers.remove(&ip);
    }
    pub async fn connect_to_seeds(&self, seeds: &[String]) {
        for seed in seeds {
            if let Ok(tcp) = timeout(CONN_TIMEOUT, TcpStream::connect(seed)).await {
                if let Ok(tcp) = tcp {
                    if let Ok(stream) = self.connector.connect(seed.as_str().try_into().context("Domain invalid")?, tcp).await {
                        self.add_peer(stream, tcp.peer_addr().context("Peer addr failed")?.ip()).await;
                    }
                }
            }
        }
    }
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
