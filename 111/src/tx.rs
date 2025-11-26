use anyhow::{bail, Context, Result};
use bincode::{deserialize, serialize};
use monero_serai::ringct::{Clsag, KeyImage};
use secp256k1::{ecdsa::Signature, Message, PublicKey};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::time::timeout;
use crate::chain::Chain;
use crate::errors::ChainError;
use crate::utils::{hash160, hash_ripemd160, sha256d, SECP, VALIDATION_TIMEOUT, MAX_RING_SIZE, MAX_BLOCK_SIZE, COINBASE_MATURITY, now_ms, PowEngine, u256_from_be, compact_to_target, GENESIS_TIMESTAMP, MIN_FEE_PER_BYTE, ANON_FEE_MULTIPLIER_NUMERATOR, ANON_FEE_MULTIPLIER_DENOMINATOR};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use bulletproofs::r1cs::Verifier;
use bulletproofs::BatchVerifier;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use tracing::debug;
use rand::rngs::OsRng;
use bulletproofs::Commitment;
use once_cell::sync::Lazy;
use lru::LruCache;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof, BatchVerifier};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
static HASH_CACHE: Lazy<Mutex<LruCache<Vec<u8>, [u8; 32]>>> = Lazy::new(|| Mutex::new(LruCache::new(LRU_CACHE_SIZE)));
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TXInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TXOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub commitment: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub is_anonymous: bool,
    pub inputs: Vec<TXInput>,
    pub outputs: Vec<TXOutput>,
    pub lock_time: u32,
    pub range_proofs: Vec<Vec<u8>>,
}
impl Transaction {
    pub fn hash(&self) -> [u8; 32] {
        let serialized = serialize(self).context("Serialize tx failed")?;
        let mut cache = HASH_CACHE.lock().unwrap();
        if let Some(&cached) = cache.get(&serialized) {
            return cached;
        }
        let hashed = sha256d(&serialized);
        cache.put(serialized, hashed);
        hashed
    }
    pub fn sighash(&self, input_idx: usize, script_pubkey: &[u8], sighash_type: u32) -> [u8; 32] {
        let mut tx_copy = self.clone();
        for input in tx_copy.inputs.iter_mut() {
            input.script_sig.clear();
        }
        tx_copy.inputs[input_idx].script_sig = script_pubkey.to_vec();
        let mut data = serialize(&tx_copy).context("Serialize sighash failed")?;
        data.extend_from_slice(&sighash_type.to_le_bytes());
        sha256d(&data)
    }
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].txid == [0u8; 32] && self.inputs[0].vout == u32::MAX
    }
    pub fn size(&self) -> usize {
        serialize(self).context("Serialize size failed")?.len()
    }
    pub fn fee(&self, outputs: &HashMap<([u8; 32], u32), TXOutput>) -> u64 {
        let input_sum: u64 = self.inputs.iter().map(|vin| outputs.get(&(vin.txid, vin.vout)).map(|o| o.value).unwrap_or(0)).try_fold(0u64, u64::checked_add).ok_or(0)?;
        let output_sum: u64 = self.outputs.iter().map(|o| o.value).try_fold(0u64, u64::checked_add).ok_or(0)?;
        input_sum.saturating_sub(output_sum)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u64,
}
impl BlockHeader {
    pub fn hash(&self, engine: &PowEngine) -> Result<[u8; 32]> {
        let serialized = bincode::serialize(self)?;
        engine.hash(&serialized)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}
impl Block {
    pub fn header_hash(&self, engine: &PowEngine) -> Result<[u8; 32]> {
        pow_hash(&serialize(&self.header)?, engine)
    }
    pub fn compute_merkle_root(txs: &[Transaction]) -> [u8; 32] {
        let mut hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.hash()).collect();
        if hashes.is_empty() { return [0u8; 32]; }
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 { hashes.push(*hashes.last().unwrap()); }
            let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
            for chunk in hashes.chunks(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[1]);
                new_hashes.push(sha256d(&combined));
            }
            hashes = new_hashes;
        }
        hashes[0]
    }
    pub fn size(&self) -> usize {
        serialize(self).context("Serialize block size failed")?.len()
    }
}
pub async fn validate_script_with_timeout(input: &TXInput, output: &TXOutput, tx: &Transaction, input_idx: usize) -> Result<()> {
    timeout(VALIDATION_TIMEOUT, async {
        if output.script_pubkey.len() != 25 && output.script_pubkey.len() != 34 {
            bail!(ChainError::InvalidScript);
        }
        if output.script_pubkey.len() == 25 {
            if output.script_pubkey[0] != 0x76 || output.script_pubkey[1] != 0x a9 || output.script_pubkey[2] != 0x14 || output.script_pubkey[23] != 0x88 || output.script_pubkey[24] != 0xac {
                bail!(ChainError::InvalidScript);
            }
            let pubkey_hash: [u8; 20] = output.script_pubkey[3..23].try_into().context("Invalid pubkey hash length")?;
            let sig_script = &input.script_sig;
            let sig_len = sig_script[0] as usize;
            if sig_len + 1 > sig_script.len() { bail!(ChainError::InvalidScript); }
            let sig = &sig_script[1..1 + sig_len];
            let pubkey_len = sig_script[1 + sig_len] as usize;
            if 2 + sig_len + pubkey_len > sig_script.len() { bail!(ChainError::InvalidScript); }
            let pubkey = &sig_script[2 + sig_len..2 + sig_len + pubkey_len];
            if hash160(pubkey) != pubkey_hash { bail!(ChainError::InvalidScript); }
            if sig.is_empty() { bail!(ChainError::InvalidScript); }
            let sighash_type = sig[sig.len() - 1] as u32;
            let sig_der = &sig[..sig.len() - 1];
            let msg_hash = tx.sighash(input_idx, &output.script_pubkey, sighash_type);
            let msg = Message::from_slice(&msg_hash).context("Invalid message")?;
            let sig = Signature::from_der(sig_der).context("Invalid DER signature")?;
            let pk = PublicKey::from_slice(pubkey).context("Invalid public key")?;
            SECP.verify_ecdsa(&msg, &sig, &pk).map_err(|_| ChainError::InvalidSignature.into())
        } else if output.script_pubkey.len() == 34 && output.script_pubkey[0] == 0x21 && output.script_pubkey[33] == 0xac {
            let pubkey = &output.script_pubkey[1..33];
            let pk = PublicKey::from_slice(pubkey).context("Invalid P2PK pubkey")?;
            let sig = &input.script_sig;
            if sig.is_empty() { bail!(ChainError::InvalidScript); }
            let sighash_type = sig[sig.len() - 1] as u32;
            let sig_der = &sig[..sig.len() - 1];
            let msg_hash = tx.sighash(input_idx, &output.script_pubkey, sighash_type);
            let msg = Message::from_slice(&msg_hash).context("Invalid message")?;
            let sig = Signature::from_der(sig_der).context("Invalid DER signature")?;
            SECP.verify_ecdsa(&msg, &sig, &pk).map_err(|_| ChainError::InvalidSignature.into())
        } else {
            bail!(ChainError::InvalidScript);
        }
    }).await.map_err(|_| ChainError::ValidationTimeout)?
}
pub async fn validate_anonymous_tx(
    tx: &Transaction,
    anonymous_outputs: &HashMap<([u8; 32], u32), TXOutput>,
    cf_key_images: &ColumnFamily,
    conn: &rocksdb::DB,
) -> Result<()> {
    let mut input_sum = 0u64;
    let mut seen_key_images = HashSet::new();
    let mut input_commitments = Vec::new();
    let pc = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let mut batch = BatchVerifier::new();
    for vin in &tx.inputs {
        if vin.script_sig.len() < 32 {
            bail!(ChainError::InvalidScript);
        }
        let key_image = KeyImage::from_slice(&vin.script_sig[0..32])
            .context(ChainError::InvalidKeyImage)?;
        if !seen_key_images.insert(key_image) {
            bail!(ChainError::DoubleSpend);
        }
        if conn.get_cf(cf_key_images, key_image.as_bytes())?.is_some() {
            bail!(ChainError::DoubleSpend);
        }
        let clsag_data = &vin.script_sig[32..];
        let clsag: Clsag = deserialize(clsag_data)
            .context("Deserialize clsag error")?;
        if clsag.ring.len() > MAX_RING_SIZE || clsag.ring.is_empty() {
            bail!(ChainError::InvalidScript);
        }
        let msg_hash = tx.hash();
        clsag.verify(&msg_hash, &key_image)
            .context("Clsag verify error")?;
        if let Some(out) = anonymous_outputs.get(&(vin.txid, vin.vout)) {
            input_sum = input_sum.checked_add(out.value)
                .ok_or(ChainError::ValueOverflow)?;
            if let Some(comm) = &out.commitment {
                let comm = CompressedRistretto::from_slice(comm).decompress()
                    .ok_or(ChainError::InvalidCommitment)?;
                input_commitments.push(comm);
            } else {
                bail!(ChainError::InvalidCommitment);
            }
        } else {
            bail!(ChainError::MissingUTXO);
        }
    }
    let output_sum: u64 = tx.outputs.iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or(ChainError::ValueOverflow)?;
    let fee = input_sum.checked_sub(output_sum)
        .ok_or(ChainError::ValueOverflow)?;
    // Batch range proofs
    for (out, proof_bytes) in tx.outputs.iter().zip(&tx.range_proofs) {
        let proof: RangeProof = deserialize(proof_bytes)
            .context("Deserialize proof error")?;
        let comm_bytes = out.commitment.as_ref()
            .ok_or(ChainError::InvalidCommitment)?;
        let commitment = CompressedRistretto::from_slice(comm_bytes)
            .decompress()
            .ok_or(ChainError::InvalidCommitment)?;
        batch.queue(&proof, &commitment, out.value, &bp_gens);
    }
    if !batch.verify(&bp_gens)
        .map_err(|_| ChainError::InvalidRangeProof)? {
        bail!(ChainError::InvalidRangeProof);
    }
    // Commitment balance check (sum_inputs = sum_outputs + fee×H)
    let mut sum_input_comm = pc.commit(Scalar::ZERO, Scalar::ZERO);
    for comm in input_commitments {
        sum_input_comm = sum_input_comm + comm;
    }
    let mut sum_output_comm = pc.commit(Scalar::zero(), Scalar::zero());
    for out in &tx.outputs {
        let comm_bytes = out.commitment.as_ref()
            .ok_or(ChainError::InvalidCommitment)?;
        let comm = CompressedRistretto::from_slice(comm_bytes)
            .decompress()
            .ok_or(ChainError::InvalidCommitment)?;
        sum_output_comm = sum_output_comm + comm;
    }
    let fee_commit = pc.commit(Scalar::from(fee), Scalar::ZERO);
    if sum_input_comm != sum_output_comm + fee_commit {
        bail!(ChainError::InvalidCommitment);
    }
    Ok(())
}
pub async fn validate_transaction(tx: &Transaction, chain: &Chain, height: usize) -> Result<()> {
    if tx.is_coinbase() { return Ok(()); }
    if tx.lock_time > chain.best_height as u32 && tx.inputs.iter().any(|i| i.sequence != u32::MAX) { bail!(ChainError::InvalidLockTime); }
    let conn = chain.db_pool.get()?;
    let cf_utxo = conn.cf_handle("utxo")?;
    let cf_anonymous = conn.cf_handle("anonymous")?;
    let cf_key_images = conn.cf_handle("key_images")?;
    let cf_coinbase = conn.cf_handle("coinbase")?;
    let mut seen = HashSet::new();
    let mut input_sum: u64 = 0;
    let mut outputs = HashMap::new();
    let mut utxo_keys = Vec::new();
    for vin in &tx.inputs {
        let key = (vin.txid, vin.vout);
        if !seen.insert(key) { bail!(ChainError::DoubleSpend); }
        if let Some(cb_height_bytes) = conn.get_cf(cf_coinbase, vin.txid)? {
            let cb_height = usize::from_be_bytes(cb_height_bytes.try_into().context("Invalid cb height bytes")?);
            if height.saturating_sub(cb_height) < COINBASE_MATURITY { bail!(ChainError::CoinbaseImmature); }
        }
        if !tx.is_anonymous {
            let mut db_key = b"u:".to_vec();
            db_key.extend_from_slice(&vin.txid);
            db_key.extend_from_slice(&vin.vout.to_be_bytes());
            utxo_keys.push(db_key);
        }
    }
    if !tx.is_anonymous {
        let snapshot = RocksSnapshot::new(&conn);
        for db_key in utxo_keys {
            if let Some(value) = snapshot.get_cf(cf_utxo, &db_key)? {
                let utxo: TXOutput = deserialize(&value).context("Deserialize utxo failed")?;
                let txid = <[u8; 32]>::try_from(&db_key[2..34])?;
                let vout = u32::from_be_bytes(db_key[34..38].try_into()?);
                input_sum = input_sum.checked_add(utxo.value).ok_or(ChainError::ValueOverflow)?;
                outputs.insert((txid, vout), utxo);
            } else {
                bail!(ChainError::MissingUTXO);
            }
        }
    }
    if tx.is_anonymous {
        let mut anon_outputs = HashMap::new();
        for vin in &tx.inputs {
            let mut key = b"a:".to_vec();
            key.extend_from_slice(&vin.txid);
            key.extend_from_slice(&vin.vout.to_be_bytes());
            if let Some(value) = conn.get_cf(cf_anonymous, &key)? {
                let output: TXOutput = deserialize(&value).context("Deserialize anon failed")?;
                anon_outputs.insert((vin.txid, vin.vout), output);
            }
        }
        validate_anonymous_tx(tx, &anon_outputs, cf_key_images, &conn).await?;
    }
    let output_sum: u64 = tx.outputs.iter().map(|o| o.value).try_fold(0u64, u64::checked_add).ok_or(ChainError::ValueOverflow)?;
    if output_sum > input_sum { bail!(ChainError::InvalidTx("Outputs exceed inputs".into())); }
    let fee = input_sum.checked_sub(output_sum).ok_or(ChainError::ValueOverflow)?;
    let required_fee = if tx.is_anonymous {
        let size_u128 = tx.size() as u128;
        let base = MIN_FEE_PER_BYTE as u128;
        ((size_u128 * base * ANON_FEE_MULTIPLIER_NUMERATOR) + (ANON_FEE_MULTIPLIER_DENOMINATOR - 1)) / ANON_FEE_MULTIPLIER_DENOMINATOR
    } else {
        (tx.size() as u64).checked_mul(MIN_FEE_PER_BYTE).ok_or(ChainError::ValueOverflow)?
    };
    if fee < required_fee as u64 {
        bail!(ChainError::InsufficientFee);
    }
    Ok(())
}
pub fn create_coinbase(height: usize, extra: &[u8], pubkey: &PublicKey) -> Transaction {
    let mut script_sig = height.to_le_bytes().to_vec();
    script_sig.extend_from_slice(extra);
    Transaction {
        version: 1,
        is_anonymous: false,
        inputs: vec![TXInput {
            txid: [0u8; 32],
            vout: u32::MAX,
            script_sig,
            sequence: u32::MAX,
        }],
        outputs: vec![TXOutput {
            value: 0,
            script_pubkey: p2pkh_script(pubkey),
            commitment: None,
        }],
        lock_time: 0,
        range_proofs: vec![],
    }
}
pub fn p2pkh_script(pubkey: &PublicKey) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&hash160(&pubkey.serialize()));
    script.extend_from_slice(&[0x88, 0xac]);
    script
}
pub fn create_genesis_block(pubkey: &PublicKey, pow_engine: &Arc<PowEngine>) -> Result<Block> {
    let script_sig = b"Lyrion Network – Privacy by Design – Launched November 20, 2025".to_vec();
    let coinbase_tx = Transaction {
        version: 1,
        is_anonymous: false,
        inputs: vec![TXInput {
            txid: [0u8; 32],
            vout: u32::MAX,
            script_sig,
            sequence: u32::MAX,
        }],
        outputs: vec![TXOutput {
            value: subsidy(0),
            script_pubkey: p2pkh_script(pubkey),
            commitment: None,
        }],
        lock_time: 0,
        range_proofs: vec![],
    };
    let mut header = BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        merkle_root: Block::compute_merkle_root(&[coinbase_tx.clone()]),
        timestamp: GENESIS_TIMESTAMP,
        bits: 0x1d00ffff,
        nonce: 0,
    };
    let target = compact_to_target(header.bits);
    let mut nonce = 0u64;
    loop {
        header.nonce = nonce;
        let hash = header.hash(pow_engine)?;
        if u256_from_be(&hash) <= target {
            break;
        }
        nonce = nonce.wrapping_add(1);
        if nonce == 0 {
            bail!("Impossible to mine genesis – increase bits");
        }
    }
    Ok(Block { header, txs: vec![coinbase_tx] })
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
    async fn test_validate_anonymous_tx_edge() {
        let mut tx = Transaction {
            version: 1,
            is_anonymous: true,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            range_proofs: vec![],
        };
        let empty_map = HashMap::new();
        let db = rocksdb::DB::open_default("test_db_tx").unwrap();
        let cf = db.cf_handle("key_images").unwrap();
        assert!(validate_anonymous_tx(&tx, &empty_map, cf, &db).await.is_err());
    }
}
use curve25519_dalek::scalar::Scalar;
use monero_serai::ringct::Clsag;
use monero_serai::keys::{PrivateKey, PublicKey};
pub fn create_prefix_hash(tx: &Transaction) -> [u8; 32] {
    // Serialize without script_sig and range_proofs
    let mut prefix_tx = tx.clone();
    for input in &mut prefix_tx.inputs {
        input.script_sig.clear();
    }
    prefix_tx.range_proofs.clear();
    sha256d(&bincode::serialize(&prefix_tx).unwrap())
}
