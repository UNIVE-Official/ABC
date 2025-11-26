use thiserror::Error;
#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Missing UTXO")]
    MissingUTXO,
    #[error("Double spend")]
    DoubleSpend,
    #[error("Invalid script")]
    InvalidScript,
    #[error("Invalid transaction: {0}")]
    InvalidTx(String),
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("Reorganization too deep")]
    ReorgTooDeep,
    #[error("Insufficient fees")]
    InsufficientFee,
    #[error("Coinbase immature")]
    CoinbaseImmature,
    #[error("Invalid coinbase fees")]
    InvalidCoinbaseFee,
    #[error("Insufficient PoW")]
    InsufficientPoW,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Invalid lock time")]
    InvalidLockTime,
    #[error("Validation timeout")]
    ValidationTimeout,
    #[error("File permission error")]
    FilePermissionError,
    #[error("Value overflow")]
    ValueOverflow,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Attack detected")]
    AttackDetected,
    #[error("Invalid range proof")]
    InvalidRangeProof,
    #[error("Invalid handshake")]
    InvalidHandshake,
    #[error("Peer banned")]
    PeerBanned,
    #[error("Peer timeout")]
    PeerTimeout,
    #[error("Mempool overflow")]
    MempoolOverflow,
    #[error("Invalid key image")]
    InvalidKeyImage,
    #[error("Decompression failed")]
    DecompressionFailed,
    #[error("Package depth exceeded")]
    PackageDepthExceeded,
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Supply validation failed")]
    SupplyMismatch,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error(transparent)]
    RocksDB(#[from] rocksdb::Error),
    #[error(transparent)]
    Bincode(#[from] bincode::Error),
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    #[error(transparent)]
    MoneroSerai(#[from] monero_serai::ringct::Error),
    #[error(transparent)]
    Libp2p(#[from] libp2p::core::error::Error),
    #[error(transparent)]
    Bulletproofs(#[from] bulletproofs::ProofError),
    #[error("File permission error: {0}")]
    FilePermissionError(String),
    #[error("Invalid encryption key")]
    InvalidEncryptionKey,
}
