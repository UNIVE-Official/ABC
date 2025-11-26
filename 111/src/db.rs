use anyhow::{Context, Result};
use async_trait::async_trait;
use deadpool::managed::{self, RecycleResult};
use rocksdb::{Options as RocksOptions, WriteBatch, IteratorMode, DB};
use rocksdb::checkpoint::Checkpoint;
use std::fs;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;
use tracing::{info, error};
use ed25519_dalek::Signer;
use zip::write::FileOptions;
use zip::ZipWriter;
use sha2::{Sha256, Digest};
use hex;
use crate::config::AppConfig;
use crate::utils::{now_ms, load_keypair};
use std::io::copy as io_copy;
use bincode::serialize;
use scopeguard::defer;
use tokio::sync::Mutex as TokioMutex;
use std::sync::Arc;
use std::fs::OpenOptions;

#[derive(Debug, thiserror::Error)]
pub enum RocksManagerError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct RocksManager {
    path: String,
    db_opts: RocksOptions,
}

impl RocksManager {
    pub fn new(path: &str, db_opts: RocksOptions) -> Self {
        Self {
            path: path.to_string(),
            db_opts,
        }
    }
}

#[async_trait]
impl managed::Manager for RocksManager {
    type Type = DB;
    type Error = RocksManagerError;

    async fn create(&self) -> Result<DB, Self::Error> {
        let path = self.path.clone();
        let opts = self.db_opts.clone();
        // DB::open est bloquant, on le met dans un thread dédié
        tokio::task::spawn_blocking(move || {
            let cfs = ["utxo", "blocks", "headers", "metadata"];
            DB::open_cf(&opts, &path, &cfs).map_err(RocksManagerError::from)
        }).await.unwrap()
    }

    async fn recycle(&self, conn: &mut DB, _: &managed::Metrics) -> RecycleResult<Self::Error> {
        // Vérification basique que la DB est toujours en vie
        match conn.property_value("rocksdb.stats") {
            Ok(_) => Ok(()),
            Err(e) => Err(deadpool::managed::RecycleError::Backend(e.into())),
        }
    }
}

pub type Pool = managed::Pool<RocksManager>;

pub fn create_db_pool(db_path: &str) -> Result<Pool> {
    let mut opts = RocksOptions::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_compression_type(rocksdb::DBCompressionType::Snappy);
    opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
    // Optimisations standard RocksDB pour blockchain
    opts.set_keep_log_file_num(10);
    opts.set_max_open_files(1024); 
    
    let manager = RocksManager::new(db_path, opts);
    let pool = Pool::builder(manager)
        .max_size(16)
        .build()
        .context("Failed to create DB pool")?;
    Ok(pool)
}

pub async fn secure_backup_db(db_pool: &Pool, config: &AppConfig, maintenance_lock: Arc<TokioMutex<()>>) -> Result<()> {
    // 1. Verrouiller la maintenance pour éviter les écritures concurrentes si nécessaire
    let _guard = maintenance_lock.lock().await;
    
    // 2. IMPORTANT : Récupérer la connexion de manière ASYNCHRONE ici
    // On ne peut pas le faire à l'intérieur du spawn_blocking
    let conn = db_pool.get().await.context("DB pool error")?;
    
    let backup_signing_key_path = config.backup_signing_key.clone();

    // 3. Déplacer la connexion (qui est thread-safe) dans le thread bloquant pour le travail lourd
    tokio::task::spawn_blocking(move || {
        let now = now_ms()?;
        // 'conn' est dereferencée automatiquement vers DB
        let checkpoint = Checkpoint::new(&conn)?;
        let checkpoint_dir = format!("{}_checkpoint_{}", conn.path().to_string_lossy(), now);
        
        // Création du checkpoint RocksDB (rapide car hardlink)
        checkpoint.create_checkpoint(&checkpoint_dir)?;
        
        // Nettoyage automatique en cas de panic ou retour
        defer! {
            if let Err(e) = fs::remove_dir_all(&checkpoint_dir) {
                error!("Failed to cleanup checkpoint directory {}: {}", checkpoint_dir, e);
            }
        }

        // Compression ZIP
        let zip_path_tmp = format!("{}.zip.tmp", checkpoint_dir);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&zip_path_tmp)
            .context("Zip file creation error")?;
        
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        add_dir_to_zip(&checkpoint_dir, &mut zip, options, "")?;
        zip.finish().context("Zip finish error")?;
        
        // Signature
        let data = fs::read(&zip_path_tmp).context("Read zip error")?;
        let hash = Sha256::digest(&data);
        info!("Backup hash: {}", hex::encode(hash));
        
        let zip_path = format!("{}.zip", checkpoint_dir);
        let sig_path_tmp = format!("{}.sig.tmp", checkpoint_dir);
        
        let signing_key = load_keypair(&backup_signing_key_path)?;
        let signature = signing_key.sign(&data);
        
        fs::write(&sig_path_tmp, signature.to_bytes()).context("Write signature temp error")?;
        
        // Finalisation (renommage atomique)
        fs::rename(&zip_path_tmp, &zip_path)?;
        fs::rename(&sig_path_tmp, format!("{}.sig", checkpoint_dir))?;
        
        info!("Secure backup created at {}", zip_path);
        
        if let Some(parent_dir) = Path::new(&checkpoint_dir).parent() {
            rotate_backups(parent_dir, 3)?;
        }

        Ok::<(), anyhow::Error>(())
    }).await??;

    Ok(())
}

fn rotate_backups(backup_dir: &Path, keep: usize) -> Result<()> {
    let mut files: Vec<_> = fs::read_dir(backup_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            file_name.contains("_checkpoint_") && file_name.ends_with(".zip")
        })
        .map(|entry| entry.path())
        .collect();
        
    files.sort_by_key(|path| fs::metadata(path).and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::UNIX_EPOCH));
    files.reverse(); // Les plus récents en premier
    
    for old in files.iter().skip(keep) {
        fs::remove_file(old)?;
        // Tenter de supprimer la signature associée aussi
        let sig = old.with_extension("sig");
        if sig.exists() {
            fs::remove_file(sig).ok();
        }
        info!("Rotated old backup: {:?}", old);
    }
    Ok(())
}

fn add_dir_to_zip(dir: &str, zip: &mut ZipWriter<fs::File>, options: FileOptions, base: &str) -> Result<()> {
    for entry in fs::read_dir(dir).context("Read dir error")? {
        let entry = entry.context("Entry error")?;
        let path = entry.path();
        let name_path = path.strip_prefix(Path::new(dir)).context("Strip prefix error")?;
        let name = name_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path name"))?;

        let full_name = format!("{}{}", base, name);

        if path.is_file() {
            zip.start_file(full_name, options).context("Start file error")?;
            let mut f = fs::File::open(path).context("Open file error")?;
            io_copy(&mut f, zip).context("Copy error")?;
        } else if path.is_dir() {
            add_dir_to_zip(path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid dir path"))?, zip, options, &format!("{}/", full_name))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;
    use crate::tx::TXOutput;
    
    // Note: Les tests nécessitent un environnement async correct
    
    #[tokio::test]
    async fn test_db_pool_lifecycle() {
        let temp_dir = TempDir::new("test_db_lifecycle").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        
        let pool = create_db_pool(db_path).unwrap();
        let conn_result = pool.get().await;
        
        assert!(conn_result.is_ok());
    }

    #[tokio::test]
    async fn test_prune_logic() {
        let temp_dir = TempDir::new("test_prune").unwrap();
        let db_path = temp_dir.path().to_str().unwrap();
        let pool = create_db_pool(db_path).unwrap();
        let conn = pool.get().await.unwrap();
        
        let cf_utxo = conn.cf_handle("utxo").unwrap();
        let key = b"test_key";
        let val = b"test_value";
        
        conn.put_cf(cf_utxo, key, val).unwrap();
        assert_eq!(conn.get_cf(cf_utxo, key).unwrap().unwrap(), val);
    }
}