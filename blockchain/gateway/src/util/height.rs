use std::fs::{File, OpenOptions};
use std::io::Result;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ethers::prelude::*;

const FILE_PATH: &str = ".last_height";

/// Data structure that saves the latest FHEVM BC's block
/// read by the Gateway's [`crate::events::manager::DecryptionEventPublisher`] in file [`FILE_PATH`]
pub struct AtomicBlockHeight {
    atomic_max: Arc<AtomicU64>,
    file_mutex: Arc<Mutex<()>>,
    file_path: String,
}

impl AtomicBlockHeight {
    /// Try to reads the latest bock height from [`FILE_PATH`]
    /// else query the blockchain using the [`Provider`]
    pub async fn new(provider: &Provider<Ws>) -> Result<Self> {
        let atomic_max = Arc::new(AtomicU64::new(0));
        let file_mutex = Arc::new(Mutex::new(()));
        let file_path = FILE_PATH.to_string();

        {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&file_path)?;
            let current_value = Self::read_number_from_file(&mut file)?;
            atomic_max.store(current_value, Ordering::SeqCst);
            if current_value == 0 {
                let block_number = provider.get_block_number().await.unwrap().as_u64();
                Self::write_number_to_file(&mut file, block_number)?;
                atomic_max.store(block_number, Ordering::SeqCst);
            }
        }

        Ok(AtomicBlockHeight {
            atomic_max,
            file_mutex,
            file_path,
        })
    }

    fn read_number_from_file(file: &mut File) -> Result<u64> {
        file.seek(SeekFrom::Start(0))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(contents.trim().parse().unwrap_or(0))
    }

    fn write_number_to_file(file: &mut File, number: u64) -> Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        let number_str = number.to_string();
        file.write_all(number_str.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn try_update(&self, new_value: u64) -> Result<()> {
        loop {
            let current_max = self.atomic_max.load(Ordering::SeqCst);
            if new_value > current_max {
                // Lock the file for writing
                let _file_lock = self.file_mutex.lock().unwrap();
                // Open the file for writing
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&self.file_path)?;
                let current_file_value = Self::read_number_from_file(&mut file)?;

                if new_value > current_file_value {
                    self.atomic_max.store(new_value, Ordering::SeqCst);
                    Self::write_number_to_file(&mut file, new_value)?;
                    break;
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn get(&self) -> u64 {
        self.atomic_max.load(Ordering::SeqCst)
    }
}
