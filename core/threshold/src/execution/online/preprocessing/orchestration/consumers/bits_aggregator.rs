use std::sync::{Arc, RwLock};

use tokio::sync::{mpsc::Receiver, Mutex};

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{online::preprocessing::BitPreprocessing, sharing::share::Share},
};

/// Simple Bit consumer that aggregate `num_bits` bits
/// into a single [`BitPreprocessing`] struct
/// by consuming them from a number of producers in a round-robin fashion
///
/// NOTE: Not actually used in DKG preprocessing as we want to process the bits
/// further
pub struct BitsAggregator<Z: Clone + Send + Sync, T: BitPreprocessing<Z>> {
    bits_writer: Arc<RwLock<T>>,
    bits_receiver_channels: Vec<Mutex<Receiver<Vec<Share<Z>>>>>,
    num_bits: usize,
}

impl<Z: Clone + Send + Sync, T: BitPreprocessing<Z>> BitsAggregator<Z, T> {
    pub fn new(
        bits_writer: Arc<RwLock<T>>,
        bits_receiver_channels: Vec<Mutex<Receiver<Vec<Share<Z>>>>>,
        num_bits: usize,
    ) -> Self {
        Self {
            bits_writer,
            bits_receiver_channels,
            num_bits,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let mut num_bits_needed = self.num_bits;
        let inner_bits_receiver_channels = self.bits_receiver_channels;
        let receiver_iterator = inner_bits_receiver_channels.iter().cycle();
        for receiver in receiver_iterator {
            let bits_batch = receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Error receiving Bits"))?;
            let num_bits = std::cmp::min(num_bits_needed, bits_batch.len());
            (*self
                .bits_writer
                .write()
                .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?)
            .append_bits(bits_batch[..num_bits].to_vec());
            num_bits_needed -= num_bits;
            if num_bits_needed == 0 {
                return Ok(());
            }
        }
        Ok::<_, anyhow::Error>(())
    }
}
