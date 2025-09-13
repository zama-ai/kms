use std::sync::Arc;

use tokio::sync::{mpsc::Receiver, Mutex, RwLock};

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{online::preprocessing::RandomPreprocessing, sharing::share::Share},
};

/// Simple Random consumer that aggregate `num_randomness` randomness
/// into a single [`RandomPreprocessing`] struct
/// by consuming them from a number of producers in a round-robin fashion
pub struct RandomsAggregator<Z: Clone + Send + Sync, T: RandomPreprocessing<Z>> {
    randomness_writer: Arc<RwLock<T>>,
    randoms_receiver_channels: Vec<Mutex<Receiver<Vec<Share<Z>>>>>,
    num_randomness: usize,
}

impl<Z: Clone + Send + Sync, T: RandomPreprocessing<Z>> RandomsAggregator<Z, T> {
    pub fn new(
        randomness_writer: Arc<RwLock<T>>,
        randoms_receiver_channels: Vec<Mutex<Receiver<Vec<Share<Z>>>>>,
        num_randomness: usize,
    ) -> Self {
        Self {
            randomness_writer,
            randoms_receiver_channels,
            num_randomness,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let mut num_randomness_needed = self.num_randomness;
        let inner_randoms_receiver_channels = self.randoms_receiver_channels;
        let receiver_iterator = inner_randoms_receiver_channels.iter().cycle();
        for receiver in receiver_iterator {
            let random_batch = receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Error receiving Randomness"))?;
            let num_randoms = std::cmp::min(num_randomness_needed, random_batch.len());
            self.randomness_writer
                .write()
                .await
                .append_randoms(random_batch[..num_randoms].to_vec());
            num_randomness_needed -= num_randoms;
            if num_randomness_needed == 0 {
                return Ok(());
            }
        }
        Ok::<_, anyhow::Error>(())
    }
}
