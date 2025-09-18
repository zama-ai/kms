use std::sync::Arc;

use tokio::sync::{mpsc::Receiver, Mutex, RwLock};

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::online::{preprocessing::TriplePreprocessing, triple::Triple},
};

/// Simple Triples consumer that aggregate `num_triples` triples
/// into a single [`TriplePreprocessing`] struct
/// by consuming them from a number of producers in a round-robin fashion
pub struct TriplesAggregator<Z: Clone + Send + Sync, T: TriplePreprocessing<Z>> {
    triple_writer: Arc<RwLock<T>>,
    triple_receiver_channels: Vec<Mutex<Receiver<Vec<Triple<Z>>>>>,
    num_triples: usize,
}

impl<Z: Clone + Send + Sync, T: TriplePreprocessing<Z>> TriplesAggregator<Z, T> {
    pub fn new(
        triple_writer: Arc<RwLock<T>>,
        triple_receiver_channels: Vec<Mutex<Receiver<Vec<Triple<Z>>>>>,
        num_triples: usize,
    ) -> Self {
        Self {
            triple_writer,
            triple_receiver_channels,
            num_triples,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let mut num_triples_needed = self.num_triples;
        let inner_triple_receiver_channels = self.triple_receiver_channels;
        let receiver_iterator = inner_triple_receiver_channels.iter().cycle();
        for receiver in receiver_iterator {
            let triple_batch = receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Error receiving Triples"))?;
            let num_triples = std::cmp::min(num_triples_needed, triple_batch.len());
            self.triple_writer
                .write()
                .await
                .append_triples(triple_batch[..num_triples].to_vec());
            num_triples_needed -= num_triples;
            if num_triples_needed == 0 {
                return Ok(());
            }
        }
        Ok::<_, anyhow::Error>(())
    }
}
