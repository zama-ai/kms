use std::sync::Arc;

use tokio::sync::{mpsc::Receiver, Mutex, RwLock};
use tracing::instrument;

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::{
            preprocessing::memory::InMemoryBitPreprocessing,
            secret_distributions::{RealSecretDistributions, SecretDistributions},
        },
        sharing::share::Share,
        tfhe_internals::parameters::NoiseInfo,
    },
    thread_handles::spawn_compute_bound,
};

use crate::{algebra::structure_traits::Ring, execution::online::preprocessing::DKGPreprocessing};

/// Custom Bit consumer that transform the bits into the different
/// noises required for TFHE-rs DKG
/// by consuming the bits from a number of producers in a round-robin fashion
pub struct DkgBitProcessor<Z: Ring + Clone, T: DKGPreprocessing<Z>> {
    output_writer: Arc<RwLock<T>>,
    tuniform_productions: Vec<NoiseInfo>,
    num_bits_required: usize,
    bit_receiver_channels: Vec<Mutex<Receiver<Vec<Share<Z>>>>>,
}

impl<Z: Ring + Clone, T: DKGPreprocessing<Z> + 'static> DkgBitProcessor<Z, T> {
    pub fn new(
        output_writer: Arc<RwLock<T>>,
        tuniform_productions: Vec<NoiseInfo>,
        num_bits_required: usize,
        bit_receiver_channels: Vec<Mutex<Receiver<Vec<Share<Z>>>>>,
    ) -> Self {
        Self {
            output_writer,
            tuniform_productions,
            num_bits_required,
            bit_receiver_channels,
        }
    }

    ///Bit processing function that creates TUniform noise from bits, and pushes
    ///these and the desired amount of raw bits to the provided
    /// [`bit_writer`]
    #[instrument(name = "Bit Processing", skip(self), fields(num_bits_required=?self.num_bits_required,tuniform_productions=?self.tuniform_productions))]
    pub async fn run(mut self) -> anyhow::Result<()> {
        let inner_bit_receiver_channels = self.bit_receiver_channels;
        let mut receiver_iterator = inner_bit_receiver_channels.iter().cycle();
        let mut bit_batch = Vec::new();
        for tuniform_production in self.tuniform_productions.iter_mut() {
            let current_bound_info = tuniform_production.bound;
            let current_bound = tuniform_production.tuniform_bound();
            let tuniform_req_bits = current_bound.0 + 2;
            while tuniform_production.amount != 0 {
                if bit_batch.len() < tuniform_req_bits {
                    bit_batch.extend(
                        receiver_iterator
                            .next()
                            .ok_or_else(|| anyhow_error_and_log("Error in channel iterator"))?
                            .lock()
                            .await
                            .recv()
                            .await
                            .ok_or_else(|| {
                                anyhow_error_and_log(format!(
                                    "Error receiving bits, remaining {}",
                                    tuniform_production.amount
                                ))
                            })?,
                    );
                }

                let current_amount = tuniform_production.amount;
                let (t_uniforms, remaining_bit_batch) = spawn_compute_bound(move || {
                    let num_bits_available = bit_batch.len();
                    let num_tuniform = std::cmp::min(
                        current_amount,
                        num_integer::Integer::div_floor(&num_bits_available, &tuniform_req_bits),
                    );
                    let num_bits = num_tuniform * tuniform_req_bits;

                    let bits = if num_bits == num_bits_available {
                        std::mem::take(&mut bit_batch)
                    } else {
                        bit_batch.drain(..num_bits).collect()
                    };

                    let mut bit_preproc = InMemoryBitPreprocessing {
                        available_bits: bits,
                    };
                    let t_uniforms = RealSecretDistributions::t_uniform(
                        num_tuniform,
                        current_bound,
                        &mut bit_preproc,
                    )?;
                    Ok::<_, anyhow::Error>((t_uniforms, bit_batch))
                })
                .await??;
                let num_tuniform = t_uniforms.len();
                self.output_writer
                    .write()
                    .await
                    .append_noises(t_uniforms, current_bound_info);
                tuniform_production.amount -= num_tuniform;
                bit_batch = remaining_bit_batch;
            }
        }

        while self.num_bits_required != 0 {
            if bit_batch.is_empty() {
                bit_batch = receiver_iterator
                    .next()
                    .ok_or_else(|| anyhow_error_and_log("Error in channel iterator"))?
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| {
                        anyhow_error_and_log(format!(
                            "Error receiving bits, remaining {}",
                            self.num_bits_required
                        ))
                    })?;
            }

            let num_bits_available = bit_batch.len();
            let num_bits = std::cmp::min(self.num_bits_required, num_bits_available);
            self.output_writer
                .write()
                .await
                .append_bits(bit_batch.drain(..num_bits).collect());
            self.num_bits_required -= num_bits;
        }
        Ok::<(), anyhow::Error>(())
    }
}
