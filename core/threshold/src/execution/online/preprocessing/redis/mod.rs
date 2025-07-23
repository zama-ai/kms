use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Ring, Solve};
use crate::execution::online::preprocessing::BasePreprocessing;
use crate::execution::online::preprocessing::BitPreprocessing;
use crate::execution::online::preprocessing::PreprocessorFactory;
use crate::execution::online::preprocessing::TriplePreprocessing;
use crate::execution::online::triple::Triple;
use crate::execution::sharing::share::Share;
use itertools::Itertools;
use redis::Client;
use redis::{Commands, RedisResult};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;

use super::RandomPreprocessing;
use crate::execution::online::preprocessing::BitDecPreprocessing;
use crate::execution::online::preprocessing::NoiseFloodPreprocessing;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConf {
    pub host: String,
    pub _user: Option<String>,
    pub _pass: Option<String>,
}

impl Default for RedisConf {
    fn default() -> Self {
        Self {
            host: "redis://127.0.0.1/".to_owned(),
            _user: Default::default(),
            _pass: Default::default(),
        }
    }
}

pub fn redis_factory<const EXTENSION_DEGREE: usize>(
    key_prefix: String,
    conf: &RedisConf,
) -> Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    Box::new(RedisPreprocessorFactory::<EXTENSION_DEGREE>::new(
        key_prefix, conf,
    ))
}

/// The RedisPreprocessorFactory is a factory for creating RedisBasePreprocessing instances
struct RedisPreprocessorFactory<const EXTENSION_DEGREE: usize> {
    key_prefix: String,
    client: Arc<Client>,
    counter_instances_created: HashMap<PreprocessingTypes, usize>,
}

impl<const EXTENSION_DEGREE: usize> RedisPreprocessorFactory<EXTENSION_DEGREE> {
    pub fn new(key_prefix: String, conf: &RedisConf) -> Self {
        let client = Client::open(conf.host.clone()).expect("Failed to create Redis client");
        Self {
            key_prefix,
            client: Arc::new(client),
            counter_instances_created: HashMap::new(),
        }
    }

    pub fn key_prefix(&self) -> String {
        self.key_prefix.clone()
    }

    pub fn get_redis_client(&self) -> Arc<Client> {
        self.client.clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CorrelatedRandomnessType {
    Triple,
    Randomness,
    Bit,
    DDecMask,
    NoiseLwe,
    NoiseLweHat,
    NoiseGlwe,
    NoiseGlweSnS,
    NoiseCompressionKSK,
    SnsNoiseCompressionKSK,
}

impl CorrelatedRandomnessType {
    pub fn get_suffix(&self) -> &str {
        match self {
            CorrelatedRandomnessType::Triple => "_triple",
            CorrelatedRandomnessType::Randomness => "_randomness",
            CorrelatedRandomnessType::Bit => "_bit",
            CorrelatedRandomnessType::DDecMask => "_mask",
            CorrelatedRandomnessType::NoiseLwe => "_noise_lwe",
            CorrelatedRandomnessType::NoiseLweHat => "_noise_lwe_hat",
            CorrelatedRandomnessType::NoiseGlwe => "_noise_glwe",
            CorrelatedRandomnessType::NoiseGlweSnS => "_noise_glwe_sns",
            CorrelatedRandomnessType::NoiseCompressionKSK => "_noise_compression_ksk",
            CorrelatedRandomnessType::SnsNoiseCompressionKSK => "_sns_noise_compression_ksk",
        }
    }
}

pub fn compute_key(key_prefix: String, correlated_randomness: CorrelatedRandomnessType) -> String {
    key_prefix + correlated_randomness.get_suffix()
}

fn store_correlated_randomness<S: Serialize>(
    client: Arc<Client>,
    data: &[S],
    correlated_randomness_type: CorrelatedRandomnessType,
    key_prefix: String,
) -> RedisResult<()> {
    let mut con = client.get_connection()?;

    let serialized: Vec<Vec<u8>> =
        data.iter()
            .map(bc2wrap::serialize)
            .try_collect()
            .map_err(|_| {
                redis::RedisError::from((redis::ErrorKind::TypeError, "Could not serialize "))
            })?;

    con.lpush(
        compute_key(key_prefix, correlated_randomness_type),
        serialized,
    )
}

fn fetch_correlated_randomness<T: for<'de> Deserialize<'de>>(
    client: Arc<Client>,
    amount: usize,
    correlated_randomness_type: CorrelatedRandomnessType,
    key_prefix: String,
) -> RedisResult<Vec<T>> {
    let mut con = client.get_connection()?;
    let serialized_correlated_randomness: Vec<Vec<u8>> = con.rpop(
        compute_key(key_prefix, correlated_randomness_type),
        NonZeroUsize::new(amount),
    )?;

    //Deserialize to T
    let correlated_randomness = serialized_correlated_randomness
        .iter()
        .map(|serialized| {
            bc2wrap::deserialize(serialized).map_err(|_| {
                redis::RedisError::from((redis::ErrorKind::TypeError, "Could not deserialize"))
            })
        })
        .collect::<Result<Vec<T>, _>>()?;

    if correlated_randomness.len() != amount {
        // Note: What was popped will be discarded.
        // But something went quite wrong already anyway.
        Err(redis::RedisError::from((
            redis::ErrorKind::ResponseError,
            "Pop length error.",
            format!(
                "Expected a vector of {:?} of length {}, but received one of length {}",
                correlated_randomness_type,
                amount,
                correlated_randomness.len()
            ),
        )))
    } else {
        Ok(correlated_randomness)
    }
}

fn correlated_randomness_len(
    client: Arc<Client>,
    correlated_randomness: CorrelatedRandomnessType,
    key_prefix: String,
) -> usize {
    let mut con = match client.get_connection() {
        Ok(con) => con,
        Err(_) => return 0,
    };

    con.llen(compute_key(key_prefix, correlated_randomness))
        .unwrap_or(0) as usize
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum PreprocessingTypes {
    Base64,
    Base128,
    Bits64,
    Bits128,
    BitDecryption,
    NoiseFlood,
    DkgWithSns,
    DkgNoSns,
}

fn get_counter_and_update(
    map: &mut HashMap<PreprocessingTypes, usize>,
    key: PreprocessingTypes,
) -> usize {
    let counter_value = if let Some(value) = map.get(&key) {
        *value
    } else {
        0
    };

    map.insert(key, counter_value + 1);
    counter_value
}

/// The RedisPreprocessorFactory is a factory for creating RedisBasePreprocessing instances
/// The factory is generic over the ring type R
impl<const EXTENSION_DEGREE: usize> PreprocessorFactory<EXTENSION_DEGREE>
    for RedisPreprocessorFactory<EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    fn create_base_preprocessing_residue_64(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Base64,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new(
                format!("{}_Base64_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }

    fn create_base_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Base128,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(
                format!("{}_Base128_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }

    fn create_bit_preprocessing_residue_64(
        &mut self,
    ) -> Box<dyn BitPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Bits64,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new(
                format!("{}_Bits64_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }

    fn create_bit_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Bits128,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(
                format!("{}_Bits128_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }

    fn create_bit_decryption_preprocessing(
        &mut self,
    ) -> Box<dyn BitDecPreprocessing<EXTENSION_DEGREE>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::BitDecryption,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new(
                format!("{}_BitDecryption_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }

    fn create_noise_flood_preprocessing(
        &mut self,
    ) -> Box<dyn NoiseFloodPreprocessing<EXTENSION_DEGREE>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::NoiseFlood,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(
                format!("{}_NoiseFlood_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }

    fn create_dkg_preprocessing_no_sns(
        &mut self,
    ) -> Box<dyn super::DKGPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::DkgNoSns,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z64, EXTENSION_DEGREE>>::new(
                format!("{}_DkgNoSnS_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }

    fn create_dkg_preprocessing_with_sns(
        &mut self,
    ) -> Box<dyn super::DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::DkgWithSns,
        );
        Box::new(
            RedisPreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>>::new(
                format!("{}_DkgWithSnS_{}", self.key_prefix(), counter_value),
                self.get_redis_client(),
            ),
        )
    }
}

#[derive(Clone)]
pub struct RedisPreprocessing<R: Ring> {
    client: Arc<Client>,
    key_prefix: String,
    _phantom: PhantomData<R>,
}

impl<R: Ring> RedisPreprocessing<R> {
    fn new(key_prefix: String, client: Arc<Client>) -> Self {
        Self {
            client,
            key_prefix,
            _phantom: PhantomData,
        }
    }

    fn key_prefix(&self) -> String {
        self.key_prefix.clone()
    }

    fn get_client(&self) -> Arc<Client> {
        self.client.clone()
    }
}

impl<R: Ring> BitPreprocessing<R> for RedisPreprocessing<R> {
    fn append_bits(&mut self, bits: Vec<Share<R>>) {
        store_correlated_randomness(
            self.get_client(),
            &bits,
            CorrelatedRandomnessType::Bit,
            self.key_prefix(),
        )
        .unwrap();
    }

    fn next_bit(&mut self) -> anyhow::Result<Share<R>> {
        fetch_correlated_randomness(
            self.get_client(),
            1,
            CorrelatedRandomnessType::Bit,
            self.key_prefix(),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .and_then(|mut opt| {
            opt.pop()
                .ok_or_else(|| anyhow::anyhow!("No more bits available"))
        })
    }

    fn next_bit_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<R>>> {
        fetch_correlated_randomness(
            self.get_client(),
            amount,
            CorrelatedRandomnessType::Bit,
            self.key_prefix(),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn bits_len(&self) -> usize {
        correlated_randomness_len(
            self.get_client(),
            CorrelatedRandomnessType::Bit,
            self.key_prefix(),
        )
    }
}

impl<Z: Ring> BasePreprocessing<Z> for RedisPreprocessing<Z> {}

impl<R: Ring> RandomPreprocessing<R> for RedisPreprocessing<R> {
    fn next_random(&mut self) -> anyhow::Result<Share<R>> {
        fetch_correlated_randomness(
            self.get_client(),
            1,
            CorrelatedRandomnessType::Randomness,
            self.key_prefix(),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .and_then(|mut opt| {
            opt.pop()
                .ok_or_else(|| anyhow::anyhow!("No more randoms available"))
        })
    }

    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<R>>> {
        fetch_correlated_randomness(
            self.get_client(),
            amount,
            CorrelatedRandomnessType::Randomness,
            self.key_prefix(),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn append_randoms(&mut self, randoms: Vec<Share<R>>) {
        store_correlated_randomness(
            self.get_client(),
            &randoms,
            CorrelatedRandomnessType::Randomness,
            self.key_prefix(),
        )
        .unwrap();
    }

    fn randoms_len(&self) -> usize {
        correlated_randomness_len(
            self.get_client(),
            CorrelatedRandomnessType::Randomness,
            self.key_prefix(),
        )
    }
}

impl<R: Ring> TriplePreprocessing<R> for RedisPreprocessing<R> {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<R>>> {
        fetch_correlated_randomness(
            self.get_client(),
            amount,
            CorrelatedRandomnessType::Triple,
            self.key_prefix(),
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    fn append_triples(&mut self, triples: Vec<Triple<R>>) {
        store_correlated_randomness(
            self.get_client(),
            &triples,
            CorrelatedRandomnessType::Triple,
            self.key_prefix(),
        )
        .unwrap();
    }

    fn triples_len(&self) -> usize {
        correlated_randomness_len(
            self.get_client(),
            CorrelatedRandomnessType::Triple,
            self.key_prefix(),
        )
    }
}

pub(crate) mod bitdec;
pub(crate) mod dkg;
pub(crate) mod noiseflood;

#[cfg(test)]
pub mod tests {
    use paste::paste;
    use std::num::Wrapping;

    use crate::algebra::base_ring::{Z128, Z64};
    use crate::algebra::galois_fields::gf16::GF16;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4;
    use crate::execution::online::triple::Triple;
    use crate::execution::runtime::party::Role;
    use crate::execution::sharing::share::Share;

    macro_rules! test_triples {
        ($z:ty) => {
            paste! {
                // create a serialization/deserialization test for the Triple and Share types
                #[test]
                fn [<test_share_serialization_deserialization $z:lower>]() {
                    let share = Share::new(
                        Role::indexed_from_one(1),
                        ResiduePolyF4::<$z>::from_scalar(Wrapping(42)),
                    );

                    let serialized = bc2wrap::serialize(&share).unwrap();
                    let deserialized = bc2wrap::deserialize(&serialized).unwrap();
                    assert_eq!(share, deserialized);
                }

                #[test]
                fn [<test_triple_serialization_deserialization $z:lower>]() {
                    let share_one = Share::new(
                        Role::indexed_from_one(1),
                        ResiduePolyF4::<$z>::from_scalar(Wrapping(42)),
                    );

                    let share_two = Share::new(
                        Role::indexed_from_one(2),
                        ResiduePolyF4::<$z>::from_scalar(Wrapping(43)),
                    );

                    let share_three = Share::new(
                        Role::indexed_from_one(3),
                        ResiduePolyF4::<$z>::from_scalar(Wrapping(42)),
                    );

                    let triple = Triple::<ResiduePolyF4<$z>>::new(share_one, share_two, share_three);
                    let serialized = bc2wrap::serialize(&triple).unwrap();
                    let deserialized: Triple<ResiduePolyF4<$z>> = bc2wrap::deserialize(&serialized).unwrap();

                    assert_eq!(triple, deserialized);
                }



            }
        };
    }

    #[test]
    fn test_share_serialization_deserialization_gf256() {
        let share = Share::new(Role::indexed_from_one(1), GF16::from(12));

        let serialized = bc2wrap::serialize(&share).unwrap();
        let deserialized: Share<GF16> = bc2wrap::deserialize(&serialized).unwrap();
        assert_eq!(share, deserialized);
    }

    test_triples![Z64];
    test_triples![Z128];
}
