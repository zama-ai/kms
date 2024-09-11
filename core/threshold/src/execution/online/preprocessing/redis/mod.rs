use crate::algebra::residue_poly::ResiduePoly128;
use crate::algebra::residue_poly::ResiduePoly64;
use crate::algebra::structure_traits::Ring;
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
use std::slice::Iter;
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

pub fn redis_factory(key_prefix: String, conf: &RedisConf) -> Box<dyn PreprocessorFactory> {
    Box::new(RedisPreprocessorFactory::new(key_prefix, conf))
}

/// The RedisPreprocessorFactory is a factory for creating RedisBasePreprocessing instances
struct RedisPreprocessorFactory {
    key_prefix: String,
    client: Arc<Client>,
    counter_instances_created: HashMap<PreprocessingTypes, usize>,
}

impl RedisPreprocessorFactory {
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
}

impl CorrelatedRandomnessType {
    pub fn iterator() -> Iter<'static, CorrelatedRandomnessType> {
        static CORRELATED_RANDOMNESS_TYPES: [CorrelatedRandomnessType; 7] = [
            CorrelatedRandomnessType::Triple,
            CorrelatedRandomnessType::Randomness,
            CorrelatedRandomnessType::Bit,
            CorrelatedRandomnessType::DDecMask,
            CorrelatedRandomnessType::NoiseLwe,
            CorrelatedRandomnessType::NoiseGlwe,
            CorrelatedRandomnessType::NoiseGlweSnS,
        ];

        CORRELATED_RANDOMNESS_TYPES.iter()
    }
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
        }
    }
}

pub fn compute_key(key_prefix: String, correlated_randomness: CorrelatedRandomnessType) -> String {
    key_prefix + correlated_randomness.get_suffix()
}

fn store_correlated_randomness<S: Serialize>(
    client: Arc<Client>,
    data: &[S],
    correlated_randomness: CorrelatedRandomnessType,
    key_prefix: String,
) -> RedisResult<()> {
    let mut con = client.get_connection()?;

    let serialized: Vec<Vec<u8>> =
        data.iter()
            .map(bincode::serialize)
            .try_collect()
            .map_err(|_| {
                redis::RedisError::from((redis::ErrorKind::TypeError, "Could not serialize "))
            })?;

    con.lpush::<std::string::String, Vec<Vec<u8>>, usize>(
        compute_key(key_prefix, correlated_randomness),
        serialized,
    )?;

    Ok(())
}

fn fetch_correlated_randomness<T: for<'de> Deserialize<'de>>(
    client: Arc<Client>,
    amount: usize,
    correlated_randomness: CorrelatedRandomnessType,
    key_prefix: String,
) -> RedisResult<Vec<T>> {
    let mut con = client.get_connection()?;
    let serialized_correlated_randomness: Vec<Vec<u8>> = con.rpop(
        compute_key(key_prefix, correlated_randomness),
        NonZeroUsize::new(amount),
    )?;

    //Deserialize to T
    let correlated_randomness = serialized_correlated_randomness
        .iter()
        .map(|serialized| {
            bincode::deserialize(serialized).map_err(|_| {
                redis::RedisError::from((redis::ErrorKind::TypeError, "Could not deserialize"))
            })
        })
        .collect::<Result<Vec<T>, _>>()?;

    Ok(correlated_randomness)
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
impl PreprocessorFactory for RedisPreprocessorFactory {
    fn create_base_preprocessing_residue_64(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly64>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Base64,
        );
        Box::new(RedisPreprocessing::<ResiduePoly64>::new(
            format!("{}_Base64_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
    }

    fn create_base_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly128>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Base128,
        );
        Box::new(RedisPreprocessing::<ResiduePoly128>::new(
            format!("{}_Base128_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
    }

    fn create_bit_preprocessing_residue_64(&mut self) -> Box<dyn BitPreprocessing<ResiduePoly64>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Bits64,
        );
        Box::new(RedisPreprocessing::<ResiduePoly64>::new(
            format!("{}_Bits64_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
    }

    fn create_bit_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BitPreprocessing<ResiduePoly128>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::Bits128,
        );
        Box::new(RedisPreprocessing::<ResiduePoly128>::new(
            format!("{}_Bits128_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
    }

    fn create_bit_decryption_preprocessing(&mut self) -> Box<dyn BitDecPreprocessing> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::BitDecryption,
        );
        Box::new(RedisPreprocessing::<ResiduePoly64>::new(
            format!("{}_BitDecryption_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
    }

    fn create_noise_flood_preprocessing(&mut self) -> Box<dyn NoiseFloodPreprocessing> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::NoiseFlood,
        );
        Box::new(RedisPreprocessing::<ResiduePoly128>::new(
            format!("{}_NoiseFlood_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
    }

    fn create_dkg_preprocessing_no_sns(
        &mut self,
    ) -> Box<dyn super::DKGPreprocessing<ResiduePoly64>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::DkgNoSns,
        );
        Box::new(RedisPreprocessing::<ResiduePoly64>::new(
            format!("{}_DkgNoSnS_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
    }

    fn create_dkg_preprocessing_with_sns(
        &mut self,
    ) -> Box<dyn super::DKGPreprocessing<ResiduePoly128>> {
        let counter_value = get_counter_and_update(
            &mut self.counter_instances_created,
            PreprocessingTypes::DkgWithSns,
        );
        Box::new(RedisPreprocessing::<ResiduePoly128>::new(
            format!("{}_DkgWithSnS_{}", self.key_prefix(), counter_value),
            self.get_redis_client(),
        ))
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

mod bitdec;
mod dkg;
mod noiseflood;

#[cfg(test)]
pub mod tests {
    use paste::paste;
    use std::num::Wrapping;

    use crate::algebra::base_ring::{Z128, Z64};
    use crate::algebra::gf256::GF256;
    use crate::algebra::residue_poly::ResiduePoly;
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
                        Role::indexed_by_one(1),
                        ResiduePoly::<$z>::from_scalar(Wrapping(42)),
                    );

                    let serialized = bincode::serialize(&share).unwrap();
                    let deserialized = bincode::deserialize(&serialized).unwrap();
                    assert_eq!(share, deserialized);
                }

                #[test]
                fn [<test_triple_serialization_deserialization $z:lower>]() {
                    let share_one = Share::new(
                        Role::indexed_by_one(1),
                        ResiduePoly::<$z>::from_scalar(Wrapping(42)),
                    );

                    let share_two = Share::new(
                        Role::indexed_by_one(2),
                        ResiduePoly::<$z>::from_scalar(Wrapping(43)),
                    );

                    let share_three = Share::new(
                        Role::indexed_by_one(3),
                        ResiduePoly::<$z>::from_scalar(Wrapping(42)),
                    );

                    let triple = Triple::<ResiduePoly<$z>>::new(share_one, share_two, share_three);
                    let serialized = bincode::serialize(&triple).unwrap();
                    let deserialized: Triple<ResiduePoly<$z>> = bincode::deserialize(&serialized).unwrap();

                    assert_eq!(triple, deserialized);
                }



            }
        };
    }

    #[test]
    fn test_share_serialization_deserialization_gf256() {
        let share = Share::new(Role::indexed_by_one(1), GF256::from(42));

        let serialized = bincode::serialize(&share).unwrap();
        let deserialized: Share<GF256> = bincode::deserialize(&serialized).unwrap();
        assert_eq!(share, deserialized);
    }

    test_triples![Z64];
    test_triples![Z128];
}
