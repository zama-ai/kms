use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::Role;
use crate::execution::runtime::sessions::base_session::BaseSessionHandles;
use crate::execution::runtime::sessions::session_parameters::DeSerializationRunTime;
use crate::execution::sharing::share::Share;
use crate::experimental::algebra::levels::*;
use crate::experimental::algebra::ntt::*;
use crate::experimental::bgv::basics::*;
use crate::experimental::bgv::ddec::keygen_shares;
use crate::networking::value::NetworkValue;
use itertools::Itertools;
use rand::CryptoRng;
use rand::RngCore;
use std::sync::Arc;
use tfhe::core_crypto::commons::math::random::RandomGenerator;
use tfhe::XofSeed;
use tfhe_csprng::generators::SoftwareRandomGenerator;
use tokio::task::JoinSet;
use tokio::time::timeout_at;

#[cfg(feature = "choreographer")]
pub(crate) fn gen_key_set() -> (PublicBgvKeySet, SecretKey) {
    use rand::SeedableRng;
    let mut rng = aes_prng::AesRng::seed_from_u64(0);

    let (pk, sk) = keygen::<aes_prng::AesRng, LevelEll, LevelKsw, N65536>(
        &mut rng,
        crate::experimental::constants::PLAINTEXT_MODULUS.get().0,
    );

    (pk, sk)
}

pub async fn transfer_pub_key<S: BaseSessionHandles>(
    session: &S,
    pubkey: Option<PublicBgvKeySet>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PublicBgvKeySet> {
    let deserialization_runtime = DeSerializationRunTime::Rayon;
    session.network().increase_round_counter().await;
    if role.one_based() == input_party_id {
        let pubkey_raw =
            pubkey.ok_or_else(|| anyhow_error_and_log("I have no public key to send!"))?;
        let num_parties = session.num_parties();

        let pkval = NetworkValue::<LevelEll>::PubBgvKeySet(Box::new(pubkey_raw.clone()));
        tracing::debug!("Sending pk to all other parties");
        let send_pk = Arc::new(pkval.to_network());

        let mut set = JoinSet::new();
        for to_send_role in 1..=num_parties {
            if to_send_role != input_party_id {
                let networking = Arc::clone(session.network());

                let send_pk = Arc::clone(&send_pk);
                set.spawn(async move {
                    let _ = networking
                        .send(send_pk, &Role::indexed_from_one(to_send_role))
                        .await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(pubkey_raw)
    } else {
        let networking = Arc::clone(session.network());
        let timeout = session.network().get_timeout_current_round().await;
        tracing::debug!(
            "Waiting for receiving public key from input party with timeout {:?}",
            timeout
        );
        let data = tokio::spawn(timeout_at(timeout, async move {
            networking
                .receive(&Role::indexed_from_one(input_party_id))
                .await
        }))
        .await??;

        let pk = match NetworkValue::<LevelEll>::from_network(data, deserialization_runtime).await?
        {
            NetworkValue::PubBgvKeySet(pk) => pk,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a public key!",
            ))?,
        };
        tracing::debug!("Received PK from input party");
        Ok(*pk)
    }
}

pub async fn transfer_secret_key<S: BaseSessionHandles>(
    session: &mut S,
    secret_key: Option<SecretKey>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PrivateBgvKeySet> {
    let deserialization_runtime = DeSerializationRunTime::Rayon;
    let num_parties = session.num_parties();
    let threshold = session.threshold();

    let mut rng = session.rng();
    if let Some(sk) = secret_key {
        let ks = keygen_shares(&mut rng, &sk, num_parties, threshold);

        let mut set = JoinSet::new();
        for (to_send_role, sk) in ks.iter().enumerate() {
            if to_send_role + 1 != role.one_based() {
                let sk_vec = sk.sk.iter().map(|item| item.value()).collect_vec();
                let network_sk_shares = NetworkValue::<LevelOne>::VecRingValue(sk_vec);

                let networking = Arc::clone(session.network());
                let send_sk = network_sk_shares.clone();

                set.spawn(async move {
                    let _ = networking
                        .send(
                            Arc::new(send_sk.to_network()),
                            &Role::indexed_from_zero(to_send_role),
                        )
                        .await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        let as_ntt = ks[role].as_ntt_repr(N65536::VALUE, N65536::THETA);
        let ntt_shares = as_ntt
            .iter()
            .map(|ntt_val| Share::new(*role, *ntt_val))
            .collect_vec();
        Ok(PrivateBgvKeySet::from_eval_domain(ntt_shares))
    } else {
        let networking = Arc::clone(session.network());
        let timeout = session.network().get_timeout_current_round().await;
        let data = tokio::spawn(timeout_at(timeout, async move {
            networking
                .receive(&Role::indexed_from_one(input_party_id))
                .await
        }))
        .await??;

        let sk = match NetworkValue::<LevelOne>::from_network(data, deserialization_runtime).await?
        {
            NetworkValue::<LevelOne>::VecRingValue(sk) => sk,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a secret key!",
            ))?,
        };
        let sk_shares = sk
            .iter()
            .map(|sk_val| Share::new(*role, *sk_val))
            .collect_vec();
        Ok(PrivateBgvKeySet::from_poly_representation(sk_shares))
    }
}

// Main reason to have this wrapper is to implement CryptoRng for it
// also adds convenient functions to initialize the XOF with the correct DSEP
pub struct XofWrapper {
    xof: RandomGenerator<SoftwareRandomGenerator>,
}

impl XofWrapper {
    pub fn new_bgv_kg(seed: u128) -> Self {
        let xof =
            RandomGenerator::<SoftwareRandomGenerator>::new(XofSeed::new_u128(seed, *b"BGV_KeyG"));
        Self { xof }
    }

    pub fn new_bgv_enc(seed: u128) -> Self {
        let xof =
            RandomGenerator::<SoftwareRandomGenerator>::new(XofSeed::new_u128(seed, *b"BGV_Enc_"));
        Self { xof }
    }

    pub fn new_bfv_kg(seed: u128) -> Self {
        let xof =
            RandomGenerator::<SoftwareRandomGenerator>::new(XofSeed::new_u128(seed, *b"BFV_KeyG"));
        Self { xof }
    }

    pub fn new_bfv_enc(seed: u128) -> Self {
        let xof =
            RandomGenerator::<SoftwareRandomGenerator>::new(XofSeed::new_u128(seed, *b"BFV_Enc_"));
        Self { xof }
    }
}

impl RngCore for XofWrapper {
    fn next_u32(&mut self) -> u32 {
        self.xof.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.xof.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.xof.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.xof.try_fill_bytes(dest)
    }
}

impl CryptoRng for XofWrapper {}
