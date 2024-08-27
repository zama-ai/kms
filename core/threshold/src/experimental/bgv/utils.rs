use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::runtime::party::Role;
use crate::execution::runtime::session::BaseSessionHandles;
use crate::execution::sharing::share::Share;
use crate::experimental::algebra::levels::LevelEll;
use crate::experimental::algebra::levels::LevelKsw;
use crate::experimental::algebra::levels::LevelOne;
use crate::experimental::algebra::ntt::Const;
use crate::experimental::algebra::ntt::NTTConstants;
use crate::experimental::algebra::ntt::N65536;
use crate::experimental::bgv::basics::{keygen, PrivateBgvKeySet, PublicBgvKeySet, SecretKey};
use crate::experimental::bgv::ddec::keygen_shares;
use crate::experimental::constants::PLAINTEXT_MODULUS;
use crate::networking::value::NetworkValue;
use aes_prng::AesRng;
use itertools::Itertools;
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio::time::timeout_at;

pub(crate) fn gen_key_set() -> (PublicBgvKeySet, SecretKey) {
    let mut rng = AesRng::seed_from_u64(0);

    let (pk, sk) =
        keygen::<AesRng, LevelEll, LevelKsw, N65536>(&mut rng, PLAINTEXT_MODULUS.get().0);

    (pk, sk)
}

pub async fn transfer_pub_key<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &S,
    pubkey: Option<PublicBgvKeySet>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PublicBgvKeySet> {
    session.network().increase_round_counter()?;
    if role.one_based() == input_party_id {
        let pubkey_raw =
            pubkey.ok_or_else(|| anyhow_error_and_log("I have no public key to send!"))?;
        let num_parties = session.num_parties();

        let pkval = NetworkValue::<LevelEll>::PubBgvKeySet(Box::new(pubkey_raw.clone()));
        tracing::debug!("Sending pk to all other parties");

        let mut set = JoinSet::new();
        for to_send_role in 1..=num_parties {
            if to_send_role != input_party_id {
                let identity = session.identity_from(&Role::indexed_by_one(to_send_role))?;

                let networking = Arc::clone(session.network());
                let send_pk = pkval.clone();

                set.spawn(async move {
                    let _ = networking.send(send_pk.to_network(), &identity).await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(pubkey_raw)
    } else {
        let receiver = session.identity_from(&Role::indexed_by_one(input_party_id))?;
        let networking = Arc::clone(session.network());
        let timeout = session.network().get_timeout_current_round()?;
        tracing::debug!(
            "Waiting for receiving public key from input party with timeout {:?}",
            timeout
        );
        let data = tokio::spawn(timeout_at(timeout, async move {
            networking.receive(&receiver).await
        }))
        .await??;

        let pk = match NetworkValue::<LevelEll>::from_network(data)? {
            NetworkValue::PubBgvKeySet(pk) => pk,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a public key!",
            ))?,
        };
        tracing::debug!("Received PK from input party");
        Ok(*pk)
    }
}

pub async fn transfer_secret_key<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &mut S,
    secret_key: Option<SecretKey>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PrivateBgvKeySet> {
    let num_parties = session.num_parties();
    let threshold = session.threshold();

    let mut rng = session.rng();
    if let Some(sk) = secret_key {
        let ks = keygen_shares(&mut rng, &sk, num_parties, threshold);

        let mut set = JoinSet::new();
        for (to_send_role, sk) in ks.iter().enumerate() {
            if to_send_role != role.zero_based() {
                let identity = session.identity_from(&Role::indexed_by_zero(to_send_role))?;
                let sk_vec = sk.sk.iter().map(|item| item.value()).collect_vec();
                let network_sk_shares = NetworkValue::<LevelOne>::VecRingValue(sk_vec);

                let networking = Arc::clone(session.network());
                let send_sk = network_sk_shares.clone();

                set.spawn(async move {
                    let _ = networking.send(send_sk.to_network(), &identity).await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        let as_ntt = ks[role.zero_based()].as_ntt_repr(N65536::VALUE, N65536::THETA);
        let ntt_shares = as_ntt
            .iter()
            .map(|ntt_val| Share::new(*role, *ntt_val))
            .collect_vec();
        Ok(PrivateBgvKeySet::from_eval_domain(ntt_shares))
    } else {
        let receiver = session.identity_from(&Role::indexed_by_one(input_party_id))?;
        let networking = Arc::clone(session.network());
        let timeout = session.network().get_timeout_current_round()?;
        let data = tokio::spawn(timeout_at(timeout, async move {
            networking.receive(&receiver).await
        }))
        .await??;

        let sk = match NetworkValue::<LevelOne>::from_network(data)? {
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
