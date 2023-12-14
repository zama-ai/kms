use std::{num::Wrapping, sync::Arc};

use ndarray::Array1;
use rand_chacha::ChaCha20Rng;
use tokio::{task::JoinSet, time::timeout_at};

use crate::{
    algebra::{residue_poly::ResiduePoly, residue_poly::ResiduePoly128, structure_traits::Ring},
    error::error_handler::anyhow_error_and_log,
    execution::{
        runtime::{
            party::Role,
            session::{
                BaseSession, BaseSessionHandles, ParameterHandles, SessionParameters, SetupMode,
                SmallSession, SmallSessionStruct, ToBaseSession,
            },
        },
        sharing::input::robust_input,
        small_execution::{agree_random::DummyAgreeRandom, prss::PRSSSetup},
    },
    lwe::{gen_key_set, PubConKeyPair, SecretKeyShare, ThresholdLWEParameters},
    networking::value::NetworkValue,
};

pub async fn transfer_pk<Z: Ring>(
    session: &BaseSession,
    pubkey: &PubConKeyPair,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PubConKeyPair> {
    session.network().increase_round_counter().await?;
    if role.one_based() == input_party_id {
        let num_parties = session.amount_of_parties();
        let pkval = NetworkValue::<Z>::PubKey(Box::new(pubkey.clone()));

        let mut set = JoinSet::new();
        for to_send_role in 1..=num_parties {
            if to_send_role != input_party_id {
                let identity = session.identity_from(&Role::indexed_by_one(to_send_role))?;

                let networking = Arc::clone(session.network());
                let session_id = session.session_id();
                let send_pk = pkval.clone();

                set.spawn(async move {
                    let _ = networking
                        .send(send_pk.to_network(), &identity, &session_id)
                        .await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(pubkey.clone())
    } else {
        let receiver = session.identity_from(&Role::indexed_by_one(input_party_id))?;
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let data = tokio::spawn(timeout_at(
            session.network().get_timeout_current_round()?,
            async move { networking.receive(&receiver, &session_id).await },
        ))
        .await??;

        let pk = match NetworkValue::<Z>::from_network(data)? {
            NetworkValue::PubKey(pk) => pk,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a public key!".to_string(),
            ))?,
        };
        Ok(*pk)
    }
}

pub async fn initialize_key_material(
    session: &mut SmallSession<ResiduePoly128>,
    setup_mode: SetupMode,
    params: ThresholdLWEParameters,
) -> anyhow::Result<(
    SecretKeyShare,
    PubConKeyPair,
    Option<PRSSSetup<ResiduePoly128>>,
)> {
    let prss_setup = if setup_mode == SetupMode::AllProtos {
        Some(
            PRSSSetup::init_with_abort::<
                DummyAgreeRandom,
                ChaCha20Rng,
                SmallSessionStruct<ResiduePoly128, ChaCha20Rng, SessionParameters>,
            >(session)
            .await?,
        )
    } else {
        None
    };

    let keyset = gen_key_set(params, &mut session.rng());

    let sk_container = keyset.sk.lwe_secret_key_128.into_container();
    let mut key_shares = Vec::new();
    let own_role = session.my_role()?;
    // iterate through sk and share each element
    for cur in sk_container {
        let secret = match own_role.one_based() {
            1 => Some(ResiduePoly::from_scalar(Wrapping::<u128>(cur))),
            _ => None,
        };
        let share =
            robust_input::<_, ChaCha20Rng>(&mut session.to_base_session(), &secret, &own_role, 1)
                .await?; //TODO(Daniel) batch this for all big_ell

        key_shares.push(share);
    }
    let pubcon = PubConKeyPair {
        pk: keyset.pk,
        ck: keyset.ck,
    };
    let transferred_pk =
        transfer_pk::<ResiduePoly128>(&session.to_base_session(), &pubcon, &own_role, 1).await?;

    let shared_sk = SecretKeyShare {
        input_key_share: Array1::from_vec(key_shares),
        threshold_lwe_parameters: params,
    };

    Ok((shared_sk, transferred_pk, prss_setup))
}
