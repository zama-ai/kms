use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{num::Wrapping, sync::Arc};
use tfhe::{
    core_crypto::{
        commons::traits::Numeric,
        entities::{GlweSecretKey, LweSecretKey},
    },
    integer::compression_keys::DecompressionKey,
    prelude::{FheDecrypt, FheTryEncrypt},
    shortint::{
        self, list_compression::CompressionPrivateKeys, ClassicPBSParameters, ShortintParameterSet,
    },
    zk::CompactPkeCrs,
    ClientKey, ConfigBuilder, Seed,
};
use tokio::{task::JoinSet, time::timeout_at};

use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        poly::Poly,
        structure_traits::{Ring, RingEmbed},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        endpoints::keygen::{
            CompressionPrivateKeySharesEnum, FhePubKeySet, GlweSecretKeyShareEnum, PrivateKeySet,
        },
        runtime::{party::Role, session::BaseSessionHandles},
        sharing::{input::robust_input, share::Share},
        tfhe_internals::{
            compression_decompression_key::CompressionPrivateKeyShares,
            glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare,
        },
    },
    networking::value::NetworkValue,
};

use super::parameters::{DKGParams, DKGParamsBasics};

/// the party ID of the party doing the reconstruction
pub const INPUT_PARTY_ID: usize = 1;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeySet {
    pub client_key: tfhe::ClientKey,
    pub public_keys: FhePubKeySet,
}
impl KeySet {
    pub fn get_raw_lwe_client_key(&self) -> LweSecretKey<Vec<u64>> {
        let (inner_client_key, _, _, _, _) = self.client_key.clone().into_raw_parts();
        let short_client_key = inner_client_key.into_raw_parts();
        let (_glwe_secret_key, lwe_secret_key, _shortint_param) = short_client_key.into_raw_parts();
        lwe_secret_key
    }

    pub fn get_raw_lwe_encryption_client_key(&self) -> LweSecretKey<Vec<u64>> {
        // We should have this key even if the compact PKE parameters are empty
        // because we want to match the behaviour of a normal DKG.
        // In the normal DKG the shares that correspond to the lwe private key
        // is copied to the encryption private key if the compact PKE parameters
        // don't exist.
        let (_, compact_private_key, _, _, _) = self.client_key.clone().into_raw_parts();
        if let Some(inner) = compact_private_key {
            let raw_parts = inner.0.into_raw_parts();
            raw_parts.into_raw_parts().0
        } else {
            self.get_raw_lwe_client_key()
        }
    }

    pub fn get_raw_compression_client_key(&self) -> Option<GlweSecretKey<Vec<u64>>> {
        let (_, _, compression_sk, _, _) = self.client_key.clone().into_raw_parts();
        if let Some(inner) = compression_sk {
            let raw_parts = inner.into_raw_parts();
            Some(raw_parts.post_packing_ks_key)
        } else {
            None
        }
    }

    pub fn get_raw_glwe_client_key(&self) -> GlweSecretKey<Vec<u64>> {
        let (inner_client_key, _, _, _, _) = self.client_key.clone().into_raw_parts();
        let short_client_key = inner_client_key.into_raw_parts();
        let (glwe_secret_key, _lwe_secret_key, _shortint_param) = short_client_key.into_raw_parts();
        glwe_secret_key
    }

    pub fn get_raw_glwe_client_sns_key(&self) -> Option<GlweSecretKey<Vec<u128>>> {
        let (_, _, _, noise_squashing_key, _) = self.client_key.clone().into_raw_parts();
        noise_squashing_key.map(|sns_key| sns_key.into_raw_parts().into_raw_parts().0)
    }

    pub fn get_raw_glwe_client_sns_key_as_lwe(&self) -> Option<LweSecretKey<Vec<u128>>> {
        self.get_raw_glwe_client_sns_key()
            .map(|inner| inner.into_lwe_secret_key())
    }

    pub fn get_cpu_params(&self) -> anyhow::Result<ClassicPBSParameters> {
        match self.client_key.computation_parameters() {
            shortint::PBSParameters::PBS(classic_pbsparameters) => Ok(classic_pbsparameters),
            shortint::PBSParameters::MultiBitPBS(_) => anyhow::bail!("GPU parameters unsupported"),
        }
    }
}

pub fn gen_key_set<R: Rng + CryptoRng>(params: DKGParams, rng: &mut R) -> KeySet {
    let pbs_params: ClassicPBSParameters = params
        .get_params_basics_handle()
        .to_classic_pbs_parameters();
    let compression_params = params
        .get_params_basics_handle()
        .get_compression_decompression_params();
    let noise_squashing_params = match params {
        DKGParams::WithoutSnS(_) => None,
        DKGParams::WithSnS(dkg_sns) => Some(dkg_sns.sns_params),
    };
    let config = ConfigBuilder::with_custom_parameters(pbs_params);
    let config = if let Some(dedicated_pk_params) =
        params.get_params_basics_handle().get_dedicated_pk_params()
    {
        config.use_dedicated_compact_public_key_parameters(dedicated_pk_params)
    } else {
        config
    };
    let config = if let Some(params) = compression_params {
        config.enable_compression(params.raw_compression_parameters)
    } else {
        config
    };
    let config = if let Some(params) = noise_squashing_params {
        config.enable_noise_squashing(params)
    } else {
        config
    };
    let seed = Seed(rng.gen());
    let client_key = ClientKey::generate_with_seed(config, seed);

    let public_key = tfhe::CompactPublicKey::new(&client_key);
    let server_key = tfhe::ServerKey::new(&client_key);

    let public_keys = FhePubKeySet {
        public_key,
        server_key,
    };
    KeySet {
        client_key,
        public_keys,
    }
}

// TODO we should add a unit test for this
pub async fn initialize_key_material<S: BaseSessionHandles, const EXTENSION_DEGREE: usize>(
    session: &mut S,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    let own_role = session.my_role();
    let params_basic_handle = params.get_params_basics_handle();

    let keyset = if own_role.one_based() == INPUT_PARTY_ID {
        tracing::info!("Keyset generated by input party {}", own_role);
        Some(gen_key_set(params, &mut session.rng()))
    } else {
        None
    };

    let lwe_sk_container64: Vec<u64> = keyset
        .as_ref()
        .map(|s| s.clone().get_raw_lwe_client_key().into_container())
        .unwrap_or_else(|| {
            // TODO: This needs to be refactor, since we have done this hack in order all the
            // parties that are not INPUT_PARTY_ID wait for INPUT_PARTY_ID to generate the keyset
            // and distribute the lwe secret key vector to the rest. Otherwise if we would have set
            // Vec::new() here, the other parties would have continued to transfer_pk and would
            // have panicked because they would have received something different from a PK.
            vec![Numeric::ZERO; params_basic_handle.lwe_dimension().0]
        });

    let lwe_encryption_sk_container64: Vec<u64> = keyset
        .as_ref()
        .map(|s| {
            s.clone()
                .get_raw_lwe_encryption_client_key()
                .into_container()
        })
        .unwrap_or_else(|| vec![Numeric::ZERO; params_basic_handle.lwe_hat_dimension().0]);

    let glwe_sk_container64: Vec<u64> = keyset
        .as_ref()
        .map(|s| s.clone().get_raw_glwe_client_key().into_container())
        .unwrap_or_else(|| vec![Numeric::ZERO; params_basic_handle.glwe_sk_num_bits()]);

    let sns_sk_container128: Option<Vec<u128>> = if let DKGParams::WithSnS(params_sns) = params {
        Some(
            keyset
                .as_ref()
                .and_then(|s| {
                    s.clone()
                        .get_raw_glwe_client_sns_key()
                        .map(|x| x.into_container())
                })
                .unwrap_or_else(|| {
                    // TODO: This needs to be refactor, since we have done this hack in order all the
                    // parties that are not INPUT_PARTY_ID wait for INPUT_PARTY_ID to generate the keyset
                    // and distribute the lwe secret key vector to the rest. Otherwise if we would have set
                    // Vec::new() here, the other parties would have continued to transfer_pk and would
                    // have panicked because they would have received something different from a PK.
                    vec![Numeric::ZERO; params_sns.glwe_sk_num_bits_sns()]
                }),
        )
    } else {
        None
    };

    // We need to check that when the compression parameters are available,
    // there is always a compression client key, otherwise there will
    // be an inconsistency between the leader (party 1) and the other parties
    // since the leader will output None for compression_sk_container64
    // and the other parties will output Some(vec![..]).
    if let Some(ks) = &keyset {
        if ks.get_raw_compression_client_key().is_none()
            && params_basic_handle
                .get_compression_decompression_params()
                .is_some()
        {
            anyhow::bail!("Compression client key is missing when parameter is available")
        }
    }

    let compression_sk_container64: Option<Vec<u64>> = match &keyset {
        Some(s) => {
            if params_basic_handle
                .get_compression_decompression_params()
                .is_none()
            {
                None
            } else {
                s.clone()
                    .get_raw_compression_client_key()
                    .map(|x| x.into_container())
            }
        }
        None => {
            if params_basic_handle
                .get_compression_decompression_params()
                .is_none()
            {
                None
            } else {
                Some(vec![
                    Numeric::ZERO;
                    params_basic_handle.compression_sk_num_bits()
                ])
            }
        }
    };

    tracing::debug!(
        "I'm {:?}, Sharing key64 to be sent: len {}",
        session.my_role(),
        lwe_sk_container64.len()
    );
    let secrets = if INPUT_PARTY_ID == own_role.one_based() {
        Some(
            lwe_sk_container64
                .iter()
                .map(|cur| ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u64>(*cur)))
                .collect_vec(),
        )
    } else {
        None
    };

    let lwe_key_shares64 = robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

    tracing::debug!(
        "I'm {:?}, Sharing encryption key64 to be sent: len {}",
        session.my_role(),
        lwe_encryption_sk_container64.len()
    );
    let secrets = if INPUT_PARTY_ID == own_role.one_based() {
        Some(
            lwe_encryption_sk_container64
                .iter()
                .map(|cur| ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u64>(*cur)))
                .collect_vec(),
        )
    } else {
        None
    };
    let lwe_encryption_key_shares64 =
        robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

    tracing::debug!(
        "I'm {:?}, Sharing glwe client key 64 to be sent: len {}",
        session.my_role(),
        glwe_sk_container64.len(),
    );

    let secrets = if INPUT_PARTY_ID == own_role.one_based() {
        Some(
            glwe_sk_container64
                .iter()
                .map(|cur| {
                    ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>((*cur).into()))
                })
                .collect_vec(),
        )
    } else {
        None
    };
    let glwe_key_shares128 = robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

    let sns_key_shares128 = if let Some(sns_sk_container128) = sns_sk_container128 {
        tracing::debug!(
            "I'm {:?}, Sharing key128 to be sent: len {}",
            session.my_role(),
            sns_sk_container128.len()
        );
        let secrets = if INPUT_PARTY_ID == own_role.one_based() {
            Some(
                sns_sk_container128
                    .iter()
                    .map(|cur| {
                        ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(*cur))
                    })
                    .collect_vec(),
            )
        } else {
            None
        };
        let sns_key_shares128 = robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;

        Some(LweSecretKeyShare {
            data: sns_key_shares128,
        })
    } else {
        None
    };

    tracing::debug!(
        "I'm {:?}, Sharing compression key: len {:?}",
        session.my_role(),
        compression_sk_container64.as_ref().map(|x| x.len()),
    );

    // there doesn't seem to be a way to get the compression key as a reference
    let mut glwe_compression_key_shares128 = Vec::new();
    if let Some(compression_container) = compression_sk_container64 {
        let secrets = if INPUT_PARTY_ID == own_role.one_based() {
            Some(
                compression_container
                    .iter()
                    .map(|cur| {
                        ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<u128>(
                            (*cur).into(),
                        ))
                    })
                    .collect_vec(),
            )
        } else {
            None
        };
        glwe_compression_key_shares128 =
            robust_input(session, &secrets, &own_role, INPUT_PARTY_ID).await?;
    };
    tracing::debug!("I'm {:?}, private keys are all sent", session.my_role());

    let glwe_secret_key_share_compression = params_basic_handle
        .get_compression_decompression_params()
        .map(|compression_params| {
            let params = compression_params.raw_compression_parameters;
            CompressionPrivateKeySharesEnum::Z128(CompressionPrivateKeyShares {
                post_packing_ks_key: GlweSecretKeyShare {
                    data: glwe_compression_key_shares128,
                    polynomial_size: params.packing_ks_polynomial_size,
                },
                params,
            })
        });

    let transferred_pub_key =
        transfer_pub_key(session, keyset.map(|set| set.public_keys), INPUT_PARTY_ID).await?;

    let shared_sk = PrivateKeySet {
        lwe_compute_secret_key_share: LweSecretKeyShare {
            data: lwe_key_shares64,
        },
        lwe_encryption_secret_key_share: LweSecretKeyShare {
            data: lwe_encryption_key_shares64,
        },
        glwe_secret_key_share: GlweSecretKeyShareEnum::Z128(GlweSecretKeyShare {
            data: glwe_key_shares128,
            polynomial_size: params_basic_handle.polynomial_size(),
        }),
        glwe_secret_key_share_sns_as_lwe: sns_key_shares128,
        parameters: params_basic_handle.to_classic_pbs_parameters(),
        glwe_secret_key_share_compression,
    };

    Ok((transferred_pub_key, shared_sk))
}

pub async fn transfer_pub_key<S: BaseSessionHandles>(
    session: &S,
    pubkey: Option<FhePubKeySet>,
    input_party_id: usize,
) -> anyhow::Result<FhePubKeySet> {
    let pkval = pubkey.map(|inner| NetworkValue::<Z128>::PubKeySet(Box::new(inner)));
    let network_val = transfer_network_value(session, pkval, input_party_id).await?;
    match network_val {
        NetworkValue::PubKeySet(pk) => Ok(*pk),
        _ => Err(anyhow_error_and_log(
            "I have received something different from a public key!",
        ))?,
    }
}

/// Send the CRS to the other parties, if I am the input party in this session. Else receive the CRS.
pub async fn transfer_crs<S: BaseSessionHandles>(
    session: &S,
    some_crs: Option<CompactPkeCrs>,
    input_party_id: usize,
) -> anyhow::Result<CompactPkeCrs> {
    let crs = some_crs.map(|inner| NetworkValue::<Z128>::Crs(Box::new(inner)));
    let network_val = transfer_network_value(session, crs, input_party_id).await?;
    match network_val {
        NetworkValue::Crs(crs) => Ok(*crs),
        _ => Err(anyhow_error_and_log(
            "I have received something different from a CRS!",
        ))?,
    }
}

pub async fn transfer_decompression_key<S: BaseSessionHandles>(
    session: &S,
    decompression_key: Option<DecompressionKey>,
    input_party_id: usize,
) -> anyhow::Result<DecompressionKey> {
    let decompression_key =
        decompression_key.map(|inner| NetworkValue::<Z128>::DecompressionKey(Box::new(inner)));
    let network_val = transfer_network_value(session, decompression_key, input_party_id).await?;
    match network_val {
        NetworkValue::DecompressionKey(dk) => Ok(*dk),
        _ => Err(anyhow_error_and_log(
            "I have received something different from a DecompressionKey!",
        ))?,
    }
}

async fn transfer_network_value<S: BaseSessionHandles>(
    session: &S,
    network_value: Option<NetworkValue<Z128>>,
    input_party_id: usize,
) -> anyhow::Result<NetworkValue<Z128>> {
    session.network().increase_round_counter()?;
    if session.my_role().one_based() == input_party_id {
        // send the value
        let network_val =
            network_value.ok_or_else(|| anyhow_error_and_log("I have no value to send!"))?;
        let num_parties = session.num_parties();
        tracing::debug!(
            "I'm the input party. Sending value to {} other parties...",
            num_parties - 1
        );

        let mut set = JoinSet::new();
        let buf_to_send = network_val.clone().to_network();
        for receiver in 1..=num_parties {
            if receiver != input_party_id {
                let rcv_identity = session.identity_from(&Role::indexed_from_one(receiver))?;

                let networking = Arc::clone(session.network());

                let cloned_buf = buf_to_send.clone();
                set.spawn(async move {
                    let _ = networking.send(cloned_buf, &rcv_identity).await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(network_val)
    } else {
        // receive the value
        let sender_identity = session.identity_from(&Role::indexed_from_one(input_party_id))?;
        let networking = Arc::clone(session.network());
        let timeout = session.network().get_timeout_current_round()?;
        tracing::debug!(
            "Waiting to receive value from input party with timeout {:?}",
            timeout
        );
        let data = tokio::spawn(timeout_at(timeout, async move {
            networking.receive(&sender_identity).await
        }))
        .await??;

        Ok(NetworkValue::<Z128>::from_network(data)?)
    }
}

pub fn to_hl_client_key(
    params: &DKGParams,
    lwe_secret_key: LweSecretKey<Vec<u64>>,
    glwe_secret_key: GlweSecretKey<Vec<u64>>,
    dedicated_compact_private_key: Option<LweSecretKey<Vec<u64>>>,
    compression_key: Option<GlweSecretKey<Vec<u64>>>,
    sns_secret_key: Option<GlweSecretKey<Vec<u128>>>,
) -> anyhow::Result<tfhe::ClientKey> {
    let regular_params = match params {
        DKGParams::WithSnS(p) => p.regular_params,
        DKGParams::WithoutSnS(p) => *p,
    };
    let ciphertext_params = regular_params.ciphertext_parameters;
    let sps = ShortintParameterSet::new_pbs_param_set(tfhe::shortint::PBSParameters::PBS(
        ciphertext_params,
    ));
    let sck = shortint::ClientKey::from_raw_parts(glwe_secret_key, lwe_secret_key, sps);

    //If necessary generate a dedicated compact private key
    let dedicated_compact_private_key =
        if let (Some(dedicated_compact_private_key), Some(pk_params)) = (
            dedicated_compact_private_key,
            regular_params.get_dedicated_pk_params(),
        ) {
            Some((
                tfhe::integer::CompactPrivateKey::from_raw_parts(
                    tfhe::shortint::CompactPrivateKey::from_raw_parts(
                        dedicated_compact_private_key,
                        pk_params.0,
                    )?,
                ),
                pk_params.1,
            ))
        } else {
            None
        };

    //If necessary generate a dedicated compression private key
    let compression_key = if let (Some(compression_private_key), Some(params)) = (
        compression_key,
        regular_params.get_compression_decompression_params(),
    ) {
        let polynomial_size = compression_private_key.polynomial_size();
        Some(
            tfhe::integer::compression_keys::CompressionPrivateKeys::from_raw_parts(
                CompressionPrivateKeys {
                    post_packing_ks_key: GlweSecretKey::from_container(
                        compression_private_key.into_container(),
                        polynomial_size,
                    ),
                    params: params.raw_compression_parameters,
                },
            ),
        )
    } else {
        None
    };

    // If necessary generate a dedicated noise squashing private key
    let noise_squashing_key = match (sns_secret_key, params) {
        (None, DKGParams::WithoutSnS(_)) => None,
        (None, DKGParams::WithSnS(_)) => {
            anyhow::bail!("missing noise squashing secret key")
        }
        (Some(_), DKGParams::WithoutSnS(_)) => {
            anyhow::bail!("missing noise squashing parameters")
        }
        (Some(sns_sk), DKGParams::WithSnS(sns_params)) => Some(
            tfhe::integer::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                tfhe::shortint::noise_squashing::NoiseSquashingPrivateKey::from_raw_parts(
                    sns_sk,
                    sns_params.sns_params,
                ),
            ),
        ),
    };
    Ok(ClientKey::from_raw_parts(
        sck.into(),
        dedicated_compact_private_key,
        compression_key,
        noise_squashing_key,
        tfhe::Tag::default(),
    ))
}

/// Keygen that generates secret key shares for many parties
/// Note that Z64 shares of glwe_secret_key_share is used. So this function
/// should not be used in combination with key rotation tests.
///
/// __NOTE__: Some secret keys are actually dummy or None, what we really need here are the key
/// passed as input.
pub fn keygen_all_party_shares<R: Rng + CryptoRng, const EXTENSION_DEGREE: usize>(
    lwe_secret_key: LweSecretKey<Vec<u64>>,
    glwe_secret_key: GlweSecretKey<Vec<u64>>,
    glwe_secret_key_sns_as_lwe: LweSecretKey<Vec<u128>>,
    parameters: ClassicPBSParameters,
    rng: &mut R,
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<Vec<PrivateKeySet<EXTENSION_DEGREE>>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    let s_vector = glwe_secret_key_sns_as_lwe.into_container();
    let s_length = s_vector.len();
    let mut vv128: Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> =
        vec![Vec::with_capacity(s_length); num_parties];

    let role_with_embeddings_z64 = (1..=num_parties)
        .map(|party_id| {
            Ok((
                Role::indexed_from_one(party_id),
                ResiduePoly::<Z64, EXTENSION_DEGREE>::embed_exceptional_set(party_id)?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let role_with_embeddings_z128 = (1..=num_parties)
        .map(|party_id| {
            Ok((
                Role::indexed_from_one(party_id),
                ResiduePoly::<Z128, EXTENSION_DEGREE>::embed_exceptional_set(party_id)?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // for each bit in the secret key generate all parties shares
    for (i, bit) in s_vector.iter().enumerate() {
        let embedded_secret = ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping(*bit));
        let poly = Poly::sample_random_with_fixed_constant(rng, embedded_secret, threshold);

        for (v, (role, embedding)) in vv128.iter_mut().zip_eq(role_with_embeddings_z128.iter()) {
            v.insert(i, Share::new(*role, poly.eval(embedding)));
        }
    }

    // do the same for 64 bit lwe key
    let s_vector64 = lwe_secret_key.into_container();
    let s_length64 = s_vector64.len();
    let mut vv64_lwe_key: Vec<Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>> =
        vec![Vec::with_capacity(s_length64); num_parties];
    // for each bit in the secret key generate all parties shares
    for (i, bit) in s_vector64.iter().enumerate() {
        let embedded_secret = ResiduePoly::<Z64, EXTENSION_DEGREE>::from_scalar(Wrapping(*bit));
        let poly = Poly::sample_random_with_fixed_constant(rng, embedded_secret, threshold);

        for (v, (role, embedding)) in vv64_lwe_key
            .iter_mut()
            .zip_eq(role_with_embeddings_z64.iter())
        {
            v.insert(i, Share::new(*role, poly.eval(embedding)));
        }
    }

    // do the same for 64 bit glwe key
    let glwe_poly_size = glwe_secret_key.polynomial_size();
    let s_vector64 = glwe_secret_key.into_container();
    let s_length64 = s_vector64.len();
    let mut vv64_glwe_key: Vec<Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>> =
        vec![Vec::with_capacity(s_length64); num_parties];
    // for each bit in the secret key generate all parties shares
    for (i, bit) in s_vector64.iter().enumerate() {
        let embedded_secret = ResiduePoly::<Z64, EXTENSION_DEGREE>::from_scalar(Wrapping(*bit));
        let poly = Poly::sample_random_with_fixed_constant(rng, embedded_secret, threshold);

        for (v, (role, embedding)) in vv64_glwe_key
            .iter_mut()
            .zip_eq(role_with_embeddings_z64.iter())
        {
            v.insert(i, Share::new(*role, poly.eval(embedding)));
        }
    }

    // put the individual parties shares into SecretKeyShare structs
    let shared_sks: Vec<_> = (0..num_parties)
        .map(|p| PrivateKeySet {
            lwe_compute_secret_key_share: LweSecretKeyShare {
                data: vv64_lwe_key[p].clone(),
            },
            //For now assume the encryption key is same as compute key
            lwe_encryption_secret_key_share: LweSecretKeyShare {
                data: vv64_lwe_key[p].clone(),
            },
            glwe_secret_key_share: GlweSecretKeyShareEnum::Z64(GlweSecretKeyShare {
                data: vv64_glwe_key[p].clone(),
                polynomial_size: glwe_poly_size,
            }),
            glwe_secret_key_share_sns_as_lwe: Some(LweSecretKeyShare {
                data: vv128[p].clone(),
            }),
            parameters,
            glwe_secret_key_share_compression: None,
        })
        .collect();

    Ok(shared_sks)
}

impl PartialEq for FhePubKeySet {
    fn eq(&self, other: &Self) -> bool {
        // check the public keys are the same
        let ok1 = {
            let (pk, tag) = self.public_key.clone().into_raw_parts();
            let (other_pk, other_tag) = other.clone().public_key.into_raw_parts();
            pk.into_raw_parts() == other_pk.into_raw_parts() && tag == other_tag
        };

        let (sks, ksk, comp, decomp, sns, tag) = self.server_key.clone().into_raw_parts();
        let (other_sks, other_ksk, other_comp, other_decomp, other_sns, other_tag) =
            other.server_key.clone().into_raw_parts();
        let ok2 = sks.into_raw_parts() == other_sks.into_raw_parts()
            && ksk.map(|x| x.into_raw_parts()) == other_ksk.map(|x| x.into_raw_parts())
            && comp.map(|x| x.into_raw_parts()) == other_comp.map(|x| x.into_raw_parts())
            && decomp.map(|x| x.into_raw_parts()) == other_decomp.map(|x| x.into_raw_parts())
            && sns.map(|x| x.into_raw_parts()) == other_sns.map(|x| x.into_raw_parts())
            && tag == other_tag;

        ok1 && ok2
    }
}

impl std::fmt::Debug for FhePubKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubKeySet")
            .field("public_key", &self.public_key)
            .field("server_key", &"ommitted")
            .finish()
    }
}

pub fn run_decompression_test(
    keyset1_client_key: &tfhe::ClientKey,
    keyset2_client_key: &tfhe::ClientKey,
    keyset1_server_key: Option<&tfhe::ServerKey>,
    decompression_key: tfhe::shortint::list_compression::DecompressionKey,
) {
    // do some sanity checks
    let server_key1 = match keyset1_server_key {
        Some(inner) => inner,
        None => &keyset1_client_key.generate_server_key(),
    };
    let (_, _, _, decompression_key1, _, _) = server_key1.clone().into_raw_parts();
    let decompression_key1 = decompression_key1.unwrap().into_raw_parts();
    assert_eq!(
        decompression_key1.blind_rotate_key.glwe_size(),
        decompression_key.blind_rotate_key.glwe_size()
    );
    assert_eq!(
        decompression_key1.blind_rotate_key.input_lwe_dimension(),
        decompression_key.blind_rotate_key.input_lwe_dimension(),
    );
    assert_eq!(
        decompression_key1.blind_rotate_key.output_lwe_dimension(),
        decompression_key.blind_rotate_key.output_lwe_dimension(),
    );
    assert_eq!(
        decompression_key1.blind_rotate_key.polynomial_size(),
        decompression_key.blind_rotate_key.polynomial_size(),
    );

    let decompression_key =
        tfhe::integer::compression_keys::DecompressionKey::from_raw_parts(decompression_key);
    // create a ciphertext using keyset 1
    tfhe::set_server_key(server_key1.clone());
    let pt = 12u32;
    let ct = tfhe::FheUint32::try_encrypt(pt, keyset1_client_key).unwrap();
    let compressed_ct = tfhe::CompressedCiphertextListBuilder::new()
        .push(ct)
        .build()
        .unwrap();

    // then decompression it into keyset 2
    println!("Decompression ct under keyset1 to keyset2");
    let (radix_ciphertext, _) = compressed_ct.into_raw_parts();
    let ct2: tfhe::FheUint32 = radix_ciphertext
        .get(0, &decompression_key)
        .unwrap()
        .unwrap();

    // finally check we can decrypt it using the client key from keyset 2
    println!("Attempting to decrypt under keyset2");
    let pt2: u32 = ct2.decrypt(keyset2_client_key);
    assert_eq!(pt, pt2);
}

#[cfg(test)]
mod tests {
    use tfhe::{
        prelude::{CiphertextList, FheDecrypt},
        set_server_key, FheUint8,
    };

    use crate::{
        execution::{constants::REAL_KEY_PATH, tfhe_internals::test_feature::KeySet},
        file_handling::tests::read_element,
    };

    // TODO does not work with test key. Enable if test keys get updated
    // // #[test]
    // fn sunshine_hl_keys_test() {
    //     sunshine_hl_keys(SMALL_TEST_KEY_PATH);
    // }

    #[test]
    fn sunshine_hl_keys_real() {
        sunshine_hl_keys(REAL_KEY_PATH);
    }

    /// Helper method for validating conversion to high level API keys.
    /// Method tries to encrypt using both public and client keys and validates
    /// that the results are correct and consistent.
    fn sunshine_hl_keys(path: &str) {
        let keyset: KeySet = read_element(path).unwrap();

        let ctxt_build = tfhe::CompactCiphertextListBuilder::new(&keyset.public_keys.public_key)
            .push(42_u8)
            .push(55_u8)
            .push(5_u8)
            .build();

        set_server_key(keyset.public_keys.server_key);
        let expanded_ctxt_build = ctxt_build.expand().unwrap();

        let ct_a: FheUint8 = expanded_ctxt_build.get(0).unwrap().unwrap();
        let ct_b: FheUint8 = expanded_ctxt_build.get(1).unwrap().unwrap();
        let ct_c: FheUint8 = expanded_ctxt_build.get(2).unwrap().unwrap();

        let compressed_list = tfhe::CompressedCiphertextListBuilder::new()
            .push(ct_a)
            .push(ct_b)
            .push(ct_c)
            .build()
            .unwrap();

        let ct_a: FheUint8 = compressed_list.get(0).unwrap().unwrap();
        let ct_b: FheUint8 = compressed_list.get(1).unwrap().unwrap();
        let ct_c: FheUint8 = compressed_list.get(2).unwrap().unwrap();

        let decrypted_a: u8 = ct_a.decrypt(&keyset.client_key);
        assert_eq!(42, decrypted_a);

        let ct_sum = ct_a.clone() + ct_b;
        let sum: u8 = ct_sum.decrypt(&keyset.client_key);
        assert_eq!(42 + 55, sum);
        let ct_product = ct_a * ct_c;
        let product: u8 = ct_product.decrypt(&keyset.client_key);
        assert_eq!(42 * 5, product);
    }
}
