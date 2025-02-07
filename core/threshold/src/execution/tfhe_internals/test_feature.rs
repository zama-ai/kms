use aligned_vec::ABox;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{num::Wrapping, sync::Arc};
use tfhe::{
    core_crypto::{
        algorithms::{
            allocate_and_generate_new_binary_glwe_secret_key,
            allocate_and_generate_new_binary_lwe_secret_key,
            convert_standard_lwe_bootstrap_key_to_fourier_128, decrypt_lwe_ciphertext,
            par_generate_lwe_bootstrap_key,
        },
        commons::{
            generators::{DeterministicSeeder, EncryptionRandomGenerator},
            math::random::DefaultRandomGenerator,
            traits::Numeric,
        },
        entities::{
            Fourier128LweBootstrapKey, GlweSecretKey, LweBootstrapKey, LweSecretKey,
            LweSecretKeyOwned,
        },
        seeders::Seeder,
    },
    integer::block_decomposition::BlockRecomposer,
    shortint::{
        self, list_compression::CompressionPrivateKeys, ClassicPBSParameters, ShortintParameterSet,
    },
    zk::CompactPkeCrs,
    ClientKey,
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
        random::{secret_rng_from_seed, seed_from_rng},
        runtime::{party::Role, session::BaseSessionHandles},
        sharing::{input::robust_input, share::Share},
        tfhe_internals::{
            compression_decompression_key::CompressionPrivateKeyShares,
            glwe_key::GlweSecretKeyShare, lwe_key::LweSecretKeyShare,
        },
    },
    networking::value::NetworkValue,
};

use super::{
    parameters::{
        AugmentedCiphertextParameters, Ciphertext128, Ciphertext128Block, DKGParams,
        DKGParamsBasics, DKGParamsRegular,
    },
    switch_and_squash::{from_expanded_msg, SwitchAndSquashKey},
};

/// the party ID of the party doing the reconstruction
pub(crate) const INPUT_PARTY_ID: usize = 1;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeySet {
    pub client_key: tfhe::ClientKey,
    pub sns_secret_key: SnsClientKey,
    pub public_keys: FhePubKeySet,
}
impl KeySet {
    pub fn get_raw_lwe_client_key(&self) -> LweSecretKey<Vec<u64>> {
        let (inner_client_key, _, _, _) = self.client_key.clone().into_raw_parts();
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
        let (_, compact_private_key, _, _) = self.client_key.clone().into_raw_parts();
        if let Some(inner) = compact_private_key {
            let raw_parts = inner.0.into_raw_parts();
            raw_parts.into_raw_parts().0
        } else {
            self.get_raw_lwe_client_key()
        }
    }

    pub fn get_raw_compression_client_key(&self) -> Option<GlweSecretKey<Vec<u64>>> {
        let (_, _, compression_sk, _) = self.client_key.clone().into_raw_parts();
        if let Some(inner) = compression_sk {
            let raw_parts = inner.into_raw_parts();
            Some(raw_parts.post_packing_ks_key)
        } else {
            None
        }
    }

    pub fn get_raw_glwe_client_key(&self) -> GlweSecretKey<Vec<u64>> {
        let (inner_client_key, _, _, _) = self.client_key.clone().into_raw_parts();
        let short_client_key = inner_client_key.into_raw_parts();
        let (glwe_secret_key, _lwe_secret_key, _shortint_param) = short_client_key.into_raw_parts();
        glwe_secret_key
    }
}

// This is called from core/service to generate the key
pub fn gen_key_set<R: Rng + CryptoRng>(parameters: DKGParams, rng: &mut R) -> KeySet {
    let basics_params = parameters.get_params_basics_handle();
    let mut secret_rng = secret_rng_from_seed(seed_from_rng(rng).0);

    let input_lwe_secret_key: LweSecretKey<Vec<u64>> =
        allocate_and_generate_new_binary_lwe_secret_key(
            basics_params.lwe_dimension(),
            &mut secret_rng,
        );
    let input_glwe_secret_key: GlweSecretKey<Vec<u64>> =
        allocate_and_generate_new_binary_glwe_secret_key(
            basics_params.glwe_dimension(),
            basics_params.polynomial_size(),
            &mut secret_rng,
        );

    let dedicated_compact_private_key = if basics_params.has_dedicated_compact_pk_params() {
        Some(allocate_and_generate_new_binary_lwe_secret_key(
            basics_params.lwe_hat_dimension(),
            &mut secret_rng,
        ))
    } else {
        None
    };

    let compression_key =
        if let Some(compression_params) = basics_params.get_compression_decompression_params() {
            Some(allocate_and_generate_new_binary_glwe_secret_key(
                compression_params
                    .raw_compression_parameters
                    .packing_ks_glwe_dimension,
                compression_params
                    .raw_compression_parameters
                    .packing_ks_polynomial_size,
                &mut secret_rng,
            ))
        } else {
            None
        };

    let regular_params = match parameters {
        DKGParams::WithSnS(p) => p.regular_params,
        DKGParams::WithoutSnS(p) => p,
    };

    let client_key = to_hl_client_key(
        &regular_params,
        input_lwe_secret_key,
        input_glwe_secret_key,
        dedicated_compact_private_key,
        compression_key,
    );

    let public_key = tfhe::CompactPublicKey::new(&client_key);
    let server_key = tfhe::ServerKey::new(&client_key);
    let (sns_secret_key, fbsk_out) = generate_large_keys(parameters, client_key.clone(), rng);

    let sns_key = SwitchAndSquashKey::new(
        fbsk_out,
        server_key.as_ref().as_ref().key_switching_key.clone(),
    );

    let public_keys = FhePubKeySet {
        public_key,
        server_key,
        sns_key: Some(sns_key),
    };
    KeySet {
        client_key,
        sns_secret_key,
        public_keys,
    }
}

/// Helper method for converting a low level client key into a high level client key.
pub fn to_hl_client_key(
    params: &DKGParamsRegular,
    lwe_secret_key: LweSecretKey<Vec<u64>>,
    glwe_secret_key: GlweSecretKey<Vec<u64>>,
    dedicated_compact_private_key: Option<LweSecretKey<Vec<u64>>>,
    compression_key: Option<GlweSecretKey<Vec<u64>>>,
) -> tfhe::ClientKey {
    let sps = ShortintParameterSet::new_pbs_param_set(tfhe::shortint::PBSParameters::PBS(
        params.ciphertext_parameters,
    ));
    let sck = shortint::ClientKey::from_raw_parts(glwe_secret_key, lwe_secret_key, sps);

    //If necessary generate a dedicated compact private key
    let dedicated_compact_private_key =
        if let (Some(dedicated_compact_private_key), Some(pk_params)) = (
            dedicated_compact_private_key,
            params.dedicated_compact_public_key_parameters,
        ) {
            Some((
                tfhe::integer::CompactPrivateKey::from_raw_parts(
                    tfhe::shortint::CompactPrivateKey::from_raw_parts(
                        dedicated_compact_private_key,
                        pk_params.0,
                    )
                    .unwrap(),
                ),
                pk_params.1,
            ))
        } else {
            None
        };

    //If necessary generate a dedicated compression private key
    let compression_key = if let (Some(compression_private_key), Some(params)) =
        (compression_key, params.compression_decompression_parameters)
    {
        let polynomial_size = compression_private_key.polynomial_size();
        Some(
            tfhe::integer::compression_keys::CompressionPrivateKeys::from_raw_parts(
                CompressionPrivateKeys {
                    post_packing_ks_key: GlweSecretKey::from_container(
                        compression_private_key.into_container(),
                        polynomial_size,
                    ),
                    params,
                },
            ),
        )
    } else {
        None
    };
    ClientKey::from_raw_parts(
        sck.into(),
        dedicated_compact_private_key,
        compression_key,
        tfhe::Tag::default(),
    )
}

// TODO we should add a unit test for this
pub async fn initialize_key_material<
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    const EXTENSION_DEGREE: usize,
>(
    session: &mut S,
    params: DKGParams,
) -> anyhow::Result<(FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>)>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    let own_role = session.my_role()?;
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
                .map(|s| s.clone().sns_secret_key.key.into_container())
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

    // iterate through sk and share each element
    let mut lwe_key_shares64 = Vec::new();
    // iterate through sk and share each element
    // TODO(Dragos) this sharing can be done in a single round
    tracing::debug!(
        "I'm {:?}, Sharing key64 to be sent: len {}",
        session.my_role(),
        lwe_sk_container64.len()
    );
    for cur in lwe_sk_container64 {
        let secret = match own_role.one_based() {
            INPUT_PARTY_ID => Some(ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<
                u64,
            >(
                cur
            ))),
            _ => None,
        };
        let share = robust_input(session, &secret, &own_role, INPUT_PARTY_ID).await?; //TODO(Daniel) batch this for all big_ell

        lwe_key_shares64.push(Share::new(own_role, share));
    }

    let mut lwe_encryption_key_shares64 = Vec::new();
    tracing::debug!(
        "I'm {:?}, Sharing encryption key64 to be sent: len {}",
        session.my_role(),
        lwe_encryption_sk_container64.len()
    );
    for cur in lwe_encryption_sk_container64 {
        let secret = match own_role.one_based() {
            INPUT_PARTY_ID => Some(ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<
                u64,
            >(
                cur
            ))),
            _ => None,
        };
        let share = robust_input(session, &secret, &own_role, INPUT_PARTY_ID).await?; //TODO(Daniel) batch this for all big_ell

        lwe_encryption_key_shares64.push(Share::new(own_role, share));
    }

    let mut glwe_key_shares128 = Vec::new();
    tracing::debug!(
        "I'm {:?}, Sharing glwe client key 64 to be sent: len {}",
        session.my_role(),
        glwe_sk_container64.len(),
    );
    for cur in glwe_sk_container64 {
        let secret = match own_role.one_based() {
            INPUT_PARTY_ID => Some(ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<
                u128,
            >(
                cur as u128, /* casting like this is ok as long as it's not shares */
            ))),
            _ => None,
        };
        let share = robust_input(session, &secret, &own_role, INPUT_PARTY_ID).await?; //TODO(Daniel) batch this for all big_ell
        glwe_key_shares128.push(Share::new(own_role, share));
    }

    let sns_key_shares128 = if let Some(sns_sk_container128) = sns_sk_container128 {
        let mut sns_key_shares128 = Vec::new();
        // TODO(Dragos) this sharing can be done in a single round
        tracing::debug!(
            "I'm {:?}, Sharing key128 to be sent: len {}",
            session.my_role(),
            sns_sk_container128.len()
        );
        for cur in sns_sk_container128 {
            let secret = match own_role.one_based() {
                INPUT_PARTY_ID => {
                    Some(ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<
                        u128,
                    >(
                        cur
                    )))
                }
                _ => None,
            };
            let share = robust_input(session, &secret, &own_role, INPUT_PARTY_ID).await?; //TODO(Daniel) batch this for all big_ell
            sns_key_shares128.push(Share::new(own_role, share));
        }
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
        for cur in compression_container {
            let secret = match own_role.one_based() {
                INPUT_PARTY_ID => {
                    Some(ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping::<
                        u128,
                    >(
                        cur as u128, /* casting like this is ok as long as it's not shares */
                    )))
                }
                _ => None,
            };
            let share = robust_input(session, &secret, &own_role, INPUT_PARTY_ID).await?; //TODO(Daniel) batch this for all big_ell
            glwe_compression_key_shares128.push(Share::new(own_role, share));
        }
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

    let transferred_pub_key = transfer_pub_key(
        session,
        keyset.map(|set| set.public_keys),
        &own_role,
        INPUT_PARTY_ID,
    )
    .await?;

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

pub async fn transfer_pub_key<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &S,
    pubkey: Option<FhePubKeySet>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<FhePubKeySet> {
    session.network().increase_round_counter()?;
    if role.one_based() == input_party_id {
        let pubkey_raw =
            pubkey.ok_or_else(|| anyhow_error_and_log("I have no public key to send!"))?;
        let num_parties = session.num_parties();
        let pkval = NetworkValue::<Z128>::PubKeySet(Box::new(pubkey_raw.clone()));

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

        let pk = match NetworkValue::<Z128>::from_network(data)? {
            NetworkValue::PubKeySet(pk) => pk,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a public key!",
            ))?,
        };
        Ok(*pk)
    }
}

/// Send the CRS to the other parties, if I am the input party in this session. Else receive the CRS.
pub async fn transfer_crs<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &S,
    some_crs: Option<CompactPkeCrs>,
    input_party_id: usize,
) -> anyhow::Result<CompactPkeCrs> {
    session.network().increase_round_counter()?;
    if session.my_role()?.one_based() == input_party_id {
        // send CRS
        let crs = some_crs.ok_or_else(|| anyhow_error_and_log("I have no CRS to send!"))?;
        let num_parties = session.num_parties();
        tracing::debug!(
            "I'm the input party. Sending CRS to {} other parties...",
            num_parties - 1
        );
        let crs_network_val = NetworkValue::<Z128>::Crs(Box::new(crs.clone()));

        let mut set = JoinSet::new();
        for receiver in 1..=num_parties {
            if receiver != input_party_id {
                let rcv_identity = session.identity_from(&Role::indexed_by_one(receiver))?;

                let networking = Arc::clone(session.network());
                let send_crs = crs_network_val.clone();

                set.spawn(async move {
                    let _ = networking.send(send_crs.to_network(), &rcv_identity).await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(crs)
    } else {
        // receive CRS
        let sender_identity = session.identity_from(&Role::indexed_by_one(input_party_id))?;
        let networking = Arc::clone(session.network());
        let timeout = session.network().get_timeout_current_round()?;
        tracing::debug!(
            "Waiting to receive CRS from input party with timeout {:?}",
            timeout
        );
        let data = tokio::spawn(timeout_at(timeout, async move {
            networking.receive(&sender_identity).await
        }))
        .await??;

        let crs = match NetworkValue::<Z128>::from_network(data)? {
            NetworkValue::Crs(crs) => crs,
            _ => Err(anyhow_error_and_log(
                "I have received something different from a CRS!",
            ))?,
        };
        Ok(*crs)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SnsClientKey {
    pub key: LweSecretKeyOwned<u128>,
    pub params: ClassicPBSParameters,
}
impl SnsClientKey {
    pub fn new(params: ClassicPBSParameters, sns_secret_key: LweSecretKeyOwned<u128>) -> Self {
        SnsClientKey {
            key: sns_secret_key,
            params,
        }
    }

    pub fn decrypt_128(&self, ct: &Ciphertext128) -> u128 {
        if ct.is_empty() {
            return 0;
        }

        let bits_in_block = self.params.message_modulus_log();
        let mut recomposer = BlockRecomposer::<u128>::new(bits_in_block);

        for encrypted_block in ct {
            let decrypted_block = self.decrypt_block_128(encrypted_block);
            if !recomposer.add_unmasked(decrypted_block.0) {
                // End of T::BITS reached no need to try more
                // recomposition
                break;
            };
        }

        recomposer.value()
    }

    pub(crate) fn decrypt_block_128(&self, ct: &Ciphertext128Block) -> Z128 {
        let total_bits = self.params.total_block_bits() as usize;
        let raw_plaintext = decrypt_lwe_ciphertext(&self.key, ct);
        from_expanded_msg(raw_plaintext.0, total_bits)
    }
}

/// Function for generating a pair of keys for the noise drowning algorithms.
/// That is, the method takes a client key working over u64 and generates a random client key working over u128.
/// Then, the method constructs a key switching key to convert ciphertext encrypted with the key over u64,
/// to ciphertexts encrypted over u128.
pub fn generate_large_keys<R: Rng + CryptoRng>(
    params: DKGParams,
    input_sk: ClientKey,
    rng: &mut R,
) -> (SnsClientKey, Fourier128LweBootstrapKey<ABox<[f64]>>) {
    let params = if let DKGParams::WithSnS(params) = params {
        params
    } else {
        panic!("Can not generate large keys without SnS params")
    };

    let output_param = params.sns_params;
    let input_param = params.to_classic_pbs_parameters();

    let mut secret_rng = secret_rng_from_seed(seed_from_rng(rng).0);
    let mut deterministic_seeder =
        DeterministicSeeder::<DefaultRandomGenerator>::new(seed_from_rng(rng));
    let mut enc_rng = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        deterministic_seeder.seed(),
        &mut deterministic_seeder,
    );

    // Generate output secret key
    let output_glwe_secret_key_out = allocate_and_generate_new_binary_glwe_secret_key(
        output_param.glwe_dimension,
        output_param.polynomial_size,
        &mut secret_rng,
    );
    let output_lwe_secret_key_out = output_glwe_secret_key_out.clone().into_lwe_secret_key();
    let client_output_key = SnsClientKey::new(input_param, output_lwe_secret_key_out);

    // Generate conversion key
    let (short_sk, _compact_privkey, _compression_privkey, _tag) = input_sk.into_raw_parts();
    let (_raw_input_glwe_secret_key, raw_input_lwe_secret_key, _short_param) =
        short_sk.into_raw_parts().into_raw_parts();
    let mut input_lwe_secret_key_out =
        LweSecretKey::new_empty_key(0_u128, input_param.lwe_dimension);
    // Convert input secret key to a u128 bit key
    input_lwe_secret_key_out
        .as_mut()
        .iter_mut()
        .zip(raw_input_lwe_secret_key.as_ref().iter())
        .for_each(|(dst, &src)| *dst = src as u128);

    let mut bsk_out = LweBootstrapKey::new(
        0_u128,
        output_param.glwe_dimension.to_glwe_size(),
        output_param.polynomial_size,
        output_param.pbs_base_log,
        output_param.pbs_level,
        input_param.lwe_dimension,
        output_param.ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        &input_lwe_secret_key_out,
        &output_glwe_secret_key_out,
        &mut bsk_out,
        output_param.glwe_noise_distribution,
        &mut enc_rng,
    );

    let mut fbsk_out = Fourier128LweBootstrapKey::new(
        input_param.lwe_dimension,
        output_param.glwe_dimension.to_glwe_size(),
        output_param.polynomial_size,
        output_param.pbs_base_log,
        output_param.pbs_level,
    );

    convert_standard_lwe_bootstrap_key_to_fourier_128(&bsk_out, &mut fbsk_out);
    drop(bsk_out);

    (client_output_key, fbsk_out)
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

    // for each bit in the secret key generate all parties shares
    for (i, bit) in s_vector.iter().enumerate() {
        let embedded_secret = ResiduePoly::<_, EXTENSION_DEGREE>::from_scalar(Wrapping(*bit));
        let poly = Poly::sample_random_with_fixed_constant(rng, embedded_secret, threshold);

        for (party_id, v) in vv128.iter_mut().enumerate().take(num_parties) {
            v.insert(
                i,
                Share::new(
                    Role::indexed_by_zero(party_id),
                    poly.eval(&ResiduePoly::<_, EXTENSION_DEGREE>::embed_exceptional_set(
                        party_id + 1,
                    )?),
                ),
            );
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

        for (party_id, v) in vv64_lwe_key.iter_mut().enumerate().take(num_parties) {
            v.insert(
                i,
                Share::new(
                    Role::indexed_by_zero(party_id),
                    poly.eval(&ResiduePoly::<_, EXTENSION_DEGREE>::embed_exceptional_set(
                        party_id + 1,
                    )?),
                ),
            );
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

        for (party_id, v) in vv64_glwe_key.iter_mut().enumerate().take(num_parties) {
            v.insert(
                i,
                Share::new(
                    Role::indexed_by_zero(party_id),
                    poly.eval(&ResiduePoly::<_, EXTENSION_DEGREE>::embed_exceptional_set(
                        party_id + 1,
                    )?),
                ),
            );
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
        let raw_parts_server_key = self.server_key.clone().into_raw_parts();
        let other_raw_parts_server_key = other.server_key.clone().into_raw_parts();
        self.public_key
            .clone()
            .into_raw_parts()
            .0
            .into_raw_parts()
            .into_raw_parts()
            == other
                .clone()
                .public_key
                .into_raw_parts()
                .0
                .into_raw_parts()
                .into_raw_parts()
            && raw_parts_server_key.0.into_raw_parts().into_raw_parts()
                == other_raw_parts_server_key
                    .0
                    .into_raw_parts()
                    .into_raw_parts()
            && self.sns_key == other.sns_key
    }
}

impl std::fmt::Debug for FhePubKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubKeySet")
            .field("public_key", &self.public_key)
            .field(
                "server_key",
                &self.server_key.clone().into_raw_parts().0.into_raw_parts(),
            )
            .field("sns_key", &self.sns_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use tfhe::{
        generate_keys,
        prelude::{CiphertextList, FheDecrypt, FheEncrypt},
        set_server_key,
        shortint::PBSParameters::PBS,
        ConfigBuilder, FheUint8,
    };

    use crate::{
        execution::{
            constants::REAL_KEY_PATH,
            tfhe_internals::{
                parameters::DKGParamsRegular,
                test_feature::{to_hl_client_key, KeySet},
            },
        },
        file_handling::read_element,
    };

    #[test]
    #[ignore]
    fn hl_sk_key_conversion() {
        let config = ConfigBuilder::default().build();
        let (client_key, _server_key) = generate_keys(config);
        let (raw_sk, _compact_privkey, _compression_privkey, _tag) =
            client_key.clone().into_raw_parts();
        let (glwe_key, lwe_key, params) = raw_sk.into_raw_parts().into_raw_parts();

        let input_param = match params.pbs_parameters() {
            Some(PBS(param)) => DKGParamsRegular {
                sec: 1,
                ciphertext_parameters: param,
                dedicated_compact_public_key_parameters: None,
                compression_decompression_parameters: None,
                flag: true,
            },
            _ => panic!("Only support for ClassicPBSParameters"),
        };

        let hl_client_key = to_hl_client_key(&input_param, lwe_key, glwe_key, None, None);
        assert_eq!(
            hl_client_key.into_raw_parts().0,
            client_key.clone().into_raw_parts().0
        );
        let ct = FheUint8::encrypt(42_u8, &client_key);
        let msg: u8 = ct.decrypt(&client_key);
        assert_eq!(42, msg);
    }

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
