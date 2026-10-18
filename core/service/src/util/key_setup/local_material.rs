//! Local generation of FHE client keys and CRSs.
//!
//! These helpers run on one node, without an MPC protocol. Insecure CRS generation, tests,
//! benchmarks and test fixtures use them.

use crate::cryptography::signing::SigningSchemeType;
use crate::cryptography::signing::identity::NodeSigningIdentity;
use crate::engine::base::CrsGenMetadata;
use kms_grpc::RequestId;
use rand::{CryptoRng, Rng};
use tfhe::zk::CompactPkeCrs;
use tfhe::{ClientKey, Seed};
use threshold_execution::{
    tfhe_internals::parameters::DKGParams, zk::ceremony::public_parameters_by_trusted_setup,
};
use threshold_types::rng::AesRng;

#[expect(clippy::too_many_arguments)]
pub(crate) async fn async_generate_crs(
    sk: &NodeSigningIdentity,
    signing_schemes: &[SigningSchemeType],
    params: DKGParams,
    max_num_bits: Option<u32>,
    eip712_domain: alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
    req_id: &RequestId,
    rng: AesRng,
) -> anyhow::Result<(CompactPkeCrs, CrsGenMetadata)> {
    let (send, recv) = tokio::sync::oneshot::channel();
    let sk_copy = sk.to_owned();
    let req_id_copy = req_id.to_owned();
    let signing_schemes = signing_schemes.to_vec();

    rayon::spawn_fifo(move || {
        let out = gen_centralized_crs(
            &sk_copy,
            &signing_schemes,
            &params,
            max_num_bits,
            &eip712_domain,
            extra_data,
            &req_id_copy,
            rng,
        );
        let _ = send.send(out);
    });
    recv.await?
}

pub fn generate_client_fhe_key(params: DKGParams, tag: tfhe::Tag, seed: Option<Seed>) -> ClientKey {
    use tfhe::prelude::Tagged;

    let config = params.to_tfhe_config();
    let mut client_key = match seed {
        Some(seed) => ClientKey::generate_with_seed(config, seed),
        None => ClientKey::generate(config),
    };
    *client_key.tag_mut() = tag;
    client_key
}

/// Computes a CRS by a trusted setup on this node and signs its metadata with `sk`.
#[expect(clippy::too_many_arguments)]
pub(crate) fn gen_centralized_crs<R: Rng + CryptoRng>(
    sk: &NodeSigningIdentity,
    signing_schemes: &[SigningSchemeType],
    params: &DKGParams,
    max_num_bits: Option<u32>,
    eip712_domain: &alloy_sol_types::Eip712Domain,
    extra_data: Vec<u8>,
    req_id: &RequestId,
    mut rng: R,
) -> anyhow::Result<(CompactPkeCrs, CrsGenMetadata)> {
    let sid = req_id.derive_session_id()?;
    let internal_pp = public_parameters_by_trusted_setup(
        &params.compact_pk_enc_params(),
        max_num_bits.map(|x| x as usize),
        sid,
        &mut rng,
    )?;
    let pke_params = params.compact_pk_enc_params();
    let pp = internal_pp.try_into_tfhe_zk_pok_pp(&pke_params, sid)?;
    let crs_info = crate::engine::base::compute_info_crs(
        sk,
        signing_schemes,
        &crate::engine::base::DSEP_PUBDATA_CRS,
        req_id,
        &pp,
        eip712_domain,
        extra_data,
    )?;
    Ok((pp, crs_info))
}

#[cfg(test)]
mod tests {
    use crate::consts::TEST_PARAM;

    #[test]
    fn sanity_check_sns_compression_test_params() {
        use tfhe::prelude::{FheDecrypt, FheEncrypt, SquashNoise};
        let params = TEST_PARAM;
        let cks = crate::util::key_setup::local_material::generate_client_fhe_key(
            params,
            tfhe::Tag::default(),
            None,
        );
        let sks = cks.generate_server_key();

        tfhe::set_server_key(sks);
        let pt = 12u32;
        let ct = tfhe::FheUint32::encrypt(pt, &cks);
        let large_ct = ct.squash_noise().unwrap();

        let compressed_large_ct = tfhe::CompressedSquashedNoiseCiphertextListBuilder::new()
            .push(large_ct)
            .build()
            .unwrap();
        let new_large_ct: tfhe::SquashedNoiseFheUint = compressed_large_ct.get(0).unwrap().unwrap();
        let actual_pt: u32 = new_large_ct.decrypt(&cks);
        assert_eq!(actual_pt, pt);
    }
}
