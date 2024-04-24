use tokio::task::JoinSet;

use crate::execution::runtime::session::{BaseSessionStruct, SessionParameters};

use crate::execution::runtime::party::Identity;
use crate::execution::runtime::session::SmallSession;
use crate::execution::small_execution::agree_random::RealAgreeRandom;
use crate::execution::small_execution::prss::PRSSSetup;
use crate::experimental::algebra::levels::LevelEll;
use crate::experimental::algebra::ntt::N65536;
use crate::experimental::bgv::runtime::BGVTestRuntime;
use crate::experimental::{
    algebra::levels::LevelOne, bgv::basics::BGVCiphertext, bgv::ddec::noise_flood_decryption,
};
use crate::session_id::{SessionId, TAG_BYTES};
use aes_prng::AesRng;
use rand::SeedableRng;
use sha3::digest::ExtendableOutput;
use sha3::Shake128;
use std::collections::HashMap;
use std::sync::Arc;

use crate::experimental::bgv::dkg::{NttForm, OwnedNttForm};

impl SessionId {
    pub fn from_bgv_ct(ciphertext: &BGVCiphertext<LevelEll, N65536>) -> anyhow::Result<SessionId> {
        let serialized_ct = bincode::serialize(ciphertext)?;

        // hash the serialized ct data into a 128-bit (TAG_BYTES) digest and convert to u128
        let mut hash = [0_u8; TAG_BYTES];
        Shake128::digest_xof(serialized_ct, &mut hash);
        Ok(SessionId(u128::from_le_bytes(hash)))
    }
}

async fn setup_small_session(
    mut base_session: BaseSessionStruct<AesRng, SessionParameters>,
) -> SmallSession<LevelOne> {
    use crate::execution::runtime::session::{ParameterHandles, SmallSessionStruct};
    let session_id = base_session.session_id();

    let prss_setup =
        PRSSSetup::<LevelOne>::init_with_abort::<RealAgreeRandom, AesRng, _>(&mut base_session)
            .await
            .unwrap();
    SmallSessionStruct::new_from_prss_state(
        base_session,
        prss_setup.new_prss_session_state(session_id),
    )
    .unwrap()
}
/// test the threshold decryption for a given BGV ciphertext
pub fn threshold_decrypt(
    runtime: &BGVTestRuntime,
    private_keys: &[NttForm<LevelOne>],
    ct: &BGVCiphertext<LevelEll, N65536>,
) -> anyhow::Result<HashMap<Identity, Vec<u16>>> {
    let session_id = SessionId::from_bgv_ct(ct)?;

    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();

    let mut set = JoinSet::new();

    for (role, identity) in runtime.role_assignments.clone().into_iter() {
        let role_assignments = runtime.role_assignments.clone();
        let net = Arc::clone(&runtime.user_nets[role.zero_based()]);
        let threshold = runtime.threshold;

        let session_params =
            SessionParameters::new(threshold, session_id, identity.clone(), role_assignments)
                .unwrap();
        let base_session =
            BaseSessionStruct::new(session_params, net, AesRng::from_entropy()).unwrap();

        let private_key = Arc::new(OwnedNttForm {
            owner: role,
            data: private_keys[role.zero_based()].clone(),
        });
        let ct_c = Arc::new(ct.clone());
        set.spawn(async move {
            let mut session = setup_small_session(base_session).await;
            let out = noise_flood_decryption(&mut session, private_key.as_ref(), ct_c.as_ref())
                .await
                .unwrap();

            (identity, out)
        });
    }
    let results = rt.block_on(async {
        let mut results = HashMap::new();
        while let Some(v) = set.join_next().await {
            let (identity, val) = v.unwrap();
            results.insert(identity, val.data);
        }
        results
    });
    Ok(results)
}
