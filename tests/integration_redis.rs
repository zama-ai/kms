use ctor::ctor;
use distributed_decryption::algebra::base_ring::{Z128, Z64};
use distributed_decryption::algebra::residue_poly::ResiduePoly;
use distributed_decryption::execution::online::preprocessing::create_redis_factory;
use distributed_decryption::execution::online::preprocessing::redis::RedisConf;
use distributed_decryption::execution::online::triple::Triple;
use distributed_decryption::execution::runtime::party::Role;
use distributed_decryption::execution::sharing::share::Share;
use paste::paste;
use redis::{Cmd, ConnectionLike};
use std::num::Wrapping;

#[cfg(feature = "testing")]
use distributed_decryption::{
    algebra::residue_poly::ResiduePoly64,
    computation::SessionId,
    execution::{
        endpoints::keygen::distributed_keygen_z64,
        online::preprocessing::orchestrator::PreprocessingOrchestrator,
        runtime::{
            session::ParameterHandles,
            test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        },
        tfhe_internals::parameters::DKGParams,
    },
};

#[cfg(feature = "testing")]
use itertools::Itertools;
#[cfg(feature = "testing")]
use std::{fs, sync::Arc, thread};

#[ctor]
#[test]
fn redis_tidy() {
    let redis_conf = RedisConf::default();
    let client = redis::Client::open(redis_conf.host).unwrap();
    let mut con = client.get_connection().unwrap();
    //delete everything from redis DB
    con.req_command(Cmd::new().arg("FLUSHALL")).unwrap();
}

macro_rules! test_triples {
    ($l:ident $z:ty) => {
        paste! {


            #[test]
            fn [<test_redis_preprocessing $z:lower>]() {
                let test_key_prefix = format!("test_redis_preprocessing_{}",stringify!($z));
                let redis_conf = RedisConf::default();
                let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
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

                let triple = Triple::new(share_one, share_two, share_three);
                let random = Share::new(
                    Role::indexed_by_one(4),
                    ResiduePoly::<$z>::from_scalar(Wrapping(7)),
                );
                let mut base_preprocessing = redis_factory.$l();
                base_preprocessing.append_triples(vec![triple.clone()]);

                base_preprocessing.append_randoms(vec![random.clone()]);

                let fetched_triple = base_preprocessing.next_triple().unwrap();
                let fetched_random = base_preprocessing.next_random().unwrap();

                assert_eq!(triple, fetched_triple);
                assert_eq!(random, fetched_random);
            }

        }
    };
}

#[test]
fn test_store_fetch_100_triples() {
    let test_key_prefix = "test_store_fetch_100_triples".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut base_redis_preprocessing = redis_factory.create_base_preprocessing_residue_64();
    let fetch_count = 100;
    let mut triples = Vec::new();
    let mut cnt = 0;
    for _i in 0..fetch_count {
        let share_one = Share::new(
            Role::indexed_by_one(1),
            ResiduePoly::<Z64>::from_scalar(Wrapping(cnt)),
        );
        cnt += 1;

        let share_two = Share::new(
            Role::indexed_by_one(2),
            ResiduePoly::<Z64>::from_scalar(Wrapping(cnt)),
        );
        cnt += 1;

        let share_three = Share::new(
            Role::indexed_by_one(3),
            ResiduePoly::<Z64>::from_scalar(Wrapping(cnt)),
        );
        cnt += 1;
        let triple = Triple::new(share_one, share_two, share_three);
        triples.push(triple);
    }
    base_redis_preprocessing.append_triples(triples.clone());
    let fetched_triples = base_redis_preprocessing
        .next_triple_vec(fetch_count)
        .unwrap();
    assert_eq!(triples, fetched_triples);
}

#[test]
fn test_store_fetch_100_randoms() {
    let test_key_prefix = "test_store_fetch_100_randoms".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut base_redis_preprocessing = redis_factory.create_base_preprocessing_residue_64();
    let fetch_count = 100;
    let mut randoms = Vec::new();
    for i in 0..fetch_count {
        let random = Share::new(
            Role::indexed_by_one(1),
            ResiduePoly::<Z64>::from_scalar(Wrapping(i)),
        );
        randoms.push(random);
    }

    base_redis_preprocessing.append_randoms(randoms.clone());
    let fetched_shares = base_redis_preprocessing
        .next_random_vec(fetch_count as usize)
        .unwrap();
    assert_eq!(randoms, fetched_shares);
}

#[test]
fn test_store_fetch_100_bits() {
    let test_key_prefix = "test_store_fetch_100_bits".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut bit_redis_preprocessing = redis_factory.create_bit_preprocessing_residue_64();
    let fetch_count = 100;
    let mut bits = Vec::new();
    for i in 0..fetch_count {
        let bit = Share::new(
            Role::indexed_by_one(1),
            ResiduePoly::<Z64>::from_scalar(Wrapping(i)),
        );
        bits.push(bit);
    }

    bit_redis_preprocessing.append_bits(bits.clone());
    let fetched_bits = bit_redis_preprocessing
        .next_bit_vec(fetch_count as usize)
        .unwrap();
    assert_eq!(bits, fetched_bits);
}

test_triples![create_base_preprocessing_residue_64 Z64];
test_triples![create_base_preprocessing_residue_128 Z128];

#[cfg(feature = "testing")]
fn test_dkg_orchestrator_large(
    num_sessions: u128,
    num_parties: usize,
    threshold: u8,
    params: DKGParams,
) {
    let params_basics_handles = params.get_params_basics_handle();
    params_basics_handles
        .write_to_file(format!(
            "{}/ORCHESTRATOR/params.json",
            params_basics_handles.get_prefix_path()
        ))
        .unwrap();

    let identities = generate_fixed_identities(num_parties);
    let runtimes = (0..num_sessions)
        .map(|_| (DistributedTestRuntime::<ResiduePoly64>::new(identities.clone(), threshold)))
        .collect_vec();
    let runtimes = Arc::new(runtimes);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut threads = Vec::new();
    for party_id in 0..num_parties {
        let runtimes = runtimes.clone();
        let rt_handle = rt.handle().clone();
        threads.push(thread::spawn(move || {
            let _guard = rt_handle.enter();
            println!("Thread created for {party_id}");

            //For each party, create num_sessions sessions
            let sessions = runtimes
                .iter()
                .zip(0..num_sessions)
                .map(|(runtime, session_id)| {
                    runtime.large_session_for_party(SessionId(session_id), party_id)
                })
                .collect_vec();

            let identity = sessions[0].own_identity();
            let redis_conf = RedisConf::default();
            let mut redis_factory =
                create_redis_factory(format!("LargeOrchestrator_{}", identity), &redis_conf);
            let orchestrator =
                PreprocessingOrchestrator::<ResiduePoly64>::new(redis_factory.as_mut(), params)
                    .unwrap();

            let (mut sessions, mut preproc) = orchestrator
                .orchestrate_large_session_dkg_processing(sessions)
                .unwrap();

            sessions.sort_by_key(|session| session.session_id());
            let dkg_session = sessions.get_mut(0).unwrap();

            let (pk, sk) = rt_handle.block_on(async {
                distributed_keygen_z64(dkg_session, preproc.as_mut(), params)
                    .await
                    .unwrap()
            });
            (party_id, pk, sk)
        }));
    }

    let mut pk_ref = None;
    for thread in threads {
        let (party_id, pk, sk) = thread.join().unwrap();
        match pk_ref {
            None => pk_ref = Some(pk),
            Some(ref ref_key) => assert_eq!(ref_key, &pk),
        };
        sk.write_to_file(format!(
            "{}/ORCHESTRATOR/sk_p{}.der",
            params_basics_handles.get_prefix_path(),
            party_id,
        ))
        .unwrap();
    }
    let pk_ref = pk_ref.unwrap();
    pk_ref
        .write_to_file(format!(
            "{}/ORCHESTRATOR/pk.der",
            params_basics_handles.get_prefix_path()
        ))
        .unwrap();
}

#[cfg(feature = "testing")]
#[test]
fn test_dkg_orchestrator_params8_small_no_sns() {
    use distributed_decryption::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;

    let params = PARAMS_TEST_BK_SNS;
    let params = params.get_params_without_sns();
    fs::create_dir_all(format!(
        "{}/ORCHESTRATOR",
        params.get_params_basics_handle().get_prefix_path()
    ))
    .unwrap();
    let num_sessions = 10;
    let num_parties = 5;
    let threshold = 1;
    test_dkg_orchestrator_large(num_sessions, num_parties, threshold, params);
}
