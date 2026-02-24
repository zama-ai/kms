use ctor::ctor;
use paste::paste;
use redis::{Cmd, ConnectionLike};
use std::num::Wrapping;
use threshold_fhe::algebra::base_ring::{Z128, Z64};
use threshold_fhe::algebra::galois_rings::degree_4::ResiduePolyF4;
use threshold_fhe::execution::online::preprocessing::redis::RedisConf;
use threshold_fhe::execution::online::preprocessing::{create_redis_factory, PreprocessorFactory};
use threshold_fhe::execution::online::triple::Triple;
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::sharing::share::Share;

#[cfg(feature = "testing")]
use threshold_fhe::{
    execution::{
        endpoints::keygen::SecureOnlineDistributedKeyGen,
        online::preprocessing::orchestration::producer_traits::SecureLargeProducerFactory,
        runtime::test_runtime::{generate_fixed_roles, DistributedTestRuntime},
        tfhe_internals::parameters::DKGParams,
    },
    session_id::SessionId,
};

#[cfg(feature = "testing")]
use std::{fs, sync::Arc, thread};

#[ctor]
fn redis_tidy() {
    let redis_conf = RedisConf::default();
    let client = redis::Client::open(redis_conf.host).unwrap();
    let mut con = client.get_connection().expect(
        "Failed to connect to Redis. Please make sure Redis is installed and running locally",
    );
    //delete everything from redis DB
    con.req_command(Cmd::new().arg("FLUSHALL")).unwrap();
}

macro_rules! test_triples {
    ($l:ident $z:ty) => {
        paste! {


            #[tokio::test]
            async fn [<test_redis_preprocessing $z:lower>]() {
                let test_key_prefix = format!("test_redis_preprocessing_{}",stringify!($z));
                let redis_conf = RedisConf::default();
                let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
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

                let triple = Triple::new(share_one, share_two, share_three);
                let random = Share::new(
                    Role::indexed_from_one(4),
                    ResiduePolyF4::<$z>::from_scalar(Wrapping(7)),
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

#[tokio::test]
async fn test_store_fetch_100_triples() {
    let test_key_prefix = "test_store_fetch_100_triples".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut base_redis_preprocessing = redis_factory.create_base_preprocessing_residue_64();
    let fetch_count = 100;
    let mut triples = Vec::new();
    let mut cnt = 0;
    for _i in 0..fetch_count {
        let share_one = Share::new(
            Role::indexed_from_one(1),
            ResiduePolyF4::<Z64>::from_scalar(Wrapping(cnt)),
        );
        cnt += 1;

        let share_two = Share::new(
            Role::indexed_from_one(2),
            ResiduePolyF4::<Z64>::from_scalar(Wrapping(cnt)),
        );
        cnt += 1;

        let share_three = Share::new(
            Role::indexed_from_one(3),
            ResiduePolyF4::<Z64>::from_scalar(Wrapping(cnt)),
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

#[tokio::test]
async fn test_store_fetch_100_randoms() {
    let test_key_prefix = "test_store_fetch_100_randoms".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut base_redis_preprocessing = redis_factory.create_base_preprocessing_residue_64();
    let fetch_count = 100;
    let mut randoms = Vec::new();
    for i in 0..fetch_count {
        let random = Share::new(
            Role::indexed_from_one(1),
            ResiduePolyF4::<Z64>::from_scalar(Wrapping(i)),
        );
        randoms.push(random);
    }

    base_redis_preprocessing.append_randoms(randoms.clone());
    let fetched_shares = base_redis_preprocessing
        .next_random_vec(fetch_count as usize)
        .unwrap();
    assert_eq!(randoms, fetched_shares);
}

#[tokio::test]
async fn test_store_fetch_100_bits() {
    let test_key_prefix = "test_store_fetch_100_bits".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut bit_redis_preprocessing = redis_factory.create_bit_preprocessing_residue_64();
    let fetch_count = 100;
    let mut bits = Vec::new();
    for i in 0..fetch_count {
        let bit = Share::new(
            Role::indexed_from_one(1),
            ResiduePolyF4::<Z64>::from_scalar(Wrapping(i)),
        );
        bits.push(bit);
    }

    bit_redis_preprocessing.append_bits(bits.clone());
    let fetched_bits = bit_redis_preprocessing
        .next_bit_vec(fetch_count as usize)
        .unwrap();
    assert_eq!(bits, fetched_bits);
}

#[tokio::test]
async fn test_fetch_more_than_stored() {
    let store_count = 100;
    let fetch_count = 101;

    let test_key_prefix = "test_fetch_more_than_stored".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut bit_redis_preprocessing = redis_factory.create_bit_preprocessing_residue_64();
    let mut bits = Vec::new();
    for i in 0..store_count {
        let bit = Share::new(
            Role::indexed_from_one(1),
            ResiduePolyF4::<Z64>::from_scalar(Wrapping(i)),
        );
        bits.push(bit);
    }

    bit_redis_preprocessing.append_bits(bits.clone());
    let fetched_bits = bit_redis_preprocessing.next_bit_vec(fetch_count);

    assert!(fetched_bits
        .unwrap_err()
        .to_string()
        .contains("Pop length error."));
}

#[tokio::test]
async fn test_cleanup_on_drop() {
    let test_key_prefix = "test_cleanup_on_drop".to_string();
    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let mut bit_redis_preprocessing = redis_factory.create_bit_preprocessing_residue_64();
    let mut random_redis_preprocessing = redis_factory.create_base_preprocessing_residue_64();

    // Create a new factory because we want to have the exact same key prefix (i.e. no counter increase)
    let mut redis_factory_bis: Box<dyn PreprocessorFactory<4>> =
        create_redis_factory(test_key_prefix.clone(), &redis_conf);
    let bit_redis_preprocessing_bis = redis_factory_bis.create_bit_preprocessing_residue_64();

    let share = Share::new(
        Role::indexed_from_one(1),
        ResiduePolyF4::<Z64>::from_scalar(Wrapping(1)),
    );

    bit_redis_preprocessing.append_bits(vec![share]);
    random_redis_preprocessing.append_randoms(vec![share]);

    // Make sure we can actually see the "bit" from the other preprocessing
    assert_eq!(bit_redis_preprocessing_bis.bits_len(), 1);
    // Drop the preprocessing instance
    drop(bit_redis_preprocessing);

    // Sleep for a while because drop of the Redis preproc is
    // sent to a tokio blocking thread so drop might return early
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Check that the shares have been cleaned up
    assert_eq!(bit_redis_preprocessing_bis.bits_len(), 0);

    // But not these ones
    assert_eq!(random_redis_preprocessing.randoms_len(), 1)
}

test_triples![create_base_preprocessing_residue_64 Z64];
test_triples![create_base_preprocessing_residue_128 Z128];

#[cfg(feature = "testing")]
fn test_dkg_orchestrator_large(
    num_sessions: u128,
    num_parties: usize,
    threshold: u8,
    params: DKGParams,
    tag: tfhe::Tag,
) {
    use itertools::Itertools;
    use threshold_fhe::{
        algebra::{galois_rings::degree_4::ResiduePolyF4Z64, structure_traits::Ring},
        execution::{
            endpoints::keygen::OnlineDistributedKeyGen, keyset_config::KeySetConfig,
            online::preprocessing::orchestration::dkg_orchestrator::PreprocessingOrchestrator,
        },
        file_handling::tests::write_element,
        networking::NetworkMode,
        thread_handles::OsThreadGroup,
    };

    let params_basics_handles = params.get_params_basics_handle();

    let roles = generate_fixed_roles(num_parties);
    //Executing offline, so require Sync network
    let runtimes = (0..num_sessions)
        .map(|_| {
            DistributedTestRuntime::<
                    ResiduePolyF4Z64,
                    Role,
                    { ResiduePolyF4Z64::EXTENSION_DEGREE },
                >::new(roles.clone(), threshold, NetworkMode::Sync, None)
        })
        .collect_vec();
    let runtimes = Arc::new(runtimes);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut handles = OsThreadGroup::new();
    for party in roles {
        let runtimes = runtimes.clone();
        let rt_handle = rt.handle().clone();
        let tag = tag.clone();
        handles.add(thread::spawn(move || {
            use threshold_fhe::execution::runtime::sessions::session_parameters::GenericParameterHandles;

            let _guard = rt_handle.enter();
            println!("Thread created for party {party}");

            //For each party, create num_sessions sessions
            let sessions = runtimes
                .iter()
                .zip_eq(0..num_sessions)
                .map(|(runtime, session_id)| {
                    runtime.large_session_for_party(SessionId::from(session_id), party)
                })
                .collect_vec();

            let redis_conf = RedisConf::default();
            let mut redis_factory =
                create_redis_factory(format!("LargeOrchestrator_{party}"), &redis_conf);
            let orchestrator = PreprocessingOrchestrator::<ResiduePolyF4Z64>::new(
                redis_factory.as_mut(),
                params,
                KeySetConfig::default(),
            )
            .unwrap();

            let (mut sessions, mut preproc) = rt_handle.block_on(async {

                orchestrator
                    .orchestrate_dkg_processing_large_session::<SecureLargeProducerFactory<ResiduePolyF4Z64>>(sessions)
                    .await
                    .unwrap()
            });

            sessions.sort_by_key(|session| session.session_id());
            let dkg_session = sessions.get_mut(0).unwrap();

            let (pk, sk) = rt_handle.block_on(async {
                SecureOnlineDistributedKeyGen::<Z64,{ResiduePolyF4Z64::EXTENSION_DEGREE}>::keygen(dkg_session, preproc.as_mut(), params, tag, None)
                    .await
                    .unwrap()
            });
            (party, pk, sk)
        }));
    }

    let mut pk_ref = None;
    for (party_id, pk, sk) in handles.join_all_with_results().unwrap() {
        match pk_ref {
            None => pk_ref = Some(pk),
            Some(ref ref_key) => assert_eq!(ref_key, &pk),
        };
        write_element(
            params_basics_handles
                .get_prefix_path()
                .join("ORCHESTRATOR")
                .join(format!("sk_p{party_id}.der")),
            &sk,
        )
        .unwrap();
    }
    let pk_ref = pk_ref.unwrap();
    write_element(
        params_basics_handles
            .get_prefix_path()
            .join("ORCHESTRATOR")
            .join("pk.der"),
        &pk_ref,
    )
    .unwrap();
}

#[cfg(feature = "testing")]
#[test]
fn test_dkg_orchestrator_params8_small_no_sns() {
    use threshold_fhe::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;

    let params = PARAMS_TEST_BK_SNS;
    let params = params.get_params_without_sns();
    fs::create_dir_all(
        params
            .get_params_basics_handle()
            .get_prefix_path()
            .join("ORCHESTRATOR"),
    )
    .unwrap();
    let num_sessions = 10;
    let num_parties = 5;
    let threshold = 1;
    test_dkg_orchestrator_large(
        num_sessions,
        num_parties,
        threshold,
        params,
        tfhe::Tag::default(),
    );
}

#[cfg(feature = "testing")]
#[tokio::test]
async fn test_cast_fail_memory_bit_dec_preprocessing() {
    use threshold_fhe::{
        execution::online::preprocessing::{
            dummy::DummyPreprocessing, BitDecPreprocessing, BitPreprocessing,
            InMemoryBitDecPreprocessing, TriplePreprocessing,
        },
        tests::helper::testing::get_dummy_parameters_for_parties,
    };

    let redis_conf = RedisConf::default();
    let mut redis_factory = create_redis_factory(
        "test_cast_fail_memory_bit_dec_preprocessing".to_owned(),
        &redis_conf,
    );
    let parameters = get_dummy_parameters_for_parties(1, 0, Role::indexed_from_one(1));

    let mut dummy_preprocessing = DummyPreprocessing::new(42, &parameters);

    let mut casted_from_dummy: InMemoryBitDecPreprocessing<4> =
        dummy_preprocessing.cast_to_in_memory_impl(1).unwrap();

    let mut redis_bit_dec_preprocessing = redis_factory.create_bit_decryption_preprocessing();

    redis_bit_dec_preprocessing.append_triples(
        casted_from_dummy
            .next_triple_vec(casted_from_dummy.triples_len())
            .unwrap(),
    );

    assert!(
        redis_bit_dec_preprocessing
            .cast_to_in_memory_impl(1)
            .unwrap_err()
            .to_string()
            .contains("Not enough bits available"),
        "Casting to in memory impl should fail when not enough bits are available"
    );

    let mut redis_bit_dec_preprocessing = redis_factory.create_bit_decryption_preprocessing();
    redis_bit_dec_preprocessing.append_bits(
        casted_from_dummy
            .next_bit_vec(casted_from_dummy.bits_len())
            .unwrap(),
    );

    assert!(
        redis_bit_dec_preprocessing
            .cast_to_in_memory_impl(1)
            .unwrap_err()
            .to_string()
            .contains("Not enough triples available"),
        "Casting to in memory impl should fail when not enough triples are available"
    );
}
