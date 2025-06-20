use tonic::transport::server::Router;

use crate::algebra::structure_traits::{Derive, ErrorCorrect, Invert, Solve, Syndrome};
use crate::execution::online::preprocessing::PreprocessorFactory;
use crate::execution::runtime::party::Identity;
use crate::grpc::server::SecureGrpcChoreography;

use crate::networking::NetworkingStrategy;
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
    },
    choreography::grpc::GrpcChoreography,
    execution::{
        large_execution::{
            coinflip::RealCoinflip, double_sharing::RealDoubleSharing,
            local_double_share::RealLocalDoubleShare, local_single_share::RealLocalSingleShare,
            offline::RealLargePreprocessing, share_dispute::RealShareDispute,
            single_sharing::RealSingleSharing, vss::RealVss,
        },
        sharing::open::SecureRobustOpen,
        small_execution::{
            agree_random::RobustRealAgreeRandom, offline::RealSmallPreprocessing,
            prss::RobustRealPrssInit,
        },
    },
    malicious_execution::{
        communication::malicious_broadcast::MaliciousBroadcastSenderEcho,
        small_execution::{
            malicious_offline::MaliciousOfflineDrop, malicious_prss::MaliciousPrssDrop,
        },
    },
};

/// Moby that lies in all its broadcast as the Sender following
/// [`MaliciousBroadcastSenderEcho`]
type GrpcChoreographyMaliciousBroadcastSenderEcho<const EXTENSION_DEGREE: usize> = GrpcChoreography<
    EXTENSION_DEGREE,
    RobustRealPrssInit<
        RobustRealAgreeRandom<SecureRobustOpen>,
        RealVss<MaliciousBroadcastSenderEcho>,
    >,
    RealSmallPreprocessing<MaliciousBroadcastSenderEcho>,
    RealLargePreprocessing<
        ResiduePoly<Z64, EXTENSION_DEGREE>,
        RealSingleSharing<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            RealLocalSingleShare<
                RealCoinflip<RealVss<MaliciousBroadcastSenderEcho>, SecureRobustOpen>,
                RealShareDispute,
                MaliciousBroadcastSenderEcho,
            >,
        >,
        RealDoubleSharing<
            ResiduePoly<Z64, EXTENSION_DEGREE>,
            RealLocalDoubleShare<
                RealCoinflip<RealVss<MaliciousBroadcastSenderEcho>, SecureRobustOpen>,
                RealShareDispute,
                MaliciousBroadcastSenderEcho,
            >,
        >,
        SecureRobustOpen,
    >,
    RealLargePreprocessing<
        ResiduePoly<Z128, EXTENSION_DEGREE>,
        RealSingleSharing<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            RealLocalSingleShare<
                RealCoinflip<RealVss<MaliciousBroadcastSenderEcho>, SecureRobustOpen>,
                RealShareDispute,
                MaliciousBroadcastSenderEcho,
            >,
        >,
        RealDoubleSharing<
            ResiduePoly<Z128, EXTENSION_DEGREE>,
            RealLocalDoubleShare<
                RealCoinflip<RealVss<MaliciousBroadcastSenderEcho>, SecureRobustOpen>,
                RealShareDispute,
                MaliciousBroadcastSenderEcho,
            >,
        >,
        SecureRobustOpen,
    >,
>;

/// Moby that drops everything
type GrpcChoreographyDropAll<const EXTENSION_DEGREE: usize> = GrpcChoreography<
    EXTENSION_DEGREE,
    MaliciousPrssDrop,
    MaliciousOfflineDrop,
    MaliciousOfflineDrop,
    MaliciousOfflineDrop,
>;

pub fn add_strategy_to_router<const EXTENSION_DEGREE: usize, L>(
    router: Router<L>,
    own_identity: Identity,
    networking_strategy: NetworkingStrategy,
    factory: Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>,
) -> Router<L>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
{
    // Read the strategy from the environment variable, defaulting to "secure"
    let strategy = std::env::var("MOBY_STRATEGY").unwrap_or_else(|_| "secure".to_owned());

    let router = match strategy.as_str() {
        "secure" => router.add_service(
            SecureGrpcChoreography::new(own_identity, networking_strategy, factory).into_server(),
        ),
        "malicious_broadcast" => router.add_service(
            GrpcChoreographyMaliciousBroadcastSenderEcho::new(
                own_identity,
                networking_strategy,
                factory,
            )
            .into_server(),
        ),
        "drop_all" => router.add_service(
            GrpcChoreographyDropAll::new(own_identity, networking_strategy, factory).into_server(),
        ),
        _ => panic!("Unknown moby strategy: {strategy}"),
    };
    router
}
