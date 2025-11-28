pub mod communication {
    pub mod malicious_broadcast;
}
pub mod small_execution {
    pub mod malicious_agree_random;
    pub mod malicious_offline;
    pub mod malicious_prss;
}
pub mod large_execution {
    pub mod malicious_coinflip;
    pub mod malicious_local_double_share;
    pub mod malicious_local_single_share;
    pub mod malicious_offline;
    pub mod malicious_share_dispute;
    pub mod malicious_vss;
}
pub mod online {
    pub mod malicious_gen_bits;
    pub mod malicious_reshare;
    pub mod preprocessing {
        pub mod orchestration {
            #[cfg(feature = "extension_degree_4")]
            pub mod malicious_producer_traits;
            pub mod producer {
                pub mod malicious_bit_producer;
                pub mod malicious_random_producer;
                pub mod malicious_triple_producer;
            }
        }
    }
}
pub mod open {
    pub mod malicious_open;
}
pub mod runtime {
    pub mod malicious_session;
}
pub mod endpoints {
    pub mod decryption;
    pub mod keygen;
}
pub mod zk {
    pub mod ceremony;
}

#[cfg(all(feature = "choreographer", not(feature = "experimental")))]
pub mod malicious_moby;
