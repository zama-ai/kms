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
pub mod open {
    pub mod malicious_open;
}
pub mod runtime {
    pub mod malicious_session;
}
pub mod endpoints {
    pub mod decryption;
}
pub mod zk {
    pub mod ceremony;
}

#[cfg(all(feature = "choreographer", not(feature = "experimental")))]
pub mod malicious_moby;
