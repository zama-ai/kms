//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../../utilities.rs"]
mod utilities;

use crate::utilities::{generate_tfhe_keys, set_plan};

use rand::prelude::*;
use std::fmt::Write;

use std::ops::*;
use tfhe::CompactCiphertextList;
use tfhe::CompactPublicKey;
use tfhe::ServerKey;

use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, FheUint64};

//use tfhe::{FheUint128, FheUint16, FheUint2, FheUint32, FheUint4,FheUint8,}

use crate::utilities::bench_memory;
use utilities::ALL_PARAMS;

fn bench_fhe_type<FheType>(
    client_key: &ClientKey,
    public_key: &CompactPublicKey,
    server_key: &ServerKey,
    bench_name: &str,
    type_name: &str,
) where
    FheType: FheEncrypt<u64, ClientKey> + FheDecrypt<u64> + Clone + Send + Sync + 'static,
    for<'a> &'a FheType: Add<&'a FheType, Output = FheType>
        + Sub<&'a FheType, Output = FheType>
        + Mul<&'a FheType, Output = FheType>
        + BitAnd<&'a FheType, Output = FheType>
        + BitOr<&'a FheType, Output = FheType>
        + BitXor<&'a FheType, Output = FheType>
        + Shl<&'a FheType, Output = FheType>
        + Shr<&'a FheType, Output = FheType>
        + RotateLeft<&'a FheType, Output = FheType>
        + RotateRight<&'a FheType, Output = FheType>
        + OverflowingAdd<&'a FheType, Output = FheType>
        + OverflowingSub<&'a FheType, Output = FheType>,
{
    let mut rng = thread_rng();

    let lhs = FheType::encrypt(rng.gen(), client_key);
    let rhs = FheType::encrypt(rng.gen(), client_key);

    let mut name = String::with_capacity(255);

    // We clone everything on purpose to measure memory
    {
        let value = rng.gen();
        write!(name, "{bench_name}_encrypt_memory({type_name})").unwrap();

        let bench_fn = |(value, public_key): (u64, CompactPublicKey)| {
            let public_key = public_key.clone();
            CompactCiphertextList::builder(&public_key)
                .push(value)
                .build();
        };

        bench_memory(bench_fn, (value, public_key.clone()), name.clone());
        name.clear();
    }

    {
        write!(name, "{bench_name}_decrypt_memory({type_name})").unwrap();
        let bench_fn = |(ct, client_key): (FheType, ClientKey)| {
            let ct = ct.clone();
            let client_key = client_key.clone();
            FheType::decrypt(&ct, &client_key)
        };
        bench_memory(bench_fn, (lhs.clone(), client_key.clone()), name.clone());
        name.clear();
    }

    {
        write!(name, "{bench_name}_mul_memory({type_name}, {type_name})").unwrap();
        let bench_fn = |(lhs, rhs, server_key): (FheType, FheType, ServerKey)| {
            let lhs = lhs.clone();
            let rhs = rhs.clone();
            set_server_key(server_key.clone());
            &lhs * &rhs
        };
        bench_memory(
            bench_fn,
            (rhs.clone(), lhs.clone(), server_key.clone()),
            name.clone(),
        );
        name.clear();
    }
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>]( cks: &ClientKey, public_key: &CompactPublicKey, server_key: &ServerKey, bench_name: &str) {
                bench_fhe_type::<$fhe_type>( cks, public_key, server_key, bench_name, stringify!($fhe_type));
            }
        }
    };
}

//bench_type!(FheUint2);
//bench_type!(FheUint4);
//bench_type!(FheUint8);
//bench_type!(FheUint16);
//bench_type!(FheUint32);
bench_type!(FheUint64);
//bench_type!(FheUint128);

#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

fn main() {
    set_plan();

    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    for (name, params) in ALL_PARAMS {
        let (client_key, compressed_server_key) = generate_tfhe_keys(params);

        let (public_key, server_key) = compressed_server_key
            .decompress()
            .expect("Decompression failed")
            .into_raw_parts();

        let bench_name = format!("non-threshold_basic-ops_{name}");

        {
            bench_fhe_uint64(&client_key, &public_key, &server_key, &bench_name);
        }
    }
}
