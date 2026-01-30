//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../../utilities.rs"]
mod utilities;

use crate::utilities::{generate_tfhe_keys, set_plan};

use rand::prelude::*;
use std::fmt::Write;
use tfhe::unset_server_key;

use std::ops::*;
use tfhe::CompactCiphertextList;
use tfhe::CompactPublicKey;

use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, FheUint64};

//use tfhe::{FheUint128, FheUint16, FheUint2, FheUint32, FheUint4,FheUint8,}

use crate::utilities::bench_memory;
use utilities::ALL_PARAMS;

fn bench_fhe_type<FheType>(
    client_key: ClientKey,
    public_key: CompactPublicKey,
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

    let mut name = String::with_capacity(255);

    let lhs = FheType::encrypt(rng.gen(), &client_key);
    let rhs = FheType::encrypt(rng.gen(), &client_key);
    {
        write!(name, "{bench_name}_mul_memory({type_name}, {type_name})").unwrap();
        let bench_fn = |(lhs, rhs): &mut (FheType, FheType)| &*lhs * &*rhs;
        bench_memory(bench_fn, &mut (rhs, lhs), name.clone());
        name.clear();
    }

    // We drop the server key and don't measure its memory usage
    // as it's not needed for enc/dec
    unset_server_key();

    {
        let value = rng.gen();
        write!(name, "{bench_name}_encrypt_memory({type_name})").unwrap();

        let bench_fn = |(value, public_key): &mut (u64, CompactPublicKey)| {
            CompactCiphertextList::builder(public_key)
                .push(*value)
                .build();
        };

        bench_memory(bench_fn, &mut (value, public_key), name.clone());
        name.clear();
    }

    let lhs = FheType::encrypt(rng.gen(), &client_key);
    {
        write!(name, "{bench_name}_decrypt_memory({type_name})").unwrap();
        let bench_fn =
            |(ct, client_key): &mut (FheType, ClientKey)| FheType::decrypt(ct, client_key);
        bench_memory(bench_fn, &mut (lhs, client_key), name.clone());
        name.clear();
    }
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>]( cks: ClientKey, public_key: CompactPublicKey, bench_name: &str) {
                bench_fhe_type::<$fhe_type>( cks, public_key, bench_name, stringify!($fhe_type));
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
        let (client_key, compressed_server_key) = generate_tfhe_keys(&params);

        let (public_key, server_key) = compressed_server_key
            .decompress()
            .expect("Decompression failed")
            .into_raw_parts();

        set_server_key(server_key);
        let bench_name = format!("non-threshold_basic-ops_{name}");

        {
            bench_fhe_uint64(client_key, public_key, &bench_name);
        }
    }
}
