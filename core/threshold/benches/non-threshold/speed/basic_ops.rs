//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../../utilities.rs"]
mod utilities;

use crate::utilities::{generate_tfhe_keys, set_plan};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion};
use rand::prelude::*;
use std::fmt::Write;
use std::hint::black_box;
use std::ops::*;
use tfhe::CompactCiphertextList;
use tfhe::CompactPublicKey;

use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, FheUint64};

//use tfhe::{FheUint128, FheUint16, FheUint2, FheUint32, FheUint4,FheUint8,}

use utilities::ALL_PARAMS;
//use tfhe::{FheUint10, FheUint12,FheUint14, FheUint6}
fn bench_fhe_type<FheType>(
    bench_group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    public_key: &CompactPublicKey,
    type_name: &str,
) where
    FheType: FheEncrypt<u64, ClientKey> + FheDecrypt<u64>,
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

    //Added encrypt and decrypt that was not in original bench in tfhe-rs
    {
        let value: u64 = rng.gen();
        write!(name, "encrypt({type_name})").unwrap();
        bench_group.bench_function(&name, |b| {
            b.iter(|| {
                black_box(
                    CompactCiphertextList::builder(public_key)
                        .push(value)
                        .build(),
                )
            })
        });
        name.clear();
    }

    {
        write!(name, "decrypt({type_name})").unwrap();
        bench_group.bench_function(&name, |b| {
            b.iter(|| black_box(FheType::decrypt(&lhs, client_key)))
        });
        name.clear();
    }

    {
        write!(name, "mul({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs * &rhs)));
        name.clear();
    }
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>](c: &mut BenchmarkGroup<'_, WallTime>, cks: &ClientKey, public_key: &CompactPublicKey) {
                bench_fhe_type::<$fhe_type>(c, cks, public_key, stringify!($fhe_type));
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

fn main() {
    set_plan();
    for (name, params) in ALL_PARAMS {
        let (client_key, compressed_server_key) = generate_tfhe_keys(&params);

        let (public_key, server_key) = compressed_server_key
            .decompress()
            .expect("Decompression failed")
            .into_raw_parts();

        set_server_key(server_key);

        let bench_name = format!("non-threshold_basic-ops_{name}");

        let mut c = Criterion::default().sample_size(10).configure_from_args();

        {
            let bench_name = format!("{bench_name}_FheUint64");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint64(&mut group, &client_key, &public_key);
        }

        c.final_summary();
    }
}
