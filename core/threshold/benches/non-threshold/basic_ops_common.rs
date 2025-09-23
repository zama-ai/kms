//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../utilities.rs"]
mod utilities;

use criterion::measurement::Measurement;
use criterion::{BenchmarkGroup, Criterion};
use rand::prelude::*;
use std::fmt::Write;
use std::hint::black_box;
use std::ops::*;
use tfhe::prelude::*;
use tfhe::{
    set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheUint128, FheUint16, FheUint2,
    FheUint32, FheUint4, FheUint64, FheUint8,
};
#[cfg(feature = "measure_memory")]
use utilities::MemoryProfiler;
use utilities::ALL_PARAMS;
//use tfhe::{FheUint10, FheUint12,FheUint14, FheUint6}

fn bench_fhe_type<FheType, M: Measurement>(
    bench_group: &mut BenchmarkGroup<'_, M>,
    client_key: &ClientKey,
    type_name: &str,
) where
    FheType: FheEncrypt<u128, ClientKey> + FheDecrypt<u128>,
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

    #[cfg(feature = "measure_memory")]
    let type_name = format!("{type_name}_memory");

    //Added encrypt and decrypt that was not in original bench in tfhe-rs
    {
        let value = rng.gen();
        write!(name, "encrypt({type_name})").unwrap();
        bench_group.bench_function(&name, |b| {
            b.iter(|| black_box(FheType::encrypt(value, client_key)))
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
        write!(name, "add({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs + &rhs)));
        name.clear();
    }

    {
        write!(name, "overflowing_add({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| {
            b.iter(|| black_box((&lhs).overflowing_add(&rhs)))
        });
        name.clear();
    }

    {
        write!(name, "overflowing_sub({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(lhs.overflowing_sub(&rhs))));
        name.clear();
    }

    {
        write!(name, "sub({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs - &rhs)));
        name.clear();
    }

    {
        write!(name, "mul({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs * &rhs)));
        name.clear();
    }

    {
        write!(name, "bitand({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs & &rhs)));
        name.clear();
    }

    {
        write!(name, "bitor({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs | &rhs)));
        name.clear();
    }

    {
        write!(name, "bitxor({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs ^ &rhs)));
        name.clear();
    }

    {
        write!(name, "shl({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs << &rhs)));
        name.clear();
    }

    {
        write!(name, "shr({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs >> &rhs)));
        name.clear();
    }

    {
        write!(name, "rotl({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box((&lhs).rotate_left(&rhs))));
        name.clear();
    }

    {
        write!(name, "rotr({type_name}, {type_name})").unwrap();
        bench_group.bench_function(&name, |b| b.iter(|| black_box((&lhs).rotate_right(&rhs))));
        name.clear();
    }
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>]<M: Measurement>(c: &mut BenchmarkGroup<'_, M>, cks: &ClientKey) {
                bench_fhe_type::<$fhe_type,M>(c, cks, stringify!($fhe_type));
            }
        }
    };
}

bench_type!(FheUint2);
bench_type!(FheUint4);
bench_type!(FheUint8);
bench_type!(FheUint16);
bench_type!(FheUint32);
bench_type!(FheUint64);
bench_type!(FheUint128);

#[cfg(feature = "measure_memory")]
#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

pub(crate) fn run_bench() {
    #[cfg(feature = "measure_memory")]
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    for (name, params) in ALL_PARAMS {
        let config = ConfigBuilder::with_custom_parameters(
            params
                .get_params_basics_handle()
                .to_classic_pbs_parameters(),
        )
        .build();

        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);
        let decompressed_sks = compressed_sks.decompress();

        set_server_key(decompressed_sks);

        let bench_name = format!("non-threshold_basic-ops_{name}");
        #[cfg(feature = "measure_memory")]
        let bench_name = format!("{bench_name}_memory");

        #[cfg(not(feature = "measure_memory"))]
        let mut c = Criterion::default().configure_from_args();

        {
            #[cfg(feature = "measure_memory")]
            let mut c = Criterion::default()
                .configure_from_args()
                .with_profiler(MemoryProfiler);

            let bench_name = format!("{bench_name}_FheUint2");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint2(&mut group, &cks);
        }

        {
            #[cfg(feature = "measure_memory")]
            let mut c = Criterion::default()
                .configure_from_args()
                .with_profiler(MemoryProfiler);
            let bench_name = format!("{bench_name}_FheUint4");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint4(&mut group, &cks);
        }

        {
            #[cfg(feature = "measure_memory")]
            let mut c = Criterion::default()
                .configure_from_args()
                .with_profiler(MemoryProfiler);
            let bench_name = format!("{bench_name}_FheUint8");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint8(&mut group, &cks);
        }

        {
            #[cfg(feature = "measure_memory")]
            let mut c = Criterion::default()
                .configure_from_args()
                .with_profiler(MemoryProfiler);
            let bench_name = format!("{bench_name}_FheUint16");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint16(&mut group, &cks);
        }

        {
            #[cfg(feature = "measure_memory")]
            let mut c = Criterion::default()
                .configure_from_args()
                .with_profiler(MemoryProfiler);
            let bench_name = format!("{bench_name}_FheUint32");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint32(&mut group, &cks);
        }

        {
            #[cfg(feature = "measure_memory")]
            let mut c = Criterion::default()
                .configure_from_args()
                .with_profiler(MemoryProfiler);
            let bench_name = format!("{bench_name}_FheUint64");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint64(&mut group, &cks);
        }

        {
            #[cfg(feature = "measure_memory")]
            let mut c = Criterion::default()
                .configure_from_args()
                .with_profiler(MemoryProfiler);
            let bench_name = format!("{bench_name}_FheUint128");
            let mut group = c.benchmark_group(&bench_name);
            bench_fhe_uint128(&mut group, &cks);
        }

        #[cfg(not(feature = "measure_memory"))]
        c.final_summary();
    }
}
