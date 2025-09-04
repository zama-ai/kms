//! This bench file is mostly a copy paste of the one in tfhe-rs.
//! It is copied here for completeness of the NIST submission as
//! well as minor differences, in particular to be able to measure memory
//! complexity as required by NIST.

#[path = "../utilities.rs"]
mod utilities;

#[cfg(not(feature = "measure_memory"))]
use criterion::{measurement::WallTime, BenchmarkGroup, Criterion, Throughput};
use rand::prelude::*;
use rand::thread_rng;
#[cfg(not(feature = "measure_memory"))]
use rayon::prelude::*;
use std::ops::{Add, Mul};
use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, FheBool, FheUint64, ServerKey};
use utilities::ALL_PARAMS;

/// This one uses overflowing sub to remove the need for comparison
/// it also uses the 'boolean' multiplication
fn transfer_overflow<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: CastFrom<FheBool> + for<'a> FheOrd<&'a FheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<FheType, Output = FheType>
        + OverflowingSub<&'a FheType, Output = FheType>
        + Mul<FheType, Output = FheType>,
{
    let (new_from, did_not_have_enough) = (from_amount).overflowing_sub(amount);

    let new_from_amount = did_not_have_enough.if_then_else(from_amount, &new_from);

    let had_enough_funds = !did_not_have_enough;
    let new_to_amount = to_amount + (amount * FheType::cast_from(had_enough_funds));

    (new_from_amount, new_to_amount)
}

#[cfg(not(feature = "measure_memory"))]
fn bench_transfer_latency<FheType, F>(
    c: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey>,
    F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType),
{
    let bench_id = format!("{bench_name}::{fn_name}::{type_name}");
    c.bench_function(&bench_id, |b| {
        let mut rng = thread_rng();

        let from_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount = FheType::encrypt(rng.gen::<u64>(), client_key);

        b.iter(|| {
            let (_, _) = transfer_func(&from_amount, &to_amount, &amount);
        })
    });
}

#[cfg(not(feature = "measure_memory"))]
fn bench_transfer_throughput<FheType, F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType) + Sync,
{
    let mut rng = thread_rng();

    {
        let num_elems = 10;
        group.throughput(Throughput::Elements(num_elems));
        let bench_id =
            format!("{bench_name}::throughput::{fn_name}::{type_name}::{num_elems}_elems");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();

            b.iter(|| {
                from_amounts
                    .par_iter()
                    .zip_eq(to_amounts.par_iter().zip_eq(amounts.par_iter()))
                    .for_each(|(from_amount, (to_amount, amount))| {
                        let (_, _) = transfer_func(from_amount, to_amount, amount);
                    })
            })
        });
    }
}

#[cfg(not(feature = "measure_memory"))]
#[allow(unused_mut)]
fn main() {
    for (name, params) in ALL_PARAMS {
        let config = params.to_tfhe_config();

        let cks = ClientKey::generate(config);
        let sks = ServerKey::new(&cks);

        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);

        let mut c = Criterion::default().sample_size(10).configure_from_args();

        let bench_name = format!("non-threshold_erc20_{name}");
        // FheUint64 latency
        {
            let mut group = c.benchmark_group(&bench_name);

            bench_transfer_latency(
                &mut group,
                &cks,
                &bench_name,
                "FheUint64",
                "overflow",
                transfer_overflow::<FheUint64>,
            );

            group.finish();
        }

        // FheUint64 Throughput
        {
            let mut group = c.benchmark_group(&bench_name);

            bench_transfer_throughput(
                &mut group,
                &cks,
                &bench_name,
                "FheUint64",
                "overflow",
                transfer_overflow::<FheUint64>,
            );

            group.finish();
        }

        c.final_summary();
    }
}

#[cfg(feature = "measure_memory")]
#[global_allocator]
pub static PEAK_ALLOC: peak_alloc::PeakAlloc = peak_alloc::PeakAlloc;

#[cfg(feature = "measure_memory")]
fn main() {
    threshold_fhe::allocator::MEM_ALLOCATOR.get_or_init(|| PEAK_ALLOC);

    let transfer = |(from_amount, to_amount, amount): (FheUint64, FheUint64, FheUint64)| {
        transfer_overflow(&from_amount, &to_amount, &amount)
    };

    for (name, params) in ALL_PARAMS {
        use crate::utilities::bench_memory;

        let bench_name = format!("non-threshold_erc20_{name}_memory");

        let config = params.to_tfhe_config();

        let cks = ClientKey::generate(config);
        let sks = ServerKey::new(&cks);

        rayon::broadcast(|_| set_server_key(sks.clone()));
        set_server_key(sks);
        let mut rng = thread_rng();

        let from_amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);
        let to_amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);
        let amount = FheUint64::encrypt(rng.gen::<u64>(), &cks);

        bench_memory(transfer, (from_amount, to_amount, amount), bench_name);
    }
}
