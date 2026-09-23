use algebra::{
    PRSSConversions,
    galois_rings::{
        degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128},
        degree_8::{ResiduePolyF8Z64, ResiduePolyF8Z128},
    },
    structure_traits::{ErrorCorrect, Invert},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use support::PrssWorkload;
use threshold_execution::small_execution::prss::DerivePRSSState;
use threshold_types::{role::Role, session_id::SessionId};
mod support;
use threshold_execution::small_execution::prf::benchmarking as prf;

struct CountingAllocator;
static ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);
static REALLOCATIONS: AtomicU64 = AtomicU64::new(0);

fn record_allocation(ptr: *mut u8, bytes: usize, reallocation: bool) {
    if !ptr.is_null() && ENABLED.load(Ordering::Relaxed) {
        if reallocation {
            REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        } else {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        REQUESTED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

// SAFETY: Every request is forwarded to System with its original pointer and layout.
// Recording uses only atomics and never allocates or changes the returned allocation.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies a valid allocation layout.
        let ptr = unsafe { System.alloc(layout) };
        record_allocation(ptr, layout.size(), false);
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies a valid allocation layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        record_allocation(ptr, layout.size(), false);
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: All pointers originate from System and retain their original layout.
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The caller supplies a System allocation and a valid new size.
        let result = unsafe { System.realloc(ptr, layout, size) };
        record_allocation(result, size, true);
        result
    }
}

// TODO: care needed to avoid overriding the custom allocator inadvertently. Figure out what to do later.
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure_allocations(mut generate_values: impl FnMut(), name: &str, values: usize) {
    generate_values(); // Warm the runtime, pool, and workload before counting.
    for sample in 1..=3 {
        ALLOCATIONS.store(0, Ordering::Relaxed);
        REQUESTED_BYTES.store(0, Ordering::Relaxed);
        REALLOCATIONS.store(0, Ordering::Relaxed);
        ENABLED.store(true, Ordering::Relaxed);
        generate_values();
        ENABLED.store(false, Ordering::Relaxed);
        println!(
            "{name},{sample},{values},{},{},{}",
            ALLOCATIONS.load(Ordering::Relaxed),
            REALLOCATIONS.load(Ordering::Relaxed),
            REQUESTED_BYTES.load(Ordering::Relaxed)
        );
    }
}

fn measure_ring<Z: ErrorCorrect + Invert + PRSSConversions>(
    rt: &tokio::runtime::Runtime,
    ring: &str,
) {
    let key = prf::PrfKey([23; 16]);
    let psi = prf::PsiAes::new(&key, SessionId::from(42));
    let chi = prf::ChiAes::new(&key, SessionId::from(42));
    measure_allocations(
        || {
            for ctr in 0..1000 {
                black_box(prf::psi::<Z>(&psi, black_box(ctr)).unwrap());
            }
        },
        &format!("prf/{ring}/psi"),
        1000,
    );
    measure_allocations(
        || {
            for ctr in 0..1000 {
                black_box(prf::chi::<Z>(&chi, black_box(ctr), 1).unwrap());
            }
        },
        &format!("prf/{ring}/chi"),
        1000,
    );
    for (parties, threshold) in [(4, 1), (7, 2), (13, 4)] {
        let prss_setup = support::setup_prss::<Z>(rt, parties, threshold);
        let mut prss_state = prss_setup
            .new_prss_session_state(SessionId::from(42), Role::indexed_from_one(1))
            .unwrap();
        for workload in PrssWorkload::for_ring::<Z>() {
            // Means triples for TripleInputs, shares for all others.
            let request_sizes: &[usize] = if matches!(workload, PrssWorkload::TripleInputs) {
                &[10_000]
            } else {
                &[1, 30_000]
            };
            for &request_size in request_sizes {
                measure_allocations(
                    || rt.block_on(workload.run(&mut prss_state, threshold, request_size)),
                    &format!(
                        "prss/{ring}/parties_{parties}_threshold_{threshold}/{}/{request_size}",
                        workload.name()
                    ),
                    workload.output_value_count(request_size),
                );
            }
        }
    }
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    println!("benchmark,sample,values,allocations,reallocations,requested_bytes");
    measure_ring::<ResiduePolyF4Z64>(&rt, "f4_z64");
    measure_ring::<ResiduePolyF4Z128>(&rt, "f4_z128");
    measure_ring::<ResiduePolyF8Z64>(&rt, "f8_z64");
    measure_ring::<ResiduePolyF8Z128>(&rt, "f8_z128");
}
