//! Linear combinations `Σ_k c_k · x_k` whose constants `c_k` are fixed and reused.
//!
//! The PRSS share of a party is `Σ_A f_A(α_i) · ψ(r_A, cnt)`: the `f_A(α_i)` are fixed for an epoch while the PRF
//! outputs change with every counter. The same shape appears wherever a party combines fresh values with
//! constants it holds (PRZS, the Lagrange combination of an opening, the key share in a partial decryption).
//!
//! [`LinearCombinator`] exploits this in two steps:
//!
//! * **Strength reduction.** Multiplication by a fixed ring element `c` is a `Z/2^k`-linear map on coefficient
//!   vectors, `c · ψ = M_c · ψ`, where column `i` of `M_c` holds the coefficients of `c · X^i`. `M_c` is computed once
//!   per constant with the reduction modulo the ring's polynomial folded into its entries, so a product costs
//!   `d²` base-ring multiply-adds and no reduction, with no subtraction and no data-dependent control flow.
//! * **Lane batching.** Independent instances (for PRSS: the counters of a group) are placed in SIMD lanes and the
//!   base-ring arithmetic runs on 52-bit limbs with AVX-512 IFMA (`vpmadd52luq`/`vpmadd52huq`), accumulating
//!   lazily and propagating carries only every [`NORMALIZE_EVERY`] terms.
//!
//! Every backend computes the exact ring element; outputs are bit-identical to the plain fold
//! ([`LinearCombinator::naive`]), which is also the reference the tests compare against.
//!
//! Backends: `Avx512Ifma` for `ResiduePolyF4Z128` on x86-64 CPUs with `avx512f` and `avx512ifma` (Sapphire
//! Rapids, Zen 4 and later), `Scalar` everywhere else. Set `MPC_LINCOMB_BACKEND=scalar` to force the scalar
//! backend (for A/B benchmarks), or `ifma` to require the fast one.

use crate::PRSSConversions;
use crate::galois_rings::degree_4::ResiduePolyF4Z128;
use crate::structure_traits::Ring;
use std::any::TypeId;
use std::sync::OnceLock;

/// Evaluation backend of a [`LinearCombinator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The ring's own multiplication, one product at a time.
    Scalar,
    /// Prepared multiplication matrices on 52-bit limbs, eight lanes per instruction (x86-64 AVX-512 IFMA).
    Avx512Ifma,
}

/// Environment variable selecting the backend: `scalar`, `ifma` or unset (auto-detect).
pub const BACKEND_ENV: &str = "MPC_LINCOMB_BACKEND";

/// Number of pushed terms between two carry propagations of the IFMA accumulators.
///
/// Every IFMA instruction adds a value below `2^52` into a 64-bit lane, so a lane overflows after `2^12 = 4096`
/// additions. One term adds at most 12 values into any accumulator (see [`avx512::mac8_f4`]), so 341 terms are
/// safe; 128 keeps a 2.6x margin.
pub const NORMALIZE_EVERY: usize = 128;

const LIMB_BITS: u32 = 52;
const M52: u64 = (1u64 << LIMB_BITS) - 1;
/// Mask of the top limb: bits 104..128 of a 128-bit value.
const M24: u64 = (1u64 << 24) - 1;
/// Prepared entries per group of eight constants: `[j][i][limb][lane]` for a degree-four ring, three limbs.
const F4_TABLE_BLOCK: usize = 4 * 4 * 3 * 8;

/// Splits a 128-bit value into three 52-bit limbs (the top one holds 24 bits).
#[inline]
fn split(x: u128) -> [u64; 3] {
    [
        (x as u64) & M52,
        ((x >> 52) as u64) & M52,
        (x >> 104) as u64,
    ]
}

/// Joins three normalised limbs back into a 128-bit value.
#[inline]
fn join(l: [u64; 3]) -> u128 {
    (l[0] as u128) | ((l[1] as u128) << 52) | ((l[2] as u128) << 104)
}

/// Propagates the carries of three lazily accumulated limbs and reduces modulo `2^128`.
#[inline]
fn normalize(l: [u64; 3]) -> [u64; 3] {
    let carry0 = l[0] >> LIMB_BITS;
    let l1 = l[1].wrapping_add(carry0);
    let carry1 = l1 >> LIMB_BITS;
    [l[0] & M52, l1 & M52, l[2].wrapping_add(carry1) & M24]
}

/// `Σ_k c_k · x_k` for fixed constants `c_k`, prepared once at construction.
///
/// Operands arrive one constant at a time through an [`Accumulator`] (see [`LinearCombinator::accumulator`]),
/// `L` independent instances per push. For a one-off combination without reuse, use [`LinearCombinator::naive`].
#[derive(Clone)]
pub struct LinearCombinator<Z> {
    constants: Vec<Z>,
    backend: Backend,
    /// IFMA table, `[k / 8][j][i][limb][k % 8]`, empty unless `backend == Avx512Ifma`.
    table: Vec<u64>,
}

impl<Z> std::fmt::Debug for LinearCombinator<Z> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinearCombinator")
            .field("len", &self.constants.len())
            .field("backend", &self.backend)
            .finish()
    }
}

impl<Z: Ring + PRSSConversions> LinearCombinator<Z> {
    /// Prepares the constants with the backend detected for `Z` on this machine.
    pub fn new(constants: impl IntoIterator<Item = Z>) -> Self {
        Self::with_backend(constants, Self::detected_backend())
    }

    /// Prepares the constants with the requested backend, falling back to [`Backend::Scalar`] when the
    /// requested one is not available for `Z` on this machine.
    pub fn with_backend(constants: impl IntoIterator<Item = Z>, backend: Backend) -> Self {
        let constants: Vec<Z> = constants.into_iter().collect();
        let backend = match backend {
            Backend::Avx512Ifma if ifma_supports::<Z>() => Backend::Avx512Ifma,
            _ => Backend::Scalar,
        };
        let table = match backend {
            Backend::Avx512Ifma => prepare_f4z128(&constants),
            Backend::Scalar => Vec::new(),
        };
        Self {
            constants,
            backend,
            table,
        }
    }

    /// The backend [`Self::new`] uses for `Z` on this machine, honouring [`BACKEND_ENV`].
    pub fn detected_backend() -> Backend {
        if !ifma_supports::<Z>() {
            return Backend::Scalar;
        }
        static CHOICE: OnceLock<Backend> = OnceLock::new();
        *CHOICE.get_or_init(|| match std::env::var(BACKEND_ENV).ok().as_deref() {
            Some("scalar") => Backend::Scalar,
            Some("ifma") => {
                if ifma_available() {
                    Backend::Avx512Ifma
                } else {
                    tracing::warn!("{BACKEND_ENV}=ifma requested but AVX-512 IFMA is not available; using scalar");
                    Backend::Scalar
                }
            }
            Some(other) => {
                tracing::warn!("Unknown {BACKEND_ENV}={other:?}; auto-detecting");
                detect_auto()
            }
            None => detect_auto(),
        })
    }

    /// The backend this instance evaluates with.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The constants, in push order.
    pub fn constants(&self) -> &[Z] {
        &self.constants
    }

    pub fn len(&self) -> usize {
        self.constants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.constants.is_empty()
    }

    /// Starts a combination of `L` independent instances: push one [`Lanes`] per constant, in order, then finish.
    /// The IFMA backend needs `L` to be a multiple of eight; other lane counts evaluate with the scalar backend.
    pub fn accumulator<const L: usize>(&self) -> Accumulator<'_, Z, L> {
        let state = match self.backend {
            Backend::Avx512Ifma if L.is_multiple_of(8) && L > 0 => {
                State::Ifma(Box::new(IfmaState {
                    acc: [[[0u64; L]; 4]; 4],
                    since_normalize: 0,
                }))
            }
            _ => State::Scalar([Z::ZERO; L]),
        };
        Accumulator {
            lc: self,
            next: 0,
            state,
        }
    }

    /// The plain fold `Σ_k constants[k] · x[k]` with the ring's multiplication: no preparation, no reuse.
    /// This is the reference every backend must agree with.
    pub fn naive(constants: &[Z], x: &[Z]) -> Z {
        assert_eq!(
            constants.len(),
            x.len(),
            "naive: operand count differs from constant count"
        );
        constants
            .iter()
            .zip(x)
            .fold(Z::ZERO, |acc, (c, v)| acc + *c * *v)
    }
}

fn detect_auto() -> Backend {
    if ifma_available() {
        Backend::Avx512Ifma
    } else {
        Backend::Scalar
    }
}

/// Whether the IFMA backend knows the representation of `Z` and the CPU can run it.
fn ifma_supports<Z: 'static>() -> bool {
    TypeId::of::<Z>() == TypeId::of::<ResiduePolyF4Z128>() && ifma_available()
}

#[cfg(target_arch = "x86_64")]
fn ifma_available() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512ifma")
}

#[cfg(not(target_arch = "x86_64"))]
fn ifma_available() -> bool {
    false
}

/// Views a `ResiduePolyF4Z128` slice behind a generic `Z` known (by `TypeId`) to be that type.
fn as_f4z128<Z: 'static>(constants: &[Z]) -> &[ResiduePolyF4Z128] {
    assert_eq!(TypeId::of::<Z>(), TypeId::of::<ResiduePolyF4Z128>());
    // SAFETY: `Z` is `ResiduePolyF4Z128` (checked above), so the slice already has that type; only the static
    // type name changes. Length and lifetime are preserved.
    unsafe {
        std::slice::from_raw_parts(
            constants.as_ptr() as *const ResiduePolyF4Z128,
            constants.len(),
        )
    }
}

/// The prepared table for `ResiduePolyF4Z128`: for constant `k`, entry `[k / 8][j][i][limb][k % 8]` is limb
/// `limb` of `M_c[j][i]`, the coefficient `j` of `c · X^i`. Padding constants are zero.
fn prepare_f4z128<Z: 'static>(constants: &[Z]) -> Vec<u64> {
    let constants = as_f4z128(constants);
    let mut table = vec![0u64; constants.len().div_ceil(8) * F4_TABLE_BLOCK];
    let x = ResiduePolyF4Z128 {
        coefs: [0u128, 1, 0, 0].map(std::num::Wrapping),
    };
    for (k, c) in constants.iter().enumerate() {
        let block = &mut table[(k / 8) * F4_TABLE_BLOCK..][..F4_TABLE_BLOCK];
        let lane = k % 8;
        // c · X^i for i = 0..4; the ring multiplication applies the reduction modulo X^4 + X + 1.
        let mut cx = *c;
        for i in 0..4 {
            for j in 0..4 {
                let limbs = split(cx.coefs[j].0);
                for (l, limb) in limbs.into_iter().enumerate() {
                    block[((j * 4 + i) * 3 + l) * 8 + lane] = limb;
                }
            }
            cx *= x;
        }
    }
    table
}

/// `L` operands of a push, coefficient-major: block `(i, lane)` is the 16 little-endian bytes of coefficient `i`
/// of instance `lane`, at byte offset `(i * L + lane) * 16`. This is the layout the AES-based PRFs produce when a
/// group of counters is encrypted coefficient by coefficient, so no copy is needed. One block per coefficient:
/// rings whose coefficients need several PRF blocks are not supported here.
#[derive(Clone, Copy)]
pub struct Lanes<'a, const L: usize> {
    blocks: &'a [u8],
    degree: usize,
}

impl<'a, const L: usize> Lanes<'a, L> {
    /// `blocks` must hold `degree * L` blocks of 16 bytes in the layout described on [`Lanes`].
    pub fn from_le_blocks(blocks: &'a [u8], degree: usize) -> Self {
        assert_eq!(
            blocks.len(),
            degree * L * 16,
            "Lanes: expected {degree} coefficients x {L} lanes x 16 bytes"
        );
        Self { blocks, degree }
    }

    /// Coefficient `i` of instance `lane` as an unsigned integer.
    #[inline]
    pub fn coefficient(&self, i: usize, lane: usize) -> u128 {
        let offset = (i * L + lane) * 16;
        u128::from_le_bytes(
            self.blocks[offset..offset + 16]
                .try_into()
                .expect("16-byte block"),
        )
    }

    /// Instance `lane` as a ring element, with the PRF's own chunk-to-element conversion.
    #[inline]
    pub fn element<Z: PRSSConversions>(&self, lane: usize) -> Z {
        Z::from_u128_iter((0..self.degree).map(|i| self.coefficient(i, lane)))
    }

    pub fn degree(&self) -> usize {
        self.degree
    }
}

/// Running sums of `L` independent linear combinations; see [`LinearCombinator::accumulator`].
pub struct Accumulator<'a, Z, const L: usize> {
    lc: &'a LinearCombinator<Z>,
    next: usize,
    state: State<Z, L>,
}

enum State<Z, const L: usize> {
    Scalar([Z; L]),
    Ifma(Box<IfmaState<L>>),
}

/// IFMA accumulators `[j][slot][lane]`: slots 0 and 1 are limbs 0 and 1, slots 2 and 3 both hold limb 2 (split
/// between two registers to shorten the dependency chains) and are folded at normalisation.
struct IfmaState<const L: usize> {
    acc: [[[u64; L]; 4]; 4],
    since_normalize: usize,
}

impl<const L: usize> IfmaState<L> {
    fn normalize(&mut self) {
        for j in 0..4 {
            for lane in 0..L {
                let folded = self.acc[j][2][lane].wrapping_add(self.acc[j][3][lane]);
                let n = normalize([self.acc[j][0][lane], self.acc[j][1][lane], folded]);
                self.acc[j][0][lane] = n[0];
                self.acc[j][1][lane] = n[1];
                self.acc[j][2][lane] = n[2];
                self.acc[j][3][lane] = 0;
            }
        }
        self.since_normalize = 0;
    }
}

impl<Z: Ring + PRSSConversions, const L: usize> Accumulator<'_, Z, L> {
    /// Adds `c_k · lanes` for the next constant `k`. Panics when pushed more often than there are constants.
    #[inline]
    pub fn push(&mut self, lanes: &Lanes<'_, L>) {
        let k = self.next;
        assert!(
            k < self.lc.constants.len(),
            "Accumulator: pushed more operands ({}) than constants ({})",
            k + 1,
            self.lc.constants.len()
        );
        self.next += 1;
        match &mut self.state {
            State::Scalar(sums) => {
                let c = self.lc.constants[k];
                for (lane, sum) in sums.iter_mut().enumerate() {
                    *sum += c * lanes.element::<Z>(lane);
                }
            }
            State::Ifma(state) => {
                #[cfg(target_arch = "x86_64")]
                {
                    debug_assert_eq!(lanes.degree, 4);
                    let block = &self.lc.table[(k / 8) * F4_TABLE_BLOCK..][..F4_TABLE_BLOCK];
                    for half in 0..L / 8 {
                        // SAFETY: the backend is only selected when `avx512f` and `avx512ifma` were detected.
                        // `acc` holds `4 * 4 * L` lanes, `lanes.blocks` holds `4 * L` blocks (checked by `Lanes`)
                        // and `block` holds a full table block, so every access below is in bounds.
                        unsafe {
                            avx512::mac8_f4(
                                state.acc.as_mut_ptr() as *mut u64,
                                L,
                                half * 8,
                                lanes.blocks.as_ptr(),
                                L * 16,
                                block.as_ptr(),
                                k % 8,
                            );
                        }
                    }
                    state.since_normalize += 1;
                    if state.since_normalize == NORMALIZE_EVERY {
                        state.normalize();
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    let _ = (state, lanes);
                    unreachable!("the IFMA backend is only ever selected on x86-64");
                }
            }
        }
    }

    /// Number of constants consumed so far.
    pub fn pushed(&self) -> usize {
        self.next
    }

    /// The `L` combinations. Panics unless exactly one push per constant happened.
    pub fn finish(self) -> [Z; L] {
        assert_eq!(
            self.next,
            self.lc.constants.len(),
            "Accumulator: finished after {} pushes for {} constants",
            self.next,
            self.lc.constants.len()
        );
        match self.state {
            State::Scalar(sums) => sums,
            State::Ifma(mut state) => {
                state.normalize();
                std::array::from_fn(|lane| {
                    Z::from_u128_iter((0..4).map(|j| {
                        join([
                            state.acc[j][0][lane],
                            state.acc[j][1][lane],
                            state.acc[j][2][lane],
                        ])
                    }))
                })
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx512 {
    use core::arch::x86_64::*;

    /// Adds `M_c · x` to the accumulators of eight lanes, for one constant and `ResiduePolyF4Z128`.
    ///
    /// * `acc`: `[j][slot][lane]` with `lane_stride` lanes per slot; lanes `lane0..lane0 + 8` are updated.
    /// * `blocks`: coefficient-major 16-byte blocks, coefficient `i` at `blocks + i * coef_stride`, lane `l` at
    ///   `+ l * 16`; lanes `lane0..lane0 + 8` are read.
    /// * `consts`: one table block `[j][i][limb][8]`; `lane_k` selects the constant.
    ///
    /// Per `(j, i)` the nine IFMA instructions are the partial products that land below `2^128`:
    /// limb 0 gets `lo(x0·b0)`; limb 1 gets `lo(x0·b1) + lo(x1·b0) + hi(x0·b0)`; limb 2 (slots 2 and 3) gets
    /// `lo(x0·b2) + lo(x1·b1) + lo(x2·b0) + hi(x0·b1) + hi(x1·b0)`. Per push each slot receives at most 12
    /// additions, which bounds [`super::NORMALIZE_EVERY`].
    ///
    /// # Safety
    /// The CPU must support `avx512f` and `avx512ifma`, and the three pointers must be valid for the accesses
    /// described above.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn mac8_f4(
        acc: *mut u64,
        lane_stride: usize,
        lane0: usize,
        blocks: *const u8,
        coef_stride: usize,
        consts: *const u64,
        lane_k: usize,
    ) {
        unsafe {
            let m52 = _mm512_set1_epi64(super::M52 as i64);
            let idx_lo = _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14);
            let idx_hi = _mm512_setr_epi64(1, 3, 5, 7, 9, 11, 13, 15);

            // Inputs: deinterleave the (lo, hi) halves of eight blocks, then split into limbs.
            let mut x = [[_mm512_setzero_si512(); 3]; 4];
            for (i, xi) in x.iter_mut().enumerate() {
                let p = blocks.add(i * coef_stride + lane0 * 16);
                let z0 = _mm512_loadu_si512(p as *const _);
                let z1 = _mm512_loadu_si512(p.add(64) as *const _);
                let lo = _mm512_permutex2var_epi64(z0, idx_lo, z1);
                let hi = _mm512_permutex2var_epi64(z0, idx_hi, z1);
                xi[0] = _mm512_and_si512(lo, m52);
                xi[1] = _mm512_and_si512(
                    _mm512_or_si512(_mm512_srli_epi64::<52>(lo), _mm512_slli_epi64::<12>(hi)),
                    m52,
                );
                xi[2] = _mm512_srli_epi64::<40>(hi);
            }

            for j in 0..4 {
                let slot = |s: usize| acc.add((j * 4 + s) * lane_stride + lane0);
                let mut a0 = _mm512_loadu_si512(slot(0) as *const _);
                let mut a1 = _mm512_loadu_si512(slot(1) as *const _);
                let mut a2 = _mm512_loadu_si512(slot(2) as *const _);
                let mut a3 = _mm512_loadu_si512(slot(3) as *const _);
                for (i, xi) in x.iter().enumerate() {
                    let entry = consts.add(((j * 4 + i) * 3) * 8 + lane_k);
                    let b0 = _mm512_set1_epi64(*entry as i64);
                    let b1 = _mm512_set1_epi64(*entry.add(8) as i64);
                    let b2 = _mm512_set1_epi64(*entry.add(16) as i64);
                    a0 = _mm512_madd52lo_epu64(a0, xi[0], b0);
                    a1 = _mm512_madd52lo_epu64(a1, xi[0], b1);
                    a1 = _mm512_madd52lo_epu64(a1, xi[1], b0);
                    a1 = _mm512_madd52hi_epu64(a1, xi[0], b0);
                    a2 = _mm512_madd52lo_epu64(a2, xi[0], b2);
                    a2 = _mm512_madd52lo_epu64(a2, xi[1], b1);
                    a3 = _mm512_madd52lo_epu64(a3, xi[2], b0);
                    a3 = _mm512_madd52hi_epu64(a3, xi[0], b1);
                    a3 = _mm512_madd52hi_epu64(a3, xi[1], b0);
                }
                _mm512_storeu_si512(slot(0) as *mut _, a0);
                _mm512_storeu_si512(slot(1) as *mut _, a1);
                _mm512_storeu_si512(slot(2) as *mut _, a2);
                _mm512_storeu_si512(slot(3) as *mut _, a3);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::galois_rings::degree_4::ResiduePolyF4Z64;
    use crate::galois_rings::degree_8::ResiduePolyF8Z128;
    use crate::structure_traits::Zero;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use std::num::Wrapping;

    /// Random coefficients biased towards the values that exercise carries: all ones, top bit set, limb edges.
    fn edgy_u128(rng: &mut StdRng) -> u128 {
        match rng.gen_range(0..6) {
            0 => u128::MAX - rng.gen_range(0..1000u128),
            1 => rng.r#gen::<u128>() | (1u128 << 127),
            2 => (1u128 << 52) - rng.gen_range(0..3u128),
            3 => (1u128 << 104) + rng.gen_range(0..3u128),
            _ => rng.r#gen(),
        }
    }

    fn random_element<Z: PRSSConversions>(rng: &mut StdRng, degree: usize) -> Z {
        Z::from_u128_iter((0..degree).map(|_| edgy_u128(rng)))
    }

    /// Coefficient-major little-endian blocks for `L` random instances of degree `degree`.
    fn random_blocks<const L: usize>(rng: &mut StdRng, degree: usize) -> Vec<u8> {
        (0..degree * L)
            .flat_map(|_| edgy_u128(rng).to_le_bytes())
            .collect()
    }

    fn check_accumulator_against_naive<Z: Ring + PRSSConversions, const L: usize>(
        rng: &mut StdRng,
        backend: Backend,
        num_constants: usize,
    ) -> Backend {
        let degree = Z::EXTENSION_DEGREE;
        let constants: Vec<Z> = (0..num_constants)
            .map(|_| random_element(rng, degree))
            .collect();
        let lc = LinearCombinator::with_backend(constants.iter().copied(), backend);
        let pushes: Vec<Vec<u8>> = (0..num_constants)
            .map(|_| random_blocks::<L>(rng, degree))
            .collect();
        let mut acc = lc.accumulator::<L>();
        for blocks in &pushes {
            acc.push(&Lanes::from_le_blocks(blocks, degree));
        }
        let got = acc.finish();
        for (lane, got) in got.iter().enumerate() {
            let operands: Vec<Z> = pushes
                .iter()
                .map(|blocks| Lanes::<L>::from_le_blocks(blocks, degree).element(lane))
                .collect();
            let expected = LinearCombinator::naive(&constants, &operands);
            assert_eq!(
                *got, expected,
                "lane {lane}, {num_constants} constants, {backend:?}"
            );
        }
        lc.backend()
    }

    #[test]
    fn prepared_matrix_reproduces_the_ring_product() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..500 {
            let c: ResiduePolyF4Z128 = random_element(&mut rng, 4);
            let psi: ResiduePolyF4Z128 = random_element(&mut rng, 4);
            let table = prepare_f4z128(std::slice::from_ref(&c));
            let expected = c * psi;
            for j in 0..4 {
                let mut sum = 0u128;
                for i in 0..4 {
                    let entry = join([
                        table[((j * 4 + i) * 3) * 8],
                        table[((j * 4 + i) * 3 + 1) * 8],
                        table[((j * 4 + i) * 3 + 2) * 8],
                    ]);
                    sum = sum.wrapping_add(entry.wrapping_mul(psi.coefs[i].0));
                }
                assert_eq!(sum, expected.coefs[j].0, "coefficient {j}");
            }
        }
    }

    #[test]
    fn limb_split_and_join_round_trip() {
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..10_000 {
            let x = edgy_u128(&mut rng);
            assert_eq!(join(split(x)), x);
            assert_eq!(join(normalize(split(x))), x);
        }
        // Lazy sums normalise modulo 2^128.
        let a = u128::MAX;
        let b = u128::MAX - 7;
        let (sa, sb) = (split(a), split(b));
        let lazy = [sa[0] + sb[0], sa[1] + sb[1], sa[2] + sb[2]];
        assert_eq!(join(normalize(lazy)), a.wrapping_add(b));
    }

    #[test]
    fn lanes_decode_coefficient_major_blocks() {
        let mut rng = StdRng::seed_from_u64(3);
        let blocks = random_blocks::<16>(&mut rng, 4);
        let lanes = Lanes::<16>::from_le_blocks(&blocks, 4);
        for lane in 0..16 {
            let element: ResiduePolyF4Z128 = lanes.element(lane);
            for i in 0..4 {
                let offset = (i * 16 + lane) * 16;
                let expected = u128::from_le_bytes(blocks[offset..offset + 16].try_into().unwrap());
                assert_eq!(element.coefs[i].0, expected);
                assert_eq!(lanes.coefficient(i, lane), expected);
            }
        }
    }

    #[test]
    fn scalar_backend_matches_naive_for_every_ring() {
        let mut rng = StdRng::seed_from_u64(4);
        for n in [1, 7, 128, 129, 495] {
            assert_eq!(
                check_accumulator_against_naive::<ResiduePolyF4Z128, 16>(
                    &mut rng,
                    Backend::Scalar,
                    n
                ),
                Backend::Scalar
            );
            check_accumulator_against_naive::<ResiduePolyF4Z64, 16>(&mut rng, Backend::Scalar, n);
            check_accumulator_against_naive::<ResiduePolyF8Z128, 8>(&mut rng, Backend::Scalar, n);
            check_accumulator_against_naive::<ResiduePolyF4Z128, 3>(&mut rng, Backend::Scalar, n);
        }
    }

    #[test]
    fn ifma_backend_matches_naive() {
        let mut rng = StdRng::seed_from_u64(5);
        if LinearCombinator::<ResiduePolyF4Z128>::with_backend([], Backend::Avx512Ifma).backend()
            != Backend::Avx512Ifma
        {
            eprintln!("skipping: AVX-512 IFMA not available on this machine");
            return;
        }
        // Counts around the normalisation cadence and a realistic subset count.
        for n in [1, 2, 8, 9, 127, 128, 129, 255, 256, 257, 495, 1000] {
            assert_eq!(
                check_accumulator_against_naive::<ResiduePolyF4Z128, 8>(
                    &mut rng,
                    Backend::Avx512Ifma,
                    n
                ),
                Backend::Avx512Ifma
            );
            check_accumulator_against_naive::<ResiduePolyF4Z128, 16>(
                &mut rng,
                Backend::Avx512Ifma,
                n,
            );
            check_accumulator_against_naive::<ResiduePolyF4Z128, 32>(
                &mut rng,
                Backend::Avx512Ifma,
                n,
            );
        }
        // Lane counts that are not multiples of eight fall back to scalar evaluation, with the same result.
        let backend = check_accumulator_against_naive::<ResiduePolyF4Z128, 12>(
            &mut rng,
            Backend::Avx512Ifma,
            20,
        );
        assert_eq!(backend, Backend::Avx512Ifma);
    }

    #[test]
    fn ifma_backend_is_only_offered_for_f4z128() {
        assert_eq!(
            LinearCombinator::<ResiduePolyF4Z64>::with_backend([], Backend::Avx512Ifma).backend(),
            Backend::Scalar
        );
        assert_eq!(
            LinearCombinator::<ResiduePolyF8Z128>::with_backend([], Backend::Avx512Ifma).backend(),
            Backend::Scalar
        );
    }

    #[test]
    fn naive_is_the_plain_fold() {
        let c = [
            ResiduePolyF4Z128 {
                coefs: [1u128, 2, 3, 4].map(Wrapping),
            },
            ResiduePolyF4Z128 {
                coefs: [5u128, 6, 7, 8].map(Wrapping),
            },
        ];
        let x = [
            ResiduePolyF4Z128 {
                coefs: [9u128, 10, 11, 12].map(Wrapping),
            },
            ResiduePolyF4Z128 {
                coefs: [13u128, 14, 15, 16].map(Wrapping),
            },
        ];
        assert_eq!(LinearCombinator::naive(&c, &x), c[0] * x[0] + c[1] * x[1]);
    }

    #[test]
    #[should_panic(expected = "pushed more operands")]
    fn accumulator_rejects_extra_pushes() {
        let lc = LinearCombinator::<ResiduePolyF4Z128>::with_backend(
            [ResiduePolyF4Z128::ZERO],
            Backend::Scalar,
        );
        let blocks = vec![0u8; 4 * 8 * 16];
        let mut acc = lc.accumulator::<8>();
        acc.push(&Lanes::from_le_blocks(&blocks, 4));
        acc.push(&Lanes::from_le_blocks(&blocks, 4));
    }

    #[test]
    #[should_panic(expected = "finished after")]
    fn accumulator_rejects_missing_pushes() {
        let lc = LinearCombinator::<ResiduePolyF4Z128>::with_backend(
            [ResiduePolyF4Z128::ZERO, ResiduePolyF4Z128::ZERO],
            Backend::Scalar,
        );
        let _ = lc.accumulator::<8>().finish();
    }
}
