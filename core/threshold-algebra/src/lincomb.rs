//! Linear combinations `Σ_k c_k · x_k` whose constants `c_k` are fixed and reused.
//!
//! The PRSS share of a party is `Σ_A f_A(α_i) · ψ(r_A, cnt)`: the `f_A(α_i)` are fixed for an epoch while the PRF
//! outputs change with every counter. The same shape appears wherever a party combines fresh values with
//! constants it holds: PRZS (`f_A(α_i) · α_i^j` times `χ`), PRSS-Mask (`f_A(α_i)` times a bounded integer) and the
//! partial decryption `⟨a, s⟩` of a ciphertext mask `a` with the key share `s`.
//!
//! [`LinearCombinator`] exploits this in two steps:
//!
//! * **Strength reduction.** Multiplication by a fixed ring element `c` is a `Z/2^k`-linear map on coefficient
//!   vectors, `c · ψ = M_c · ψ`, where column `i` of `M_c` holds the coefficients of `c · X^i`. `M_c` is computed once
//!   per constant with the reduction modulo the ring's polynomial folded into its entries, so a product costs
//!   `d²` base-ring multiply-adds and no reduction, with no subtraction and no data-dependent control flow. When
//!   the operands are base-ring scalars rather than ring elements, only the first column is needed (`d`
//!   multiply-adds per product).
//! * **Lane batching.** Independent instances (for PRSS: the counters of a group; for decryption: the blocks of a
//!   ciphertext) are placed in SIMD lanes and the base-ring arithmetic runs on 52-bit limbs with AVX-512 IFMA
//!   (`vpmadd52luq`/`vpmadd52huq`), accumulating lazily and propagating carries only every
//!   [`NORMALIZE_EVERY`] terms. For a single instance with many scalar operands ([`LinearCombinator::dot`]),
//!   eight consecutive constants go into the lanes instead.
//!
//! Every backend computes the exact ring element; outputs are bit-identical to the plain folds
//! ([`LinearCombinator::naive`], [`LinearCombinator::naive_scalars`]), which are also the references the tests
//! compare against.
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

/// What a [`LinearCombinator`] multiplies its constants with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// Ring elements, one per lane (PRSS, PRZS): a product is the full `d × d` matrix.
    Element,
    /// Base-ring scalars, one 128-bit value per lane (PRSS-Mask, partial decryption): a product is the
    /// constant's coefficient vector scaled by the operand.
    Scalar,
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
/// Prepared entries per group of eight constants with ring-element operands: `[j][i][limb][lane]` for a
/// degree-four ring, three limbs.
const F4_ELEMENT_BLOCK: usize = 4 * 4 * 3 * 8;
/// Prepared entries per group of eight constants with scalar operands: `[j][limb][lane]`.
const F4_SCALAR_BLOCK: usize = 4 * 3 * 8;

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
/// `L` independent instances per push; a single instance with scalar operands uses [`LinearCombinator::dot`].
/// For a one-off combination without reuse, use [`LinearCombinator::naive`].
#[derive(Clone)]
pub struct LinearCombinator<Z> {
    constants: Vec<Z>,
    backend: Backend,
    operand: Operand,
    /// IFMA table, empty unless `backend == Avx512Ifma`: `[k / 8][j][i][limb][k % 8]` for element operands,
    /// `[k / 8][j][limb][k % 8]` for scalar operands.
    table: Vec<u64>,
}

impl<Z> std::fmt::Debug for LinearCombinator<Z> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinearCombinator")
            .field("len", &self.constants.len())
            .field("backend", &self.backend)
            .field("operand", &self.operand)
            .finish()
    }
}

impl<Z: Ring + PRSSConversions> LinearCombinator<Z> {
    /// Prepares the constants for ring-element operands with the backend detected for `Z` on this machine.
    pub fn new(constants: impl IntoIterator<Item = Z>) -> Self {
        Self::with_backend(constants, Operand::Element, Self::detected_backend())
    }

    /// Prepares the constants for scalar operands with the backend detected for `Z` on this machine.
    pub fn for_scalars(constants: impl IntoIterator<Item = Z>) -> Self {
        Self::with_backend(constants, Operand::Scalar, Self::detected_backend())
    }

    /// Prepares the constants with the requested backend, falling back to [`Backend::Scalar`] when the
    /// requested one is not available for `Z` on this machine.
    pub fn with_backend(
        constants: impl IntoIterator<Item = Z>,
        operand: Operand,
        backend: Backend,
    ) -> Self {
        let constants: Vec<Z> = constants.into_iter().collect();
        let backend = match backend {
            Backend::Avx512Ifma if ifma_supports::<Z>() => Backend::Avx512Ifma,
            _ => Backend::Scalar,
        };
        let table = match (backend, operand) {
            (Backend::Avx512Ifma, Operand::Element) => prepare_f4z128_element(&constants),
            (Backend::Avx512Ifma, Operand::Scalar) => prepare_f4z128_scalar(&constants),
            (Backend::Scalar, _) => Vec::new(),
        };
        Self {
            constants,
            backend,
            operand,
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

    /// The operand shape this instance was prepared for.
    pub fn operand(&self) -> Operand {
        self.operand
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

    /// `Σ_k c_k · x[k]` for one instance with scalar operands ([`Operand::Scalar`]): the inner product of a
    /// ciphertext mask with a key share, say. With the IFMA backend eight consecutive constants share one
    /// instruction. Panics if the instance was prepared for element operands or `x.len()` differs from the
    /// constant count.
    pub fn dot(&self, x: &[u128]) -> Z {
        assert_eq!(
            self.operand,
            Operand::Scalar,
            "dot: the constants were prepared for ring-element operands"
        );
        assert_eq!(
            x.len(),
            self.constants.len(),
            "dot: operand count differs from constant count"
        );
        match self.backend {
            Backend::Scalar => Self::naive_scalars(&self.constants, x),
            Backend::Avx512Ifma => {
                #[cfg(target_arch = "x86_64")]
                {
                    Z::from_u128_iter(dot_f4z128_ifma(&self.table, x).into_iter())
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    unreachable!("the IFMA backend is only ever selected on x86-64")
                }
            }
        }
    }

    /// The plain fold `Σ_k constants[k] · x[k]` with the ring's multiplication: no preparation, no reuse.
    /// This is the reference every backend must agree with for element operands.
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

    /// The plain fold `Σ_k constants[k] · x[k]` for scalar operands, with the ring's scalar multiplication.
    /// This is the reference every backend must agree with for scalar operands.
    pub fn naive_scalars(constants: &[Z], x: &[u128]) -> Z {
        assert_eq!(
            constants.len(),
            x.len(),
            "naive_scalars: operand count differs from constant count"
        );
        constants
            .iter()
            .zip(x)
            .fold(Z::ZERO, |acc, (c, v)| acc + c.mul_by_u128(*v))
    }

    /// Length of one table block (eight constants) for this operand shape.
    #[inline]
    fn block_len(&self) -> usize {
        match self.operand {
            Operand::Element => F4_ELEMENT_BLOCK,
            Operand::Scalar => F4_SCALAR_BLOCK,
        }
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

/// The prepared table for `ResiduePolyF4Z128` and element operands: for constant `k`, entry
/// `[k / 8][j][i][limb][k % 8]` is limb `limb` of `M_c[j][i]`, the coefficient `j` of `c · X^i`. Padding constants
/// are zero.
fn prepare_f4z128_element<Z: 'static>(constants: &[Z]) -> Vec<u64> {
    let constants = as_f4z128(constants);
    let mut table = vec![0u64; constants.len().div_ceil(8) * F4_ELEMENT_BLOCK];
    let x = ResiduePolyF4Z128 {
        coefs: [0u128, 1, 0, 0].map(std::num::Wrapping),
    };
    for (k, c) in constants.iter().enumerate() {
        let block = &mut table[(k / 8) * F4_ELEMENT_BLOCK..][..F4_ELEMENT_BLOCK];
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

/// The prepared table for `ResiduePolyF4Z128` and scalar operands: for constant `k`, entry
/// `[k / 8][j][limb][k % 8]` is limb `limb` of coefficient `j` of `c` (the first column of `M_c`). Padding
/// constants are zero.
fn prepare_f4z128_scalar<Z: 'static>(constants: &[Z]) -> Vec<u64> {
    let constants = as_f4z128(constants);
    let mut table = vec![0u64; constants.len().div_ceil(8) * F4_SCALAR_BLOCK];
    for (k, c) in constants.iter().enumerate() {
        let block = &mut table[(k / 8) * F4_SCALAR_BLOCK..][..F4_SCALAR_BLOCK];
        let lane = k % 8;
        for j in 0..4 {
            let limbs = split(c.coefs[j].0);
            for (l, limb) in limbs.into_iter().enumerate() {
                block[(j * 3 + l) * 8 + lane] = limb;
            }
        }
    }
    table
}

/// `Σ_k c_k · x[k]` over 52-bit limbs with eight constants per lane; `table` is the scalar-operand table.
/// Returns the four coefficients of the result.
#[cfg(target_arch = "x86_64")]
fn dot_f4z128_ifma(table: &[u64], x: &[u128]) -> [u128; 4] {
    // Accumulators `[j][slot][lane]`, slots as in `IfmaState`; the kernel keeps them in registers for a whole
    // run and writes them back normalised.
    let mut acc = [[[0u64; 8]; 4]; 4];
    let full_blocks = x.len() / 8;
    // SAFETY: the backend is only selected when `avx512f` and `avx512ifma` were detected; `acc` holds
    // 4 × 4 × 8 lanes, `x` holds `8 * full_blocks` values and `table` as many full blocks.
    unsafe {
        avx512::dot_run_f4(
            acc.as_mut_ptr() as *mut u64,
            x.as_ptr() as *const u8,
            table.as_ptr(),
            full_blocks,
        );
    }
    let tail = &x[full_blocks * 8..];
    if !tail.is_empty() {
        // The last block is short: pad it with zeros (the table's padding constants are zero too).
        let mut padded = [0u128; 8];
        padded[..tail.len()].copy_from_slice(tail);
        // SAFETY: as above, with one padded block of operands and the table's last block.
        unsafe {
            avx512::dot_run_f4(
                acc.as_mut_ptr() as *mut u64,
                padded.as_ptr() as *const u8,
                table.as_ptr().add(full_blocks * F4_SCALAR_BLOCK),
                1,
            );
        }
    }
    // Fold the eight lanes: normalised limbs are below 2^52, so eight of them add without overflow.
    std::array::from_fn(|j| {
        let sum: [u64; 3] = std::array::from_fn(|limb| acc[j][limb].iter().sum());
        join(normalize(sum))
    })
}

/// `L` operands of a push: either coefficient-major little-endian blocks (block `(i, lane)` is the 16 bytes of
/// coefficient `i` of instance `lane`, at byte offset `(i * L + lane) * 16`, the layout the AES-based PRFs
/// produce when a group of counters is encrypted coefficient by coefficient, so no copy is needed) or, for
/// scalar operands, `L` unsigned 128-bit values. One block per coefficient: rings whose coefficients need
/// several PRF blocks are not supported here.
#[derive(Clone, Copy)]
pub struct Lanes<'a, const L: usize> {
    source: Source<'a>,
    degree: usize,
}

#[derive(Clone, Copy)]
enum Source<'a> {
    Blocks(&'a [u8]),
    Scalars(&'a [u128]),
}

impl<'a, const L: usize> Lanes<'a, L> {
    /// `blocks` must hold `degree * L` blocks of 16 bytes in the layout described on [`Lanes`].
    pub fn from_le_blocks(blocks: &'a [u8], degree: usize) -> Self {
        assert_eq!(
            blocks.len(),
            degree * L * 16,
            "Lanes: expected {degree} coefficients x {L} lanes x 16 bytes"
        );
        Self {
            source: Source::Blocks(blocks),
            degree,
        }
    }

    /// `L` scalar operands, one per lane (degree one).
    pub fn from_scalars(values: &'a [u128]) -> Self {
        assert_eq!(values.len(), L, "Lanes: expected {L} scalars");
        Self {
            source: Source::Scalars(values),
            degree: 1,
        }
    }

    /// Coefficient `i` of instance `lane` as an unsigned integer.
    #[inline]
    pub fn coefficient(&self, i: usize, lane: usize) -> u128 {
        match self.source {
            Source::Blocks(blocks) => {
                let offset = (i * L + lane) * 16;
                u128::from_le_bytes(
                    blocks[offset..offset + 16]
                        .try_into()
                        .expect("16-byte block"),
                )
            }
            Source::Scalars(values) => {
                assert_eq!(i, 0, "Lanes: scalar operands have one coefficient");
                values[lane]
            }
        }
    }

    /// Instance `lane` as a ring element, with the PRF's own chunk-to-element conversion.
    #[inline]
    pub fn element<Z: PRSSConversions>(&self, lane: usize) -> Z {
        Z::from_u128_iter((0..self.degree).map(|i| self.coefficient(i, lane)))
    }

    /// Instance `lane` as a scalar (degree one).
    #[inline]
    pub fn scalar(&self, lane: usize) -> u128 {
        self.coefficient(0, lane)
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    /// The operands as coefficient-major little-endian blocks, for the IFMA kernels. A scalar slice has that
    /// layout on little-endian targets, and the kernels only run on x86-64.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn block_ptr(&self) -> *const u8 {
        match self.source {
            Source::Blocks(blocks) => blocks.as_ptr(),
            Source::Scalars(values) => values.as_ptr() as *const u8,
        }
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
    /// Adds `c_k · lanes` for the next constant `k`. The lanes must match the operand shape the constants were
    /// prepared for: `Z::EXTENSION_DEGREE` coefficients for [`Operand::Element`], one for [`Operand::Scalar`].
    /// Panics when pushed more often than there are constants.
    #[inline]
    pub fn push(&mut self, lanes: &Lanes<'_, L>) {
        let k = self.next;
        assert!(
            k < self.lc.constants.len(),
            "Accumulator: pushed more operands ({}) than constants ({})",
            k + 1,
            self.lc.constants.len()
        );
        let expected_degree = match self.lc.operand {
            Operand::Element => Z::EXTENSION_DEGREE,
            Operand::Scalar => 1,
        };
        assert_eq!(
            lanes.degree, expected_degree,
            "Accumulator: operands of degree {} pushed into a combinator prepared for {:?} operands",
            lanes.degree, self.lc.operand
        );
        self.next += 1;
        match &mut self.state {
            State::Scalar(sums) => {
                let c = self.lc.constants[k];
                match self.lc.operand {
                    Operand::Element => {
                        for (lane, sum) in sums.iter_mut().enumerate() {
                            *sum += c * lanes.element::<Z>(lane);
                        }
                    }
                    Operand::Scalar => {
                        for (lane, sum) in sums.iter_mut().enumerate() {
                            *sum += c.mul_by_u128(lanes.scalar(lane));
                        }
                    }
                }
            }
            State::Ifma(state) => {
                #[cfg(target_arch = "x86_64")]
                {
                    let block_len = self.lc.block_len();
                    let block = &self.lc.table[(k / 8) * block_len..][..block_len];
                    for half in 0..L / 8 {
                        // SAFETY: the backend is only selected when `avx512f` and `avx512ifma` were detected.
                        // `acc` holds `4 * 4 * L` lanes, `lanes` holds `degree * L` blocks (checked by `Lanes`)
                        // and `block` holds a full table block, so every access below is in bounds.
                        unsafe {
                            match self.lc.operand {
                                Operand::Element => avx512::mac8_f4(
                                    state.acc.as_mut_ptr() as *mut u64,
                                    L,
                                    half * 8,
                                    lanes.block_ptr(),
                                    L * 16,
                                    block.as_ptr(),
                                    k % 8,
                                ),
                                Operand::Scalar => avx512::mac8_f4_scalar(
                                    state.acc.as_mut_ptr() as *mut u64,
                                    L,
                                    half * 8,
                                    lanes.block_ptr(),
                                    block.as_ptr(),
                                    k % 8,
                                ),
                            }
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

    /// Loads eight 128-bit little-endian values at `p` and splits them into three 52-bit limbs per lane.
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    unsafe fn load_limbs(p: *const u8) -> [__m512i; 3] {
        unsafe {
            let m52 = _mm512_set1_epi64(super::M52 as i64);
            let idx_lo = _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14);
            let idx_hi = _mm512_setr_epi64(1, 3, 5, 7, 9, 11, 13, 15);
            let z0 = _mm512_loadu_si512(p as *const _);
            let z1 = _mm512_loadu_si512(p.add(64) as *const _);
            let lo = _mm512_permutex2var_epi64(z0, idx_lo, z1);
            let hi = _mm512_permutex2var_epi64(z0, idx_hi, z1);
            [
                _mm512_and_si512(lo, m52),
                _mm512_and_si512(
                    _mm512_or_si512(_mm512_srli_epi64::<52>(lo), _mm512_slli_epi64::<12>(hi)),
                    m52,
                ),
                _mm512_srli_epi64::<40>(hi),
            ]
        }
    }

    /// Adds the nine partial products of `x · b` that land below `2^128` to the four accumulator slots:
    /// limb 0 gets `lo(x0·b0)`; limb 1 gets `lo(x0·b1) + lo(x1·b0) + hi(x0·b0)`; limb 2 (slots 2 and 3) gets
    /// `lo(x0·b2) + lo(x1·b1) + lo(x2·b0) + hi(x0·b1) + hi(x1·b0)`. Per call each slot receives at most three
    /// additions, which bounds [`super::NORMALIZE_EVERY`].
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn mac_limbs(a: &mut [__m512i; 4], x: &[__m512i; 3], b: [__m512i; 3]) {
        a[0] = _mm512_madd52lo_epu64(a[0], x[0], b[0]);
        a[1] = _mm512_madd52lo_epu64(a[1], x[0], b[1]);
        a[1] = _mm512_madd52lo_epu64(a[1], x[1], b[0]);
        a[1] = _mm512_madd52hi_epu64(a[1], x[0], b[0]);
        a[2] = _mm512_madd52lo_epu64(a[2], x[0], b[2]);
        a[2] = _mm512_madd52lo_epu64(a[2], x[1], b[1]);
        a[3] = _mm512_madd52lo_epu64(a[3], x[2], b[0]);
        a[3] = _mm512_madd52hi_epu64(a[3], x[0], b[1]);
        a[3] = _mm512_madd52hi_epu64(a[3], x[1], b[0]);
    }

    /// Adds `M_c · x` to the accumulators of eight lanes, for one constant and `ResiduePolyF4Z128` element
    /// operands.
    ///
    /// * `acc`: `[j][slot][lane]` with `lane_stride` lanes per slot; lanes `lane0..lane0 + 8` are updated.
    /// * `blocks`: coefficient-major 16-byte blocks, coefficient `i` at `blocks + i * coef_stride`, lane `l` at
    ///   `+ l * 16`; lanes `lane0..lane0 + 8` are read.
    /// * `consts`: one element table block `[j][i][limb][8]`; `lane_k` selects the constant.
    ///
    /// Per push each slot receives at most 12 additions (four `(j, i)` pairs per `j`).
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
            let mut x = [[_mm512_setzero_si512(); 3]; 4];
            for (i, xi) in x.iter_mut().enumerate() {
                *xi = load_limbs(blocks.add(i * coef_stride + lane0 * 16));
            }
            for j in 0..4 {
                let slot = |s: usize| acc.add((j * 4 + s) * lane_stride + lane0);
                let mut a = [
                    _mm512_loadu_si512(slot(0) as *const _),
                    _mm512_loadu_si512(slot(1) as *const _),
                    _mm512_loadu_si512(slot(2) as *const _),
                    _mm512_loadu_si512(slot(3) as *const _),
                ];
                for (i, xi) in x.iter().enumerate() {
                    let entry = consts.add(((j * 4 + i) * 3) * 8 + lane_k);
                    let b = [
                        _mm512_set1_epi64(*entry as i64),
                        _mm512_set1_epi64(*entry.add(8) as i64),
                        _mm512_set1_epi64(*entry.add(16) as i64),
                    ];
                    mac_limbs(&mut a, xi, b);
                }
                for (s, a) in a.iter().enumerate() {
                    _mm512_storeu_si512(slot(s) as *mut _, *a);
                }
            }
        }
    }

    /// Adds `c · x` to the accumulators of eight lanes, for one constant `c` and eight scalar operands `x`
    /// (`ResiduePolyF4Z128` times a base-ring scalar: every coefficient of `c` is scaled by `x`).
    ///
    /// * `acc`: as in [`mac8_f4`].
    /// * `scalars`: 16-byte little-endian values, lane `l` at `+ l * 16`; lanes `lane0..lane0 + 8` are read.
    /// * `consts`: one scalar table block `[j][limb][8]`; `lane_k` selects the constant.
    ///
    /// Per push each slot receives at most three additions.
    ///
    /// # Safety
    /// As for [`mac8_f4`].
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn mac8_f4_scalar(
        acc: *mut u64,
        lane_stride: usize,
        lane0: usize,
        scalars: *const u8,
        consts: *const u64,
        lane_k: usize,
    ) {
        unsafe {
            let x = load_limbs(scalars.add(lane0 * 16));
            for j in 0..4 {
                let slot = |s: usize| acc.add((j * 4 + s) * lane_stride + lane0);
                let mut a = [
                    _mm512_loadu_si512(slot(0) as *const _),
                    _mm512_loadu_si512(slot(1) as *const _),
                    _mm512_loadu_si512(slot(2) as *const _),
                    _mm512_loadu_si512(slot(3) as *const _),
                ];
                let entry = consts.add((j * 3) * 8 + lane_k);
                let b = [
                    _mm512_set1_epi64(*entry as i64),
                    _mm512_set1_epi64(*entry.add(8) as i64),
                    _mm512_set1_epi64(*entry.add(16) as i64),
                ];
                mac_limbs(&mut a, &x, b);
                for (s, a) in a.iter().enumerate() {
                    _mm512_storeu_si512(slot(s) as *mut _, *a);
                }
            }
        }
    }

    /// Propagates the carries of the four accumulator slots of one coefficient, in registers: slots 2 and 3 are
    /// folded, limbs 0 and 1 are reduced to 52 bits, limb 2 to 24 bits (the reduction modulo `2^128`).
    #[inline]
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn normalize_limbs(a: &mut [__m512i; 4], m52: __m512i, m24: __m512i) {
        let folded = _mm512_add_epi64(a[2], a[3]);
        let carry0 = _mm512_srli_epi64::<52>(a[0]);
        let a1 = _mm512_add_epi64(a[1], carry0);
        let carry1 = _mm512_srli_epi64::<52>(a1);
        a[0] = _mm512_and_si512(a[0], m52);
        a[1] = _mm512_and_si512(a1, m52);
        a[2] = _mm512_and_si512(_mm512_add_epi64(folded, carry1), m24);
        a[3] = _mm512_setzero_si512();
    }

    /// Adds `c_k · x_k` for `blocks` runs of eight consecutive constants `k` (one per lane) and their scalar
    /// operands, keeping the sixteen accumulators in registers for the whole run.
    ///
    /// * `acc`: `[j][slot][8]`, read at the start and written back normalised at the end.
    /// * `scalars`: `8 * blocks` 16-byte little-endian values.
    /// * `consts`: `blocks` scalar table blocks `[j][limb][8]`: lane `l` holds constant `l`'s limbs.
    ///
    /// Per block each slot receives at most three additions; the carries are propagated every
    /// [`super::NORMALIZE_EVERY`] blocks and at the end.
    ///
    /// # Safety
    /// As for [`mac8_f4`].
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) unsafe fn dot_run_f4(
        acc: *mut u64,
        scalars: *const u8,
        consts: *const u64,
        blocks: usize,
    ) {
        unsafe {
            let m52 = _mm512_set1_epi64(super::M52 as i64);
            let m24 = _mm512_set1_epi64(super::M24 as i64);
            let mut a = [[_mm512_setzero_si512(); 4]; 4];
            for (j, aj) in a.iter_mut().enumerate() {
                for (s, slot) in aj.iter_mut().enumerate() {
                    *slot = _mm512_loadu_si512(acc.add((j * 4 + s) * 8) as *const _);
                }
            }
            let mut since_normalize = 0;
            for block in 0..blocks {
                let x = load_limbs(scalars.add(block * 128));
                let table_block = consts.add(block * super::F4_SCALAR_BLOCK);
                for (j, aj) in a.iter_mut().enumerate() {
                    let entry = table_block.add((j * 3) * 8);
                    let b = [
                        _mm512_loadu_si512(entry as *const _),
                        _mm512_loadu_si512(entry.add(8) as *const _),
                        _mm512_loadu_si512(entry.add(16) as *const _),
                    ];
                    mac_limbs(aj, &x, b);
                }
                since_normalize += 1;
                if since_normalize == super::NORMALIZE_EVERY {
                    for aj in a.iter_mut() {
                        normalize_limbs(aj, m52, m24);
                    }
                    since_normalize = 0;
                }
            }
            for (j, aj) in a.iter_mut().enumerate() {
                normalize_limbs(aj, m52, m24);
                for (s, slot) in aj.iter().enumerate() {
                    _mm512_storeu_si512(acc.add((j * 4 + s) * 8) as *mut _, *slot);
                }
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

    fn ifma_is_available() -> bool {
        let available = LinearCombinator::<ResiduePolyF4Z128>::with_backend(
            [],
            Operand::Element,
            Backend::Avx512Ifma,
        )
        .backend()
            == Backend::Avx512Ifma;
        if !available {
            eprintln!("skipping: AVX-512 IFMA not available on this machine");
        }
        available
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
        let lc =
            LinearCombinator::with_backend(constants.iter().copied(), Operand::Element, backend);
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

    /// Scalar operands through the accumulator (lanes = instances) and through `dot` (lanes = constants).
    fn check_scalar_operands_against_naive<Z: Ring + PRSSConversions, const L: usize>(
        rng: &mut StdRng,
        backend: Backend,
        num_constants: usize,
    ) -> Backend {
        let degree = Z::EXTENSION_DEGREE;
        let constants: Vec<Z> = (0..num_constants)
            .map(|_| random_element(rng, degree))
            .collect();
        let lc =
            LinearCombinator::with_backend(constants.iter().copied(), Operand::Scalar, backend);
        let pushes: Vec<Vec<u128>> = (0..num_constants)
            .map(|_| (0..L).map(|_| edgy_u128(rng)).collect())
            .collect();
        let mut acc = lc.accumulator::<L>();
        for values in &pushes {
            acc.push(&Lanes::from_scalars(values));
        }
        let got = acc.finish();
        for (lane, got) in got.iter().enumerate() {
            let operands: Vec<u128> = pushes.iter().map(|values| values[lane]).collect();
            let expected = LinearCombinator::naive_scalars(&constants, &operands);
            assert_eq!(
                *got, expected,
                "push: lane {lane}, {num_constants} constants, {backend:?}"
            );
            assert_eq!(
                lc.dot(&operands),
                expected,
                "dot: lane {lane}, {num_constants} constants, {backend:?}"
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
            let table = prepare_f4z128_element(std::slice::from_ref(&c));
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
            // The scalar table is the first column.
            let scalar_table = prepare_f4z128_scalar(std::slice::from_ref(&c));
            for j in 0..4 {
                let entry = join([
                    scalar_table[(j * 3) * 8],
                    scalar_table[(j * 3 + 1) * 8],
                    scalar_table[(j * 3 + 2) * 8],
                ]);
                assert_eq!(entry, c.coefs[j].0, "coefficient {j}");
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
        let values: Vec<u128> = (0..8).map(|_| edgy_u128(&mut rng)).collect();
        let lanes = Lanes::<8>::from_scalars(&values);
        assert_eq!(lanes.degree(), 1);
        for (lane, value) in values.iter().enumerate() {
            assert_eq!(lanes.scalar(lane), *value);
            assert_eq!(lanes.coefficient(0, lane), *value);
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
            check_scalar_operands_against_naive::<ResiduePolyF4Z128, 16>(
                &mut rng,
                Backend::Scalar,
                n,
            );
            check_scalar_operands_against_naive::<ResiduePolyF4Z64, 8>(
                &mut rng,
                Backend::Scalar,
                n,
            );
            check_scalar_operands_against_naive::<ResiduePolyF8Z128, 3>(
                &mut rng,
                Backend::Scalar,
                n,
            );
        }
    }

    #[test]
    fn ifma_backend_matches_naive() {
        let mut rng = StdRng::seed_from_u64(5);
        if !ifma_is_available() {
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
    fn ifma_backend_matches_naive_for_scalar_operands() {
        let mut rng = StdRng::seed_from_u64(6);
        if !ifma_is_available() {
            return;
        }
        // Counts around the cadence of both kernels (128 pushes; 128 blocks of eight constants for `dot`),
        // partial last blocks, a subset count and a key dimension.
        for n in [
            1, 2, 7, 8, 9, 127, 128, 129, 495, 1023, 1024, 1025, 2049, 4096,
        ] {
            assert_eq!(
                check_scalar_operands_against_naive::<ResiduePolyF4Z128, 8>(
                    &mut rng,
                    Backend::Avx512Ifma,
                    n
                ),
                Backend::Avx512Ifma
            );
            check_scalar_operands_against_naive::<ResiduePolyF4Z128, 16>(
                &mut rng,
                Backend::Avx512Ifma,
                n,
            );
            check_scalar_operands_against_naive::<ResiduePolyF4Z128, 32>(
                &mut rng,
                Backend::Avx512Ifma,
                n,
            );
        }
        let backend = check_scalar_operands_against_naive::<ResiduePolyF4Z128, 12>(
            &mut rng,
            Backend::Avx512Ifma,
            20,
        );
        assert_eq!(backend, Backend::Avx512Ifma);
    }

    #[test]
    fn ifma_backend_is_only_offered_for_f4z128() {
        for operand in [Operand::Element, Operand::Scalar] {
            assert_eq!(
                LinearCombinator::<ResiduePolyF4Z64>::with_backend(
                    [],
                    operand,
                    Backend::Avx512Ifma
                )
                .backend(),
                Backend::Scalar
            );
            assert_eq!(
                LinearCombinator::<ResiduePolyF8Z128>::with_backend(
                    [],
                    operand,
                    Backend::Avx512Ifma
                )
                .backend(),
                Backend::Scalar
            );
        }
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
        assert_eq!(
            LinearCombinator::naive_scalars(&c, &[3, u128::MAX]),
            c[0] * Wrapping(3u128) + c[1] * Wrapping(u128::MAX)
        );
    }

    #[test]
    #[should_panic(expected = "pushed more operands")]
    fn accumulator_rejects_extra_pushes() {
        let lc = LinearCombinator::<ResiduePolyF4Z128>::with_backend(
            [ResiduePolyF4Z128::ZERO],
            Operand::Element,
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
            Operand::Element,
            Backend::Scalar,
        );
        let _ = lc.accumulator::<8>().finish();
    }

    #[test]
    #[should_panic(expected = "operands of degree 1")]
    fn accumulator_rejects_the_wrong_operand_shape() {
        let lc = LinearCombinator::<ResiduePolyF4Z128>::with_backend(
            [ResiduePolyF4Z128::ZERO],
            Operand::Element,
            Backend::Scalar,
        );
        let values = [0u128; 8];
        lc.accumulator::<8>().push(&Lanes::from_scalars(&values));
    }

    #[test]
    #[should_panic(expected = "prepared for ring-element operands")]
    fn dot_rejects_element_constants() {
        let lc = LinearCombinator::<ResiduePolyF4Z128>::with_backend(
            [ResiduePolyF4Z128::ZERO],
            Operand::Element,
            Backend::Scalar,
        );
        let _ = lc.dot(&[0]);
    }
}
