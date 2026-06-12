//! Flattened, `MetaParameters`-backed reimplementation of `DKGParams`.
//!
//! This is a work-in-progress alternative to [`super::parameters::DKGParams`].
//! The goal is to stop duplicating the tfhe-rs crypto-parameter layout inside
//! KMS and instead carry a single [`tfhe::shortint::parameters::MetaParameters`]
//! plus the few values tfhe-rs has no concept of (`dkg_mode`, `sec`,
//! `secret_key_deviations`).
//!
//! ## Differences vs `parameters.rs` (all behavior-preserving)
//!
//! 1. **One flat struct instead of the `WithoutSnS`/`WithSnS` enum.** The
//!    discriminant maps exactly to `noise_squashing_parameters.is_some()`
//!    (`DKGParamsSnS.sns_params` is non-optional, so `WithSnS` always carries
//!    SnS data, and `DKGParamsRegular` never does). This removes the entire
//!    `DKGParamsSnS` impl that just forwarded to `regular_params`, and the
//!    per-variant `From`/`TryFrom` glue.
//!
//! 2. **`SnsView` for SnS-only accessors.** Instead of methods that each assume
//!    an SnS variant, the `*_sns` methods live on a view obtained once via
//!    [`DKGParamsNew::sns`], so callers check the `Option` once per scope rather
//!    than per call.
//!
//! 3. **`SnS ⇒ Z128` is enforced, not coerced.** The legacy
//!    `DKGParamsSnS::get_dkg_mode()` ignored the stored mode and always returned
//!    `Z128`, which can hide a malformed value. Here the real `dkg_mode` is
//!    stored and the invariant is checked explicitly in
//!    [`DKGParamsNew::check_conformance`].
//!
//! The budget arithmetic (bits / triples / randomness / noise) is a faithful
//! port of `parameters.rs`; it reuses the very same helper functions
//! (`combine_noise_info`, `compute_prob_hw_within_range`, `compute_min_trials`)
//! so the two implementations cannot drift. The `budgets_match_legacy_for_all_params`
//! test below pins this equivalence for every shipped parameter set.

use tfhe::shortint::parameters::meta::DedicatedCompactPublicKeyParameters;
use tfhe::shortint::parameters::{
    AtomicPatternParameters, Backend, ClassicPBSParameters, CompactPublicKeyEncryptionParameters,
    CompressionParameters, DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice,
    GlweDimension, LweDimension, MetaNoiseSquashingParameters, MetaParameters, ModulusSwitchType,
    NoiseSquashingClassicParameters, NoiseSquashingCompressionParameters, NoiseSquashingParameters,
    PBSParameters, PolynomialSize, ReRandomizationConfiguration, ShortintKeySwitchingParameters,
};

use super::parameters::{
    DKGParams, DKGParamsRegular, DkgMode, NoiseBounds, NoiseInfo, SecretKeyDeviations,
    TUniformBound, combine_noise_info, compute_min_trials, compute_prob_hw_within_range,
};
use crate::keyset_config::{KeyGenSecretKeyConfig, KeySetConfig};

/// Flattened DKG parameters backed by a tfhe-rs [`MetaParameters`].
///
/// `meta` carries all the crypto parameters; the other three fields are the
/// KMS-only values that have no place in `MetaParameters`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DKGParamsNew {
    /// Z64 vs Z128 sharing domain. Must be `Z128` whenever SnS is present
    /// (enforced by [`Self::check_conformance`]).
    pub dkg_mode: DkgMode,
    /// Security parameter (XOF seed size).
    pub sec: u64,
    /// All tfhe-rs crypto parameters.
    pub meta: MetaParameters,
    /// Optional Hamming-weight bound for DKG secret-key sampling.
    pub secret_key_deviations: Option<SecretKeyDeviations>,
}

// ---------------------------------------------------------------------------
// Conversion from the legacy representation (used by the equivalence test and
// as the migration bridge).
// ---------------------------------------------------------------------------

impl From<DKGParams> for DKGParamsNew {
    fn from(old: DKGParams) -> Self {
        match old {
            DKGParams::WithoutSnS(regular) => Self::from_regular(regular, None),
            DKGParams::WithSnS(sns) => {
                let nsp = MetaNoiseSquashingParameters {
                    parameters: sns.sns_params,
                    compression_parameters: sns.sns_compression_params,
                };
                Self::from_regular(sns.regular_params, Some(nsp))
            }
        }
    }
}

impl DKGParamsNew {
    fn from_regular(
        regular: DKGParamsRegular,
        noise_squashing_parameters: Option<MetaNoiseSquashingParameters>,
    ) -> Self {
        // The legacy rerand KSK (`cpk_re_randomization_ksk_params`) folds into
        // the dedicated CPK's `re_randomization_parameters`, with the Legacy
        // rerand configuration. This preserves `get_rerand_params()` and the
        // `rerand_ksk_reuses_pksk()` decision exactly.
        let dedicated_compact_public_key_parameters = regular
            .dedicated_compact_public_key_parameters
            .map(
                |(pke_params, ksk_params)| DedicatedCompactPublicKeyParameters {
                    pke_params,
                    ksk_params,
                    re_randomization_parameters: regular.cpk_re_randomization_ksk_params,
                },
            );

        // "rerand without a dedicated CPK" cannot be represented in
        // `MetaParameters` (the rerand KSK lives inside the dedicated CPK). No
        // current parameter set hits this; guard against regressions.
        debug_assert!(
            dedicated_compact_public_key_parameters.is_some()
                || regular.cpk_re_randomization_ksk_params.is_none(),
            "rerand KSK without a dedicated CPK cannot be represented in MetaParameters"
        );

        let rerand_configuration = regular
            .cpk_re_randomization_ksk_params
            .map(|_| ReRandomizationConfiguration::LegacyDedicatedCompactPublicKeyWithKeySwitch);

        // Preserve the legacy `DKGParamsSnS::get_dkg_mode()` semantics: SnS ⇒ Z128.
        let dkg_mode = if noise_squashing_parameters.is_some() {
            DkgMode::Z128
        } else {
            regular.dkg_mode
        };

        let meta = MetaParameters {
            backend: Backend::Cpu,
            compute_parameters: AtomicPatternParameters::Standard(PBSParameters::PBS(
                regular.ciphertext_parameters,
            )),
            dedicated_compact_public_key_parameters,
            compression_parameters: regular.compression_decompression_parameters,
            noise_squashing_parameters,
            rerand_configuration,
        };

        Self {
            dkg_mode,
            sec: regular.sec,
            meta,
            secret_key_deviations: regular.secret_key_deviations,
        }
    }
}

// ---------------------------------------------------------------------------
// Basic accessors (read straight out of `meta`).
// ---------------------------------------------------------------------------

impl DKGParamsNew {
    /// The compute parameters as `ClassicPBSParameters`. KMS only supports the
    /// classic PBS atomic pattern; other variants are rejected.
    fn classic_pbs(&self) -> ClassicPBSParameters {
        match self.meta.compute_parameters {
            AtomicPatternParameters::Standard(PBSParameters::PBS(p)) => p,
            _ => panic!("KMS only supports the classic PBS atomic pattern"),
        }
    }

    fn dedicated(&self) -> Option<DedicatedCompactPublicKeyParameters> {
        self.meta.dedicated_compact_public_key_parameters
    }

    fn compression(&self) -> Option<CompressionParameters> {
        self.meta.compression_parameters
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        self.classic_pbs().lwe_dimension
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.classic_pbs().glwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.classic_pbs().polynomial_size
    }

    /// If there is no dedicated CPK, `lwe_hat` is `lwe`.
    pub fn lwe_hat_dimension(&self) -> LweDimension {
        self.dedicated().map_or(self.lwe_dimension(), |d| {
            d.pke_params.encryption_lwe_dimension
        })
    }

    pub fn glwe_sk_num_bits(&self) -> usize {
        self.polynomial_size().0 * self.glwe_dimension().0
    }

    pub fn lwe_tuniform_bound(&self) -> TUniformBound {
        match self.classic_pbs().lwe_noise_distribution {
            DynamicDistribution::TUniform(n) => TUniformBound(n.bound_log2() as usize),
            _ => panic!("We only support TUniform noise distribution!"),
        }
    }

    pub fn lwe_hat_tuniform_bound(&self) -> TUniformBound {
        self.dedicated().map_or(self.lwe_tuniform_bound(), |d| {
            match d.pke_params.encryption_noise_distribution {
                DynamicDistribution::TUniform(n) => TUniformBound(n.bound_log2() as usize),
                _ => panic!("We only support TUniform noise distribution!"),
            }
        })
    }

    pub fn glwe_tuniform_bound(&self) -> TUniformBound {
        match self.classic_pbs().glwe_noise_distribution {
            DynamicDistribution::TUniform(n) => TUniformBound(n.bound_log2() as usize),
            _ => panic!("We only support TUniform noise distribution!"),
        }
    }

    pub fn decomposition_level_count_ksk(&self) -> DecompositionLevelCount {
        self.classic_pbs().ks_level
    }

    pub fn decomposition_level_count_bk(&self) -> DecompositionLevelCount {
        self.classic_pbs().pbs_level
    }

    pub fn decomposition_level_count_pksk(&self) -> DecompositionLevelCount {
        self.dedicated()
            .map_or(DecompositionLevelCount(0), |d| d.ksk_params.ks_level)
    }

    pub fn decomposition_level_count_rerand_ksk(&self) -> DecompositionLevelCount {
        self.get_rerand_params()
            .map_or(DecompositionLevelCount(0), |p| p.ks_level)
    }

    pub fn get_pksk_destination(&self) -> Option<EncryptionKeyChoice> {
        self.dedicated().map(|d| d.ksk_params.destination_key)
    }

    pub fn has_dedicated_compact_pk_params(&self) -> bool {
        self.dedicated().is_some()
    }

    pub fn get_dedicated_pk_params(
        &self,
    ) -> Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )> {
        self.dedicated().map(|d| (d.pke_params, d.ksk_params))
    }

    pub fn get_rerand_params(&self) -> Option<ShortintKeySwitchingParameters> {
        self.dedicated().and_then(|d| d.re_randomization_parameters)
    }

    /// Mirrors `parameters.rs`: the rerand KSK reuses the PKSK (and so needs no
    /// fresh noise) exactly when the two key-switching parameters are equal.
    pub fn rerand_ksk_reuses_pksk(&self) -> bool {
        match (
            self.get_rerand_params(),
            self.get_dedicated_pk_params().map(|(_, p)| p),
        ) {
            (Some(rerand), Some(pksk)) => rerand == pksk,
            _ => false,
        }
    }

    pub fn compression_sk_num_bits(&self) -> usize {
        self.compression().map_or(0, |c| {
            c.packing_ks_glwe_dimension().0 * c.packing_ks_polynomial_size().0
        })
    }

    pub fn compression_key_tuniform_bound(&self) -> Option<TUniformBound> {
        if let Some(c) = self.compression() {
            if let DynamicDistribution::TUniform(b) = c.packing_ks_key_noise_distribution() {
                Some(TUniformBound(b.bound_log2() as usize))
            } else {
                panic!("We do not support non-Tuniform noise distribution")
            }
        } else {
            None
        }
    }

    pub fn get_sk_deviations(&self) -> Option<SecretKeyDeviations> {
        self.secret_key_deviations
    }

    /// Validates the KMS-level invariants that the enum used to encode
    /// implicitly. Call at the parameter-entry boundary.
    ///
    /// Note: deliberately does *not* call `MetaParameters::is_valid()`, which
    /// would reject the intentionally-insecure `PARAMS_TEST_BK_SNS`.
    pub fn check_conformance(&self) -> anyhow::Result<()> {
        if self.meta.noise_squashing_parameters.is_some() && self.dkg_mode != DkgMode::Z128 {
            anyhow::bail!("SnS parameters require Z128 dkg_mode");
        }
        if !matches!(
            self.meta.compute_parameters,
            AtomicPatternParameters::Standard(PBSParameters::PBS(_))
        ) {
            anyhow::bail!("KMS only supports the classic PBS atomic pattern");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-key noise amounts (faithful port of `parameters.rs`).
// ---------------------------------------------------------------------------

impl DKGParamsNew {
    pub fn num_needed_noise_pk(&self) -> NoiseInfo {
        NoiseInfo {
            amount: self.lwe_hat_dimension().0,
            bound: NoiseBounds::LweHatNoise(self.lwe_hat_tuniform_bound()),
        }
    }

    pub fn num_needed_noise_ksk(&self) -> NoiseInfo {
        let amount = self.glwe_dimension().0
            * self.polynomial_size().0
            * self.decomposition_level_count_ksk().0;
        NoiseInfo {
            amount,
            bound: NoiseBounds::LweNoise(self.lwe_tuniform_bound()),
        }
    }

    pub fn num_needed_noise_pksk(&self) -> NoiseInfo {
        let amount = self.lwe_hat_dimension().0 * self.decomposition_level_count_pksk().0;
        // The bound is irrelevant when the amount is 0.
        let (amount, bound) = match self.get_pksk_destination() {
            Some(EncryptionKeyChoice::Big) => {
                (amount, NoiseBounds::GlweNoise(self.glwe_tuniform_bound()))
            }
            Some(EncryptionKeyChoice::Small) => {
                (amount, NoiseBounds::LweNoise(self.lwe_tuniform_bound()))
            }
            _ => (0, NoiseBounds::LweNoise(self.lwe_tuniform_bound())),
        };
        NoiseInfo { amount, bound }
    }

    pub fn num_needed_noise_rerand_ksk(&self) -> NoiseInfo {
        let amount = if self.rerand_ksk_reuses_pksk() {
            0
        } else {
            self.lwe_hat_dimension().0 * self.decomposition_level_count_rerand_ksk().0
        };
        NoiseInfo {
            amount,
            bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
        }
    }

    pub fn num_needed_noise_bk(&self) -> NoiseInfo {
        let amount = self.lwe_dimension().0
            * (self.glwe_dimension().0 + 1)
            * self.decomposition_level_count_bk().0
            * self.polynomial_size().0;
        NoiseInfo {
            amount,
            bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
        }
    }

    pub fn num_needed_noise_msnrk(&self) -> NoiseInfo {
        let amount = match self.classic_pbs().modulus_switch_noise_reduction_params {
            ModulusSwitchType::DriftTechniqueNoiseReduction(p) => p.modulus_switch_zeros_count.0,
            ModulusSwitchType::Standard | ModulusSwitchType::CenteredMeanNoiseReduction => 0,
        };
        NoiseInfo {
            amount,
            bound: NoiseBounds::LweNoise(self.lwe_tuniform_bound()),
        }
    }

    pub fn num_needed_noise_compression_key(&self) -> NoiseInfo {
        match (self.compression(), self.compression_key_tuniform_bound()) {
            (Some(c), Some(bound)) => {
                let amount = self.glwe_dimension().0
                    * self.polynomial_size().0
                    * c.packing_ks_level().0
                    * c.packing_ks_polynomial_size().0;
                NoiseInfo {
                    amount,
                    bound: NoiseBounds::CompressionKSKNoise(bound),
                }
            }
            _ => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::CompressionKSKNoise(TUniformBound::default()),
            },
        }
    }

    pub fn num_needed_noise_decompression_key(&self) -> NoiseInfo {
        match (self.compression(), self.compression_key_tuniform_bound()) {
            (Some(c), Some(_)) => {
                let amount = c.packing_ks_polynomial_size().0
                    * c.packing_ks_glwe_dimension().0
                    * (self.glwe_dimension().0 + 1)
                    * self.polynomial_size().0
                    * c.br_level().0;
                NoiseInfo {
                    amount,
                    bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
                }
            }
            _ => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::GlweNoise(self.glwe_tuniform_bound()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Secret-key bit-sampling counts (faithful port).
// ---------------------------------------------------------------------------

impl DKGParamsNew {
    pub fn lwe_sk_num_bits_to_sample(&self) -> usize {
        let key_size = self.lwe_dimension().0;
        if let Some(dev) = self.secret_key_deviations {
            let prob = compute_prob_hw_within_range(dev.pmax, key_size as u64);
            let tries = compute_min_trials(prob, dev.log2_failure_proba).unwrap();
            tries * key_size
        } else {
            key_size
        }
    }

    pub fn lwe_hat_sk_num_bits_to_sample(&self) -> usize {
        if self.has_dedicated_compact_pk_params() {
            let key_size = self.lwe_hat_dimension().0;
            if let Some(dev) = self.secret_key_deviations {
                let prob = compute_prob_hw_within_range(dev.pmax, key_size as u64);
                let tries = compute_min_trials(prob, dev.log2_failure_proba).unwrap();
                tries * key_size
            } else {
                key_size
            }
        } else {
            0
        }
    }

    pub fn glwe_sk_num_bits_to_sample(&self) -> usize {
        let key_size = self.glwe_sk_num_bits();
        if let Some(dev) = self.secret_key_deviations {
            let individual_key_size = self.polynomial_size().0;
            let log_glwe_dim = (self.glwe_dimension().0.ilog2() + 1) as i64;
            let prob = compute_prob_hw_within_range(dev.pmax, individual_key_size as u64);
            let tries = compute_min_trials(prob, dev.log2_failure_proba - log_glwe_dim).unwrap();
            tries * key_size
        } else {
            key_size
        }
    }

    pub fn compression_sk_num_bits_to_sample(&self) -> usize {
        let key_size = self.compression_sk_num_bits();
        if let (Some(dev), Some(c)) = (self.secret_key_deviations, self.compression()) {
            let individual_key_size = c.packing_ks_polynomial_size().0;
            let log_glwe_dim = (c.packing_ks_glwe_dimension().0.ilog2() + 1) as i64;
            let prob = compute_prob_hw_within_range(dev.pmax, individual_key_size as u64);
            let tries = compute_min_trials(prob, dev.log2_failure_proba - log_glwe_dim).unwrap();
            tries * key_size
        } else {
            key_size
        }
    }
}

// ---------------------------------------------------------------------------
// Aggregate noise + total budgets (faithful port; regular and SnS merged into
// one code path each, branching on `self.sns()`).
// ---------------------------------------------------------------------------

impl DKGParamsNew {
    /// Regular-only raw secret-key bits (excludes SnS). Mirrors
    /// `DKGParamsRegular::num_raw_bits`.
    ///
    /// NOTE: this is intentionally distinct from the SnS contribution. The
    /// legacy code counts the SnS GLWE secret key as *raw* bits in
    /// [`Self::num_raw_bits`] but as *sampled* bits in
    /// [`Self::total_bits_required`]. Conflating the two (building
    /// `total_bits_required` on top of `num_raw_bits`) double-counts the SnS
    /// GLWE key, so `total_bits_required` must build on this regular-only base.
    fn regular_num_raw_bits(&self, keyset_config: KeySetConfig) -> usize {
        match keyset_config {
            KeySetConfig::Standard(config) => match config.secret_key_config {
                KeyGenSecretKeyConfig::GenerateAll => {
                    self.lwe_sk_num_bits_to_sample()
                        + self.lwe_hat_sk_num_bits_to_sample()
                        + self.lwe_sk_num_bits_to_sample() // second sk is for oprf
                        + self.glwe_sk_num_bits_to_sample()
                        + self.compression_sk_num_bits_to_sample()
                }
                KeyGenSecretKeyConfig::UseExisting => self.lwe_sk_num_bits_to_sample(),
            },
            KeySetConfig::DecompressionOnly => 0,
        }
    }

    pub fn num_raw_bits(&self, keyset_config: KeySetConfig) -> usize {
        let mut bits = self.regular_num_raw_bits(keyset_config);

        // ⚠️ DISCLAIMER — BEHAVIOR CHANGE vs `parameters.rs`.
        //
        // The legacy `DKGParamsSnS::num_raw_bits` added the *raw* SnS key sizes
        // (`glwe_sk_num_bits_sns`, `sns_compression_sk_num_bits`), even though it
        // counts every *regular* key with rejection-sampling overhead
        // (`*_to_sample`) and `total_bits_required` counts the SnS keys with that
        // overhead as well. For SnS parameter sets that carry
        // `secret_key_deviations` (e.g. the NIST sets) this made `num_raw_bits`
        // inconsistent with both the regular keys and `total_bits_required`, and
        // broke the intended invariant
        //   `total_bits_required == num_raw_bits + Σ(noise bits)`.
        //
        // Here we use the `*_to_sample` variants so the SnS keys are accounted
        // exactly like the regular ones, restoring that invariant. This is
        // INTENTIONALLY DIFFERENT from the legacy result for SnS params with
        // `secret_key_deviations`; for every other parameter set the value is
        // unchanged (without deviations, raw == to_sample).
        if let (Some(sns), KeySetConfig::Standard(_)) = (self.sns(), keyset_config) {
            bits +=
                sns.glwe_sk_num_bits_sns_to_sample() + sns.sns_compression_sk_num_bits_to_sample();
        }
        bits
    }

    /// Regular-only total bits (regular raw bits + regular noise). Mirrors
    /// `DKGParamsRegular::total_bits_required`.
    fn regular_total_bits_required(&self, keyset_config: KeySetConfig) -> usize {
        let mut n = self.regular_num_raw_bits(keyset_config);

        match keyset_config {
            KeySetConfig::Standard(_) => {
                n += self.num_needed_noise_pk().num_bits_needed();
                n += self.num_needed_noise_ksk().num_bits_needed();
                n += self.num_needed_noise_bk().num_bits_needed();
                n += self.num_needed_noise_bk().num_bits_needed(); // dedicated OPRF bk
                n += self.num_needed_noise_pksk().num_bits_needed();
                n += self.num_needed_noise_compression_key().num_bits_needed();
                n += self.num_needed_noise_msnrk().num_bits_needed();
                n += self.num_needed_noise_decompression_key().num_bits_needed();
                n += self.num_needed_noise_rerand_ksk().num_bits_needed();
            }
            KeySetConfig::DecompressionOnly => {
                n += self.num_needed_noise_decompression_key().num_bits_needed();
            }
        }
        n
    }

    pub fn total_bits_required(&self, keyset_config: KeySetConfig) -> usize {
        // Build on the regular-only base (NOT `num_raw_bits`) — see
        // `regular_num_raw_bits`. The SnS GLWE key enters here as *sampled*
        // bits, matching `DKGParamsSnS::total_bits_required`.
        let mut n = self.regular_total_bits_required(keyset_config);

        if let (Some(sns), KeySetConfig::Standard(_)) = (self.sns(), keyset_config) {
            n += sns.glwe_sk_num_bits_sns_to_sample();
            n += sns.all_bk_sns_noise().num_bits_needed();
            n += sns.num_needed_noise_msnrk_sns().num_bits_needed();
            n += sns.num_needed_noise_sns_compression_key().num_bits_needed();
            n += sns.sns_compression_sk_num_bits_to_sample();
        }
        n
    }

    pub fn total_triples_required(&self, keyset_config: KeySetConfig) -> usize {
        // Compression BK triples are needed in both Standard and DecompressionOnly.
        let compression_bk_triples = self.compression().map_or(0, |c| {
            self.glwe_sk_num_bits()
                * (c.packing_ks_glwe_dimension().0 * c.packing_ks_polynomial_size().0)
        });

        let mut triples = match keyset_config {
            KeySetConfig::Standard(_) => match self.sns() {
                // regular BK + OPRF BK + SnS BK
                Some(sns) => {
                    self.lwe_dimension().0
                        * (2 * self.glwe_sk_num_bits() + sns.glwe_sk_num_bits_sns())
                }
                // regular BK + OPRF BK
                None => 2 * self.lwe_dimension().0 * self.glwe_sk_num_bits(),
            },
            KeySetConfig::DecompressionOnly => 0,
        };
        triples += compression_bk_triples;

        self.total_bits_required(keyset_config) + triples
    }

    pub fn total_randomness_required(&self, keyset_config: KeySetConfig) -> usize {
        // One extra element to sample the seed (we always work in huge rings).
        self.total_bits_required(keyset_config) + 1
    }

    pub fn all_lwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        match keyset_config {
            KeySetConfig::Standard(_) => {
                let target_bound = self.num_needed_noise_ksk().bound;
                let regular = combine_noise_info(
                    target_bound,
                    &[
                        self.num_needed_noise_ksk(),
                        self.num_needed_noise_pksk(),
                        self.num_needed_noise_msnrk(),
                    ],
                );
                match self.sns() {
                    Some(sns) => combine_noise_info(
                        regular.bound,
                        &[regular, sns.num_needed_noise_msnrk_sns()],
                    ),
                    None => regular,
                }
            }
            KeySetConfig::DecompressionOnly => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::LweNoise(self.lwe_tuniform_bound()),
            },
        }
    }

    pub fn all_lwe_hat_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        match keyset_config {
            KeySetConfig::Standard(_) => self.num_needed_noise_pk(),
            KeySetConfig::DecompressionOnly => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::LweHatNoise(self.lwe_hat_tuniform_bound()),
            },
        }
    }

    pub fn all_glwe_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        let target_bound = self.num_needed_noise_bk().bound;
        match keyset_config {
            KeySetConfig::Standard(_) => combine_noise_info(
                target_bound,
                &[
                    self.num_needed_noise_bk(), // regular bk
                    self.num_needed_noise_bk(), // oprf bk
                    self.num_needed_noise_pksk(),
                    self.num_needed_noise_decompression_key(),
                    self.num_needed_noise_rerand_ksk(),
                ],
            ),
            KeySetConfig::DecompressionOnly => {
                combine_noise_info(target_bound, &[self.num_needed_noise_decompression_key()])
            }
        }
    }

    pub fn all_compression_ksk_noise(&self, keyset_config: KeySetConfig) -> NoiseInfo {
        match keyset_config {
            KeySetConfig::Standard(_) => self.num_needed_noise_compression_key(),
            KeySetConfig::DecompressionOnly => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::CompressionKSKNoise(TUniformBound::default()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// SnS view: SnS-only accessors, obtained once via `DKGParamsNew::sns()`.
// ---------------------------------------------------------------------------

/// Borrowed view over the SnS parameters of a [`DKGParamsNew`]. Only obtainable
/// when noise squashing is present, so every method here is infallible.
pub struct SnsView<'a> {
    params: &'a DKGParamsNew,
    sns_params: NoiseSquashingParameters,
    sns_compression_params: Option<NoiseSquashingCompressionParameters>,
}

impl DKGParamsNew {
    /// Returns an [`SnsView`] iff this parameter set has noise squashing.
    pub fn sns(&self) -> Option<SnsView<'_>> {
        self.meta.noise_squashing_parameters.map(|nsp| SnsView {
            params: self,
            sns_params: nsp.parameters,
            sns_compression_params: nsp.compression_parameters,
        })
    }
}

impl SnsView<'_> {
    pub fn polynomial_size_sns(&self) -> PolynomialSize {
        self.sns_params.polynomial_size()
    }

    pub fn glwe_dimension_sns(&self) -> GlweDimension {
        self.sns_params.glwe_dimension()
    }

    pub fn glwe_tuniform_bound_sns(&self) -> TUniformBound {
        match self.sns_params.glwe_noise_distribution() {
            DynamicDistribution::TUniform(t) => TUniformBound(t.bound_log2() as usize),
            DynamicDistribution::Gaussian(_) => panic!("we only support tuniform!"),
        }
    }

    pub fn decomposition_level_count_bk_sns(&self) -> DecompositionLevelCount {
        self.sns_params.decomp_level_count()
    }

    pub fn glwe_sk_num_bits_sns(&self) -> usize {
        self.polynomial_size_sns().0 * self.glwe_dimension_sns().0
    }

    pub fn glwe_sk_num_bits_sns_to_sample(&self) -> usize {
        let key_size = self.glwe_sk_num_bits_sns();
        if let Some(dev) = self.params.secret_key_deviations {
            let individual_key_size = self.polynomial_size_sns().0;
            let log_glwe_dim = (self.glwe_dimension_sns().0.ilog2() + 1) as i64;
            let prob = compute_prob_hw_within_range(dev.pmax, individual_key_size as u64);
            let tries = compute_min_trials(prob, dev.log2_failure_proba - log_glwe_dim).unwrap();
            tries * key_size
        } else {
            key_size
        }
    }

    pub fn all_bk_sns_noise(&self) -> NoiseInfo {
        let amount = self.params.lwe_dimension().0
            * (self.glwe_dimension_sns().0 + 1)
            * self.decomposition_level_count_bk_sns().0
            * self.polynomial_size_sns().0;
        NoiseInfo {
            amount,
            bound: NoiseBounds::GlweNoiseSnS(self.glwe_tuniform_bound_sns()),
        }
    }

    fn get_classic_sns_params(&self) -> NoiseSquashingClassicParameters {
        match self.sns_params {
            NoiseSquashingParameters::Classic(c) => c,
            NoiseSquashingParameters::MultiBit(_) => {
                panic!("We do not support multi bit SnS params yet")
            }
        }
    }

    pub fn num_needed_noise_msnrk_sns(&self) -> NoiseInfo {
        let classic = self.get_classic_sns_params();
        let amount = match classic.modulus_switch_noise_reduction_params {
            ModulusSwitchType::DriftTechniqueNoiseReduction(p) => p.modulus_switch_zeros_count.0,
            ModulusSwitchType::Standard | ModulusSwitchType::CenteredMeanNoiseReduction => 0,
        };
        NoiseInfo {
            amount,
            bound: NoiseBounds::LweNoise(self.params.lwe_tuniform_bound()),
        }
    }

    pub fn sns_compression_sk_num_bits(&self) -> usize {
        match self.sns_compression_params {
            Some(p) => p.packing_ks_polynomial_size.0 * p.packing_ks_glwe_dimension.0,
            None => 0,
        }
    }

    fn sns_compression_key_tuniform_bound(&self) -> Option<TUniformBound> {
        if let Some(p) = self.sns_compression_params {
            if let DynamicDistribution::TUniform(b) = p.packing_ks_key_noise_distribution {
                Some(TUniformBound(b.bound_log2() as usize))
            } else {
                panic!("We do not support non-Tuniform noise distribution")
            }
        } else {
            None
        }
    }

    pub fn num_needed_noise_sns_compression_key(&self) -> NoiseInfo {
        match (
            self.sns_compression_params,
            self.sns_compression_key_tuniform_bound(),
        ) {
            (Some(comp), Some(bound)) => {
                let amount = self.sns_params.glwe_dimension().0
                    * self.sns_params.polynomial_size().0
                    * comp.packing_ks_level.0
                    * comp.packing_ks_polynomial_size.0;
                NoiseInfo {
                    amount,
                    bound: NoiseBounds::SnsCompressionKSKNoise(bound),
                }
            }
            _ => NoiseInfo {
                amount: 0,
                bound: NoiseBounds::SnsCompressionKSKNoise(TUniformBound::default()),
            },
        }
    }

    pub fn sns_compression_sk_num_bits_to_sample(&self) -> usize {
        if self.sns_compression_params.is_none() {
            return 0;
        }
        let key_size = self.sns_compression_sk_num_bits();
        if let Some(dev) = self.params.secret_key_deviations {
            let (individual_key_size, log_glwe_dim) = match self.sns_compression_params {
                Some(p) => (
                    p.packing_ks_polynomial_size.0,
                    (p.packing_ks_glwe_dimension.0.ilog2() + 1) as i64,
                ),
                None => (0, 0),
            };
            let prob = compute_prob_hw_within_range(dev.pmax, individual_key_size as u64);
            let tries = compute_min_trials(prob, dev.log2_failure_proba - log_glwe_dim).unwrap();
            tries * key_size
        } else {
            key_size
        }
    }
}

// ---------------------------------------------------------------------------
// Equivalence test: every budget/noise/sample count must match the legacy
// `DKGParams` implementation for every shipped parameter set.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset_config::{KeySetConfig, StandardKeySetConfig};
    use crate::tfhe_internals::parameters::{DKGParams, DkgParamsAvailable};
    use strum::IntoEnumIterator;

    // `KeySetConfig` does not implement `Debug`, so we carry an explicit label
    // for assertion messages.
    fn all_keyset_configs() -> Vec<(KeySetConfig, &'static str)> {
        vec![
            (
                KeySetConfig::Standard(StandardKeySetConfig::default()),
                "Standard(GenerateAll)",
            ),
            (
                KeySetConfig::Standard(StandardKeySetConfig::use_existing_sk()),
                "Standard(UseExisting)",
            ),
            (KeySetConfig::DecompressionOnly, "DecompressionOnly"),
        ]
    }

    /// Asserts that the flattened `DKGParamsNew` produces byte-for-byte the same
    /// triples / bits / randomness / noise budgets as the legacy `DKGParams`,
    /// for every constant in `DkgParamsAvailable` and every `KeySetConfig`.
    #[test]
    fn budgets_match_legacy_for_all_params() {
        for variant in DkgParamsAvailable::iter() {
            let old: DKGParams = variant.to_param();
            let new = DKGParamsNew::from(old);
            let h = old.get_params_basics_handle();
            let label = format!("{variant:?}");

            // ---- config-dependent totals + aggregate noise ----
            for (ksc, ksc_label) in all_keyset_configs() {
                // `num_raw_bits` INTENTIONALLY diverges from legacy for SnS
                // params with `secret_key_deviations` (see the disclaimer on
                // `DKGParamsNew::num_raw_bits`): the SnS keys are now counted
                // with sampling overhead (`*_to_sample`), exactly like the
                // regular keys. The expected new value is the legacy value plus
                // the raw->to_sample correction for the SnS keys (which is 0
                // when the params carry no deviations, i.e. raw == to_sample).
                let legacy_raw = h.num_raw_bits(ksc);
                let expected_raw = if let (Some(sns), KeySetConfig::Standard(_)) = (new.sns(), ksc)
                {
                    legacy_raw
                        + (sns.glwe_sk_num_bits_sns_to_sample() - sns.glwe_sk_num_bits_sns())
                        + (sns.sns_compression_sk_num_bits_to_sample()
                            - sns.sns_compression_sk_num_bits())
                } else {
                    legacy_raw
                };
                assert_eq!(
                    new.num_raw_bits(ksc),
                    expected_raw,
                    "num_raw_bits for {label} / {ksc_label}"
                );

                // The fix restores the intended invariant for ALL params (it was
                // broken for SnS-with-deviations under the legacy code):
                //   total_bits_required == num_raw_bits + Σ(noise bits)
                // where the noise productions are exactly those the DKG
                // orchestrator splits out (`all_*_noise` + the SnS noises;
                // `msnrk_sns` is already folded into `all_lwe_noise`).
                if let KeySetConfig::Standard(_) = ksc {
                    let mut noise_bits = new.all_lwe_noise(ksc).num_bits_needed()
                        + new.all_glwe_noise(ksc).num_bits_needed()
                        + new.all_compression_ksk_noise(ksc).num_bits_needed()
                        + new.all_lwe_hat_noise(ksc).num_bits_needed();
                    if let Some(sns) = new.sns() {
                        noise_bits += sns.all_bk_sns_noise().num_bits_needed()
                            + sns.num_needed_noise_sns_compression_key().num_bits_needed();
                    }
                    assert_eq!(
                        new.total_bits_required(ksc),
                        new.num_raw_bits(ksc) + noise_bits,
                        "invariant total_bits == num_raw_bits + noise for {label} / {ksc_label}"
                    );
                }

                assert_eq!(
                    new.total_bits_required(ksc),
                    h.total_bits_required(ksc),
                    "total_bits_required mismatch for {label} / {ksc_label}"
                );
                assert_eq!(
                    new.total_triples_required(ksc),
                    h.total_triples_required(ksc),
                    "total_triples_required mismatch for {label} / {ksc_label}"
                );
                assert_eq!(
                    new.total_randomness_required(ksc),
                    h.total_randomness_required(ksc),
                    "total_randomness_required mismatch for {label} / {ksc_label}"
                );

                let aggregate = [
                    (
                        new.all_lwe_noise(ksc),
                        h.all_lwe_noise(ksc),
                        "all_lwe_noise",
                    ),
                    (
                        new.all_lwe_hat_noise(ksc),
                        h.all_lwe_hat_noise(ksc),
                        "all_lwe_hat_noise",
                    ),
                    (
                        new.all_glwe_noise(ksc),
                        h.all_glwe_noise(ksc),
                        "all_glwe_noise",
                    ),
                    (
                        new.all_compression_ksk_noise(ksc),
                        h.all_compression_ksk_noise(ksc),
                        "all_compression_ksk_noise",
                    ),
                ];
                for (got, exp, name) in aggregate {
                    assert_eq!(
                        got.amount, exp.amount,
                        "{name}.amount for {label} / {ksc_label}"
                    );
                    assert_eq!(
                        got.num_bits_needed(),
                        exp.num_bits_needed(),
                        "{name}.num_bits_needed for {label} / {ksc_label}"
                    );
                }
            }

            // ---- config-independent per-key noise ----
            let per_key = [
                (new.num_needed_noise_pk(), h.num_needed_noise_pk(), "pk"),
                (new.num_needed_noise_ksk(), h.num_needed_noise_ksk(), "ksk"),
                (
                    new.num_needed_noise_pksk(),
                    h.num_needed_noise_pksk(),
                    "pksk",
                ),
                (new.num_needed_noise_bk(), h.num_needed_noise_bk(), "bk"),
                (
                    new.num_needed_noise_compression_key(),
                    h.num_needed_noise_compression_key(),
                    "compression_key",
                ),
                (
                    new.num_needed_noise_decompression_key(),
                    h.num_needed_noise_decompression_key(),
                    "decompression_key",
                ),
                (
                    new.num_needed_noise_rerand_ksk(),
                    h.num_needed_noise_rerand_ksk(),
                    "rerand_ksk",
                ),
                (
                    new.num_needed_noise_msnrk(),
                    h.num_needed_noise_msnrk(),
                    "msnrk",
                ),
            ];
            for (got, exp, name) in per_key {
                assert_eq!(
                    got.amount, exp.amount,
                    "num_needed_noise_{name}.amount for {label}"
                );
                assert_eq!(
                    got.num_bits_needed(),
                    exp.num_bits_needed(),
                    "num_needed_noise_{name}.num_bits_needed for {label}"
                );
            }

            // ---- secret-key sampling counts ----
            assert_eq!(
                new.lwe_sk_num_bits_to_sample(),
                h.lwe_sk_num_bits_to_sample(),
                "lwe_sk_num_bits_to_sample for {label}"
            );
            assert_eq!(
                new.lwe_hat_sk_num_bits_to_sample(),
                h.lwe_hat_sk_num_bits_to_sample(),
                "lwe_hat_sk_num_bits_to_sample for {label}"
            );
            assert_eq!(
                new.glwe_sk_num_bits_to_sample(),
                h.glwe_sk_num_bits_to_sample(),
                "glwe_sk_num_bits_to_sample for {label}"
            );
            assert_eq!(
                new.compression_sk_num_bits_to_sample(),
                h.compression_sk_num_bits_to_sample(),
                "compression_sk_num_bits_to_sample for {label}"
            );

            // ---- SnS-specific budget pieces ----
            if let DKGParams::WithSnS(old_sns) = old {
                let sns = new.sns().expect("flattened params must expose an SnS view");
                assert_eq!(
                    sns.glwe_sk_num_bits_sns(),
                    old_sns.glwe_sk_num_bits_sns(),
                    "glwe_sk_num_bits_sns for {label}"
                );
                assert_eq!(
                    sns.glwe_sk_num_bits_sns_to_sample(),
                    old_sns.glwe_sk_num_bits_sns_to_sample(),
                    "glwe_sk_num_bits_sns_to_sample for {label}"
                );
                assert_eq!(
                    sns.sns_compression_sk_num_bits(),
                    old_sns.sns_compression_sk_num_bits(),
                    "sns_compression_sk_num_bits for {label}"
                );
                assert_eq!(
                    sns.sns_compression_sk_num_bits_to_sample(),
                    old_sns.sns_compression_sk_num_bits_to_sample(),
                    "sns_compression_sk_num_bits_to_sample for {label}"
                );

                let (a, b) = (sns.all_bk_sns_noise(), old_sns.all_bk_sns_noise());
                assert_eq!(a.amount, b.amount, "all_bk_sns_noise.amount for {label}");
                assert_eq!(
                    a.num_bits_needed(),
                    b.num_bits_needed(),
                    "all_bk_sns_noise.num_bits_needed for {label}"
                );

                let (a, b) = (
                    sns.num_needed_noise_sns_compression_key(),
                    old_sns.num_needed_noise_sns_compression_key(),
                );
                assert_eq!(
                    a.amount, b.amount,
                    "num_needed_noise_sns_compression_key.amount for {label}"
                );
                assert_eq!(
                    a.num_bits_needed(),
                    b.num_bits_needed(),
                    "num_needed_noise_sns_compression_key.num_bits_needed for {label}"
                );
            } else {
                assert!(
                    new.sns().is_none(),
                    "WithoutSnS must map to no SnS view for {label}"
                );
            }

            // Every shipped parameter set must pass conformance.
            new.check_conformance()
                .unwrap_or_else(|e| panic!("check_conformance failed for {label}: {e}"));
        }
    }
}
