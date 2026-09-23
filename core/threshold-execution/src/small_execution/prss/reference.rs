//! Temporary benchmark reference from a3c86dbcb: preserve the original storage and compute paths.
//! Do not adapt this layout to SessionPrfs; it is the control for measuring that refactor.
use super::*;
use crate::small_execution::prf::psi_pair;
#[derive(Debug, Clone)]
pub(crate) struct PrfAes {
    phi_aes: PhiAes,
    psi_aes: PsiAes,
    chi_aes: ChiAes,
}

/// PRSS state for use within a given session.
/// Secure implementation of the [`PRSSPrimitives`] trait.
#[derive(Debug, Clone)]
pub struct ReferencePrssState<Z: Default + Clone + Serialize, B: Broadcast> {
    /// set of counters that increases on every call to the respective .next()
    pub(crate) counters: PRSSCounters,
    /// PRSSSetup
    pub(crate) prss_setup: PRSSSetup<Z>,
    /// the initialized PRFs for each set
    pub(crate) prfs: Arc<Vec<PrfAes>>,
    pub(crate) broadcast: B,
}

impl<Z: Default + Clone + Serialize, B: Broadcast> ProtocolDescription
    for ReferencePrssState<Z, B>
{
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        // Using a fat arrow here to indicate that this is a byproduct of Setup
        format!(
            "{}=>ReferencePrssState:\n{}",
            indent,
            B::protocol_desc(depth + 1)
        )
    }
}

/// Alias for [`ReferencePrssState`] with a secure implementation of [`Broadcast`]
pub type SecureReferencePrssState<Z> = ReferencePrssState<Z, SyncReliableBroadcast>;
// Exploration reference: preserve the original implementation for direct output
// comparisons and adjacent Criterion cases. This is not another protocol primitive.
#[cfg(any(test, feature = "testing"))]
impl<Z, B> ReferencePrssState<Z, B>
where
    Z: RingWithExceptionalSequence + Invert + PRSSConversions,
    B: Broadcast,
{
    /// PRSS.Next() for a single party
    ///
    /// __NOTE__: telemetry is done at the caller because this function isn't batched
    /// and we want to avoid creating too many telemetry spans
    #[instrument(name="PRSS.Next",skip_all,fields(batch_size=?amount))]
    pub async fn prss_next_vec_orig(
        &mut self,
        party_role: Role,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        //Cheap to clone as everything is an Arc or atomic types
        let prfs = self.prfs.clone();
        let prss_setup = self.prss_setup.clone();
        let prss_ctr = self.counters.prss_ctr;

        // Independent per-counter elements, assembled in parallel. Element `idx`
        // uses `ctr = prss_ctr + idx`.
        let res = spawn_compute_bound(move || -> anyhow::Result<Vec<Z>> {
            if amount == 0 {
                return Ok(Vec::new());
            }

            // Per-set invariants (membership, PRF key, f_A), computed once instead of per element.
            let mut set_data: Vec<(&PrfAes, Z)> = Vec::with_capacity(prss_setup.sets.len());
            for (i, set) in prss_setup.sets.iter().enumerate() {
                if !set.parties.contains(&party_role) {
                    return Err(anyhow_error_and_log(format!(
                        "Called prss.next() with party role {party_role} that is not in a precomputed set of parties!"
                    )));
                }
                let aes_prf = prfs.get(i).ok_or_else(|| {
                    anyhow_error_and_log("PRFs not properly initialized!".to_string())
                })?;
                // f_A(alpha_i): the embedded party ID indexes into f_a_points (from zero)
                set_data.push((aes_prf, set.f_a_points[&party_role]));
            }

            (0..amount)
                .into_par_iter()
                .with_min_len(*crate::constants::PRSS_GEN_PAR_MIN_CHUNK)
                .map(|idx| {
                    let ctr = prss_ctr + idx as u128;
                    let mut res = Z::ZERO;
                    for &(aes_prf, f_a) in &set_data {
                        let psi = psi(&aes_prf.psi_aes, ctr)?;
                        res += f_a * psi;
                    }
                    Ok(res)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .instrument(tracing::Span::current())
        .await??;

        self.counters.prss_ctr += amount as u128;

        Ok(res)
    }

    /// Exploration control: the original scalar traversal with iterator-based PRF conversion.
    /// Keep this copy beside `_orig` so the experiment changes only the PRF call.
    /// Submission, Rayon splitting, accumulation, collection, and counter updates match it.
    #[instrument(name="PRSS.Next",skip_all,fields(batch_size=?amount))]
    pub async fn prss_next_vec_iter(
        &mut self,
        party_role: Role,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        //Cheap to clone as everything is an Arc or atomic types
        let prfs = self.prfs.clone();
        let prss_setup = self.prss_setup.clone();
        let prss_ctr = self.counters.prss_ctr;

        // Independent per-counter elements, assembled in parallel. Element `idx`
        // uses `ctr = prss_ctr + idx`.
        let res = spawn_compute_bound(move || -> anyhow::Result<Vec<Z>> {
            if amount == 0 {
                return Ok(Vec::new());
            }

            // Per-set invariants (membership, PRF key, f_A), computed once instead of per element.
            let mut set_data: Vec<(&PrfAes, Z)> = Vec::with_capacity(prss_setup.sets.len());
            for (i, set) in prss_setup.sets.iter().enumerate() {
                if !set.parties.contains(&party_role) {
                    return Err(anyhow_error_and_log(format!(
                        "Called prss.next() with party role {party_role} that is not in a precomputed set of parties!"
                    )));
                }
                let aes_prf = prfs.get(i).ok_or_else(|| {
                    anyhow_error_and_log("PRFs not properly initialized!".to_string())
                })?;
                // f_A(alpha_i): the embedded party ID indexes into f_a_points (from zero)
                set_data.push((aes_prf, set.f_a_points[&party_role]));
            }

            (0..amount)
                .into_par_iter()
                .with_min_len(*crate::constants::PRSS_GEN_PAR_MIN_CHUNK)
                .map(|idx| {
                    let ctr = prss_ctr + idx as u128;
                    let mut res = Z::ZERO;
                    for &(aes_prf, f_a) in &set_data {
                        let psi = crate::small_execution::prf::psi_iter(&aes_prf.psi_aes, ctr)?;
                        res += f_a * psi;
                    }
                    Ok(res)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .instrument(tracing::Span::current())
        .await??;

        self.counters.prss_ctr += amount as u128;

        Ok(res)
    }

    /// Compares const-sized PRF counter groups inside the original compute submission.
    /// Each output keeps the original subset order and counter encoding.
    /// Short final groups use scalar PRFs; counters commit only after the request succeeds.
    #[instrument(name="PRSS.Next",skip_all,fields(batch_size=?amount))]
    pub async fn prss_next_vec_grouped<const COUNTERS: usize>(
        &mut self,
        party_role: Role,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        assert!(
            COUNTERS > 0,
            "a PRSS group must contain at least one counter"
        );
        //Cheap to clone as everything is an Arc or atomic types
        let prfs = self.prfs.clone();
        let prss_setup = self.prss_setup.clone();
        let prss_ctr = self.counters.prss_ctr;

        // Keep one compute submission and the original per-request subset table.
        let res = spawn_compute_bound(move || -> anyhow::Result<Vec<Z>> {
            if amount == 0 {
                return Ok(Vec::new());
            }

            // Per-set invariants (membership, PRF key, f_A), computed once instead of per element.
            let mut set_data: Vec<(&PrfAes, Z)> = Vec::with_capacity(prss_setup.sets.len());
            for (i, set) in prss_setup.sets.iter().enumerate() {
                if !set.parties.contains(&party_role) {
                    return Err(anyhow_error_and_log(format!(
                        "Called prss.next() with party role {party_role} that is not in a precomputed set of parties!"
                    )));
                }
                let aes_prf = prfs.get(i).ok_or_else(|| {
                    anyhow_error_and_log("PRFs not properly initialized!".to_string())
                })?;
                // f_A(alpha_i): the embedded party ID indexes into f_a_points (from zero)
                set_data.push((aes_prf, set.f_a_points[&party_role]));
            }

            let groups = amount.div_ceil(COUNTERS);
            // Rayon counts groups here, so convert the minimum back from output
            // values. Rounding can move task boundaries by less than one group.
            let min_groups = (*crate::constants::PRSS_GEN_PAR_MIN_CHUNK).div_ceil(COUNTERS);
            (0..groups)
                .into_par_iter()
                .with_min_len(min_groups)
                .flat_map_iter(|group| {
                    let idx = group * COUNTERS;
                    let count = (amount - idx).min(COUNTERS);
                    let ctr = prss_ctr + idx as u128;
                    let result = (|| -> anyhow::Result<[Z; COUNTERS]> {
                        let mut sums = [Z::ZERO; COUNTERS];
                        for &(aes_prf, f_a) in &set_data {
                            if count == COUNTERS {
                                let random = crate::small_execution::prf::psi_counters::<Z, COUNTERS>(&aes_prf.psi_aes, ctr)?;
                                for (sum, random) in sums.iter_mut().zip(random) {
                                    *sum += f_a * random;
                                }
                            } else {
                                // Only the last group can be short. Evaluate its
                                // actual counters individually: padding could cross
                                // the counter limit and would add unused AES work.
                                for (offset, sum) in sums[..count].iter_mut().enumerate() {
                                    *sum += f_a * crate::small_execution::prf::psi_iter(&aes_prf.psi_aes, ctr + offset as u128)?;
                                }
                            }
                        }
                        Ok(sums)
                    })();
                    // Yield the group's outputs or one error without allocating
                    // a Vec per group. The final collector retains output order.
                    let (values, error) = match result {
                        Ok(sums) => (Some(sums), None),
                        Err(error) => (None, Some(error)),
                    };
                    values.into_iter().flatten().take(count).map(Ok).chain(error.map(Err))
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .instrument(tracing::Span::current())
        .await??;

        self.counters.prss_ctr += amount as u128;
        Ok(res)
    }

    /// PRSS.Next() for a single party
    ///
    /// __NOTE__: telemetry is done at the caller to avoid creating too many telemetry spans.
    ///
    /// E2 exploration: encrypt counter pairs inside the request. This is unrelated
    /// to splitting a request into separately awaited compute submissions.
    #[instrument(name="PRSS.Next",skip_all,fields(batch_size=?amount))]
    pub async fn prss_next_vec_pair(
        &mut self,
        party_role: Role,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        //Cheap to clone as everything is an Arc or atomic types
        let prfs = self.prfs.clone();
        let prss_setup = self.prss_setup.clone();
        let prss_ctr = self.counters.prss_ctr;

        // One compute submission for the entire request, as before. AES pairs live
        // inside it; this does not add awaited submissions or change the counter
        // commit point after the complete vector succeeds.
        let res = spawn_compute_bound(move || -> anyhow::Result<Vec<Z>> {
            if amount == 0 {
                return Ok(Vec::new());
            }

            // Per-set invariants (membership, PRF key, f_A), computed once instead of per element.
            let mut set_data: Vec<(&PrfAes, Z)> = Vec::with_capacity(prss_setup.sets.len());
            for (i, set) in prss_setup.sets.iter().enumerate() {
                if !set.parties.contains(&party_role) {
                    return Err(anyhow_error_and_log(format!(
                        "Called prss.next() with party role {party_role} that is not in a precomputed set of parties!"
                    )));
                }
                let aes_prf = prfs.get(i).ok_or_else(|| {
                    anyhow_error_and_log("PRFs not properly initialized!".to_string())
                })?;
                // f_A(alpha_i): the embedded party ID indexes into f_a_points (from zero)
                set_data.push((aes_prf, set.f_a_points[&party_role]));
            }

            // E2 starts with pairs, not a request-wide buffer of PRF results.
            // The traversal becomes pair -> subset -> the two output counters.
            // Each subset key encrypts both counters together; each output still
            // accumulates exactly the same terms in the same subset order.
            const COUNTERS_PER_GROUP: usize = 2;
            let groups = amount.div_ceil(COUNTERS_PER_GROUP);

            // Rayon now counts pairs. Keep its minimum expressed in output values:
            // the default 1024 values becomes 512 pairs, not 1024 pairs.
            // This keeps splitting comparable; it does not promise identical task
            // boundaries for every request length or environment override.
            let min_groups = (*crate::constants::PRSS_GEN_PAR_MIN_CHUNK)
                .div_ceil(COUNTERS_PER_GROUP);
            (0..groups)
                .into_par_iter()
                .with_min_len(min_groups)
                .flat_map_iter(|group| {
                    let idx = group * COUNTERS_PER_GROUP;
                    let count = (amount - idx).min(COUNTERS_PER_GROUP);
                    let ctr = prss_ctr + idx as u128;
                    let result = (|| -> anyhow::Result<[Z; 2]> {
                        let mut sums = [Z::ZERO; 2];
                        for &(aes_prf, f_a) in &set_data {
                            if count == 2 {
                                let random = psi_pair(&aes_prf.psi_aes, ctr)?;
                                sums[0] += f_a * random[0];
                                sums[1] += f_a * random[1];
                            } else {
                                // Do not pad an odd request by evaluating an unused
                                // counter: it could lie beyond psi's valid range.
                                sums[0] += f_a * psi(&aes_prf.psi_aes, ctr)?;
                            }
                        }
                        Ok(sums)
                    })();

                    // Flatten the stack array into the existing fallible collector.
                    // This adapter adds no Vec per pair and no second full-output copy.
                    // An error yields one Err; a short final pair yields one value.
                    // Parallel collection preserves the pair/counter output order.
                    let values = match result {
                        Ok([first, second]) => [Some(Ok(first)), (count == 2).then_some(Ok(second))],
                        Err(error) => [Some(Err(error)), None],
                    };
                    values.into_iter().flatten()
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .instrument(tracing::Span::current())
        .await??;

        self.counters.prss_ctr += amount as u128;

        Ok(res)
    }
}
#[async_trait]
impl<Z, B> PRSSPrimitives<Z> for ReferencePrssState<Z, B>
where
    Z: RingWithExceptionalSequence,
    Z: Invert,
    Z: PRSSConversions,
    B: Broadcast,
{
    /// PRSS-Mask.Next() for a single party
    ///
    /// __NOTE__ : using [`STATSEC`] const.
    ///
    /// __NOTE__ : The output share is not uniformly random,
    /// and this method will panic if executed for Z an extension of Z64.
    #[instrument(name="Mask.Next",skip_all,fields(batch_size=?amount))]

    async fn mask_next_vec(
        &mut self,
        party_role: Role,
        bd: u128,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        let bd1 = bd << STATSEC;

        //Cheap to clone as everything is an Arc or atomic types
        let prfs = self.prfs.clone();
        let prss_setup = self.prss_setup.clone();
        let mask_ctr = self.counters.mask_ctr;

        // Element `idx` is the f_A-weighted sum over all sets of
        // phi(mask_ctr+2*idx) + phi(mask_ctr+2*idx+1). This matches repeated
        // scalar calls while still batching each chunk's AES-PRF evaluations.
        let res = spawn_compute_bound(move || -> anyhow::Result<Vec<Z>> {
            let chunk = (*crate::constants::PRSS_GEN_PAR_MIN_CHUNK).max(1);
            let mut res = vec![Z::ZERO; amount];
            res.par_chunks_mut(chunk)
                .enumerate()
                .try_for_each(|(chunk_idx, out)| -> anyhow::Result<()> {
                    let lo = chunk_idx * chunk;
                    for (i, set) in prss_setup.sets.iter().enumerate() {
                        if !set.parties.contains(&party_role) {
                            return Err(anyhow_error_and_log(format!(
                                "Called prss.mask_next() with party role {party_role} that is not in a precomputed set of parties!"
                            )));
                        }
                        let aes_prf = prfs.get(i).ok_or_else(|| {
                            anyhow_error_and_log("PRFs not properly initialized!".to_string())
                        })?;
                        // compute f_A(alpha_i): the embedded party ID indexes into f_a_points (from zero)
                        let f_a = set.f_a_points[&party_role];

                        // One pipelined AES call for the chunk's counter range. Element `idx`
                        // consumes two distinct phi counters, matching one scalar mask_next().
                        let phi_vals = phi_range(
                            &aes_prf.phi_aes,
                            mask_ctr + 2 * lo as u128,
                            2 * out.len(),
                            bd1,
                        )?;

                        for (j, out_elem) in out.iter_mut().enumerate() {
                            let phi = phi_vals[2 * j] + phi_vals[2 * j + 1];
                            // mul_by_i128 scales by the signed scalar via from_i128, so it is a
                            // cheap coefficient scale for ResiduePoly yet still correct for base
                            // rings whose modulus does not divide 2^128 (e.g. the BGV prime
                            // modulus). Do NOT use mul_by_u128(phi as u128): that mis-reduces
                            // negative phi on such rings (the wrong large mask would wrap mod q and
                            // corrupt the decrypted plaintext).
                            *out_elem += f_a.mul_by_i128(phi);
                        }
                    }
                    Ok(())
                })?;
            Ok(res)
        })
        .instrument(tracing::Span::current())
        .await??;

        // Advance the counter by two per element, matching one mask_next() call per
        // element (each consumes two phi counters).
        self.counters.mask_ctr += 2 * (amount as u128);

        Ok(res)
    }

    /// PRSS.Next() for a single party
    ///
    /// __NOTE__: telemetry is done at the caller because this function isn't batched
    /// and we want to avoid creating too many telemetry spans
    #[instrument(name="PRSS.Next",skip_all,fields(batch_size=?amount))]
    async fn prss_next_vec(&mut self, party_role: Role, amount: usize) -> anyhow::Result<Vec<Z>> {
        //Cheap to clone as everything is an Arc or atomic types
        let prfs = self.prfs.clone();
        let prss_setup = self.prss_setup.clone();
        let prss_ctr = self.counters.prss_ctr;

        // Independent per-counter elements, assembled in parallel. Element `idx`
        // uses `ctr = prss_ctr + idx`.
        let res = spawn_compute_bound(move || -> anyhow::Result<Vec<Z>> {
            if amount == 0 {
                return Ok(Vec::new());
            }

            // Per-set invariants (membership, PRF key, f_A), computed once instead of per element.
            let mut set_data: Vec<(&PrfAes, Z)> = Vec::with_capacity(prss_setup.sets.len());
            for (i, set) in prss_setup.sets.iter().enumerate() {
                if !set.parties.contains(&party_role) {
                    return Err(anyhow_error_and_log(format!(
                        "Called prss.next() with party role {party_role} that is not in a precomputed set of parties!"
                    )));
                }
                let aes_prf = prfs.get(i).ok_or_else(|| {
                    anyhow_error_and_log("PRFs not properly initialized!".to_string())
                })?;
                // f_A(alpha_i): the embedded party ID indexes into f_a_points (from zero)
                set_data.push((aes_prf, set.f_a_points[&party_role]));
            }

            (0..amount)
                .into_par_iter()
                .with_min_len(*crate::constants::PRSS_GEN_PAR_MIN_CHUNK)
                .map(|idx| {
                    let ctr = prss_ctr + idx as u128;
                    let mut res = Z::ZERO;
                    for &(aes_prf, f_a) in &set_data {
                        let psi = psi(&aes_prf.psi_aes, ctr)?;
                        res += f_a * psi;
                    }
                    Ok(res)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .instrument(tracing::Span::current())
        .await??;

        self.counters.prss_ctr += amount as u128;

        Ok(res)
    }

    /// PRZS.Next() for a single party
    /// `party_id`: The party's role to derive IDs
    /// `t`: The threshold parameter for the session
    ///
    /// __NOTE__: telemetry is done at the caller because this function isn't batched
    /// and we want to avoid creating too many telemetry spans
    #[instrument(name="PRZS.Next",skip_all,fields(batch_size=?amount))]
    async fn przs_next_vec(
        &mut self,
        party_role: Role,
        threshold: u8,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        //Cheap to clone as everything is an Arc or atomic types
        let prfs = self.prfs.clone();
        let prss_setup = self.prss_setup.clone();
        let przs_ctr = self.counters.przs_ctr;

        // Independent per-counter elements, assembled in parallel. Element `idx`
        // uses `ctr = przs_ctr + idx`.
        let res = spawn_compute_bound(move || -> anyhow::Result<Vec<Z>> {
            if amount == 0 {
                return Ok(Vec::new());
            }

            // Per-set invariants, computed once instead of per element: the products
            // f_A(alpha_i) * alpha_i^j (for j in 1..=threshold) do not depend on the counter.
            let mut set_data: Vec<(&PrfAes, Vec<Z>)> = Vec::with_capacity(prss_setup.sets.len());
            for (i, set) in prss_setup.sets.iter().enumerate() {
                if !set.parties.contains(&party_role) {
                    return Err(anyhow_error_and_log(format!(
                        "Called przs.next() with party role {party_role} that is not in a precomputed set of parties!"
                    )));
                }
                let aes_prf = prfs.get(i).ok_or_else(|| {
                    anyhow_error_and_log("PRFs not properly initialized!".to_string())
                })?;
                // f_A(alpha_i): the embedded party ID indexes into f_a_points (from zero)
                let f_a = set.f_a_points[&party_role];
                let mut fa_alpha = Vec::with_capacity(threshold as usize);
                for j in 1..=threshold {
                    // power of alpha_i^j
                    let alpha_j = prss_setup.alpha_powers[&party_role][j as usize];
                    fa_alpha.push(f_a * alpha_j);
                }
                set_data.push((aes_prf, fa_alpha));
            }

            (0..amount)
                .into_par_iter()
                .with_min_len(*crate::constants::PRSS_GEN_PAR_MIN_CHUNK)
                .map(|idx| {
                    let ctr = przs_ctr + idx as u128;
                    let mut res = Z::ZERO;
                    for (aes_prf, fa_alpha) in &set_data {
                        for (j_idx, fa_alpha_j) in fa_alpha.iter().enumerate() {
                            let chi = chi(&aes_prf.chi_aes, ctr, (j_idx + 1) as u8)?;
                            res += *fa_alpha_j * chi;
                        }
                    }
                    Ok(res)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .instrument(tracing::Span::current())
        .await??;

        self.counters.przs_ctr += amount as u128;

        Ok(res)
    }

    /// Compute the PRSS.check() method which returns the summed up psi value for each party based on the supplied counter `ctr`.
    /// If parties are behaving maliciously they get added to the corruption list in [SmallSessionHandles]
    #[instrument(name = "PRSS.check", skip(self, session), fields(sid=?session.session_id(), my_role=?session.my_role()))]
    async fn prss_check<S: BaseSessionHandles>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        let sets = &self.prss_setup.sets;

        //Compute all psi values for subsets I am part of
        let mut psi_values = Vec::with_capacity(sets.len());
        for (i, cur_set) in sets.iter().enumerate() {
            if let Some(aes_prf) = &self.prfs.get(i) {
                let psi = vec![psi(&aes_prf.psi_aes, ctr)?];
                psi_values.push((cur_set.parties.clone(), psi));
            } else {
                return Err(anyhow_error_and_log(
                    "PRFs not properly initialized!".to_string(),
                ));
            }
        }

        //Broadcast (as sender and receiver) all the psi values
        let broadcast_result = self
            .broadcast
            .broadcast_from_all_w_corrupt_set_update::<Z, S>(
                session,
                BroadcastValue::PRSSVotes(psi_values),
            )
            .await?;

        // Sort the votes received from the broadcast
        let count = sort_votes(&broadcast_result, session)?;
        // Find which values have received most votes
        let true_psi_vals = find_winning_prf_values(&count, session)?;
        // Find the parties who did not vote for the results and add them to the corrupt set
        handle_non_voting_parties(&true_psi_vals, &count, session)?;
        // Compute result based on majority votes
        compute_party_shares(&true_psi_vals, session, ComputeShareMode::Prss)
    }

    /// Compute the PRZS.check() method which returns the summed up chi value for each party based on the supplied counter `ctr`.
    /// If parties are behaving maliciously they get added to the corruption list in [SmallSessionHandles]
    #[instrument(name = "PRZS.Check", skip(self, session, ctr), fields(sid=?session.session_id(), my_role=?session.my_role()))]
    async fn przs_check<S: BaseSessionHandles>(
        &self,
        session: &mut S,
        ctr: u128,
    ) -> anyhow::Result<HashMap<Role, Z>> {
        let sets = &self.prss_setup.sets;
        let mut chi_values = Vec::with_capacity(sets.len());
        for (i, cur_set) in sets.iter().enumerate() {
            if let Some(aes_prf) = &self.prfs.get(i) {
                let mut chi_list = Vec::with_capacity(session.threshold() as usize);
                for j in 1..=session.threshold() {
                    chi_list.push(chi(&aes_prf.chi_aes, ctr, j)?);
                }
                chi_values.push((cur_set.parties.clone(), chi_list.clone()));
            } else {
                return Err(anyhow_error_and_log(
                    "PRFs not properly initialized!".to_string(),
                ));
            }
        }

        let broadcast_result = self
            .broadcast
            .broadcast_from_all_w_corrupt_set_update::<Z, S>(
                session,
                BroadcastValue::PRSSVotes(chi_values),
            )
            .await?;

        // Sort the votes received from the broadcast
        let count = sort_votes(&broadcast_result, session)?;
        // Find which values have received most votes
        let true_chi_vals = find_winning_prf_values(&count, session)?;
        // Find the parties who did not vote for the results and add them to the corrupt set
        handle_non_voting_parties(&true_chi_vals, &count, session)?;
        // Compute result based on majority votes
        compute_party_shares(&true_chi_vals, session, ComputeShareMode::Przs)
    }

    fn get_counters(&self) -> PRSSCounters {
        self.counters
    }
}
impl<Z: RingWithExceptionalSequence + Invert + PRSSConversions> PRSSSetup<Z> {
    /// initializes a PRSS state for a new session
    /// PRxS counters are set to zero
    /// PRFs are initialized with agreed keys XORed with the session id
    pub fn new_prss_reference_state(&self, sid: SessionId) -> SecureReferencePrssState<Z> {
        let mut prfs = Vec::new();

        // initialize AES PRFs once with random agreed keys and sid
        for set in self.sets.iter() {
            let chi_aes = ChiAes::new(&set.set_key, sid);
            let psi_aes = PsiAes::new(&set.set_key, sid);
            let phi_aes = PhiAes::new(&set.set_key, sid);

            prfs.push(PrfAes {
                phi_aes,
                psi_aes,
                chi_aes,
            });
        }

        ReferencePrssState {
            counters: PRSSCounters::default(),
            prss_setup: self.clone(),
            prfs: Arc::new(prfs),
            broadcast: SyncReliableBroadcast::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};
    #[tokio::test]
    async fn test_prss_group_sizes_match_original() {
        async fn check<
            Z: RingWithExceptionalSequence + Invert + PRSSConversions,
            const N: usize,
        >() {
            let role = Role::indexed_from_one(1);
            let setup = PRSSSetup::<Z>::testing_party_epoch_init(4, 1, role)
                .await
                .unwrap();
            let initial = setup.new_prss_reference_state(SessionId::from(23425));
            // Exercise full groups, short tails, and requests split by Rayon.
            for amount in [0, 1, N - 1, N, N + 1, 2 * N + 1, 2049] {
                let mut original = initial.clone();
                let mut grouped = initial.clone();
                original.counters.prss_ctr = 255;
                grouped.counters.prss_ctr = 255;
                assert_eq!(
                    grouped
                        .prss_next_vec_grouped::<N>(role, amount)
                        .await
                        .unwrap(),
                    original.prss_next_vec_orig(role, amount).await.unwrap(),
                );
                assert_eq!(grouped.counters.prss_ctr, original.counters.prss_ctr);
                assert_eq!(grouped.counters.mask_ctr, original.counters.mask_ctr);
                assert_eq!(grouped.counters.przs_ctr, original.counters.przs_ctr);
            }
            for (start, amount) in [
                ((1_u128 << 112) - N as u128, N),
                ((1_u128 << 112) - N as u128 - 1, N + 1),
                ((1_u128 << 112) - N as u128 + 1, N),
                (1_u128 << 112, 0),
            ] {
                let mut original = initial.clone();
                let mut grouped = initial.clone();
                original.counters.prss_ctr = start;
                grouped.counters.prss_ctr = start;
                let expected = original.prss_next_vec_orig(role, amount).await;
                let actual = grouped.prss_next_vec_grouped::<N>(role, amount).await;
                match (expected, actual) {
                    (Ok(a), Ok(b)) => assert_eq!(a, b),
                    (Err(a), Err(b)) => assert_eq!(
                        a.to_string().split_once("ctr in psi").unwrap().1,
                        b.to_string().split_once("ctr in psi").unwrap().1,
                    ),
                    mismatch => panic!("group size {N} disagrees with original: {mismatch:?}"),
                }
                assert_eq!(grouped.counters.prss_ctr, original.counters.prss_ctr);
            }
        }
        macro_rules! sizes {
            ($ring:ty) => {{
                check::<$ring, 1>().await;
                check::<$ring, 2>().await;
                check::<$ring, 4>().await;
                check::<$ring, 5>().await;
                check::<$ring, 6>().await;
                check::<$ring, 8>().await;
                check::<$ring, 10>().await;
                check::<$ring, 11>().await;
                check::<$ring, 16>().await;
                check::<$ring, 21>().await;
            }};
        }
        sizes!(ResiduePolyF4Z64);
        sizes!(ResiduePolyF4Z128);
        // The experiment measures F4, but the shared kernel also supports F8.
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z64, 6>().await;
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z128, 6>().await;
    }

    // Compare full vectors against the preserved implementation, not just against
    // prss_next(), which itself delegates to the modified vector method.
    #[tokio::test]
    async fn test_prss_pairs_match_original() {
        async fn check<Z: RingWithExceptionalSequence + Invert + PRSSConversions>() {
            let role = Role::indexed_from_one(1);
            for (parties, threshold) in [(4, 1), (13, 4)] {
                let setup = PRSSSetup::<Z>::testing_party_epoch_init(parties, threshold, role)
                    .await
                    .unwrap();
                let mut original = setup.new_prss_reference_state(SessionId::from(23425));
                let mut paired = original.clone();
                let mut iterator = original.clone();
                let mut prepared = setup
                    .new_prss_session_state(SessionId::from(23425), role)
                    .unwrap();
                // Nonzero counter with a carry inside the first pair.
                original.counters.prss_ctr = 255;
                paired.counters.prss_ctr = 255;
                iterator.counters.prss_ctr = 255;
                prepared.counters.prss_ctr = 255;
                // A 1024-value minimum first permits two tasks at 2048
                // values. Include both that boundary and a four-task request.
                for amount in [0, 1, 2, 3, 4, 1023, 1024, 1025, 2047, 2048, 2049, 4097] {
                    let expected = original.prss_next_vec_orig(role, amount).await.unwrap();
                    assert_eq!(
                        prepared.prss_next_vec(role, amount).await.unwrap(),
                        expected
                    );
                    assert_eq!(prepared.counters.prss_ctr, original.counters.prss_ctr);
                    assert_eq!(
                        paired.prss_next_vec_pair(role, amount).await.unwrap(),
                        expected,
                    );
                    assert_eq!(
                        iterator.prss_next_vec_iter(role, amount).await.unwrap(),
                        expected
                    );
                    assert_eq!(paired.counters.prss_ctr, original.counters.prss_ctr);
                    assert_eq!(paired.counters.mask_ctr, original.counters.mask_ctr);
                    assert_eq!(paired.counters.przs_ctr, original.counters.przs_ctr);
                    assert_eq!(iterator.counters.prss_ctr, original.counters.prss_ctr);
                    assert_eq!(iterator.counters.mask_ctr, original.counters.mask_ctr);
                    assert_eq!(iterator.counters.przs_ctr, original.counters.przs_ctr);
                }
                // Empty, paired and odd requests may end exactly at the limit.
                // An invalid pair must fail without committing any counter change.
                for (start, amount) in [
                    ((1 << 112) - 2, 2),
                    ((1 << 112) - 3, 3),
                    ((1 << 112) - 1, 2),
                    (1 << 112, 0),
                    (1 << 112, 1),
                ] {
                    original.counters.prss_ctr = start;
                    paired.counters.prss_ctr = start;
                    iterator.counters.prss_ctr = start;
                    prepared.counters.prss_ctr = start;
                    let expected = original.prss_next_vec_orig(role, amount).await;
                    let actual = paired.prss_next_vec_pair(role, amount).await;
                    let scalar_iter = iterator.prss_next_vec_iter(role, amount).await;
                    let prepared_result = prepared.prss_next_vec(role, amount).await;
                    for result in [&actual, &scalar_iter, &prepared_result] {
                        match (&expected, result) {
                            (Ok(a), Ok(b)) => assert_eq!(a, b),
                            (Err(a), Err(b)) => {
                                // error_utils prefixes diagnostics with the call site's
                                // file/line. Each helper necessarily has a different
                                // location; compare the domain/counter error itself.
                                let a = a.to_string();
                                let b = b.to_string();
                                assert_eq!(
                                    a.split_once("ctr in psi").unwrap().1,
                                    b.split_once("ctr in psi").unwrap().1,
                                );
                            }
                            mismatch => panic!("PRSS variants disagree: {mismatch:?}"),
                        }
                    }
                    assert_eq!(paired.counters.prss_ctr, original.counters.prss_ctr);
                    assert_eq!(iterator.counters.prss_ctr, original.counters.prss_ctr);
                    assert_eq!(prepared.counters.prss_ctr, original.counters.prss_ctr);
                }
            }
        }
        check::<ResiduePolyF4Z64>().await;
        check::<ResiduePolyF4Z128>().await;
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z64>().await;
        check::<algebra::galois_rings::degree_8::ResiduePolyF8Z128>().await;
    }
}
