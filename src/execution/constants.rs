/// log_2 of parameter Bd, computed from values in the paper
pub(crate) const LOG_BD: u64 = 72;

/// parameter pow, taken from the paper
pub(crate) const POW: u64 = 47;

/// log_2 of nominator of Bd1
pub(crate) const LOG_BD1_NOM: u32 = (((1_u128 << POW) - 1) * (1_u128 << LOG_BD)).ilog2();
