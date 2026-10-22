/// Struct expressing the amount of triples to preprocess in a batch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchParams {
    pub triples: usize,
    pub randoms: usize,
}
