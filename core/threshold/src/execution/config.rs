/// Struct expressing the amount of triples to preprocess in a batch
#[derive(Debug, Clone, Copy)]
pub struct BatchParams {
    pub triples: usize,
    pub randoms: usize,
}
