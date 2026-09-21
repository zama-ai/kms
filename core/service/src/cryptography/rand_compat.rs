use rand::{CryptoRng, RngCore};
use rand_core_0_10::{TryCryptoRng, TryRng};

/// Adapts the workspace's `rand_core` 0.6 generators to the 0.10 traits used by
/// the current RustCrypto KEM implementations.
pub(super) struct RandCore010Adapter<'a, R: ?Sized>(&'a mut R);

impl<'a, R: ?Sized> RandCore010Adapter<'a, R> {
    pub(super) fn new(rng: &'a mut R) -> Self {
        Self(rng)
    }
}

impl<R: RngCore + ?Sized> TryRng for RandCore010Adapter<'_, R> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(output);
        Ok(())
    }
}

impl<R: CryptoRng + RngCore + ?Sized> TryCryptoRng for RandCore010Adapter<'_, R> {}
