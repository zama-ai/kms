/// Compression configuration for a keyset.
/// The default is to generate a new compression secret key.
#[derive(Copy, Clone, PartialEq)]
pub enum KeySetCompressionConfig {
    /// Generate a new compression secret key.
    Generate,
    /// Use an existing compression secret key.
    UseExisting,
}

impl Default for KeySetCompressionConfig {
    fn default() -> Self {
        Self::Generate
    }
}

/// Configure the contents of a keyset.
///
/// The contents of a keyset changes the preprocessing material.
/// This struct implements [Default], use it if no configuration
/// is needed.
#[derive(Copy, Clone, Default)]
pub struct KeySetConfig {
    /// The compression configuration.
    pub compression_config: KeySetCompressionConfig,
    // more will come later
}

impl KeySetConfig {
    /// Create a new keyset configuration that does not have a compression
    /// secret key. Instead, an existing one, from another keyset, is used.
    pub fn use_existing_compression_sk() -> Self {
        Self {
            compression_config: KeySetCompressionConfig::UseExisting,
        }
    }

    pub fn is_using_existing_compression_sk(&self) -> bool {
        self.compression_config == KeySetCompressionConfig::UseExisting
    }
}
