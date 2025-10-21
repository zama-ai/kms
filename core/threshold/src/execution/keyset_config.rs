#[derive(Copy, Clone, PartialEq, Default)]
pub enum ComputeKeyType {
    #[default]
    Cpu,
}

/// Compression configuration for a keyset.
/// The default is to generate a new compression secret key.
#[derive(Copy, Clone, PartialEq, Default)]
pub enum KeySetCompressionConfig {
    /// Generate a new compression secret key.
    #[default]
    Generate,
    /// Use an existing compression secret key.
    UseExisting,
}

/// Configure the contents of a keyset.
///
/// The contents of a keyset changes the preprocessing material.
/// This struct implements [Default], use it if no configuration
/// is needed.
#[derive(Copy, Clone)]
pub enum KeySetConfig {
    Standard(StandardKeySetConfig),
    DecompressionOnly,
}

impl Default for KeySetConfig {
    fn default() -> Self {
        KeySetConfig::Standard(StandardKeySetConfig::default())
    }
}

impl KeySetConfig {
    pub fn use_existing_compression_sk() -> Self {
        KeySetConfig::Standard(StandardKeySetConfig::use_existing_compression_sk())
    }

    pub fn is_standard_using_existing_compression_sk(&self) -> bool {
        match self {
            KeySetConfig::Standard(standard_key_set_config) => {
                standard_key_set_config.is_using_existing_compression_sk()
            }
            _ => false,
        }
    }

    pub fn is_standard(&self) -> bool {
        matches!(self, KeySetConfig::Standard(_))
    }

    pub fn is_standard_cpu_generate_compression_key(&self) -> bool {
        match self {
            KeySetConfig::Standard(inner) => {
                match (inner.computation_key_type, inner.compression_config) {
                    (ComputeKeyType::Cpu, KeySetCompressionConfig::Generate) => true,
                    (ComputeKeyType::Cpu, KeySetCompressionConfig::UseExisting) => false,
                }
            }
            _ => false,
        }
    }
}

#[derive(Copy, Clone, Default)]
pub struct StandardKeySetConfig {
    pub computation_key_type: ComputeKeyType,
    /// The compression configuration.
    pub compression_config: KeySetCompressionConfig,
    // more will come later
}

impl StandardKeySetConfig {
    /// Create a new keyset configuration that does not have a compression
    /// secret key. Instead, an existing one, from another keyset, is used.
    pub fn use_existing_compression_sk() -> Self {
        Self {
            computation_key_type: ComputeKeyType::default(),
            compression_config: KeySetCompressionConfig::UseExisting,
        }
    }

    pub fn is_using_existing_compression_sk(&self) -> bool {
        self.compression_config == KeySetCompressionConfig::UseExisting
    }
}
