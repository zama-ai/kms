#[derive(Copy, Clone, PartialEq, Default)]
pub enum ComputeKeyType {
    #[default]
    Cpu,
}

/// Whether to generate compressed keys.
/// This is independent of KeyGenSecretKeyConfig which is related to
/// generating keys for compressing ciphertexts.
#[derive(Copy, Clone, PartialEq, Default)]
pub enum CompressedKeyConfig {
    /// Do not use compressed keys.
    #[default]
    None,
    /// Use compression keys for the full keyset.
    All,
}

/// Configure the contents of a keyset.
///
/// The contents of a keyset changes the preprocessing material.
/// This struct implements [Default], use it if no configuration
/// is needed.
#[derive(Copy, Clone)]
pub enum KeySetConfig {
    /// The standard configuration is the one that generates the full keyset.
    /// Which includes the public key, server key, compression keys, private key shares and so on.
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
                match (inner.computation_key_type, inner.secret_key_config) {
                    (ComputeKeyType::Cpu, KeyGenSecretKeyConfig::GenerateAll) => true,
                    (
                        ComputeKeyType::Cpu,
                        KeyGenSecretKeyConfig::UseExistingCompressionSecretKey,
                    ) => false,
                    (ComputeKeyType::Cpu, KeyGenSecretKeyConfig::UseExisting) => false,
                }
            }
            _ => false,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Default)]
pub enum KeyGenSecretKeyConfig {
    #[default]
    GenerateAll,
    UseExisting,
    UseExistingCompressionSecretKey,
}

#[derive(Copy, Clone, Default)]
pub struct StandardKeySetConfig {
    pub computation_key_type: ComputeKeyType,
    pub secret_key_config: KeyGenSecretKeyConfig,
    pub compressed_key_config: CompressedKeyConfig,
}

impl StandardKeySetConfig {
    /// Create a new keyset configuration that does not have a compression
    /// secret key. Instead, an existing one, from another keyset, is used.
    pub fn use_existing_compression_sk() -> Self {
        Self {
            computation_key_type: ComputeKeyType::default(),
            secret_key_config: KeyGenSecretKeyConfig::UseExistingCompressionSecretKey,
            compressed_key_config: CompressedKeyConfig::default(),
        }
    }

    pub fn is_using_existing_compression_sk(&self) -> bool {
        self.secret_key_config == KeyGenSecretKeyConfig::UseExistingCompressionSecretKey
    }
}
