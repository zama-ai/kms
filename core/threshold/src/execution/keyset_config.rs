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
    pub fn is_standard(&self) -> bool {
        matches!(self, KeySetConfig::Standard(_))
    }
}

#[derive(Copy, Clone, PartialEq, Default)]
pub enum KeyGenSecretKeyConfig {
    #[default]
    GenerateAll,
    UseExisting,
}

#[derive(Copy, Clone, Default)]
pub struct StandardKeySetConfig {
    pub computation_key_type: ComputeKeyType,
    pub secret_key_config: KeyGenSecretKeyConfig,
    pub compressed_key_config: CompressedKeyConfig,
}

impl StandardKeySetConfig {
    pub fn use_existing_sk() -> Self {
        Self {
            computation_key_type: ComputeKeyType::default(),
            secret_key_config: KeyGenSecretKeyConfig::UseExisting,
            compressed_key_config: CompressedKeyConfig::default(),
        }
    }
}
