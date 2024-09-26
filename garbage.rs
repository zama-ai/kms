pub enum OperationValue {
    Decrypt(DecryptValues),
    #[strum(serialize = "decrypt_response")]
    #[strum(serialize = "reencrypt")]
    #[strum(serialize = "reencrypt_response")]
    #[strum(serialize = "keygen")]
    #[strum(serialize = "keygen_response")]
    #[strum(serialize = "keygen_preproc")]
    #[strum(serialize = "keygen_preproc_response")]
    #[strum(serialize = "crs_gen")]
    #[strum(serialize = "crs_gen_response")]
}