pub fn extract_ciphertext_size(ciphertext_handle: &[u8]) -> u32 {
    ((ciphertext_handle[0] as u32) << 24)
        | ((ciphertext_handle[1] as u32) << 16)
        | ((ciphertext_handle[2] as u32) << 8)
        | (ciphertext_handle[3] as u32)
}
