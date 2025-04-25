use bincode::serialize;
use serde::Serialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Domain separator for hashing elements.
/// This is used to ensure that the hash is unique to the context in which it is used.
pub type DomainSep = [u8; DSEP_LEN];
pub const DSEP_LEN: usize = 8;

/// The amount of bytes in a digest
pub const DIGEST_BYTES: usize = 256 / 8;

/// The maximum size of the serialized element in bytes. Limit set for security reasons as well as a sanity check.
pub const SAFE_SER_SIZE_LIMIT: u64 = 1024 * 1024 * 1024 * 2;

const DSEP_LIST: DomainSep = *b"HASH_LST";

/// Hash an element using SHAKE-256 with a chosen domain separator and a specified output size in bytes.
pub fn hash_element_w_size<T>(domain_separator: &DomainSep, element: &T, bytes: usize) -> Vec<u8>
where
    T: ?Sized + AsRef<[u8]>,
{
    let mut hasher = Shake256::default();
    hasher.update(domain_separator);
    hasher.update(element.as_ref());
    let mut output_reader = hasher.finalize_xof();
    let mut digest = vec![0u8; bytes];
    output_reader.read(&mut digest);
    digest.to_vec()
}

/// Hash an element using SHAKE-256 with a chosen domain separator and an output size of DIGEST_BYTES.
pub fn hash_element<T>(domain_separator: &DomainSep, element: &T) -> Vec<u8>
where
    T: ?Sized + AsRef<[u8]>,
{
    hash_element_w_size(domain_separator, element, DIGEST_BYTES)
}

/// Compute the SHAKE-256 digest with a specified output size of a list of elements where all except AT MOST one MUST be of constant length.
/// WARNING: If more than one of the `elements` are of variable length, the hash will NOT be guaranteed to be unique per list.
pub fn unsafe_hash_list_w_size<T>(
    domain_separator: &DomainSep,
    elements: &[&T],
    bytes: usize,
) -> Vec<u8>
where
    T: ?Sized + AsRef<[u8]>,
{
    let mut hasher = Shake256::default();
    hasher.update(&DSEP_LIST);
    hasher.update(domain_separator);
    hasher.update(&(elements.len() as u64).to_le_bytes());
    for cur_elem in elements {
        hasher.update(cur_elem.as_ref());
    }
    let mut output_reader = hasher.finalize_xof();
    let mut digest = vec![0u8; bytes];
    output_reader.read(&mut digest);
    digest.to_vec()
}

/// Compute a digest of length DIGEST_BYTES using SHAKE-256 of a list of elements where all except AT MOST one MUST be of constant length.
/// WARNING: If more than one of the `elements` are of variable length, the hash will NOT be guaranteed to be unique per list.
pub fn unsafe_hash_list<T>(domain_separator: &DomainSep, elements: &[&T]) -> Vec<u8>
where
    T: ?Sized + AsRef<[u8]>,
{
    unsafe_hash_list_w_size(domain_separator, elements, DIGEST_BYTES)
}

/// Serialize an element and hash it using SHAKE-256. Returns the hash as a vector of bytes.
/// The function requires a domain separator to define the unique usage context.
pub fn serialize_hash_element<T>(domain_separator: &DomainSep, msg: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize + ?Sized,
{
    let to_hash = match serialize(msg) {
        Ok(to_hash) => to_hash,
        Err(e) => {
            anyhow::bail!("Could not encode message due to error: {:?}", e);
        }
    };
    Ok(hash_element(domain_separator, &to_hash))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::DomainSep;
    use crate::hashing::{hash_element, serialize_hash_element, unsafe_hash_list};

    const DSEP_TEST: DomainSep = *b"test_1__";
    const DSEP_TEST2: DomainSep = *b"test_2__";

    #[test]
    fn sunshine_hash() {
        let digest = hash_element(&DSEP_TEST, &"test".as_bytes());
        let digest2 = hash_element(&DSEP_TEST, &"test".as_bytes());
        assert_eq!(digest, digest2);
    }

    #[test]
    fn negative_hash() {
        let digest = hash_element(&DSEP_TEST, &"test".as_bytes());
        let digest_other_domain = hash_element(&DSEP_TEST2, &"test".as_bytes());
        let digest_other_val = hash_element(&DSEP_TEST, &"test2".as_bytes());
        assert_ne!(digest, digest_other_domain);
        assert_ne!(digest, digest_other_val);
    }

    #[test]
    fn sunshine_unsafe_list() {
        let digest = unsafe_hash_list(&DSEP_TEST, &["1", "aa"]);
        let digest2 = unsafe_hash_list(&DSEP_TEST, &["1", "aa"]);
        assert_eq!(digest, digest2);
    }

    #[test]
    fn encoding_unsafe_list() {
        let digest = unsafe_hash_list(&DSEP_TEST, &["1", "aa"]);
        let digest2 = unsafe_hash_list(&DSEP_TEST, &["1a", "a"]);
        let digest3 = unsafe_hash_list(&DSEP_TEST, &["1", "aa", "A"]);
        // Observe the elements in the list are expected to be constant length
        assert_eq!(digest, digest2);
        assert_ne!(digest, digest3);
    }

    #[test]
    fn negative_unsafe_list() {
        let digest = unsafe_hash_list(&DSEP_TEST, &["1", "aa"]);
        let digest_other_domain = unsafe_hash_list(&DSEP_TEST2, &["1", "aa"]);
        let digest_other_val = unsafe_hash_list(&DSEP_TEST2, &["1", "bb"]);
        assert_ne!(digest, digest_other_domain);
        assert_ne!(digest, digest_other_val);
    }

    #[test]
    fn sunshine_serialize_hash() {
        let digest = serialize_hash_element(&DSEP_TEST, "test").unwrap();
        let digest2 = serialize_hash_element(&DSEP_TEST, "test").unwrap();
        assert_eq!(digest, digest2);
    }

    #[test]
    fn negative_serialize_hash() {
        let digest = serialize_hash_element(&DSEP_TEST, "test").unwrap();
        let digest_other_domain = serialize_hash_element(&DSEP_TEST2, "test").unwrap();
        let digest_other_val = serialize_hash_element(&DSEP_TEST, "test2").unwrap();
        assert_ne!(digest, digest_other_domain);
        assert_ne!(digest, digest_other_val);
    }
}
