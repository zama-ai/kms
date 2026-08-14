//! A [`std::io::Write`] sink whose contents live in a zeroizing buffer.
//!
//! Serializing into a plain `Vec<u8>` and wrapping the result in [`Zeroizing`] only wipes the
//! *final* allocation. Every time the vector grows it copies into a fresh allocation and releases
//! the old one with the plaintext still in it, so an N-byte secret ends up scattered over roughly
//! log2(N) freed allocations. `zeroize` documents this limitation on its own `Vec` impl: "Cannot
//! ensure that previous reallocations did not leave values on the heap."
//!
//! [`ZeroizingWriter`] closes that gap by performing the growth itself and wiping each
//! intermediate buffer before it is released.

use std::io::Write;
use zeroize::Zeroizing;

/// Capacity of the first allocation, so that short messages never reallocate at all.
const MIN_CAPACITY: usize = 128;

pub(crate) struct ZeroizingWriter {
    buf: Zeroizing<Vec<u8>>,
}

impl ZeroizingWriter {
    pub(crate) fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
        }
    }

    /// Borrow the bytes written so far.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Make room for `additional` more bytes, wiping the outgoing allocation if we have to grow.
    ///
    /// `Vec::reserve` would copy the contents into the new allocation and release the old one
    /// as-is, so we do the move by hand and let `Zeroizing` wipe what we leave behind.
    fn grow_for(&mut self, additional: usize) {
        let required = self.buf.len() + additional;
        if required <= self.buf.capacity() {
            return;
        }
        let new_capacity = required.max(self.buf.capacity() * 2).max(MIN_CAPACITY);
        let mut grown = Zeroizing::new(Vec::with_capacity(new_capacity));
        grown.extend_from_slice(self.buf.as_slice());
        // Dropping the previous buffer here wipes it before its allocation is released.
        self.buf = grown;
    }
}

impl Write for ZeroizingWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.grow_for(data.len());
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_are_concatenated_in_order() {
        let mut writer = ZeroizingWriter::new();
        writer.write_all(b"four legs good, ").unwrap();
        writer.write_all(b"two legs better").unwrap();
        assert_eq!(writer.as_slice(), b"four legs good, two legs better");
    }

    #[test]
    fn growth_preserves_contents_across_many_reallocations() {
        // Write well past MIN_CAPACITY one byte at a time so that `grow_for` has to move the
        // buffer repeatedly, and check nothing is lost or reordered on the way.
        let expected: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let mut writer = ZeroizingWriter::new();
        for byte in &expected {
            writer.write_all(&[*byte]).unwrap();
        }
        assert_eq!(writer.as_slice(), expected.as_slice());
    }

    #[test]
    fn empty_writer_yields_no_bytes() {
        let mut writer = ZeroizingWriter::new();
        writer.write_all(b"").unwrap();
        assert!(writer.as_slice().is_empty());
    }
}
