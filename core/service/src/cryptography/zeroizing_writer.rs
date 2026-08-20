//! A [`std::io::Write`] sink that wipes its buffer, including old allocations on growth.
//!
//! Unlike wrapping a finished `Vec<u8>` in [`Zeroizing`], it wipes each allocation before release.

use std::io::Write;
use zeroize::Zeroizing;

/// Initial capacity for short messages.
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

    /// Grow without releasing an unwiped allocation.
    fn grow_for(&mut self, additional: usize) {
        let required = self.buf.len() + additional;
        if required <= self.buf.capacity() {
            return;
        }
        let new_capacity = required.max(self.buf.capacity() * 2).max(MIN_CAPACITY);
        let mut grown = Zeroizing::new(Vec::with_capacity(new_capacity));
        grown.extend_from_slice(self.buf.as_slice());
        // Replacing `buf` drops and wipes the old buffer.
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
        // Force repeated growth and verify contents are preserved.
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
