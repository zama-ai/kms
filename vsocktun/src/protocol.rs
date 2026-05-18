//! Session handshake and packet framing used by `vsocktun`.
//!
//! The tunnel transport itself is stream-oriented, so this module provides the
//! two pieces of structure the relay needs on top of raw bytes:
//! - a small session header that lets both sides assemble shard streams into
//!   one logical tunnel session and agree on the framing mode
//! - length-prefixed packet framing so TUN payloads can be forwarded without
//!   depending on any stream-level message boundaries

use std::io;
#[cfg(test)]
use std::io::{Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HELLO_MAGIC: [u8; 8] = *b"VSTUN002";
const HELLO_RESERVED_BYTES: usize = 4;
const HELLO_CAP_RAW_TUN_FRAMES: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hello {
    pub(crate) session_id: u64,
    pub(crate) queues: u16,
    pub(crate) shard: u16,
    capabilities: u32,
}

impl Hello {
    pub(crate) const ENCODED_LEN: usize = HELLO_MAGIC.len() + 8 + 2 + 2 + HELLO_RESERVED_BYTES;

    pub(crate) fn new(session_id: u64, queues: u16, shard: u16, raw_tun_frames: bool) -> Self {
        Self {
            session_id,
            queues,
            shard,
            capabilities: if raw_tun_frames {
                HELLO_CAP_RAW_TUN_FRAMES
            } else {
                0
            },
        }
    }

    pub(crate) fn supports_raw_tun_frames(self) -> bool {
        self.capabilities & HELLO_CAP_RAW_TUN_FRAMES != 0
    }

    pub(crate) fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        bytes[..HELLO_MAGIC.len()].copy_from_slice(&HELLO_MAGIC);
        bytes[8..16].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.queues.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.shard.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.capabilities.to_be_bytes());
        bytes
    }

    #[cfg(test)]
    pub(crate) fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        reader.read_exact(&mut bytes)?;

        Self::decode(bytes)
    }

    pub(crate) async fn read_from_async<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        reader.read_exact(&mut bytes).await?;

        Self::decode(bytes)
    }

    fn decode(bytes: [u8; Self::ENCODED_LEN]) -> io::Result<Self> {
        if bytes[..HELLO_MAGIC.len()] != HELLO_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received invalid vsocktun session header magic",
            ));
        }

        let session_id = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "received truncated vsocktun session identifier",
            )
        })?);
        let queues = u16::from_be_bytes(bytes[16..18].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "received truncated vsocktun queue count",
            )
        })?);
        let shard = u16::from_be_bytes(bytes[18..20].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "received truncated vsocktun shard identifier",
            )
        })?);
        let capabilities = u32::from_be_bytes(bytes[20..24].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "received truncated vsocktun capability flags",
            )
        })?);

        Ok(Self {
            session_id,
            queues,
            shard,
            capabilities,
        })
    }

    pub(crate) async fn write_to_async<W: AsyncWrite + Unpin>(
        self,
        writer: &mut W,
    ) -> io::Result<()> {
        writer.write_all(&self.encode()).await
    }
}

/// Incremental decoder for framed TUN payloads read from a VSOCK byte stream.
///
/// It keeps enough state to resume a partially read frame without assuming that
/// every socket read returns a whole frame.
#[derive(Debug)]
pub(crate) struct FrameReader {
    header: [u8; 4],
    header_read: usize,
    max_payload_bytes: usize,
    payload: Vec<u8>,
    payload_len: usize,
    payload_read: usize,
    frame_ready: bool,
}

impl FrameReader {
    pub(crate) fn new(max_payload_bytes: usize) -> Self {
        Self {
            header: [0_u8; 4],
            header_read: 0,
            max_payload_bytes,
            payload: Vec::new(),
            payload_len: 0,
            payload_read: 0,
            frame_ready: false,
        }
    }

    pub(crate) fn current_payload(&self) -> &[u8] {
        debug_assert!(
            self.frame_ready,
            "current_payload requires a completed frame"
        );
        &self.payload[..self.payload_len]
    }

    pub(crate) fn finish_frame(&mut self) {
        self.header = [0_u8; 4];
        self.header_read = 0;
        self.payload_len = 0;
        self.payload_read = 0;
        self.frame_ready = false;
    }

    #[cfg(test)]
    fn payload_capacity(&self) -> usize {
        self.payload.capacity()
    }

    fn begin_payload(&mut self) -> io::Result<()> {
        let payload_len = u32::from_be_bytes(self.header) as usize;
        if payload_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "received empty framed packet",
            ));
        }
        if payload_len > self.max_payload_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "received framed packet larger than configured maximum of {} bytes",
                    self.max_payload_bytes
                ),
            ));
        }

        self.payload.resize(payload_len, 0);
        self.payload_len = payload_len;
        self.payload_read = 0;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn read_frame<R: Read>(&mut self, reader: &mut R) -> io::Result<Option<usize>> {
        loop {
            if self.header_read < self.header.len() {
                match reader.read(&mut self.header[self.header_read..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vsock shard closed while reading packet header",
                        ));
                    }
                    Ok(read) => {
                        self.header_read += read;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                    Err(err) => return Err(err),
                }

                if self.header_read < self.header.len() {
                    continue;
                }

                self.begin_payload()?;
            }

            match reader.read(&mut self.payload[self.payload_read..self.payload_len]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vsock shard closed while reading packet payload",
                    ));
                }
                Ok(read) => {
                    self.payload_read += read;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }

            if self.payload_read < self.payload_len {
                continue;
            }

            self.frame_ready = true;
            return Ok(Some(self.payload_len));
        }
    }

    pub(crate) async fn read_frame_async<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Option<usize>> {
        if self.header_read < self.header.len() {
            match reader.read(&mut self.header[self.header_read..]).await {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vsock shard closed while reading packet header",
                    ));
                }
                Ok(read) => {
                    self.header_read += read;
                }
                Err(err) => return Err(err),
            }

            if self.header_read < self.header.len() {
                return Ok(None);
            }

            self.begin_payload()?;
        }

        match reader
            .read(&mut self.payload[self.payload_read..self.payload_len])
            .await
        {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vsock shard closed while reading packet payload",
                ));
            }
            Ok(read) => {
                self.payload_read += read;
            }
            Err(err) => return Err(err),
        }

        if self.payload_read < self.payload_len {
            return Ok(None);
        }

        self.frame_ready = true;
        Ok(Some(self.payload_len))
    }
}

/// Best-effort writer for a borrowed payload slice.
///
/// This keeps partial-write bookkeeping separate from the higher-level shard
/// control flow without copying the payload into a new owned buffer.
#[derive(Debug)]
pub(crate) struct PendingSliceWrite<'a> {
    bytes: &'a [u8],
    written: usize,
}

impl<'a> PendingSliceWrite<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, written: 0 }
    }

    pub(crate) fn remaining(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    pub(crate) fn advance(&mut self, written: usize) -> bool {
        self.written += written;
        self.written == self.bytes.len()
    }

    #[cfg(test)]
    pub(crate) fn write_to<W: Write>(&mut self, writer: &mut W) -> io::Result<bool> {
        match writer.write(self.remaining()) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to make forward progress while writing packet",
            )),
            Ok(written) => Ok(self.advance(written)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(err),
        }
    }
}

/// Best-effort writer for a framed payload without copying the payload into a
/// separate owned buffer.
#[derive(Debug)]
pub(crate) struct PendingFramedWrite<'a> {
    header: [u8; 4],
    header_written: usize,
    body: &'a [u8],
    body_written: usize,
}

impl<'a> PendingFramedWrite<'a> {
    pub(crate) fn new(payload: &'a [u8]) -> io::Result<Self> {
        let payload_len = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds maximum framed size of 4294967295 bytes",
            )
        })?;

        Ok(Self {
            header: payload_len.to_be_bytes(),
            header_written: 0,
            body: payload,
            body_written: 0,
        })
    }

    fn remaining(&self) -> &[u8] {
        if self.header_written < self.header.len() {
            &self.header[self.header_written..]
        } else {
            &self.body[self.body_written..]
        }
    }

    fn advance(&mut self, written: usize) -> bool {
        if self.header_written < self.header.len() {
            self.header_written += written;
        } else {
            self.body_written += written;
        }

        self.header_written == self.header.len() && self.body_written == self.body.len()
    }

    #[cfg(test)]
    pub(crate) fn write_to<W: Write>(&mut self, writer: &mut W) -> io::Result<bool> {
        match writer.write(self.remaining()) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to make forward progress while writing packet",
            )),
            Ok(written) => Ok(self.advance(written)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub(crate) async fn write_to_async<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> io::Result<bool> {
        match writer.write(self.remaining()).await {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to make forward progress while writing packet",
            )),
            Ok(written) => Ok(self.advance(written)),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameReader, Hello, PendingFramedWrite, PendingSliceWrite};
    use std::fs::File;
    use std::io::{self, Seek, SeekFrom, Write};
    use tempfile::tempfile;

    struct LimitedWriter {
        chunk_size: usize,
        bytes: Vec<u8>,
    }

    impl LimitedWriter {
        fn new(chunk_size: usize) -> Self {
            Self {
                chunk_size,
                bytes: Vec::new(),
            }
        }
    }

    impl Write for LimitedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let written = buf.len().min(self.chunk_size);
            self.bytes.extend_from_slice(&buf[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn reset_file(file: &mut File) -> io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    #[test]
    fn hello_round_trip() {
        let hello = Hello::new(42, 8, 3, true);

        let encoded = hello.encode();
        let mut file = tempfile().expect("temporary file should be created");
        file.write_all(&encoded)
            .expect("hello bytes should be written to temporary file");
        reset_file(&mut file).expect("temporary file should rewind");

        let decoded = Hello::read_from(&mut file).expect("hello bytes should decode");
        assert_eq!(decoded, hello);
        assert!(decoded.supports_raw_tun_frames());
    }

    #[test]
    fn framed_packet_round_trip() {
        let packet = vec![1_u8, 2, 3, 4, 5];
        let mut outgoing =
            PendingFramedWrite::new(&packet).expect("packet should fit into framed payload");
        let mut file = tempfile().expect("temporary file should be created");

        while !outgoing
            .write_to(&mut file)
            .expect("packet should write to temporary file")
        {}

        reset_file(&mut file).expect("temporary file should rewind");
        let mut reader = FrameReader::new(4096);
        let decoded_len = reader
            .read_frame(&mut file)
            .expect("reader should decode file-backed packet")
            .expect("reader should produce one packet");
        let decoded = reader.current_payload();

        assert_eq!(decoded_len, packet.len());
        assert_eq!(decoded, packet);
    }

    #[test]
    fn frame_reader_keeps_payload_storage_after_completed_frame() {
        let packet = vec![9_u8, 8, 7, 6, 5];
        let mut outgoing =
            PendingFramedWrite::new(&packet).expect("packet should fit into framed payload");
        let mut file = tempfile().expect("temporary file should be created");

        while !outgoing
            .write_to(&mut file)
            .expect("packet should write to temporary file")
        {}

        reset_file(&mut file).expect("temporary file should rewind");
        let mut reader = FrameReader::new(4096);
        let _decoded_len = reader
            .read_frame(&mut file)
            .expect("reader should decode file-backed packet")
            .expect("reader should produce one packet");
        let capacity_before_finish = reader.payload_capacity();

        assert!(capacity_before_finish >= packet.len());
        reader.finish_frame();
        assert_eq!(reader.payload_capacity(), capacity_before_finish);
    }

    #[test]
    fn pending_slice_write_handles_partial_writes() {
        let packet = [1_u8, 2, 3, 4, 5];
        let mut writer = LimitedWriter::new(2);
        let mut pending = PendingSliceWrite::new(&packet);

        while !pending
            .write_to(&mut writer)
            .expect("partial writes should make progress")
        {}

        assert_eq!(writer.bytes, packet);
    }

    #[test]
    fn pending_framed_write_handles_partial_writes() {
        let packet = [1_u8, 2, 3, 4, 5];
        let mut writer = LimitedWriter::new(2);
        let mut pending =
            PendingFramedWrite::new(&packet).expect("packet should fit into framed payload");

        while !pending
            .write_to(&mut writer)
            .expect("partial writes should make progress")
        {}

        assert_eq!(writer.bytes, [0, 0, 0, 5, 1, 2, 3, 4, 5]);
    }
}
