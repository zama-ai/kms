//! Session handshake and packet framing used by `vsocktun`.
//!
//! The tunnel transport itself is stream-oriented, so this module provides the
//! two pieces of structure the relay needs on top of raw bytes:
//! - a small session header that lets both sides assemble shard streams into
//!   one logical tunnel session and agree on the framing mode
//! - length-prefixed packet framing so TUN payloads can be forwarded without
//!   depending on any stream-level message boundaries

use std::future::poll_fn;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HELLO_MAGIC: [u8; 8] = *b"VSTUN002";
const HELLO_RESERVED_BYTES: usize = 4;
const HELLO_CAP_RAW_TUN_FRAMES: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Handshake header sent once on each shard stream before packet forwarding.
///
/// Every shard in one logical session carries the same `session_id` and queue
/// count, but a distinct `shard` index. That lets the parent assemble several
/// independently accepted VSOCK streams back into one tunnel session.
pub(crate) struct Hello {
    /// Logical session identifier shared by every shard in one reconnect attempt.
    pub(crate) session_id: u64,
    /// Total shard count the sender expects the peer to assemble.
    pub(crate) queues: u16,
    /// Zero-based index of this shard inside the logical session.
    pub(crate) shard: u16,
    capabilities: u32,
}

impl Hello {
    /// Number of bytes in the fixed-width handshake header.
    pub(crate) const ENCODED_LEN: usize = HELLO_MAGIC.len() + 8 + 2 + 2 + HELLO_RESERVED_BYTES;

    /// Builds the handshake header for one shard connection.
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

    /// Reports whether the sender expects framed payloads to contain raw TUN
    /// frames, including virtio-net headers.
    pub(crate) fn supports_raw_tun_frames(self) -> bool {
        self.capabilities & HELLO_CAP_RAW_TUN_FRAMES != 0
    }

    /// Encodes the handshake into the exact on-the-wire byte layout.
    pub(crate) fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        bytes[..HELLO_MAGIC.len()].copy_from_slice(&HELLO_MAGIC);
        bytes[8..16].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.queues.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.shard.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.capabilities.to_be_bytes());
        bytes
    }

    /// Reads and decodes one complete handshake from an asynchronous byte
    /// stream.
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

    /// Writes the fixed-width handshake to an asynchronous byte stream.
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
    /// Prepares a reader that rejects frames larger than one local TUN packet
    /// buffer.
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

    /// Borrows the payload from the most recently completed frame.
    ///
    /// The borrow stays valid until [`FrameReader::finish_frame`] starts the
    /// next packet.
    pub(crate) fn current_payload(&self) -> &[u8] {
        debug_assert!(
            self.frame_ready,
            "current_payload requires a completed frame"
        );
        &self.payload[..self.payload_len]
    }

    /// Marks the current frame as consumed while keeping any allocated storage
    /// for reuse by the next packet.
    pub(crate) fn finish_frame(&mut self) {
        self.header = [0_u8; 4];
        self.header_read = 0;
        self.payload.clear();
        self.payload_len = 0;
        self.payload_read = 0;
        self.frame_ready = false;
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

        self.payload.clear();
        if self.payload.capacity() < payload_len {
            self.payload.reserve(payload_len);
        }
        self.payload_len = payload_len;
        self.payload_read = 0;
        Ok(())
    }

    async fn read_payload_async<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<usize> {
        debug_assert_eq!(self.payload.len(), self.payload_read);

        let remaining = self.payload_len.saturating_sub(self.payload_read);
        let read = poll_fn(|cx| {
            let spare = self.payload.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(&mut spare[..remaining]);
            match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        // Safety: `poll_read` initialized exactly `read` bytes into the slice borrowed from
        // `spare_capacity_mut`, and the vector length tracked initialized bytes before the call.
        unsafe {
            self.payload.set_len(self.payload_read + read);
        }
        self.payload_read += read;
        Ok(read)
    }

    /// Advances decoding by reading as many bytes as are currently available.
    ///
    /// Returns `Ok(None)` while the frame is still incomplete and `Ok(Some(len))`
    /// once a full packet payload is ready in [`FrameReader::current_payload`].
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

        match self.read_payload_async(reader).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vsock shard closed while reading packet payload",
                ));
            }
            Ok(_read) => {}
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
    /// Tracks a borrowed packet while repeated writes drain it into the TUN
    /// queue.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, written: 0 }
    }

    /// Returns the suffix that still needs to be written.
    pub(crate) fn remaining(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    /// Records one successful write and reports whether the whole slice is now
    /// complete.
    pub(crate) fn advance(&mut self, written: usize) -> bool {
        self.written += written;
        self.written == self.bytes.len()
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
    /// Prepares a borrowed packet for length-prefixed transmission on a VSOCK
    /// shard.
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

    fn remaining_header(&self) -> &[u8] {
        &self.header[self.header_written..]
    }

    fn remaining_body(&self) -> &[u8] {
        &self.body[self.body_written..]
    }

    fn advance(&mut self, written: usize) -> bool {
        let header_remaining = self.header.len() - self.header_written;
        if written < header_remaining {
            self.header_written += written;
        } else {
            self.header_written = self.header.len();
            self.body_written += written - header_remaining;
        }

        self.header_written == self.header.len() && self.body_written == self.body.len()
    }

    /// Writes as much of the frame as the underlying stream currently accepts
    /// and reports whether header and payload are both complete.
    pub(crate) async fn write_to_async<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> io::Result<bool> {
        let header = self.remaining_header();
        let body = self.remaining_body();
        let written = if !header.is_empty() && !body.is_empty() {
            let bufs = [IoSlice::new(header), IoSlice::new(body)];
            writer.write_vectored(&bufs).await?
        } else {
            writer
                .write(if !header.is_empty() { header } else { body })
                .await?
        };

        match written {
            0 => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to make forward progress while writing packet",
            )),
            written => Ok(self.advance(written)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameReader, Hello, PendingFramedWrite, PendingSliceWrite};
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use tempfile::tempfile;
    use tokio::io::{self as tokio_io, AsyncWriteExt};
    use tokio::runtime::Builder;

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

    fn test_runtime() -> tokio::runtime::Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should be created")
    }

    fn read_hello<R: Read>(reader: &mut R) -> io::Result<Hello> {
        let mut bytes = [0_u8; Hello::ENCODED_LEN];
        reader.read_exact(&mut bytes)?;

        Hello::decode(bytes)
    }

    fn frame_reader_payload_capacity(reader: &FrameReader) -> usize {
        reader.payload.capacity()
    }

    fn read_frame<R: Read>(reader: &mut FrameReader, input: &mut R) -> io::Result<Option<usize>> {
        loop {
            if reader.header_read < reader.header.len() {
                match input.read(&mut reader.header[reader.header_read..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vsock shard closed while reading packet header",
                        ));
                    }
                    Ok(read) => {
                        reader.header_read += read;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                    Err(err) => return Err(err),
                }

                if reader.header_read < reader.header.len() {
                    continue;
                }

                reader.begin_payload()?;
                reader.payload.resize(reader.payload_len, 0);
            }

            match input.read(&mut reader.payload[reader.payload_read..reader.payload_len]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vsock shard closed while reading packet payload",
                    ));
                }
                Ok(read) => {
                    reader.payload_read += read;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }

            if reader.payload_read < reader.payload_len {
                continue;
            }

            reader.frame_ready = true;
            return Ok(Some(reader.payload_len));
        }
    }

    fn write_pending_slice<W: Write>(
        pending: &mut PendingSliceWrite<'_>,
        writer: &mut W,
    ) -> io::Result<bool> {
        match writer.write(pending.remaining()) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to make forward progress while writing packet",
            )),
            Ok(written) => Ok(pending.advance(written)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn write_pending_framed<W: Write>(
        pending: &mut PendingFramedWrite<'_>,
        writer: &mut W,
    ) -> io::Result<bool> {
        let header = pending.remaining_header();
        let body = pending.remaining_body();
        let bytes = if !header.is_empty() { header } else { body };
        match writer.write(bytes) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to make forward progress while writing packet",
            )),
            Ok(written) => Ok(pending.advance(written)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(err),
        }
    }

    #[test]
    fn hello_round_trip() {
        // This locks down the handshake wire format so both tunnel endpoints keep
        // agreeing on session metadata and capability bits.
        let hello = Hello::new(42, 8, 3, true);

        let encoded = hello.encode();
        let mut file = tempfile().expect("temporary file should be created");
        file.write_all(&encoded)
            .expect("hello bytes should be written to temporary file");
        reset_file(&mut file).expect("temporary file should rewind");

        let decoded = read_hello(&mut file).expect("hello bytes should decode");
        assert_eq!(decoded, hello);
        assert!(decoded.supports_raw_tun_frames());
    }

    #[test]
    fn framed_packet_round_trip() {
        // This proves the length-prefix framing preserves payload boundaries when
        // packets move between stream-oriented VSOCK and packet-oriented TUN.
        let packet = vec![1_u8, 2, 3, 4, 5];
        let mut outgoing =
            PendingFramedWrite::new(&packet).expect("packet should fit into framed payload");
        let mut file = tempfile().expect("temporary file should be created");

        while !write_pending_framed(&mut outgoing, &mut file)
            .expect("packet should write to temporary file")
        {}

        reset_file(&mut file).expect("temporary file should rewind");
        let mut reader = FrameReader::new(4096);
        let decoded_len = read_frame(&mut reader, &mut file)
            .expect("reader should decode file-backed packet")
            .expect("reader should produce one packet");
        let decoded = reader.current_payload();

        assert_eq!(decoded_len, packet.len());
        assert_eq!(decoded, packet);
    }

    #[test]
    fn frame_reader_keeps_payload_storage_after_completed_frame() {
        // This guards the reuse path that avoids reallocating for every packet on
        // long-lived shard streams.
        let packet = vec![9_u8, 8, 7, 6, 5];
        let mut outgoing =
            PendingFramedWrite::new(&packet).expect("packet should fit into framed payload");
        let mut file = tempfile().expect("temporary file should be created");

        while !write_pending_framed(&mut outgoing, &mut file)
            .expect("packet should write to temporary file")
        {}

        reset_file(&mut file).expect("temporary file should rewind");
        let mut reader = FrameReader::new(4096);
        let _decoded_len = read_frame(&mut reader, &mut file)
            .expect("reader should decode file-backed packet")
            .expect("reader should produce one packet");
        let capacity_before_finish = frame_reader_payload_capacity(&reader);

        assert!(capacity_before_finish >= packet.len());
        reader.finish_frame();
        assert_eq!(
            frame_reader_payload_capacity(&reader),
            capacity_before_finish
        );
    }

    #[test]
    fn pending_slice_write_handles_partial_writes() {
        // TUN writes may accept only part of a packet, so this verifies the
        // resumable write helper does not lose or duplicate bytes.
        let packet = [1_u8, 2, 3, 4, 5];
        let mut writer = LimitedWriter::new(2);
        let mut pending = PendingSliceWrite::new(&packet);

        while !write_pending_slice(&mut pending, &mut writer)
            .expect("partial writes should make progress")
        {}

        assert_eq!(writer.bytes, packet);
    }

    #[test]
    fn pending_framed_write_handles_partial_writes() {
        // VSOCK writes can also stop mid-header or mid-payload; this keeps the
        // framed writer honest across those boundaries.
        let packet = [1_u8, 2, 3, 4, 5];
        let mut writer = LimitedWriter::new(2);
        let mut pending =
            PendingFramedWrite::new(&packet).expect("packet should fit into framed payload");

        while !write_pending_framed(&mut pending, &mut writer)
            .expect("partial writes should make progress")
        {}

        assert_eq!(writer.bytes, [0, 0, 0, 5, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn async_frame_reader_grows_buffer_after_smaller_frame() {
        // Sessions carry differently sized packets back-to-back, so this checks
        // that one small frame does not prevent the next larger frame from being
        // read on the same shard.
        test_runtime().block_on(async {
            let small_packet = [1_u8, 2, 3, 4, 5];
            let large_packet = vec![7_u8; 72];
            let (mut writer, mut reader) = tokio_io::duplex(256);

            writer
                .write_all(
                    &u32::try_from(small_packet.len())
                        .expect("small frame len fits")
                        .to_be_bytes(),
                )
                .await
                .expect("small frame header should write");
            writer
                .write_all(&small_packet)
                .await
                .expect("small frame payload should write");

            let mut frame_reader = FrameReader::new(4096);
            let first_len = frame_reader
                .read_frame_async(&mut reader)
                .await
                .expect("first frame should decode")
                .expect("first frame should be complete");
            assert_eq!(first_len, small_packet.len());
            assert_eq!(frame_reader.current_payload(), small_packet);
            frame_reader.finish_frame();

            writer
                .write_all(
                    &u32::try_from(large_packet.len())
                        .expect("large frame len fits")
                        .to_be_bytes(),
                )
                .await
                .expect("large frame header should write");
            writer
                .write_all(&large_packet)
                .await
                .expect("large frame payload should write");

            let second_len = frame_reader
                .read_frame_async(&mut reader)
                .await
                .expect("larger second frame should decode")
                .expect("second frame should be complete");
            assert_eq!(second_len, large_packet.len());
            assert_eq!(frame_reader.current_payload(), large_packet);
        });
    }
}
