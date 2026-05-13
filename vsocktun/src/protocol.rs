use std::fs::File;
use std::io::{self, Read, Write};

const HELLO_MAGIC: [u8; 8] = *b"VSTUN001";
const HELLO_RESERVED_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hello {
    pub(crate) session_id: u64,
    pub(crate) queues: u16,
    pub(crate) shard: u16,
}

impl Hello {
    pub(crate) const ENCODED_LEN: usize = HELLO_MAGIC.len() + 8 + 2 + 2 + HELLO_RESERVED_BYTES;

    pub(crate) fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        bytes[..HELLO_MAGIC.len()].copy_from_slice(&HELLO_MAGIC);
        bytes[8..16].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.queues.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.shard.to_be_bytes());
        bytes
    }

    pub(crate) fn read_from(file: &mut File) -> io::Result<Self> {
        let mut bytes = [0_u8; Self::ENCODED_LEN];
        file.read_exact(&mut bytes)?;

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

        Ok(Self {
            session_id,
            queues,
            shard,
        })
    }

    pub(crate) fn write_to(self, file: &mut File) -> io::Result<()> {
        file.write_all(&self.encode())
    }
}

#[derive(Debug)]
pub(crate) struct FrameReader {
    header: [u8; 2],
    header_read: usize,
    payload: Vec<u8>,
    payload_read: usize,
}

impl FrameReader {
    pub(crate) fn new() -> Self {
        Self {
            header: [0_u8; 2],
            header_read: 0,
            payload: Vec::new(),
            payload_read: 0,
        }
    }

    pub(crate) fn read_packet(&mut self, file: &mut File) -> io::Result<Option<Vec<u8>>> {
        loop {
            if self.header_read < self.header.len() {
                match file.read(&mut self.header[self.header_read..]) {
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

                let payload_len = u16::from_be_bytes(self.header) as usize;
                if payload_len == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "received empty framed packet",
                    ));
                }

                self.payload.clear();
                self.payload.resize(payload_len, 0);
                self.payload_read = 0;
            }

            match file.read(&mut self.payload[self.payload_read..]) {
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

            if self.payload_read < self.payload.len() {
                continue;
            }

            self.header = [0_u8; 2];
            self.header_read = 0;
            self.payload_read = 0;
            return Ok(Some(std::mem::take(&mut self.payload)));
        }
    }
}

#[derive(Debug)]
pub(crate) struct OutgoingBuffer {
    bytes: Vec<u8>,
    written: usize,
}

impl OutgoingBuffer {
    pub(crate) fn framed(packet: &[u8]) -> io::Result<Self> {
        let packet_len = u16::try_from(packet.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds maximum framed size of 65535 bytes",
            )
        })?;

        let mut bytes = Vec::with_capacity(packet.len() + 2);
        bytes.extend_from_slice(&packet_len.to_be_bytes());
        bytes.extend_from_slice(packet);
        Ok(Self { bytes, written: 0 })
    }

    pub(crate) fn raw(packet: Vec<u8>) -> Self {
        Self {
            bytes: packet,
            written: 0,
        }
    }

    pub(crate) fn write_to(&mut self, file: &mut File) -> io::Result<bool> {
        match file.write(&self.bytes[self.written..]) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to make forward progress while writing packet",
            )),
            Ok(written) => {
                self.written += written;
                Ok(self.written == self.bytes.len())
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameReader, Hello, OutgoingBuffer};
    use std::fs::File;
    use std::io::{self, Seek, SeekFrom, Write};
    use tempfile::tempfile;

    fn reset_file(file: &mut File) -> io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    #[test]
    fn hello_round_trip() {
        let hello = Hello {
            session_id: 42,
            queues: 8,
            shard: 3,
        };

        let encoded = hello.encode();
        let mut file = tempfile().expect("temporary file should be created");
        file.write_all(&encoded)
            .expect("hello bytes should be written to temporary file");
        reset_file(&mut file).expect("temporary file should rewind");

        let decoded = Hello::read_from(&mut file).expect("hello bytes should decode");
        assert_eq!(decoded, hello);
    }

    #[test]
    fn framed_packet_round_trip() {
        let packet = vec![1_u8, 2, 3, 4, 5];
        let mut outgoing =
            OutgoingBuffer::framed(&packet).expect("packet should fit into two-byte frame");
        let mut file = tempfile().expect("temporary file should be created");

        while !outgoing
            .write_to(&mut file)
            .expect("packet should write to temporary file")
        {}

        reset_file(&mut file).expect("temporary file should rewind");
        let mut reader = FrameReader::new();
        let decoded = reader
            .read_packet(&mut file)
            .expect("reader should decode file-backed packet")
            .expect("reader should produce one packet");

        assert_eq!(decoded, packet);
    }
}
