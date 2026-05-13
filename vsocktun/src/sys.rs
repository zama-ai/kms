use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::raw::{c_int, c_short, c_ulong, c_void};

pub(crate) const AF_VSOCK: c_int = 40;
pub(crate) const F_GETFL: c_int = 3;
pub(crate) const F_SETFL: c_int = 4;
pub(crate) const IFF_MULTI_QUEUE: c_short = 0x0100;
pub(crate) const IFF_NO_PI: c_short = 0x1000;
pub(crate) const IFF_TUN: c_short = 0x0001;
pub(crate) const O_NONBLOCK: c_int = 0x0800;
pub(crate) const POLLERR: c_short = 0x0008;
pub(crate) const POLLHUP: c_short = 0x0010;
pub(crate) const POLLIN: c_short = 0x0001;
pub(crate) const POLLOUT: c_short = 0x0004;
pub(crate) const SOCK_STREAM: c_int = 1;
pub(crate) const TUNSETIFF: c_ulong = 0x4004_54ca;
pub(crate) const VMADDR_CID_ANY: u32 = u32::MAX;

#[repr(C)]
pub(crate) struct SockAddrVm {
    pub(crate) svm_family: u16,
    pub(crate) svm_reserved1: u16,
    pub(crate) svm_port: u32,
    pub(crate) svm_cid: u32,
    pub(crate) svm_zero: [u8; 4],
}

impl SockAddrVm {
    pub(crate) fn new(cid: u32, port: u32) -> Self {
        Self {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0_u8; 4],
        }
    }
}

#[repr(C)]
pub(crate) struct IfReq {
    pub(crate) name: [u8; 16],
    pub(crate) flags: c_short,
    pub(crate) padding: [u8; 24],
}

impl IfReq {
    pub(crate) fn new(name: &str, flags: c_short) -> io::Result<Self> {
        if name.is_empty() || name.len() >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN interface name must be between 1 and 15 bytes",
            ));
        }

        let mut req = Self {
            name: [0_u8; 16],
            flags,
            padding: [0_u8; 24],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(req)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PollFd {
    pub(crate) fd: RawFd,
    pub(crate) events: c_short,
    pub(crate) revents: c_short,
}

unsafe extern "C" {
    fn accept(fd: c_int, addr: *mut c_void, addrlen: *mut u32) -> c_int;
    fn bind(fd: c_int, addr: *const c_void, addrlen: u32) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, addrlen: u32) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, arg: c_int) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, argp: *mut c_void) -> c_int;
    fn listen(fd: c_int, backlog: c_int) -> c_int;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
    fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
}

pub(crate) struct Listener {
    fd: RawFd,
}

impl Listener {
    pub(crate) fn bind_vsock(port: u32, backlog: c_int) -> io::Result<Self> {
        let fd = create_vsock_socket()?;
        let addr = SockAddrVm::new(VMADDR_CID_ANY, port);
        let bind_result = unsafe {
            bind(
                fd,
                (&addr as *const SockAddrVm).cast(),
                size_of::<SockAddrVm>() as u32,
            )
        };

        if bind_result != 0 {
            let err = io::Error::last_os_error();
            let _ = unsafe { close(fd) };
            return Err(err);
        }

        let listen_result = unsafe { listen(fd, backlog) };
        if listen_result != 0 {
            let err = io::Error::last_os_error();
            let _ = unsafe { close(fd) };
            return Err(err);
        }

        Ok(Self { fd })
    }

    pub(crate) fn accept(&self) -> io::Result<File> {
        let fd = unsafe { accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let file = unsafe { File::from_raw_fd(fd) };
        Ok(file)
    }

    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = unsafe { close(self.fd) };
    }
}

pub(crate) fn connect_vsock(cid: u32, port: u32) -> io::Result<File> {
    let fd = create_vsock_socket()?;
    let addr = SockAddrVm::new(cid, port);
    let connect_result = unsafe {
        connect(
            fd,
            (&addr as *const SockAddrVm).cast(),
            size_of::<SockAddrVm>() as u32,
        )
    };

    if connect_result != 0 {
        let err = io::Error::last_os_error();
        let _ = unsafe { close(fd) };
        return Err(err);
    }

    let file = unsafe { File::from_raw_fd(fd) };
    Ok(file)
}

pub(crate) fn set_nonblocking(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let flags = unsafe { fcntl(fd, F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }

    let set_result = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if set_result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub(crate) fn tun_set_iff(file: &File, request: &mut IfReq) -> io::Result<()> {
    let result = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, (request as *mut IfReq).cast()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub(crate) fn poll_once(fds: &mut [PollFd], timeout_ms: i32) -> io::Result<()> {
    let ready = unsafe { poll(fds.as_mut_ptr(), fds.len(), timeout_ms) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn create_vsock_socket() -> io::Result<RawFd> {
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(fd)
}
