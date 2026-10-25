use std::{io, net::UdpSocket};

pub(super) enum BatchError {
    Unsupported,
    Retry,
    Failed(io::Error),
    /// The segmented send completed, but restoring the socket option failed.
    #[cfg(windows)]
    SentThenFailed(usize),
}

#[cfg(target_os = "linux")]
pub(super) struct BatchSender;

#[cfg(target_os = "linux")]
impl BatchSender {
    pub(super) fn new(_: &UdpSocket) -> Self {
        Self
    }

    pub(super) fn send(
        &self,
        socket: &UdpSocket,
        payload: &[u8],
        segment_size: usize,
    ) -> Result<usize, BatchError> {
        send_linux(socket, payload, segment_size)
    }
}

#[cfg(windows)]
pub(super) struct BatchSender;

#[cfg(windows)]
impl BatchSender {
    pub(super) fn new(_: &UdpSocket) -> Self {
        Self
    }

    pub(super) fn send(
        &self,
        socket: &UdpSocket,
        payload: &[u8],
        segment_size: usize,
    ) -> Result<usize, BatchError> {
        send_windows(socket, payload, segment_size)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(super) struct BatchSender;

#[cfg(not(any(target_os = "linux", windows)))]
impl BatchSender {
    pub(super) fn new(_: &UdpSocket) -> Self {
        Self
    }

    pub(super) fn send(&self, _: &UdpSocket, _: &[u8], _: usize) -> Result<usize, BatchError> {
        Err(BatchError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
fn send_linux(
    socket: &UdpSocket,
    payload: &[u8],
    segment_size: usize,
) -> Result<usize, BatchError> {
    use std::os::fd::AsRawFd;

    // UDP_SEGMENT is Linux UAPI option 103 (linux/udp.h). The control buffer
    // stays alive and suitably aligned until sendmsg returns.
    const UDP_SEGMENT: libc::c_int = 103;
    #[repr(C, align(8))]
    struct Control([u8; 24]);

    let mut control = Control([0; 24]);
    let control_alignment = std::mem::size_of::<usize>();
    let control_data_offset = align_up(std::mem::size_of::<libc::cmsghdr>(), control_alignment);
    let control_message_length = control_data_offset + std::mem::size_of::<u16>();
    let control_length = align_up(control_message_length, control_alignment);
    let header = libc::cmsghdr {
        cmsg_len: control_message_length,
        cmsg_level: libc::IPPROTO_UDP,
        cmsg_type: UDP_SEGMENT,
    };
    // SAFETY: the aligned byte buffer is at least CMSG_SPACE(sizeof(u16)); its
    // header and data pointers lie inside it and remain valid through sendmsg.
    unsafe {
        control.0.as_mut_ptr().cast::<libc::cmsghdr>().write(header);
        control
            .0
            .as_mut_ptr()
            .add(control_data_offset)
            .cast::<u16>()
            .write(segment_size as u16);
    }
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: all pointed-to buffers remain alive for the synchronous syscall.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control_length;

    // SAFETY: socket is a live connected UDP socket and msg references valid
    // Rust-owned buffers for the duration of sendmsg.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, 0) };
    if sent >= 0 {
        return Ok(sent as usize);
    }
    classify_linux_error(io::Error::last_os_error())
}

#[cfg(target_os = "linux")]
fn classify_linux_error(error: io::Error) -> Result<usize, BatchError> {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Err(BatchError::Retry),
        _ if matches!(error.raw_os_error(), Some(22 | 38 | 90 | 92 | 95)) => {
            // EMSGSIZE, EINVAL, ENOSYS, ENOPROTOOPT or EOPNOTSUPP means this
            // batch cannot use UDP_SEGMENT. No datagrams were accepted, so
            // retrying the group as individual sends is safe.
            Err(BatchError::Unsupported)
        }
        _ => Err(BatchError::Failed(error)),
    }
}

#[cfg(windows)]
fn send_windows(
    socket: &UdpSocket,
    payload: &[u8],
    segment_size: usize,
) -> Result<usize, BatchError> {
    use std::{mem::size_of, os::windows::io::AsRawSocket};
    use windows_sys::Win32::Networking::WinSock::{
        IPPROTO_UDP, SOCKET, UDP_SEND_MSG_SIZE, WSAGetLastError, setsockopt,
    };

    let raw_socket = socket.as_raw_socket() as SOCKET;
    let segment_size = segment_size as u32;
    // Microsoft documents UDP_SEND_MSG_SIZE as an IPPROTO_UDP socket option
    // (with WSASetUdpSendMessageSize as its typed wrapper), not a WSAMSG cmsg.
    // Set it for this synchronous send and restore zero before reusing the
    // socket for another packet size.
    // SAFETY: setsockopt reads the live DWORD pointer for the provided length.
    if unsafe {
        setsockopt(
            raw_socket,
            IPPROTO_UDP,
            UDP_SEND_MSG_SIZE,
            (&segment_size as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    } != 0
    {
        return classify_windows_error(unsafe { WSAGetLastError() });
    }

    let send_result = socket.send(payload);
    let disabled_size = 0_u32;
    // SAFETY: this resets the same option using a live DWORD pointer.
    let reset_result = unsafe {
        setsockopt(
            raw_socket,
            IPPROTO_UDP,
            UDP_SEND_MSG_SIZE,
            (&disabled_size as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if reset_result != 0 {
        let reset_error = unsafe { WSAGetLastError() };
        return match send_result {
            Ok(bytes) => Err(BatchError::SentThenFailed(bytes)),
            Err(_) => Err(BatchError::Failed(io::Error::other(format!(
                "failed to restore UDP segmentation size (Winsock error {reset_error})"
            )))),
        };
    }
    send_result.map_err(classify_windows_io_error)
}

#[cfg(windows)]
fn classify_windows_error(code: i32) -> Result<usize, BatchError> {
    match code {
        10004 | 10035 => Err(BatchError::Retry), // WSAEINTR / WSAEWOULDBLOCK
        10022 | 10040 | 10042 | 10045 | 10047 => Err(BatchError::Unsupported),
        _ => Err(BatchError::Failed(io::Error::other(format!(
            "Winsock send error {code}"
        )))),
    }
}

#[cfg(windows)]
fn classify_windows_io_error(error: io::Error) -> BatchError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => BatchError::Retry,
        _ if matches!(
            error.raw_os_error(),
            Some(10022 | 10040 | 10042 | 10045 | 10047)
        ) =>
        {
            BatchError::Unsupported
        }
        _ => BatchError::Failed(error),
    }
}

#[cfg(target_os = "linux")]
fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}
