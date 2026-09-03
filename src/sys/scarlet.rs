// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ffi::c_void;
use std::io::{self, IoSlice, Read, Write};
use std::mem::{self, ManuallyDrop, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::ptr;
use std::slice;
use std::time::Duration;

use scarlet_os::poll::{poll, PollHandle, POLLERR, POLLHUP, POLLOUT};
use scarlet_os::socket::{
    DatagramOps, Inet4SocketAddress, ShutdownHow, Socket as NativeSocket, SocketAddress,
    SocketDomain, SocketError, SocketProtocol, SocketType,
};

use crate::{Domain, MsgHdr, Protocol, RecvFlags, SockAddr, SockAddrStorage, TcpKeepalive, Type};

pub(crate) use std::ffi::c_int;

#[allow(non_camel_case_types)]
pub type sa_family_t = u16;
#[allow(non_camel_case_types)]
pub type socklen_t = u32;

pub(crate) const AF_UNIX: c_int = 1;
pub(crate) const AF_INET: c_int = 2;
pub(crate) const AF_INET6: c_int = 3;

pub(crate) const SOCK_STREAM: c_int = 1;
pub(crate) const SOCK_DGRAM: c_int = 2;
pub(crate) const SOCK_RAW: c_int = 3;
pub(crate) const SOCK_SEQPACKET: c_int = 4;

pub(crate) const IPPROTO_IP: c_int = 0;
pub(crate) const IPPROTO_ICMP: c_int = 1;
pub(crate) const IPPROTO_TCP: c_int = 6;
pub(crate) const IPPROTO_UDP: c_int = 17;
pub(crate) const IPPROTO_IPV6: c_int = 41;
pub(crate) const IPPROTO_ICMPV6: c_int = 58;

pub(crate) const SOL_SOCKET: c_int = 1;
pub(crate) const SO_REUSEADDR: c_int = 2;
pub(crate) const SO_TYPE: c_int = 3;
pub(crate) const SO_ERROR: c_int = 4;
pub(crate) const SO_BROADCAST: c_int = 6;
pub(crate) const SO_SNDBUF: c_int = 7;
pub(crate) const SO_RCVBUF: c_int = 8;
pub(crate) const SO_KEEPALIVE: c_int = 9;
pub(crate) const SO_OOBINLINE: c_int = 10;
pub(crate) const SO_LINGER: c_int = 13;
pub(crate) const SO_RCVTIMEO: c_int = 20;
pub(crate) const SO_SNDTIMEO: c_int = 21;

pub(crate) const IP_TOS: c_int = 1;
pub(crate) const IP_TTL: c_int = 2;
pub(crate) const IP_HDRINCL: c_int = 3;
pub(crate) const IP_MULTICAST_IF: c_int = 32;
pub(crate) const IP_MULTICAST_TTL: c_int = 33;
pub(crate) const IP_MULTICAST_LOOP: c_int = 34;
pub(crate) const IP_ADD_MEMBERSHIP: c_int = 35;
pub(crate) const IP_DROP_MEMBERSHIP: c_int = 36;
pub(crate) const IP_RECVTOS: c_int = 13;
pub(crate) const IP_ADD_SOURCE_MEMBERSHIP: c_int = 39;
pub(crate) const IP_DROP_SOURCE_MEMBERSHIP: c_int = 40;

pub(crate) const IPV6_V6ONLY: c_int = 26;
pub(crate) const IPV6_UNICAST_HOPS: c_int = 16;
pub(crate) const IPV6_MULTICAST_IF: c_int = 17;
pub(crate) const IPV6_MULTICAST_HOPS: c_int = 18;
pub(crate) const IPV6_MULTICAST_LOOP: c_int = 19;
pub(crate) const IPV6_ADD_MEMBERSHIP: c_int = 20;
pub(crate) const IPV6_DROP_MEMBERSHIP: c_int = 21;
pub(crate) const IPV6_RECVHOPLIMIT: c_int = 51;
pub(crate) const IPV6_RECVTCLASS: c_int = 66;

pub(crate) const TCP_NODELAY: c_int = 1;

pub(crate) const MSG_OOB: c_int = 0x01;
pub(crate) const MSG_PEEK: c_int = 0x02;
pub(crate) const MSG_TRUNC: c_int = 0x20;
const MSG_EOR: c_int = 0x80;

pub(crate) type Bool = c_int;

mod constants {
    pub(super) use super::{
        AF_INET, AF_INET6, AF_UNIX, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
        SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
    };
}

impl_debug!(
    Domain,
    constants::AF_INET,
    constants::AF_INET6,
    constants::AF_UNIX,
);

impl_debug!(
    Type,
    constants::SOCK_STREAM,
    constants::SOCK_DGRAM,
    constants::SOCK_RAW,
    constants::SOCK_SEQPACKET,
);

impl_debug!(
    Protocol,
    constants::IPPROTO_ICMP,
    constants::IPPROTO_ICMPV6,
    constants::IPPROTO_TCP,
    constants::IPPROTO_UDP,
);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    _padding: [u8; 126],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct sockaddr_un {
    sun_family: sa_family_t,
    sun_path: [i8; 108],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct IpMreq {
    pub(crate) imr_multiaddr: in_addr,
    pub(crate) imr_interface: in_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct IpMreqSource {
    pub(crate) imr_multiaddr: in_addr,
    pub(crate) imr_interface: in_addr,
    pub(crate) imr_sourceaddr: in_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Ipv6Mreq {
    pub(crate) ipv6mr_multiaddr: in6_addr,
    pub(crate) ipv6mr_interface: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct IpMreqn {
    imr_multiaddr: in_addr,
    imr_address: in_addr,
    imr_ifindex: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct linger {
    pub(crate) l_onoff: c_int,
    pub(crate) l_linger: c_int,
}

#[repr(transparent)]
pub struct MaybeUninitSlice<'a>(&'a mut [MaybeUninit<u8>]);

// SAFETY: `MaybeUninitSlice` exclusively borrows a mutable byte slice, whose
// elements are `Send` and `Sync`.
unsafe impl<'a> Send for MaybeUninitSlice<'a> {}
// SAFETY: See the `Send` implementation above.
unsafe impl<'a> Sync for MaybeUninitSlice<'a> {}

impl<'a> MaybeUninitSlice<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> MaybeUninitSlice<'a> {
        MaybeUninitSlice(buf)
    }

    pub(crate) fn as_slice(&self) -> &[MaybeUninit<u8>] {
        self.0
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        self.0
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub(crate) struct msghdr {
    msg_name: *mut c_void,
    msg_namelen: socklen_t,
    msg_iov: *mut c_void,
    msg_iovlen: usize,
    msg_control: *mut c_void,
    msg_controllen: usize,
    msg_flags: c_int,
}

pub(crate) fn set_msghdr_name(msg: &mut msghdr, name: &SockAddr) {
    msg.msg_name = name.as_ptr().cast_mut().cast();
    msg.msg_namelen = name.len();
}

pub(crate) fn set_msghdr_iov(msg: &mut msghdr, ptr: *mut c_void, len: usize) {
    msg.msg_iov = ptr;
    msg.msg_iovlen = len;
}

pub(crate) fn set_msghdr_control(msg: &mut msghdr, ptr: *mut c_void, len: usize) {
    msg.msg_control = ptr;
    msg.msg_controllen = len;
}

pub(crate) fn set_msghdr_flags(msg: &mut msghdr, flags: c_int) {
    msg.msg_flags = flags;
}

pub(crate) fn msghdr_flags(msg: &msghdr) -> RecvFlags {
    RecvFlags(msg.msg_flags)
}

pub(crate) fn msghdr_control_len(msg: &msghdr) -> usize {
    msg.msg_controllen
}

impl RecvFlags {
    /// Check if this is the final record in a sequenced-packet message.
    pub const fn is_end_of_record(self) -> bool {
        self.0 & MSG_EOR != 0
    }

    /// Check if the message contains out-of-band data.
    pub const fn is_out_of_band(self) -> bool {
        self.0 & MSG_OOB != 0
    }
}

impl std::fmt::Debug for RecvFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvFlags")
            .field("is_end_of_record", &self.is_end_of_record())
            .field("is_out_of_band", &self.is_out_of_band())
            .field("is_truncated", &self.is_truncated())
            .finish()
    }
}

pub(crate) struct Socket(NativeSocket);
pub(crate) type RawSocket = c_int;

pub(crate) unsafe fn socket_from_raw(socket: RawSocket) -> Socket {
    // SAFETY: the caller transfers ownership of a valid Scarlet socket handle.
    Socket(unsafe { NativeSocket::from_raw(socket) })
}

pub(crate) fn socket_as_raw(socket: &Socket) -> RawSocket {
    socket.0.as_raw()
}

pub(crate) fn socket_into_raw(socket: Socket) -> RawSocket {
    native_socket_into_raw(socket.0)
}

fn native_socket_into_raw(socket: NativeSocket) -> RawSocket {
    let handle = ManuallyDrop::new(socket.into_handle());
    handle.as_raw()
}

fn borrowed_socket(fd: RawSocket) -> ManuallyDrop<NativeSocket> {
    // SAFETY: all callers hold a live owning `sys::Socket` for `fd`. The
    // `ManuallyDrop` makes this a borrowed view and prevents a second close.
    ManuallyDrop::new(unsafe { NativeSocket::from_raw(fd) })
}

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<RawSocket> {
    let domain = match family {
        AF_UNIX => SocketDomain::Local,
        AF_INET => SocketDomain::Inet4,
        AF_INET6 => SocketDomain::Inet6,
        _ => return Err(invalid_input("unsupported Scarlet socket domain")),
    };
    let socket_type = match ty {
        SOCK_STREAM => SocketType::Stream,
        SOCK_DGRAM => SocketType::Datagram,
        SOCK_RAW => SocketType::Raw,
        SOCK_SEQPACKET => SocketType::SeqPacket,
        _ => return Err(invalid_input("unsupported Scarlet socket type")),
    };
    let protocol = match protocol {
        0 => SocketProtocol::Default,
        IPPROTO_ICMP => SocketProtocol::Icmp,
        IPPROTO_TCP => SocketProtocol::Tcp,
        IPPROTO_UDP => SocketProtocol::Udp,
        _ => return Err(invalid_input("unsupported Scarlet socket protocol")),
    };

    NativeSocket::new_with_domain(domain, socket_type, protocol)
        .map(native_socket_into_raw)
        .map_err(socket_error)
}

pub(crate) fn bind(fd: RawSocket, addr: &SockAddr) -> io::Result<()> {
    let socket = borrowed_socket(fd);
    match addr.as_socket() {
        Some(SocketAddr::V4(addr)) => socket.bind_inet(to_native_v4(addr)).map_err(socket_error),
        Some(SocketAddr::V6(_)) => Err(unsupported("Scarlet IPv6 sockets are not implemented")),
        None if addr.family() == AF_UNIX as sa_family_t => {
            with_unix_address(addr, |name, abstract_name| {
                if abstract_name {
                    socket.bind_abstract(name)
                } else {
                    socket.bind(name)
                }
            })
        }
        None => Err(invalid_input("unsupported Scarlet socket address")),
    }
}

pub(crate) fn connect(fd: RawSocket, addr: &SockAddr) -> io::Result<()> {
    let socket = borrowed_socket(fd);
    match addr.as_socket() {
        Some(SocketAddr::V4(addr)) => socket
            .connect_inet(to_native_v4(addr))
            .map_err(socket_error),
        Some(SocketAddr::V6(_)) => Err(unsupported("Scarlet IPv6 sockets are not implemented")),
        None if addr.family() == AF_UNIX as sa_family_t => {
            with_unix_address(addr, |name, abstract_name| {
                if abstract_name {
                    socket.connect_abstract(name)
                } else {
                    socket.connect(name)
                }
            })
        }
        None => Err(invalid_input("unsupported Scarlet socket address")),
    }
}

pub(crate) fn poll_connect(socket: &crate::Socket, timeout: Duration) -> io::Result<()> {
    let timeout_ns = i64::try_from(timeout.as_nanos()).unwrap_or(i64::MAX);
    let mut handles = [PollHandle::new(
        socket.as_raw() as u32,
        POLLOUT | POLLERR | POLLHUP,
    )];
    let ready = poll(&mut handles, timeout_ns)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Scarlet poll failed"))?;
    if ready == 0 {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if handles[0].revents & (POLLERR | POLLHUP) != 0 {
        return match socket.take_error()? {
            Some(error) => Err(error),
            None => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Scarlet socket connect failed",
            )),
        };
    }
    Ok(())
}

pub(crate) fn listen(fd: RawSocket, backlog: c_int) -> io::Result<()> {
    if backlog < 0 {
        return Err(invalid_input("negative socket backlog"));
    }
    borrowed_socket(fd)
        .listen(backlog as usize)
        .map_err(socket_error)
}

pub(crate) fn accept(fd: RawSocket) -> io::Result<(RawSocket, SockAddr)> {
    let socket = borrowed_socket(fd).accept().map_err(socket_error)?;
    let peer = native_address(SocketAddress::Inet(
        socket.peer_addr_inet().map_err(socket_error)?,
    ))?;
    Ok((native_socket_into_raw(socket), peer))
}

pub(crate) fn getsockname(fd: RawSocket) -> io::Result<SockAddr> {
    let address = borrowed_socket(fd)
        .local_addr_inet()
        .map_err(socket_error)?;
    native_address(SocketAddress::Inet(address))
}

pub(crate) fn getpeername(fd: RawSocket) -> io::Result<SockAddr> {
    let address = borrowed_socket(fd).peer_addr_inet().map_err(socket_error)?;
    native_address(SocketAddress::Inet(address))
}

pub(crate) fn try_clone(fd: RawSocket) -> io::Result<RawSocket> {
    let socket = borrowed_socket(fd);
    let handle = socket
        .as_handle()
        .duplicate()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to duplicate Scarlet handle"))?;
    NativeSocket::from_handle(handle)
        .map(native_socket_into_raw)
        .map_err(socket_error)
}

pub(crate) fn nonblocking(fd: RawSocket) -> io::Result<bool> {
    borrowed_socket(fd).is_nonblocking().map_err(socket_error)
}

pub(crate) fn set_nonblocking(fd: RawSocket, nonblocking: bool) -> io::Result<()> {
    borrowed_socket(fd)
        .set_nonblocking(nonblocking)
        .map_err(socket_error)
}

pub(crate) fn shutdown(fd: RawSocket, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Read => ShutdownHow::Read,
        Shutdown::Write => ShutdownHow::Write,
        Shutdown::Both => ShutdownHow::Both,
    };
    borrowed_socket(fd).shutdown(how).map_err(socket_error)
}

pub(crate) fn recv(fd: RawSocket, buf: &mut [MaybeUninit<u8>], flags: c_int) -> io::Result<usize> {
    require_no_flags(flags)?;
    let mut initialized = vec![0; buf.len()];
    let read = borrowed_socket(fd).read(&mut initialized)?;
    copy_to_uninit(buf, &initialized[..read]);
    Ok(read)
}

pub(crate) fn recv_from(
    fd: RawSocket,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    require_no_flags(flags)?;
    let mut initialized = vec![0; buf.len()];
    let (read, address) = borrowed_socket(fd)
        .recvfrom(&mut initialized)
        .map_err(socket_error)?;
    copy_to_uninit(buf, &initialized[..read]);
    Ok((read, native_address(address)?))
}

pub(crate) fn peek_sender(_fd: RawSocket) -> io::Result<SockAddr> {
    Err(unsupported("Scarlet socket peek is not implemented"))
}

pub(crate) fn recv_vectored(
    fd: RawSocket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags)> {
    require_no_flags(flags)?;
    let capacity = bufs.iter().map(|buf| buf.len()).sum();
    let mut initialized = vec![0; capacity];
    let read = borrowed_socket(fd).read(&mut initialized)?;
    scatter_to_uninit(bufs, &initialized[..read]);
    Ok((read, RecvFlags(0)))
}

pub(crate) fn recv_from_vectored(
    fd: RawSocket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags, SockAddr)> {
    require_no_flags(flags)?;
    let capacity = bufs.iter().map(|buf| buf.len()).sum();
    let mut initialized = vec![0; capacity];
    let (read, address) = borrowed_socket(fd)
        .recvfrom(&mut initialized)
        .map_err(socket_error)?;
    scatter_to_uninit(bufs, &initialized[..read]);
    Ok((read, RecvFlags(0), native_address(address)?))
}

pub(crate) fn send(fd: RawSocket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    require_no_flags(flags)?;
    borrowed_socket(fd).write(buf)
}

pub(crate) fn send_vectored(
    fd: RawSocket,
    bufs: &[IoSlice<'_>],
    flags: c_int,
) -> io::Result<usize> {
    require_no_flags(flags)?;
    let buffer = gather(bufs);
    borrowed_socket(fd).write(&buffer)
}

pub(crate) fn send_to(
    fd: RawSocket,
    buf: &[u8],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    require_no_flags(flags)?;
    let address = sockaddr_to_native(addr)?;
    borrowed_socket(fd)
        .sendto(buf, &address)
        .map_err(socket_error)
}

pub(crate) fn send_to_vectored(
    fd: RawSocket,
    bufs: &[IoSlice<'_>],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    send_to(fd, &gather(bufs), addr, flags)
}

pub(crate) fn sendmsg(
    _fd: RawSocket,
    _msg: &MsgHdr<'_, '_, '_>,
    _flags: c_int,
) -> io::Result<usize> {
    Err(unsupported("Scarlet sendmsg is not implemented"))
}

pub(crate) fn timeout_opt(
    _fd: RawSocket,
    _opt: c_int,
    _val: c_int,
) -> io::Result<Option<Duration>> {
    Err(unsupported("Scarlet socket timeouts are not implemented"))
}

pub(crate) fn set_timeout_opt(
    _fd: RawSocket,
    _opt: c_int,
    _val: c_int,
    _duration: Option<Duration>,
) -> io::Result<()> {
    Err(unsupported("Scarlet socket timeouts are not implemented"))
}

pub(crate) fn tcp_keepalive_time(_fd: RawSocket) -> io::Result<Duration> {
    Err(unsupported("Scarlet TCP keepalive is not implemented"))
}

pub(crate) fn set_tcp_keepalive(_fd: RawSocket, keepalive: &TcpKeepalive) -> io::Result<()> {
    let _ = (keepalive.time, keepalive.interval, keepalive.retries);
    Err(unsupported("Scarlet TCP keepalive is not implemented"))
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn getsockopt<T>(fd: RawSocket, opt: c_int, val: c_int) -> io::Result<T> {
    if opt == SOL_SOCKET && val == SO_ERROR {
        if mem::size_of::<T>() != mem::size_of::<c_int>() {
            return Err(invalid_input("invalid Scarlet socket option type"));
        }
        let value: c_int = borrowed_socket(fd)
            .take_error()
            .map_err(socket_error)?
            .unwrap_or(0);
        // SAFETY: the option contract requires `T` to be `c_int`, verified by
        // size above. `c_int` has no drop glue and the copied value is valid.
        return Ok(unsafe { ptr::read(ptr::addr_of!(value).cast::<T>()) });
    }
    Err(unsupported("Scarlet socket option is not implemented"))
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn setsockopt<T>(
    _fd: RawSocket,
    _opt: c_int,
    _val: c_int,
    _payload: T,
) -> io::Result<()> {
    Err(unsupported("Scarlet socket option is not implemented"))
}

pub(crate) const fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
    in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(addr: in_addr) -> Ipv4Addr {
    Ipv4Addr::from(addr.s_addr.to_ne_bytes())
}

pub(crate) const fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    in6_addr {
        s6_addr: addr.octets(),
    }
}

pub(crate) fn from_in6_addr(addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

pub(crate) const fn to_mreqn(
    multiaddr: &Ipv4Addr,
    interface: &crate::socket::InterfaceIndexOrAddress,
) -> IpMreqn {
    match interface {
        crate::socket::InterfaceIndexOrAddress::Index(interface) => IpMreqn {
            imr_multiaddr: to_in_addr(multiaddr),
            imr_address: to_in_addr(&Ipv4Addr::UNSPECIFIED),
            imr_ifindex: *interface as c_int,
        },
        crate::socket::InterfaceIndexOrAddress::Address(interface) => IpMreqn {
            imr_multiaddr: to_in_addr(multiaddr),
            imr_address: to_in_addr(interface),
            imr_ifindex: 0,
        },
    }
}

pub(crate) fn unix_sockaddr(path: &Path) -> io::Result<SockAddr> {
    let path = path
        .to_str()
        .ok_or_else(|| invalid_input("Scarlet local socket path must be UTF-8"))?;
    let bytes = path.as_bytes();
    let abstract_name = bytes.first() == Some(&0);
    let payload = if abstract_name { &bytes[1..] } else { bytes };
    if payload.is_empty() || payload.len() + usize::from(!abstract_name) > 108 {
        return Err(invalid_input("Scarlet local socket path is invalid"));
    }
    if payload.contains(&0) {
        return Err(invalid_input("Scarlet local socket path contains NUL"));
    }

    let mut storage = SockAddrStorage::zeroed();
    // SAFETY: `sockaddr_un` fits inside `SockAddrStorage` and is one of the
    // address representations used by this backend.
    let raw = unsafe { storage.view_as::<sockaddr_un>() };
    raw.sun_family = AF_UNIX as sa_family_t;
    let mut written = 0;
    if abstract_name {
        raw.sun_path[0] = 0;
        written = 1;
    }
    for (destination, source) in raw.sun_path[written..].iter_mut().zip(payload) {
        *destination = *source as i8;
        written += 1;
    }
    if !abstract_name {
        raw.sun_path[written] = 0;
        written += 1;
    }
    let len = (offset_of_path(raw) + written) as socklen_t;
    // SAFETY: `storage` contains a fully initialized `sockaddr_un` through
    // `len`, with a matching family and length.
    Ok(unsafe { SockAddr::new(storage, len) })
}

fn offset_of_path(address: &sockaddr_un) -> usize {
    let base = ptr::from_ref(address) as usize;
    let path = ptr::addr_of!(address.sun_path) as usize;
    path - base
}

fn with_unix_address<T>(
    addr: &SockAddr,
    operation: impl FnOnce(&str, bool) -> Result<T, SocketError>,
) -> io::Result<T> {
    if addr.len() as usize <= mem::size_of::<sa_family_t>() {
        return Err(invalid_input("empty Scarlet local socket address"));
    }
    // SAFETY: the family was checked by the caller and the address length is
    // validated before the path bytes are read.
    let raw = unsafe { &*addr.as_ptr().cast::<sockaddr_un>() };
    let available = (addr.len() as usize - offset_of_path(raw)).min(raw.sun_path.len());
    // SAFETY: `available` is bounded by `sun_path` above.
    let bytes = unsafe { slice::from_raw_parts(raw.sun_path.as_ptr().cast::<u8>(), available) };
    let abstract_name = bytes.first() == Some(&0);
    let bytes = if abstract_name { &bytes[1..] } else { bytes };
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let name = std::str::from_utf8(&bytes[..end])
        .map_err(|_| invalid_input("Scarlet local socket name must be UTF-8"))?;
    if name.is_empty() {
        return Err(invalid_input("empty Scarlet local socket name"));
    }
    operation(name, abstract_name).map_err(socket_error)
}

fn to_native_v4(address: SocketAddrV4) -> Inet4SocketAddress {
    Inet4SocketAddress::new(address.ip().octets(), address.port())
}

fn sockaddr_to_native(address: &SockAddr) -> io::Result<SocketAddress> {
    match address.as_socket() {
        Some(SocketAddr::V4(address)) => Ok(SocketAddress::Inet(to_native_v4(address))),
        Some(SocketAddr::V6(_)) => Err(unsupported("Scarlet IPv6 sockets are not implemented")),
        None => Err(invalid_input("unsupported Scarlet datagram address")),
    }
}

fn native_address(address: SocketAddress) -> io::Result<SockAddr> {
    match address {
        SocketAddress::Inet(address) => Ok(SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::from(address.addr),
            address.port,
        ))),
        SocketAddress::Unspecified => {
            Ok(SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
        }
    }
}

fn require_no_flags(flags: c_int) -> io::Result<()> {
    if flags == 0 {
        Ok(())
    } else {
        Err(unsupported(
            "Scarlet socket message flags are not implemented",
        ))
    }
}

fn gather(bufs: &[IoSlice<'_>]) -> Vec<u8> {
    let capacity = bufs.iter().map(|buf| buf.len()).sum();
    let mut output = Vec::with_capacity(capacity);
    for buffer in bufs {
        output.extend_from_slice(buffer);
    }
    output
}

fn copy_to_uninit(destination: &mut [MaybeUninit<u8>], source: &[u8]) {
    for (destination, source) in destination.iter_mut().zip(source) {
        destination.write(*source);
    }
}

fn scatter_to_uninit(destination: &mut [crate::MaybeUninitSlice<'_>], source: &[u8]) {
    let mut remaining = source;
    for buffer in destination {
        let copied = remaining.len().min(buffer.len());
        copy_to_uninit(&mut buffer[..copied], &remaining[..copied]);
        remaining = &remaining[copied..];
        if remaining.is_empty() {
            break;
        }
    }
}

fn socket_error(error: SocketError) -> io::Error {
    if let SocketError::SystemError(errno) = error {
        return io::Error::from_raw_os_error(errno);
    }
    let kind = match error {
        SocketError::WouldBlock => io::ErrorKind::WouldBlock,
        SocketError::InvalidHandle | SocketError::InvalidAddress | SocketError::InvalidPath => {
            io::ErrorKind::InvalidInput
        }
        SocketError::AlreadyBound => io::ErrorKind::AddrInUse,
        SocketError::AddressNotAvailable => io::ErrorKind::AddrNotAvailable,
        SocketError::NotListening => io::ErrorKind::NotConnected,
        SocketError::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        SocketError::ConnectionReset => io::ErrorKind::ConnectionReset,
        SocketError::NotConnected => io::ErrorKind::NotConnected,
        SocketError::Interrupted => io::ErrorKind::Interrupted,
        SocketError::TimedOut => io::ErrorKind::TimedOut,
        SocketError::ReceiveBufferTooSmall { .. } => io::ErrorKind::InvalidData,
        SocketError::MessageTooLarge => io::ErrorKind::InvalidInput,
        SocketError::SyscallFailed => io::ErrorKind::Other,
        SocketError::SystemError(_) => unreachable!(),
    };
    io::Error::new(kind, "Scarlet socket operation failed")
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

impl AsFd for crate::Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the returned borrow cannot outlive `self`.
        unsafe { BorrowedFd::borrow_raw(self.as_raw()) }
    }
}

impl AsRawFd for crate::Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw()
    }
}

impl From<crate::Socket> for OwnedFd {
    fn from(socket: crate::Socket) -> OwnedFd {
        // SAFETY: `Socket::into_raw` transfers a live, owned handle.
        unsafe { OwnedFd::from_raw_fd(socket.into_raw()) }
    }
}

impl IntoRawFd for crate::Socket {
    fn into_raw_fd(self) -> RawFd {
        self.into_raw()
    }
}

impl From<OwnedFd> for crate::Socket {
    fn from(fd: OwnedFd) -> crate::Socket {
        // SAFETY: `OwnedFd` transfers a live, owned handle.
        unsafe { crate::Socket::from_raw_fd(fd.into_raw_fd()) }
    }
}

impl FromRawFd for crate::Socket {
    unsafe fn from_raw_fd(fd: RawFd) -> crate::Socket {
        crate::Socket::from_raw(fd)
    }
}
