//! Per-core socket helpers using `SO_REUSEPORT`.
//!
//! Each worker thread in a thread-per-core deployment constructs its own
//! UDP (QUIC) and TCP (HTTPS) socket via these helpers. The kernel then
//! distributes incoming packets/connections across the sockets by hashing
//! the 4-tuple, giving us shared-nothing concurrency without a userspace
//! dispatcher and without cross-core lock contention on the hot path.

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// Bind a UDP socket with `SO_REUSEADDR + SO_REUSEPORT` set.
///
/// The returned socket is non-blocking and ready to be handed to
/// [`krot_transport::KrotEndpoint::server_on_socket`].
pub fn reuseport_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// Bind a TCP listener with `SO_REUSEADDR + SO_REUSEPORT` set.
///
/// `backlog` matches the traditional `listen(2)` argument.
pub fn reuseport_tcp(addr: SocketAddr, backlog: i32) -> std::io::Result<std::net::TcpListener> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(backlog)?;
    Ok(sock.into())
}
