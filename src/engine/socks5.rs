//! SOCKS5 relay layer: TCP CONNECT and UDP ASSOCIATE for HTTP/3 (QUIC)
//! traversal of residential proxies.
//!
//! Datagram wire format (egress):
//! RSV(2) FRAG(1) ATYP(1) DST.ADDR(4|16|n) DST.PORT(2) | QUIC datagram
//!
//! The TCP control connection is held open for the association's lifetime —
//! dropping it tears the UDP relay down. A custom [`quinn::AsyncUdpSocket`]
//! wraps outgoing QUIC datagrams in the SOCKS5 UDP header form and peels it
//! on ingress so Quinn sees a plain UDP socket.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use crate::error::{K2Error, K2Result};

#[derive(Debug, Clone)]
pub struct Socks5Spec {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl Socks5Spec {
    /// Parses `socks5://user:pass@host:port` (or bare `host:port`).
    pub fn parse(s: &str) -> K2Result<Self> {
        let body = s
            .strip_prefix("socks5://")
            .or_else(|| s.strip_prefix("socks5h://"))
            .ok_or_else(|| K2Error::Proxy(format!("expected socks5:// URL, got {s}")))?;
        let (userinfo, hostport) = match body.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, body),
        };
        let mut user = None;
        let mut pass = None;
        if let Some(ui) = userinfo {
            let mut it = ui.splitn(2, ':');
            user = it.next().map(|x| x.to_string());
            pass = it.next().map(|x| x.to_string());
            if user.as_deref().unwrap_or("").is_empty() && pass.as_deref().unwrap_or("").is_empty()
            {
                user = None;
                pass = None;
            }
        }
        let hostport = hostport.trim();
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => {
                let n = p
                    .parse::<u16>()
                    .map_err(|e| K2Error::Proxy(format!("bad proxy port: {e}")))?;
                (h.to_string(), n)
            }
            None => (hostport.to_string(), 1080),
        };
        Ok(Self {
            host,
            port,
            user,
            pass,
        })
    }
}

const VER: u8 = 5;
const METH_NOAUTH: u8 = 0x00;
const METH_USERPASS: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const CMD_CONNECT: u8 = 0x01;

/// An established SOCKS5 UDP association: TCP control stream + relay address.
#[derive(Debug)]
pub struct Association {
    pub control: Mutex<TcpStream>,
    pub relay: SocketAddr,
}

/// Establish a UDP ASSOCIATE. Keep the returned association alive while
/// datagrams flow.
pub async fn udp_associate(proxy: &Socks5Spec) -> K2Result<Association> {
    let mut control = tcp_raw(proxy).await?;
    authorize(&mut control, proxy).await?;
    // DST.ADDR/PORT are hints only; every datagram carries its own destination.
    let req = [VER, CMD_UDP_ASSOCIATE, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    control.write_all(&req).await.map_err(K2Error::Io)?;
    let _ver = control.read_u8().await.map_err(K2Error::Io)?;
    let rep = control.read_u8().await.map_err(K2Error::Io)?;
    if rep != 0 {
        return Err(K2Error::Proxy(format!("udp associate refused ({rep})")));
    }
    let _rsv = control.read_u8().await.map_err(K2Error::Io)?;
    let atyp = control.read_u8().await.map_err(K2Error::Io)?;
    let relay = read_bnd_addr(&mut control, atyp).await?;
    let relay = if relay.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
        match control.peer_addr() {
            Ok(a) => SocketAddr::new(a.ip(), relay.port()),
            Err(_) => relay,
        }
    } else {
        relay
    };
    Ok(Association {
        control: Mutex::new(control),
        relay,
    })
}

/// TCP CONNECT tunnel to `host:port` via SOCKS5.
pub async fn tcp_connect(proxy: &Socks5Spec, host: &str, port: u16) -> K2Result<TcpStream> {
    let mut control = tcp_raw(proxy).await?;
    authorize(&mut control, proxy).await?;
    let mut req = vec![VER, CMD_CONNECT, 0x00, 0x03];
    req.push(host.len().min(255) as u8);
    req.extend_from_slice(&host.as_bytes()[..host.len().min(255)]);
    req.push((port >> 8) as u8);
    req.push((port & 0xff) as u8);
    control.write_all(&req).await.map_err(K2Error::Io)?;
    control.flush().await.map_err(K2Error::Io)?;
    let _ = control.read_u8().await.map_err(K2Error::Io)?;
    let rep = control.read_u8().await.map_err(K2Error::Io)?;
    if rep != 0 {
        return Err(K2Error::Proxy(format!("connect refused ({rep})")));
    }
    consume_bnd(&mut control).await?;
    Ok(control)
}

async fn tcp_raw(proxy: &Socks5Spec) -> K2Result<TcpStream> {
    TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|e| K2Error::Proxy(format!("tcp connect: {e}")))
}

async fn authorize(c: &mut TcpStream, proxy: &Socks5Spec) -> K2Result<()> {
    let creds = proxy.user.is_some() || proxy.pass.is_some();
    if creds && (proxy.user.is_none() || proxy.pass.is_none()) {
        return Err(K2Error::Proxy("user requires password".into()));
    }
    let nmethods = if creds { 2u8 } else { 1u8 };
    let mut greet = vec![VER, nmethods, METH_NOAUTH];
    if creds {
        greet.push(METH_USERPASS);
    }
    c.write_all(&greet).await.map_err(K2Error::Io)?;
    c.flush().await.map_err(K2Error::Io)?;
    let _ver = c.read_u8().await.map_err(K2Error::Io)?;
    let method = c.read_u8().await.map_err(K2Error::Io)?;
    if method == METH_USERPASS {
        let user = proxy.user.as_deref().unwrap_or("");
        let pass = proxy.pass.as_deref().unwrap_or("");
        let mut up = vec![1u8, user.len().min(255) as u8];
        up.extend_from_slice(&user.as_bytes()[..user.len().min(255)]);
        up.push(pass.len().min(255) as u8);
        up.extend_from_slice(&pass.as_bytes()[..pass.len().min(255)]);
        c.write_all(&up).await.map_err(K2Error::Io)?;
        c.flush().await.map_err(K2Error::Io)?;
        let _ = c.read_u8().await.map_err(K2Error::Io)?;
        let ok = c.read_u8().await.map_err(K2Error::Io)?;
        if ok != 0 {
            return Err(K2Error::Proxy("user/pass rejected".into()));
        }
    } else if method != METH_NOAUTH {
        return Err(K2Error::Proxy("no acceptable auth method".into()));
    }
    Ok(())
}

async fn read_bnd_addr(c: &mut TcpStream, atyp: u8) -> K2Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await.map_err(K2Error::Io)?;
            let port = c.read_u16().await.map_err(K2Error::Io)?;
            Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(b), port)))
        }
        0x04 => {
            let mut b = [0u8; 16];
            c.read_exact(&mut b).await.map_err(K2Error::Io)?;
            let port = c.read_u16().await.map_err(K2Error::Io)?;
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(b),
                port,
                0,
                0,
            )))
        }
        0x03 => {
            let n = usize::from(c.read_u8().await.map_err(K2Error::Io)?);
            let mut name = vec![0u8; n];
            c.read_exact(&mut name).await.map_err(K2Error::Io)?;
            let port = c.read_u16().await.map_err(K2Error::Io)?;
            let h = String::from_utf8_lossy(&name).to_string();
            resolve_first(&h, port).ok_or_else(|| K2Error::Proxy(format!("unresolvable relay {h}")))
        }
        other => Err(K2Error::Proxy(format!("bad atyp {other}"))),
    }
}

async fn consume_bnd(c: &mut TcpStream) -> K2Result<()> {
    let atyp = c.read_u8().await.map_err(K2Error::Io)?;
    read_bnd_addr(c, atyp).await?;
    Ok(())
}

fn resolve_first(host: &str, port: u16) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port).to_socket_addrs().ok()?.next()
}

/// QUIC-facing socket speaking SOCKS5 UDP encapsulation toward `relay`.
#[derive(Debug)]
pub struct Socks5UdpSocket {
    udp: Arc<UdpSocket>,
    relay: SocketAddr,
    // Holds the TCP control alive for the socket's lifetime.
    _control: Arc<Association>,
}

impl Socks5UdpSocket {
    pub fn new(udp: Arc<UdpSocket>, association: Association, relay: SocketAddr) -> Self {
        Self {
            udp,
            relay,
            _control: Arc::new(association),
        }
    }
}

fn encode_header(dst: SocketAddr, out: &mut Vec<u8>) {
    out.push(0);
    out.push(0);
    out.push(0); // RSV + FRAG
    match dst.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    let p = dst.port();
    out.push((p >> 8) as u8);
    out.push((p & 0xff) as u8);
}

/// Decode an encapsulated datagram: (header-provided source, header length).
pub fn decode_header(buf: &[u8], fallback: SocketAddr) -> io::Result<(SocketAddr, usize)> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short udp header",
        ));
    }
    let atyp = buf[3];
    let (addr, hdr_len) = match atyp {
        0x01 => {
            if buf.len() < 10 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short v4"));
            }
            let oct = [buf[4], buf[5], buf[6], buf[7]];
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(oct), port)),
                10usize,
            )
        }
        0x04 => {
            if buf.len() < 22 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "short v6"));
            }
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(oct), port, 0, 0)),
                22usize,
            )
        }
        // Some relays reply with a domain-typed source; treat datagrams as
        // sourced from the relay itself in that case.
        0x03 => (
            fallback,
            5usize + usize::from(buf.get(4).copied().unwrap_or(0)) + 2usize,
        ),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("atyp {other}"),
            ));
        }
    };
    Ok((addr, hdr_len))
}

#[derive(Debug)]
struct SendPoller {
    udp: Arc<UdpSocket>,
}

impl quinn::UdpPoller for SendPoller {
    fn poll_writable(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.udp.poll_send_ready(cx)
    }
}

impl quinn::AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SendPoller {
            udp: self.udp.clone(),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let mut datagram = Vec::with_capacity(transmit.contents.len() + 24);
        encode_header(transmit.destination, &mut datagram);
        datagram.extend_from_slice(transmit.contents);
        self.udp.try_io(Interest::WRITABLE, || {
            self.udp.try_send_to(&datagram, self.relay).map(|_| ())
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.udp.poll_recv_ready(cx))?;
            let res = self
                .udp
                .try_io(Interest::READABLE, || self.udp.try_recv(&mut bufs[0]));
            match res {
                Ok(n) => {
                    let bytes = &bufs[0][..n];
                    let (src, off) = decode_header(bytes, self.relay)?;
                    if off > n {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "udp header longer than datagram",
                        )));
                    }
                    let payload_len = n - off;
                    // Shift payload to the buffer start; Quinn reads raw QUIC bytes.
                    bufs[0].copy_within(off..n, 0);
                    meta[0] = quinn::udp::RecvMeta {
                        addr: src,
                        len: payload_len,
                        stride: payload_len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                // try_io cleared read readiness; re-register and wait again.
                Err(_) => continue,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_v4() {
        let mut snd = Vec::new();
        encode_header("1.2.3.4:5555".parse().unwrap(), &mut snd);
        assert_eq!(snd[3], 0x01);
        let (src, off) = decode_header(&snd, "10.0.0.1:1".parse().unwrap()).unwrap();
        assert_eq!(src.to_string(), "1.2.3.4:5555");
        assert_eq!(off, 10);
    }

    #[test]
    fn header_roundtrip_v6() {
        let mut snd = Vec::new();
        encode_header("[2001:db8::1]:443".parse().unwrap(), &mut snd);
        let (src, off) = decode_header(&snd, "10.0.0.1:1".parse().unwrap()).unwrap();
        assert_eq!(src.to_string(), "[2001:db8::1]:443");
        assert_eq!(off, 22);
    }

    #[test]
    fn spec_parse_with_auth() {
        let s = Socks5Spec::parse("socks5://user:pw@res-host:1080").unwrap();
        assert_eq!(s.host, "res-host");
        assert_eq!(s.port, 1080);
        assert_eq!(s.user.as_deref(), Some("user"));
        assert_eq!(s.pass.as_deref(), Some("pw"));
        let bare = Socks5Spec::parse("socks5://host:9").unwrap();
        assert_eq!(bare.port, 9);
        assert!(bare.user.is_none());
    }
}
