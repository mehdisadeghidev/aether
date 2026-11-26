//! The tun front end: the tunnel as an ordinary IP interface.
//!
//! The socks front end needs a userspace tcp stack (`netstack`) because it
//! hands applications a byte stream and has to terminate their connections.
//! A tun does not: the kernel owns tcp, udp, nat and the routing table, so all
//! this module does is move whole IP packets between the device and the
//! tunnel's packet channels. That is the entire difference between the two.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::sync::{mpsc, oneshot};

use crate::relay::TaskGuard;

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("--tun {0} is not a device name: 1 to 15 bytes, no spaces")]
    BadName(String),
    #[error("--tun-addr wants addresses like 172.16.0.2/32: {0}")]
    BadAddr(String),
    #[error("cannot open /dev/net/tun: {0}; a container needs the device passed through")]
    Open(std::io::Error),
    #[error("cannot attach {0}: {1}; a tun needs CAP_NET_ADMIN")]
    Attach(String, std::io::Error),
    #[error("cannot configure {name}: {error}")]
    Configure { name: String, error: std::io::Error },
    #[error("reading the tun device failed: {0}")]
    Read(std::io::Error),
    #[error("writing the tun device failed: {0}")]
    Write(std::io::Error),
    #[error("the tun device took {0} bytes and then refused the rest of the packet")]
    ShortWrite(usize),
    #[error("the tun device stopped")]
    Stopped,
    #[error("--tun needs linux")]
    NotLinux,
}

/// What the tunnel waits on while a tun front end carries it. The pump itself
/// runs in the background; this only reports how it ended.
pub struct TunFrontend {
    fatal: Option<oneshot::Receiver<TunError>>,
    _guard: TaskGuard,
}

/// Where a tun front end sends the TCP a peer opens on it, instead of carrying
/// it into the tunnel: a stack that terminates it, so the connection can be
/// dialled out again somewhere else (through Psiphon, in the chained mode).
/// Everything else still rides the tunnel, and so does TCP whose source is one
/// of the addresses the tun was given — that is the machine's own traffic, and
/// sending it to the stack would dial it back into itself.
pub struct TunSplit {
    pub to_stack: mpsc::Sender<Vec<u8>>,
    pub from_stack: mpsc::Receiver<Vec<u8>>,
    own: Vec<IpAddr>,
}

impl TunSplit {
    pub fn new(
        ipv4: &str,
        ipv6: &str,
        to_stack: mpsc::Sender<Vec<u8>>,
        from_stack: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        let mut own = Vec::new();
        if let Some(addr) = ipv4.split('/').next().and_then(|a| a.parse().ok()) {
            own.push(IpAddr::V4(addr));
        }
        if let Some(addr) = ipv6.split('/').next().and_then(|a| a.parse().ok()) {
            own.push(IpAddr::V6(addr));
        }
        Self {
            to_stack,
            from_stack,
            own,
        }
    }
}

/// The source address and protocol number of an IPv4 or IPv6 packet, or None
/// for anything else (a fragment with extension headers, a short packet).
fn ip_source(packet: &[u8]) -> Option<(IpAddr, u8)> {
    match packet.first()? >> 4 {
        4 => {
            let src = Ipv4Addr::new(
                *packet.get(12)?,
                *packet.get(13)?,
                *packet.get(14)?,
                *packet.get(15)?,
            );
            Some((IpAddr::V4(src), *packet.get(9)?))
        }
        6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(packet.get(8..24)?);
            Some((IpAddr::V6(Ipv6Addr::from(octets)), *packet.get(6)?))
        }
        _ => None,
    }
}

impl TunFrontend {
    pub async fn wait(&mut self) -> TunError {
        match self.fatal.as_mut() {
            Some(report) => match report.await {
                Ok(error) => error,
                Err(_) => TunError::Stopped,
            },
            None => std::future::pending().await,
        }
    }
}

pub struct Tun {
    name: String,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fd: std::sync::Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
}

impl Tun {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use tokio::io::unix::AsyncFd;
    use tokio::sync::{mpsc, oneshot};

    use super::{Tun, TunError, TunFrontend};
    use crate::error::Result;
    use crate::relay::TaskGuard;
    use crate::{settings, stats};

    const IFNAMSIZ: usize = 16;

    /// `ifreq`, whose union member we address as bytes: an int for the mtu and
    /// the flags, or a `sockaddr_in` for an address.
    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; IFNAMSIZ],
        data: [u8; 24],
    }

    impl IfReq {
        fn new(name: &str) -> std::result::Result<Self, TunError> {
            let bytes = name.as_bytes();
            if bytes.is_empty()
                || bytes.len() >= IFNAMSIZ
                || bytes.iter().any(u8::is_ascii_whitespace)
            {
                return Err(TunError::BadName(name.to_string()));
            }
            let mut req = Self {
                name: [0; IFNAMSIZ],
                data: [0; 24],
            };
            for (slot, byte) in req.name.iter_mut().zip(bytes) {
                *slot = *byte as libc::c_char;
            }
            Ok(req)
        }

        fn set_flags(&mut self, flags: libc::c_short) {
            self.data = [0; 24];
            self.data[..2].copy_from_slice(&flags.to_ne_bytes());
        }

        fn flags(&self) -> libc::c_short {
            libc::c_short::from_ne_bytes([self.data[0], self.data[1]])
        }

        fn set_mtu(&mut self, mtu: usize) {
            self.data = [0; 24];
            self.data[..4].copy_from_slice(&(mtu as libc::c_int).to_ne_bytes());
        }

        fn set_v4(&mut self, addr: Ipv4Addr) {
            self.data = [0; 24];
            self.data[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            self.data[4..8].copy_from_slice(&addr.octets());
        }
    }

    fn ioctl<T>(fd: libc::c_int, request: libc::c_ulong, req: &mut T) -> io::Result<()> {
        // SAFETY: every caller passes a live `ifreq` or `in6_ifreq` and one of
        // the SIOCS*/TUNSETIFF requests, which all take that shape.
        if unsafe { libc::ioctl(fd, request as _, req as *mut T) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn datagram_socket(domain: libc::c_int) -> io::Result<OwnedFd> {
        // SAFETY: a plain socket() call; the fd is checked and owned from here.
        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn netmask(prefix: u8) -> Ipv4Addr {
        let prefix = prefix.min(32);
        if prefix == 0 {
            return Ipv4Addr::UNSPECIFIED;
        }
        Ipv4Addr::from(u32::MAX << (32 - prefix))
    }

    fn split_addr(raw: &str) -> (&str, u8) {
        match raw.trim().split_once('/') {
            Some((addr, prefix)) => (addr, prefix.parse().unwrap_or(32)),
            None => (raw.trim(), 32),
        }
    }

    impl Tun {
        pub fn open(name: &str) -> Result<Self> {
            let mut req = IfReq::new(name)?;

            // SAFETY: a plain open() of a device path; the fd is checked below.
            let raw = unsafe {
                libc::open(
                    c"/dev/net/tun".as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(TunError::Open(io::Error::last_os_error()).into());
            }
            // SAFETY: `raw` is a fresh fd and is not used again.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            req.set_flags((libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short);
            ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, &mut req)
                .map_err(|error| TunError::Attach(name.to_string(), error))?;

            let fd = AsyncFd::new(fd).map_err(TunError::Open)?;
            Ok(Self {
                name: name.to_string(),
                fd: std::sync::Arc::new(fd),
            })
        }

        /// Give the device the addresses and mtu the tunnel assigned us, and
        /// bring it up. `--tun-addr` overrides them, for a router that would
        /// rather hand out its own.
        pub fn configure(&self, ipv4: &str, ipv6: &str, mtu: usize) -> Result<()> {
            let wanted: Vec<String> = match settings::var("AETHER_TUN_ADDR").ok() {
                Some(list) => list
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(str::to_string)
                    .collect(),
                None => [ipv4.trim(), ipv6.trim()]
                    .into_iter()
                    .filter(|addr| !addr.is_empty())
                    .map(str::to_string)
                    .collect(),
            };

            let v4 = wanted.iter().find_map(|addr| {
                let (ip, prefix) = split_addr(addr);
                ip.parse::<Ipv4Addr>().ok().map(|ip| (ip, prefix))
            });
            let v6 = wanted.iter().find_map(|addr| {
                let (ip, prefix) = split_addr(addr);
                ip.parse::<Ipv6Addr>().ok().map(|ip| (ip, prefix))
            });

            if !wanted.is_empty() && v4.is_none() && v6.is_none() {
                return Err(TunError::BadAddr(wanted.join(",")).into());
            }

            let fail = |error: io::Error| TunError::Configure {
                name: self.name.clone(),
                error,
            };

            let sock = datagram_socket(libc::AF_INET).map_err(fail)?;
            let mut req = IfReq::new(&self.name)?;

            req.set_mtu(mtu);
            ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU, &mut req).map_err(fail)?;

            if let Some((addr, prefix)) = v4 {
                req.set_v4(addr);
                ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR, &mut req).map_err(fail)?;
                req.set_v4(netmask(prefix));
                ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK, &mut req).map_err(fail)?;
            }

            if let Some((addr, prefix)) = v6 {
                let sock6 = datagram_socket(libc::AF_INET6).map_err(fail)?;
                // SAFETY: if_nametoindex only reads the name we pass it.
                let index = unsafe { libc::if_nametoindex(req.name.as_ptr()) };
                if index == 0 {
                    return Err(fail(io::Error::last_os_error()).into());
                }
                let mut req6 = libc::in6_ifreq {
                    ifr6_addr: libc::in6_addr {
                        s6_addr: addr.octets(),
                    },
                    ifr6_prefixlen: u32::from(prefix.min(128)),
                    ifr6_ifindex: index as libc::c_int,
                };
                ioctl(sock6.as_raw_fd(), libc::SIOCSIFADDR, &mut req6).map_err(fail)?;
            }

            ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req).map_err(fail)?;
            req.set_flags(req.flags() | (libc::IFF_UP as libc::c_short));
            ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &mut req).map_err(fail)?;

            log::info!("[+] tun {} is up, {mtu} byte mtu", self.name);
            Ok(())
        }

        /// Start carrying the tunnel on the device. One task moves both ways,
        /// so a reconnect never leaves two pumps reading the same queue.
        pub fn pump(
            &self,
            mtu: usize,
            inbound_rx: mpsc::Receiver<Vec<u8>>,
            outbound_tx: mpsc::Sender<Vec<u8>>,
        ) -> TunFrontend {
            self.pump_split(mtu, inbound_rx, outbound_tx, None)
        }

        /// The same, with the TCP a peer opens on the device going to `split`
        /// instead of into the tunnel.
        pub fn pump_split(
            &self,
            mtu: usize,
            inbound_rx: mpsc::Receiver<Vec<u8>>,
            outbound_tx: mpsc::Sender<Vec<u8>>,
            split: Option<super::TunSplit>,
        ) -> TunFrontend {
            let fd = self.fd.clone();
            let name = self.name.clone();
            let (fatal_tx, fatal) = oneshot::channel();

            let task = tokio::spawn(async move {
                if let Err(error) = carry(&fd, mtu, inbound_rx, outbound_tx, split).await {
                    log::warn!("[-] tun {name} stopped: {error}");
                    let _ = fatal_tx.send(error);
                    return;
                }
                // The tunnel ended; the tunnel's own task reports that, so stay
                // quiet and keep the report channel open rather than racing it.
                log::debug!("[tun] {name} has no tunnel to carry");
                std::future::pending::<()>().await;
            });

            let mut guard = TaskGuard::new();
            guard.push(task.abort_handle());

            TunFrontend {
                fatal: Some(fatal),
                _guard: guard,
            }
        }
    }

    async fn carry(
        fd: &AsyncFd<OwnedFd>,
        mtu: usize,
        mut inbound_rx: mpsc::Receiver<Vec<u8>>,
        outbound_tx: mpsc::Sender<Vec<u8>>,
        split: Option<super::TunSplit>,
    ) -> std::result::Result<(), TunError> {
        // Exactly one packet fits, so a read can never hand us two of them.
        let mut buf = vec![0u8; mtu.max(576)];
        let (to_stack, mut from_stack, own) = match split {
            Some(split) => (Some(split.to_stack), Some(split.from_stack), split.own),
            None => (None, None, Vec::new()),
        };

        loop {
            let from_stack_packet = async {
                match from_stack.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };

            tokio::select! {
                packet = inbound_rx.recv() => {
                    let Some(packet) = packet else { return Ok(()) };
                    stats::add_down(packet.len());
                    write_packet(fd, &packet).await?;
                }

                packet = from_stack_packet => {
                    let Some(packet) = packet else { return Ok(()) };
                    stats::add_down(packet.len());
                    write_packet(fd, &packet).await?;
                }

                read = read_packet(fd, &mut buf) => {
                    let read = read?;
                    stats::add_up(read);
                    let packet = &buf[..read];
                    let claimed = matches!(
                        super::ip_source(packet),
                        Some((src, 6)) if !own.contains(&src)
                    );
                    if let (true, Some(to_stack)) = (claimed, to_stack.as_ref()) {
                        // A stack that cannot keep up drops the segment and the
                        // peer retransmits, rather than stalling the device.
                        let _ = to_stack.try_send(packet.to_vec());
                    } else if outbound_tx.send(packet.to_vec()).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn read_packet(
        fd: &AsyncFd<OwnedFd>,
        buf: &mut [u8],
    ) -> std::result::Result<usize, TunError> {
        loop {
            let mut ready = fd.readable().await.map_err(TunError::Read)?;
            let attempt = ready.try_io(|inner| {
                // SAFETY: `buf` is live and writable for its whole length.
                let read =
                    unsafe { libc::read(inner.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if read < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(read as usize)
                }
            });
            match attempt {
                Ok(Ok(read)) => return Ok(read),
                Ok(Err(error)) => return Err(TunError::Read(error)),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_packet(
        fd: &AsyncFd<OwnedFd>,
        packet: &[u8],
    ) -> std::result::Result<(), TunError> {
        loop {
            let mut ready = fd.writable().await.map_err(TunError::Write)?;
            let attempt = ready.try_io(|inner| {
                // SAFETY: `packet` is live and readable for its whole length.
                let wrote =
                    unsafe { libc::write(inner.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
                if wrote < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(wrote as usize)
                }
            });
            match attempt {
                // One write is one packet: a short one would lose its framing.
                Ok(Ok(wrote)) if wrote == packet.len() => return Ok(()),
                Ok(Ok(wrote)) => return Err(TunError::ShortWrite(wrote)),
                Ok(Err(error)) => return Err(TunError::Write(error)),
                Err(_would_block) => continue,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::OwnedFd;

        /// A datagram socket pair stands in for the device: one packet per
        /// read, one packet per write, exactly like a tun with IFF_NO_PI.
        #[tokio::test]
        async fn packets_cross_the_device_in_both_directions() {
            let (device, peer) = tokio::net::UnixDatagram::pair().unwrap();
            let device: OwnedFd = device.into_std().unwrap().into();
            let device = std::sync::Arc::new(AsyncFd::new(device).unwrap());

            let (in_tx, in_rx) = mpsc::channel(4);
            let (out_tx, mut out_rx) = mpsc::channel(4);

            let mover = tokio::spawn({
                let device = device.clone();
                async move { carry(&device, 1500, in_rx, out_tx, None).await }
            });

            in_tx.send(vec![1, 2, 3]).await.unwrap();
            let mut buf = [0u8; 1500];
            let read = peer.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..read], &[1, 2, 3]);

            peer.send(&[9, 9]).await.unwrap();
            assert_eq!(out_rx.recv().await.unwrap(), vec![9, 9]);

            drop(in_tx);
            assert!(mover.await.unwrap().is_ok());
        }

        fn v4(src: Ipv4Addr, protocol: u8) -> Vec<u8> {
            let mut packet = vec![0u8; 20];
            packet[0] = 0x45;
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&src.octets());
            packet
        }

        fn v6(src: Ipv6Addr, protocol: u8) -> Vec<u8> {
            let mut packet = vec![0u8; 40];
            packet[0] = 0x60;
            packet[6] = protocol;
            packet[8..24].copy_from_slice(&src.octets());
            packet
        }

        /// With a split, a peer's tcp is handed to the stack that terminates it,
        /// while the machine's own tcp, its udp and its icmp still ride the
        /// tunnel: the first is what Psiphon carries, the rest is what carries
        /// Psiphon and the tunnel itself.
        #[tokio::test]
        async fn the_split_takes_a_peers_tcp_and_leaves_the_rest_to_the_tunnel() {
            let (device, peer) = tokio::net::UnixDatagram::pair().unwrap();
            let device: OwnedFd = device.into_std().unwrap().into();
            let device = std::sync::Arc::new(AsyncFd::new(device).unwrap());

            let (in_tx, in_rx) = mpsc::channel(4);
            let (out_tx, mut out_rx) = mpsc::channel(4);
            let (to_stack_tx, mut to_stack_rx) = mpsc::channel(4);
            let (from_stack_tx, from_stack_rx) = mpsc::channel(4);
            let split = super::super::TunSplit::new(
                "172.16.0.2/32",
                "2606:4700:110:8a36::2/128",
                to_stack_tx,
                from_stack_rx,
            );

            let mover =
                tokio::spawn(async move { carry(&device, 1500, in_rx, out_tx, Some(split)).await });

            let theirs = v4(Ipv4Addr::new(10, 0, 0, 9), 6);
            peer.send(&theirs).await.unwrap();
            assert_eq!(to_stack_rx.recv().await.unwrap(), theirs);

            let theirs6 = v6("2001:db8::9".parse().unwrap(), 6);
            peer.send(&theirs6).await.unwrap();
            assert_eq!(to_stack_rx.recv().await.unwrap(), theirs6);

            let own = v4(Ipv4Addr::new(172, 16, 0, 2), 6);
            peer.send(&own).await.unwrap();
            assert_eq!(out_rx.recv().await.unwrap(), own);

            let udp = v4(Ipv4Addr::new(10, 0, 0, 9), 17);
            peer.send(&udp).await.unwrap();
            assert_eq!(out_rx.recv().await.unwrap(), udp);

            from_stack_tx.send(vec![7, 7]).await.unwrap();
            let mut buf = [0u8; 1500];
            let read = peer.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..read], &[7, 7]);

            drop(in_tx);
            assert!(mover.await.unwrap().is_ok());
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl Tun {
    pub fn open(_name: &str) -> crate::error::Result<Self> {
        Err(TunError::NotLinux.into())
    }

    pub fn configure(&self, _ipv4: &str, _ipv6: &str, _mtu: usize) -> crate::error::Result<()> {
        Err(TunError::NotLinux.into())
    }

    pub fn pump(
        &self,
        _mtu: usize,
        _inbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        _outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> TunFrontend {
        TunFrontend {
            fatal: None,
            _guard: TaskGuard::new(),
        }
    }

    pub fn pump_split(
        &self,
        _mtu: usize,
        _inbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        _outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        _split: Option<TunSplit>,
    ) -> TunFrontend {
        TunFrontend {
            fatal: None,
            _guard: TaskGuard::new(),
        }
    }
}
