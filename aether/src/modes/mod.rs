pub mod endpoints;
pub mod gool;
pub mod masque;
pub mod mim;
pub mod wireguard;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::error::{AetherError, Result};
use crate::{aethernoize, exitloc, masque_h2, netstack, noize, prober, socks, tun};

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("bad peer address {0}")]
    BadPeer(String),
    #[error("[{label}] tunnel exited before validation")]
    ExitedBeforeValidation { label: String },
    #[error("[{label}] tunnel failed before validation: {reason}")]
    FailedBeforeValidation { label: String, reason: String },
    #[error("[{label}] tunnel task join error: {reason}")]
    LabelledJoin { label: String, reason: String },
    #[error("[{label}] tunnel startup timed out after {after:?}")]
    StartupTimeout {
        label: String,
        after: std::time::Duration,
    },
    #[error("tunnel exited: {0}")]
    Exited(String),
    #[error("tunnel task join error: {0}")]
    Join(String),
    #[error("tunnel failed validation: {0}")]
    Validation(String),
    #[error("wireguard tunnel exited: {0}")]
    WireGuardExited(String),
    #[error("[{label}] tunnel failed validation: {reason}")]
    LabelledValidation { label: String, reason: String },
    #[error("[{label}] {reason}")]
    Labelled { label: String, reason: String },
    #[error("no inner masque edge answered through the outer tunnel")]
    NoInnerMasqueEdge,
    #[error("no second masque edge is known for the inner hop")]
    NoSecondMasqueEdge,
    #[error("warp-in-warp needs two separate edges but both hops landed on {0}")]
    SameEdge(IpAddr),
    #[error("no wireguard endpoint to try")]
    NoWireGuardEndpoint,
    #[error("the {what} stopped{reason}")]
    ServerStopped { what: &'static str, reason: String },
    #[error(
        "{what} needs the userspace tcp stack that --tun replaces, so it cannot run with --tun"
    )]
    NoStack { what: &'static str },
}

pub(crate) fn parse_local_v4(s: &str) -> Ipv4Addr {
    s.split('/')
        .next()
        .unwrap_or(s)
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

const TUNNEL_MTU: usize = 1280;

const INNER_MTU: usize = 1200;

const H2_TUNNEL_MTU: usize = 1500;

const H3_MAX_TUNNEL_MTU: usize = crate::quic::MAX_DATAGRAM_SIZE - 50;

fn masque_tunnel_mtu() -> usize {
    let asked = crate::settings::var("AETHER_MASQUE_MTU")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok());
    tunnel_mtu(asked, masque_h2::enabled())
}

fn tunnel_mtu(asked: Option<usize>, h2: bool) -> usize {
    match asked.filter(|mtu| (576..=1500).contains(mtu)) {
        Some(mtu) if !h2 && mtu > H3_MAX_TUNNEL_MTU => {
            log::warn!(
                "[-] AETHER_MASQUE_MTU {mtu} is more than one http/3 datagram carries; using {H3_MAX_TUNNEL_MTU}"
            );
            H3_MAX_TUNNEL_MTU
        }
        Some(mtu) => mtu,
        None if h2 => H2_TUNNEL_MTU,
        None => TUNNEL_MTU,
    }
}

pub(crate) struct Listeners {
    pub(crate) socks: tokio::net::TcpListener,
    http: Option<tokio::net::TcpListener>,
    broken: tokio::sync::mpsc::UnboundedSender<AetherError>,
}

impl Listeners {
    pub(crate) async fn bind(
        listen: SocketAddr,
        broken: tokio::sync::mpsc::UnboundedSender<AetherError>,
    ) -> Result<Self> {
        Ok(Self {
            socks: socks::bind_listener("socks5", listen, "--bind").await?,
            http: bind_http_proxy().await?,
            broken,
        })
    }

    pub(crate) fn into_socks(self) -> tokio::net::TcpListener {
        self.socks
    }

    async fn serve(&self, stack: &netstack::StackHandle) -> std::convert::Infallible {
        let http = async {
            match &self.http {
                Some(listener) => socks::serve_http(listener, stack.clone()).await,
                None => std::future::pending().await,
            }
        };
        let (what, stopped) = tokio::select! {
            stopped = socks::serve(&self.socks, stack.clone()) => ("socks5 server", stopped),
            stopped = http => ("http proxy", stopped),
        };
        let _ = self
            .broken
            .send(AetherError::from(TunnelError::ServerStopped {
                what,
                reason: stopped.err().map(|e| format!(": {e}")).unwrap_or_default(),
            }));
        std::future::pending().await
    }
}

/// Where a tunnel's packets meet this machine: the socks front end's userspace
/// stack, which terminates what clients ask it to carry, or a tun device, where
/// the kernel does the same job.
pub(crate) enum Wire {
    Stack(netstack::StackHandle),
    Tun(tun::TunFrontend),
}

impl Wire {
    pub(crate) fn stack(&self) -> Option<&netstack::StackHandle> {
        match self {
            Wire::Stack(stack) => Some(stack),
            Wire::Tun(_) => None,
        }
    }

    pub(crate) fn needs_stack(&self, what: &'static str) -> Result<&netstack::StackHandle> {
        self.stack()
            .ok_or_else(|| AetherError::from(TunnelError::NoStack { what }))
    }

    /// What the tunnel waits on beside its own task. A stack is carried by the
    /// socks listeners and never ends; a tun reports how its pump died.
    pub(crate) async fn serve(&mut self, frontend: &Frontend) -> AetherError {
        match (self, frontend) {
            (Wire::Stack(stack), Frontend::Socks(listeners)) => {
                match listeners.serve(stack).await {}
            }
            (Wire::Tun(front), _) => front.wait().await.into(),
            (Wire::Stack(_), Frontend::Tun(_)) => AetherError::from(TunnelError::NoStack {
                what: "the socks listeners",
            }),
        }
    }
}

/// What a tunnel is served on. Picked once, from `--tun`, and carried through
/// every reconnect.
pub(crate) enum Frontend {
    Socks(Listeners),
    Tun(std::sync::Arc<tun::Tun>),
}

impl Frontend {
    pub(crate) async fn bind(
        listen: SocketAddr,
        broken: tokio::sync::mpsc::UnboundedSender<AetherError>,
    ) -> Result<Self> {
        let Some(name) = env_value("AETHER_TUN") else {
            return Ok(Frontend::Socks(Listeners::bind(listen, broken).await?));
        };

        for (key, flag) in [
            ("AETHER_SOCKS", "--bind"),
            ("AETHER_HTTP_PROXY", "--http-proxy"),
            ("AETHER_ROUTES_FILE", "--routes"),
            ("AETHER_ROUTE_BLOCK", "--route-block"),
            ("AETHER_ROUTE_DIRECT", "--route-direct"),
        ] {
            if crate::settings::var(key).is_ok() {
                log::warn!("[-] {flag} belongs to the socks5 front end and is ignored with --tun");
            }
        }

        if crate::settings::var("AETHER_MARK").is_err() {
            log::warn!(
                "[-] --mark is not set: on a router that routes traffic into the tun, the \
                 tunnel's own sockets will loop back into it; set --mark and let a rule around \
                 that mark reach the internet directly"
            );
        }

        let tun = tun::Tun::open(&name)?;
        log::info!("[+] serving the tunnel on tun {name} instead of socks5");
        Ok(Frontend::Tun(std::sync::Arc::new(tun)))
    }

    pub(crate) fn tun(&self) -> Option<std::sync::Arc<tun::Tun>> {
        match self {
            Frontend::Socks(_) => None,
            Frontend::Tun(tun) => Some(tun.clone()),
        }
    }

    pub(crate) fn listeners(&self) -> Result<&Listeners> {
        match self {
            Frontend::Socks(listeners) => Ok(listeners),
            Frontend::Tun(_) => Err(AetherError::from(TunnelError::NoStack {
                what: "the socks5 front end",
            })),
        }
    }

    pub(crate) fn socks_addr(&self) -> Option<SocketAddr> {
        match self {
            Frontend::Socks(listeners) => listeners.socks.local_addr().ok(),
            Frontend::Tun(_) => None,
        }
    }

    pub(crate) fn into_socks(self) -> Result<tokio::net::TcpListener> {
        match self {
            Frontend::Socks(listeners) => Ok(listeners.into_socks()),
            Frontend::Tun(_) => Err(AetherError::from(TunnelError::NoStack {
                what: "tor-only and psiphon-only",
            })),
        }
    }

    pub(crate) fn into_listeners(self) -> Result<Listeners> {
        match self {
            Frontend::Socks(listeners) => Ok(listeners),
            Frontend::Tun(_) => Err(AetherError::from(TunnelError::NoStack {
                what: "a nested tunnel",
            })),
        }
    }
}

/// The one place a tunnel chooses between the userspace stack and the device.
pub(crate) fn packet_wire(
    tun: Option<&std::sync::Arc<tun::Tun>>,
    ipv4: &str,
    ipv6: &str,
    mtu: usize,
    inbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) -> Result<Wire> {
    match tun {
        Some(tun) => Ok(Wire::Tun(tun.pump(mtu, inbound_rx, outbound_tx))),
        None => Ok(Wire::Stack(netstack::spawn(
            ipv4,
            ipv6,
            mtu,
            inbound_rx,
            outbound_tx,
        )?)),
    }
}

pub(crate) fn env_value(key: &str) -> Option<String> {
    crate::settings::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|l| l.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::debug!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}

fn team_endpoint() -> Option<SocketAddr> {
    crate::settings::var("AETHER_TEAM_ENDPOINT")
        .ok()
        .and_then(|value| value.parse().ok())
}

fn noize_profile() -> String {
    crate::settings::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string())
}

fn noize_config() -> noize::NoizeConfig {
    let profile = noize_profile();
    log::info!("[+] obfuscation profile: {profile}");
    noize::from_profile(&profile)
}

fn aethernoize_config() -> aethernoize::AetherNoizeConfig {
    let profile = crate::settings::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize profile: {profile}");
    aethernoize::from_profile(&profile)
}

const TUNNEL_STAYED_UP: std::time::Duration = std::time::Duration::from_secs(300);

fn count_tunnel_end(in_a_row: u32, lasted: std::time::Duration) -> u32 {
    if lasted >= TUNNEL_STAYED_UP {
        0
    } else {
        in_a_row.saturating_add(1)
    }
}

async fn exit_policy_guard(
    stack: Option<&netstack::StackHandle>,
    policy: &Option<exitloc::Policy>,
) -> AetherError {
    match (stack, policy) {
        (Some(stack), Some(policy)) => exitloc::watch(stack, policy).await,
        _ => std::future::pending().await,
    }
}

fn edge_network(ip: IpAddr) -> Option<[u8; 3]> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some([octets[0], octets[1], octets[2]])
        }
        IpAddr::V6(_) => None,
    }
}

fn verified_scan_selected(settings: &Option<(String, prober::IpScan)>) -> bool {
    let named = match settings {
        Some((mode, _)) => mode.clone(),
        None => crate::settings::var("AETHER_SCAN").unwrap_or_default(),
    };
    prober::ScanMode::parse(&named) == prober::ScanMode::Verified
}

fn spread_hops(found: &mut [SocketAddr]) {
    if found.len() < 2 {
        return;
    }
    let first = found[0];
    let network = edge_network(first.ip());
    if let Some(other) = found
        .iter()
        .position(|peer| edge_network(peer.ip()) != network)
    {
        if other >= 1 {
            found.swap(1, other);
        }
    }
}

type TunnelExit = tokio::task::JoinHandle<Result<()>>;

fn http_proxy_listen() -> Option<SocketAddr> {
    let raw = crate::settings::var("AETHER_HTTP_PROXY").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(_) => {
            log::warn!("[-] ignoring an unparsable http proxy address: {trimmed}");
            None
        }
    }
}

async fn bind_http_proxy() -> Result<Option<tokio::net::TcpListener>> {
    match http_proxy_listen() {
        Some(listen) => Ok(Some(
            socks::bind_listener("http proxy", listen, "--http-proxy").await?,
        )),
        None => Ok(None),
    }
}

fn scan_settings_from_env() -> (String, prober::IpScan) {
    let mode = crate::settings::var("AETHER_SCAN").unwrap_or_default();
    let ip = crate::settings::var("AETHER_IP")
        .map(|value| prober::IpScan::parse(&value))
        .unwrap_or(prober::IpScan::V4);
    (mode, ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_http3_tunnel_never_asks_for_more_than_one_datagram_carries() {
        assert_eq!(tunnel_mtu(Some(1400), false), H3_MAX_TUNNEL_MTU);
        assert_eq!(tunnel_mtu(Some(1400), true), 1400);
        assert_eq!(tunnel_mtu(Some(1200), false), 1200);
        assert_eq!(tunnel_mtu(None, false), TUNNEL_MTU);
        assert_eq!(tunnel_mtu(None, true), H2_TUNNEL_MTU);
        assert_eq!(tunnel_mtu(Some(9000), false), TUNNEL_MTU);
        const { assert!(H3_MAX_TUNNEL_MTU >= TUNNEL_MTU) };
    }

    async fn http_answers(address: SocketAddr) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Ok(mut sock) = tokio::net::TcpStream::connect(address).await else {
            return false;
        };
        if sock.write_all(b"NOT A REQUEST\r\n\r\n").await.is_err() {
            return false;
        }
        let mut head = [0u8; 12];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sock.read_exact(&mut head),
        )
        .await;
        matches!(read, Ok(Ok(_))) && head.starts_with(b"HTTP/1.1 400")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_listeners_answer_while_a_tunnel_serves_them_and_stay_held_between_tunnels() {
        let (_to_stack, stack_in) = tokio::sync::mpsc::channel(8);
        let (stack_out, _from_stack) = tokio::sync::mpsc::channel(8);
        let stack = netstack::spawn(
            "172.16.0.2",
            "2606:4700:110:8a36::1",
            1280,
            stack_in,
            stack_out,
        )
        .expect("a stack");
        let (broken, mut breaks) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
        let listeners = Listeners {
            socks: socks::bind_listener("socks5", "127.0.0.1:0".parse().unwrap(), "--bind")
                .await
                .unwrap(),
            http: Some(
                socks::bind_listener("http proxy", "127.0.0.1:0".parse().unwrap(), "--http-proxy")
                    .await
                    .unwrap(),
            ),
            broken,
        };
        let socks_at = listeners.socks.local_addr().unwrap();
        let http_at = listeners.http.as_ref().unwrap().local_addr().unwrap();

        for tunnel in 1..=2 {
            tokio::select! {
                never = listeners.serve(&stack) => match never {},
                () = async {
                    assert!(
                        socks::answers(socks_at, std::time::Duration::from_secs(2)).await,
                        "tunnel {tunnel}: the socks5 server"
                    );
                    assert!(http_answers(http_at).await, "tunnel {tunnel}: the http proxy");
                } => {}
            }
            assert!(std::net::TcpListener::bind(socks_at).is_err());
            assert!(std::net::TcpListener::bind(http_at).is_err());
            assert!(!socks::answers(socks_at, std::time::Duration::from_millis(300)).await);
        }
        assert!(breaks.try_recv().is_err());
    }

    #[tokio::test]
    async fn tor_or_psiphon_alone_keeps_the_socks5_listener_and_frees_the_http_proxy() {
        let (broken, _breaks) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
        let listeners = Listeners {
            socks: socks::bind_listener("socks5", "127.0.0.1:0".parse().unwrap(), "--bind")
                .await
                .unwrap(),
            http: Some(
                socks::bind_listener("http proxy", "127.0.0.1:0".parse().unwrap(), "--http-proxy")
                    .await
                    .unwrap(),
            ),
            broken,
        };
        let socks_at = listeners.socks.local_addr().unwrap();
        let http_at = listeners.http.as_ref().unwrap().local_addr().unwrap();

        let socks = listeners.into_socks();
        assert_eq!(socks.local_addr().unwrap(), socks_at);
        assert!(std::net::TcpListener::bind(socks_at).is_err());
        assert!(std::net::TcpListener::bind(http_at).is_ok());
    }

    const SOON: std::time::Duration = std::time::Duration::from_secs(10);

    #[test]
    fn only_a_tunnel_that_ended_soon_counts_against_its_gateway_or_endpoint() {
        let almost = TUNNEL_STAYED_UP - std::time::Duration::from_secs(1);
        assert_eq!(count_tunnel_end(0, std::time::Duration::ZERO), 1);
        assert_eq!(count_tunnel_end(1, almost), 2);
        assert_eq!(count_tunnel_end(1, TUNNEL_STAYED_UP), 0);
        assert_eq!(count_tunnel_end(7, TUNNEL_STAYED_UP * 2), 0);
        assert_eq!(count_tunnel_end(u32::MAX, SOON), u32::MAX);
    }

    #[test]
    fn spreading_hops_puts_a_different_range_second() {
        let mut found: Vec<SocketAddr> = vec![
            "162.159.192.1:2408".parse().unwrap(),
            "162.159.192.9:2408".parse().unwrap(),
            "188.114.96.1:2408".parse().unwrap(),
        ];
        spread_hops(&mut found);

        assert_eq!(edge_network(found[0].ip()), Some([162, 159, 192]));
        assert_ne!(
            edge_network(found[1].ip()),
            edge_network(found[0].ip()),
            "the second hop must sit in another range"
        );
    }
}
