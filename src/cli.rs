use std::env;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0} requires a value")]
    MissingValue(String),
    #[error("unknown option '{0}'\n\n{usage}", usage = USAGE)]
    UnknownOption(String),
    #[error(
        "--tor-reverse and --psiphon-reverse both want to carry the tunnel; pick one, or put the \
         other inside it with --tor or --psiphon"
    )]
    TwoTunnelCarriers,
    #[error(
        "tor carries tcp only and warp's wireguard endpoints answer on udp alone, so {0} can \
         never be reached through tor; use --masque or --gool, which this mode runs over \
         http/2, or put tor inside the tunnel instead with --tor"
    )]
    UdpOverTor(String),
    #[error(
        "psiphon carries tcp only and warp's wireguard endpoints answer on udp alone, so {0} can \
         never be reached through psiphon; use --masque or --gool, which this mode runs over \
         http/2, or put psiphon inside the tunnel instead with --psiphon"
    )]
    UdpOverPsiphon(String),
    #[error(
        "--tun cannot carry {0}: it replaces socks5 with a kernel interface, and this mode needs the userspace tcp stack that socks5 gives it"
    )]
    TunNeedsStack(String),
    #[error("--bind {0} is not an address and port aether can listen on, such as 127.0.0.1:1819")]
    BadListen(String),
    #[error("--register takes masque, wg, gool, gool-classic, mim or all, not '{0}'")]
    UnknownRegistration(String),
    #[error("--tor-reverse and --psiphon-reverse both want to carry the registration; pick one")]
    TwoRegistrationCarriers,
}

const USAGE: &str = "\
Aether — a censorship circumvention client. It finds a way out of a filtered
network, opens an encrypted tunnel, and serves it as a local SOCKS5 proxy.

Usage:
  aether [OPTIONS]
  aether help              show this text

With no options it asks what it needs: protocol, scan mode, IP version. Every
question has a flag, and passing the flag is what stops the question. Nothing
is read from the environment.

  aether                                   answer the questions as they come
  aether --masque --turbo -4               nothing asked, straight to work
  aether --wg --thorough --noize gfw       classic wireguard on a strict network
  aether --gool --gool-outer 162.159.192.1:2408 --gool-inner 188.114.96.1:2408
  aether --mim                             two masque hops, for a different exit

Front end:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --http-proxy <addr>      also serve an HTTP CONNECT proxy here (off by default)
  --tun <name>             carry the tunnel on this tun device instead of SOCKS5;
                           the kernel then owns tcp, udp and routing (needs root
                           or CAP_NET_ADMIN). --bind, --http-proxy and --route-*
                           no longer apply, and modes that need the userspace
                           tcp stack are refused: --gool, --gool-classic, --mim,
                           --tor-only, --psiphon-only, --team, --gateway,
                           --exit-country
  --tun-addr <a/p,...>     addresses to give the device, e.g. 172.16.0.2/32
  --upstream <url>         dial out through this proxy, e.g.
                           socks5://127.0.0.1:1080 or http://user:pass@host:8080;
                           tor and psiphon dial through it too when no tunnel
                           carries them (tor takes a socks5 address only)
  --fwmark <n>             set SO_MARK on every socket aether opens (Linux and
                           Android, needs root or CAP_NET_ADMIN), so a tun front
                           end on the same router can let them past. Without
                           --upstream a hostname is resolved outside the mark, so
                           the WARP API calls need --api-address as an IP
  --exit-country <spec>    refuse tunnels whose exit country is not wanted:
                           !IR,AZ,RU blocks those, DE,SE allows only those.
                           Checked through the tunnel before serving and again
                           every --exit-check-secs (off: nothing is looked up)
  --exit-check-secs <n>    how often to recheck the exit country (default 60)
  --stats                  log bytes up/down and uptime (off by default)
  --stats-secs <n>         how often to log that line (default 60)
  --quick-reconnect        reuse the last working gateway without asking
  --no-quick-reconnect     always scan fresh, ignore the saved gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both
  --ip <v4|v6|both>        the same choice written out
  --peer <ip:port>         force the peer and skip the scan
  --wg-peer <ip:port>      force the WireGuard peer, skip the scan

Protocol:
  --masque                 MASQUE over QUIC/HTTP-3 (default)
  --wg                     classic WireGuard
  --gool                   WireGuard carried inside MASQUE: the inner hop is
                           dialled from inside WARP, so Cloudflare gives it a
                           different exit than your own address gets
  --gool-classic           the older gool: WireGuard inside WireGuard
  --mim                    MASQUE inside MASQUE: two hops on one carrier (HTTP/3
                           in HTTP/3, or --h2 in --h2), for a different exit
  --protocol <name>        masque | wg | gool | mim

gool endpoint:
  --gool-wg-peer <ip:port> the WireGuard endpoint dialled inside the tunnel
                           (default: the one its registration names, port 2408)

Classic gool (WireGuard in WireGuard) endpoints:
  Both hops are found by the scan unless named here. The port is required:
  which port gets through is what differs between networks. Name one hop and
  the scan finds the other, keeping your address out of the sweep. The two hops
  must be different addresses, and naming one selects classic gool by itself.
  --gool-outer <ip:port>   the outer hop, the one your network sees
  --gool-inner <ip:port>   the inner hop, reached through the outer one
  --gool-peers <out[,in]>  both hops in one value, or only the outer one
  --gool-scan              scan for both, ignoring any endpoint named

MASQUE-in-MASQUE endpoints:
  The outer hop is found by the scan and the inner one is picked for you,
  unless named here. The port is required and the hops must differ; naming one
  selects MASQUE-in-MASQUE by itself.
  --mim-outer <ip:port>    the outer hop, the one your network sees
  --mim-inner <ip:port>    the inner hop, reached through the outer one
  --mim-peers <out[,in]>   both hops in one value, or only the outer one
  --mim-scan               find the outer hop by scanning, ignoring any named

Scan mode:
  --scan <mode>            turbo | balanced | thorough | verified | ironclad
  --turbo                  stop at the first candidate that answers
  --balanced               default: collect a few, keep the fastest
  --thorough               sweep whole ranges, when everything looks blocked
  --verified               dial only the edges measured to answer connect-ip,
                           never a guessed neighbour; on --gool and --mim the
                           two hops also stay in separate ranges
  --ironclad               open a real tunnel and make a real HTTP request per
                           candidate, so a gateway is trusted only once it has
                           carried traffic

Obfuscation:
  --noize <profile>        off | light | firewall | balanced | gfw | aggressive
                           (default firewall for MASQUE, balanced for WireGuard
                           and gool; reach for gfw when the default fails)

Transport:
  --h2                     use HTTP/2 (TCP) instead of HTTP/3 (QUIC)
  --h3                     use HTTP/3 (QUIC), without asking
  --no-quic-v2             do not send the QUIC v2 opener, which opens a path on
                           networks that block v1 but let v2 through
  --h2-peer <ip:port>      override the peer used by the HTTP/2 transport
  --h2-keepalive-secs <n>  HTTP/2 keepalive interval (default 15)
  --h2-timeout-secs <n>    how long a keepalive may go unanswered (default 20)
  --masque-sni <name>      server name in the MASQUE ClientHello (default
                           www.cloudflare.com; the WARP client sends
                           consumer-masque.cloudflareclient.com); the HTTP host
                           and :authority stay cloudflareaccess.com. With --ech
                           it is the name inside the encrypted ClientHello
  --dns <list>             resolvers used inside the tunnel
                           (default 1.1.1.1,1.0.0.1)
  --mtu <n>                tunnel MTU, 576 to 1500 (default 1280, or the most an
                           http/3 datagram carries)
  --startup-secs <n>       total MASQUE startup deadline (default 30)
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --no-data-check          skip the end-to-end data-plane validation
  --reconnect-secs <n>     delay before reconnecting after a drop (default 2)
  --fragment               fragment the TLS ClientHello on HTTP/2 and on the
                           WARP API calls, for firewalls that reset a whole
                           ClientHello whose SNI ends in cloudflareclient.com
  --fragment-size <n|a-b>  fragment size in bytes (default 8-16)
  --fragment-delay-ms <n|a-b>
                           delay between fragments in ms (default 2-10)
  --fragment-sni           split the server name itself across two fragments

TLS:
  The tunnel's handshakes, MASQUE over HTTP/2 and HTTP/3, the WARP API calls and
  the DoH lookup of --ech-dns carry Chrome's fingerprint as BoringSSL writes it,
  with what these flags change. Certificates go unchecked, except the MASQUE
  gateway's with --team or --tls-verify.
  --tls-verify             hold the MASQUE gateway's certificate to aether's pins
                           (on by default with --team)
  --no-tls-verify          do not, even with --team
  --ech <auto|base64>      offer Encrypted Client Hello on the MASQUE handshakes
                           and WARP API calls, with the key looked up (auto) or
                           given in base64; without a key to offer, neither goes
                           ahead rather than send a name in the clear
  --ech-dns <url>          resolver --ech auto asks for the key: udp://ip[:port],
                           tcp://ip[:port] (port 53) or https:// (port 443)
                           (default udp://1.1.1.1); @address=<ip|name> dials
                           elsewhere and @sni=<name> sets the ClientHello name
  --ech-domain <name>      domain whose key --ech auto takes
                           (default cloudflare-ech.com)
  --tls12-ciphers <list>   TLS 1.2 suites, ':'-separated, after the TLS 1.3 ones
                           (default Chrome's ALL:!aPSK:!ECDSA+SHA1:!3DES)
  --tls13-ciphers <list>   TLS 1.3 suites, in order (default Chrome's order)
  --tls-groups <list>      TLS groups, in order (default P-256:X25519:P-384)
  --tls-key-shares <list>  which groups get a key share, in order (default
                           Chrome's: the first group, and the first of the other
                           kind, post-quantum or not)
  --tls-sigalgs <list>     signature algorithms, in order, by BoringSSL's names
                           (default Chrome's eight, then rsa_pkcs1_sha1)
  --no-grease              leave out the GREASE values (RFC 8701) that Chrome's
                           suites, extensions, groups, key shares and versions
                           carry
  --grease-sigalgs         put a GREASE value first among the signature
                           algorithms as well, as Chrome does
  --tls-cert-compress <list>
                           certificate compression offered, in order, of zlib,
                           brotli and zstd (default none)
  --tls-alps <new|old>     offer ALPS for h2 and h3 under the codepoint Chrome
                           sends now (new, 0x44cd) or sent before (old, 0x4469)
  --tls-anchors <list>     trust anchor IDs asked for, in order, dotted,
                           ':'-separated (default none)
  --tls-padding <n>        bytes of padding asked of the server, 0 to 65535, as
                           Chrome asks 6000 (default none)
  --ech-grease             send a GREASE ECH extension when no ECH key is
                           offered, as Chrome and Firefox do
  --no-ocsp                leave out status_request (OCSP), which Chrome sends
  --no-sct                 leave out signed_certificate_timestamp, which Chrome
                           sends
  --no-session-ticket      leave out session_ticket, which Chrome sends
  --no-ext-shuffle         keep one fixed extension order instead of Chrome's
                           per-handshake shuffle

WireGuard:
  --wg-keepalive-secs <n>  persistent keepalive interval (default 5)
  --no-profile-retry       do not retry other obfuscation profiles during a scan
  --wg-stale-secs <n>      silence before the tunnel counts as dead (default 10)
  --wg-cooldown-secs <n>   how long an endpoint is left out of rescans after two
                           tunnels ended within five minutes of starting
                           (default 300)

Tor (needs a build with --features tor):
  --tor                    carry tor inside the tunnel: aether -> warp -> tor ->
                           internet; the usual proxy keeps the warp exit, and a
                           second one on --tor-bind comes out of tor
  --tor-reverse            dial the tunnel through tor, so warp is reached from
                           a tor exit and your network never sees it; tor
                           carries tcp only, so this runs masque over http/2 and
                           refuses --wg and --gool-classic
  --tor-only               no tunnel: the proxy on --bind is plain tor
  --tor-bind <addr>        where tor listens with --tor and --tor-reverse
                           (default 127.0.0.1:1820)
  --tor-http <addr>        also serve tor as an HTTP CONNECT proxy here
  --tor-bridge-file <path> read bridge lines from this file, one per line, as
                           torrc writes them
  --tor-relays <what>      use running relays from onionoo as plain bridges:
                           auto (default, alongside bridgedb), only, off, or a
                           count such as 80
  --tor-relay-ports <set>  relay ports to consider: web (default, 80 and 443) or
                           any; tor's own ports are always skipped
  --tor-dir <path>         tor's directory cache and state (default <config>-tor)
  --tor-country <cc>       ask bridgedb for bridges of this country, e.g. ir
  --tor-check <host:port>  an address tor must reach to count as working
                           (default check.torproject.org:443)
  --tor-log <level>        how loud tor is: info, debug or trace
  --tor-direct-secs <n>    how long to try tor plainly before bridges
                           (default 75)
  --tor-stall-secs <n>     give up on a bridge after this long with no headway
                           (default 75)
  --tor-bridge-secs <n>    the longest any one bridge may take (default 360)

  On a blocked network aether fetches bridges from bridgedb and finds the
  pluggable transports already on this machine, tor browser's included; the
  flags below override what it picks.
  --tor-bridges            go to bridges at once, without trying tor plainly
  --no-tor-bridges         never use bridges, however blocked the network looks
  --tor-bridge <line>      a bridge line of your own; repeat for more than one
  --tor-pt [name=]<path>   the pluggable transport binary a bridge needs, e.g.
                           --tor-pt /usr/bin/lyrebird (obfs4 is assumed)
  --tor-pt-dir <path>      another folder to look in for those binaries

Psiphon:
  --psiphon                carry psiphon inside the tunnel: aether -> warp ->
                           psiphon -> internet, served on --psiphon-bind
  --psiphon-reverse        dial the tunnel through psiphon; it carries tcp only,
                           so this runs masque over http/2 and refuses --wg and
                           --gool-classic
  --psiphon-only           no tunnel: the proxy on --bind is plain psiphon
  --psiphon-mode <shape>   auto (default), cdn (meek through a cdn only) or
                           direct (no fronting)
  --psiphon-config <path>  your own psiphon json config, laid over the built-in
                           one
  --psiphon-cdn-ips <list> addresses to try as cdn fronting edges (default: the
                           list built into psiphon)
  --psiphon-cdn-sni <list> server names to present to those edges
  --psiphon-cdn-sets <list>
                           which built-in edge lists the fronting scan tries:
                           cloudflare, fastly, cloudfront, psiphon-akamai,
                           psiphon-bunny, vercel, github, curated-fronting,
                           legacy-android-overrides (default all)
  --psiphon-bind <addr>    where psiphon listens with --psiphon and
                           --psiphon-reverse (default 127.0.0.1:1821)
  --psiphon-http <addr>    also serve psiphon as an HTTP CONNECT proxy here
  --psiphon-region <cc>    ask psiphon to leave from this country, e.g. DE
  --psiphon-dir <path>     where psiphon keeps its data
                           (default <config>-psiphon)
  --psiphon-bin <path>     the psiphon-tunnel-core binary, when it is not next to
                           aether, in ./pt, or on PATH
  --psiphon-entries <path> server entries psiphon starts with, so the first
                           connection need not download the list
  --psiphon-ready-secs <n> how long to wait for psiphon to tunnel (default 180)
  --psiphon-interface <name>
                           the interface psiphon listens on
  --psiphon-sponsor-id <id> the sponsor id psiphon presents
  --psiphon-channel-id <id> the propagation channel id psiphon presents
  --psiphon-server-list <url>
                           where psiphon fetches its remote server list

Zero Trust (WARP for organizations):
  --team <name>            enrol into a Zero Trust organization by team name
  --access-id <id>         service token client id (headless enrolment)
  --access-secret <secret> service token client secret (headless enrolment)
  --access-email <addr>    sign in with a one-time code emailed here
  --access-token <jwt>     an enrolment token from
                           https://<team>.cloudflareaccess.com/warp
  --gateway                send http and https through the organization's
                           gateway proxy so its filtering and logging apply
                           (off by default: it adds a hop and logs your browsing)

Routing:
  --route-block <list>     never let these reach the network at all
  --route-direct <list>    send these straight out, bypassing the tunnel
  --routes <path>          load both lists from a file with [block] and [direct]
                           sections
                           Entries are comma or newline separated, and may be:
                             example.com          the name and every subdomain
                             full:example.com     that exact name only
                             keyword:doubleclick  any name containing it
                             regexp:^ad[0-9]+     a regular expression
                             10.0.0.0/8           a network, or a bare address
                             port:25              a port, or port:3000-3010
                             private              lan, loopback and cgnat space
                           block is checked first, then direct, else the tunnel

Config:
  --config <path>          base identity config path (default aether.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE (classic gool adds a
                           second wireguard identity beside it, named
                           <config>-secondary.toml)
  --register <which>       register identities and exit, with no scan and no
                           tunnel: masque, wg, gool, gool-classic, mim or all.
                           Each new identity is saved only once WARP is enabled
                           on it; an existing file is kept, never replaced
  --api-address <ip|name[:port]>
                           where the WARP API calls go: port 443 unless one
                           follows, an IPv6 address in brackets (default: the
                           --api-sni name, on 443); with --fwmark and no
                           --upstream, an IP address only
  --api-sni <name>         server name in the ClientHello of those calls
                           (default: the --api-host name); with --ech, the name
                           inside the encrypted ClientHello
  --api-host <name>        the HTTP host of those calls (default
                           api.devices.cloudflare.com); a name that gets no
                           answer falls back to api.cloudflareclient.com

Advanced:
  --perf <low|medium|high> force a resource profile instead of detecting from
                           cpu and ram (low: routers and small boards, medium:
                           typical desktop, high: servers)
  --max-clients <n>        proxy clients served at once; past it new ones wait
                           (default by resources, 512 to 8192)
  --half-close-secs <n>    how long a half-closed connection may sit silent
                           before it is closed (default 30)
  --tcp-keepalive-secs <n> idle time before a keepalive probes the other end;
                           three unanswered ones close it (default 60)
  --tcp-connect-secs <n>   how long a connection through the tunnel may take to
                           open (default 30)
  --route-sniff-ms <n>     how long to wait for the bytes that name the server,
                           which is what makes routing rules work behind a tun
                           front end (default 400)
  --no-route-sniff         stop reading the server name from those bytes
  --ironclad-port <n>      port the ironclad scan makes its real HTTP request to
                           (default 80)
  --no-reprovision         stop replacing an identity Cloudflare has refused
                           with a freshly registered one
  --log-level <level>      error | warn | info | debug | trace (default info)
  --verbose                shortcut for --log-level debug

  -v, --version            show version and exit
  -h, --help, help         show this help and exit

After startup the proxy is at the address --bind names, 127.0.0.1:1819 by
default. Check it with:

  curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace

The reply should show a Cloudflare colo and warp=on. The proxy has no
authentication, so bind it to 0.0.0.0 only when you mean to share the tunnel
with your network.
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    Run,
    Done,
}

pub fn parse_and_apply() -> crate::error::Result<Parsed> {
    parse_args(env::args().skip(1).collect())
}

pub fn parse_args(args: Vec<String>) -> crate::error::Result<Parsed> {
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();

        macro_rules! next_value {
            () => {{
                i += 1;
                args.get(i)
                    .ok_or_else(|| CliError::MissingValue(arg.to_string()))?
            }};
        }

        match arg {
            "-v" | "--version" => {
                println!("aether {}", env!("CARGO_PKG_VERSION"));
                return Ok(Parsed::Done);
            }

            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                return Ok(Parsed::Done);
            }

            "--bind" => set("AETHER_SOCKS", next_value!()),
            "--http-proxy" => set("AETHER_HTTP_PROXY", next_value!()),
            "--upstream" => set("AETHER_UPSTREAM", next_value!()),
            "--tor" => set("AETHER_TOR", "chain"),
            "--tor-reverse" => set("AETHER_TOR", "reverse"),
            "--tor-only" => set("AETHER_TOR", "only"),
            "--tor-bridge" => append("AETHER_TOR_BRIDGES", next_value!()),
            "--tor-bridges" => set("AETHER_TOR_BRIDGES", "auto"),
            "--tor-bridge-file" => set("AETHER_TOR_BRIDGE_FILE", next_value!()),
            "--tor-relays" => set("AETHER_TOR_RELAYS", next_value!()),
            "--tor-relay-ports" => set("AETHER_TOR_RELAY_PORTS", next_value!()),
            "--no-tor-bridges" => set("AETHER_TOR_BRIDGES", "off"),
            "--tor-pt" => append("AETHER_TOR_PT", next_value!()),
            "--tor-pt-dir" => append("AETHER_TOR_PT_DIR", next_value!()),
            "--tor-bind" => set("AETHER_TOR_BIND", next_value!()),
            "--tor-http" => set("AETHER_TOR_HTTP", next_value!()),
            "--tor-dir" => set("AETHER_TOR_DIR", next_value!()),
            "--tor-country" => set("AETHER_TOR_COUNTRY", next_value!()),
            "--tor-check" => set("AETHER_TOR_CHECK", next_value!()),
            "--tor-log" => set("AETHER_TOR_LOG", next_value!()),
            "--tor-direct-secs" => set("AETHER_TOR_DIRECT_SECS", next_value!()),
            "--tor-stall-secs" => set("AETHER_TOR_STALL_SECS", next_value!()),
            "--tor-bridge-secs" => set("AETHER_TOR_BRIDGE_SECS", next_value!()),
            "--psiphon" => set("AETHER_PSIPHON", "chain"),
            "--psiphon-reverse" => set("AETHER_PSIPHON", "reverse"),
            "--psiphon-only" => set("AETHER_PSIPHON", "only"),
            "--psiphon-config" => set("AETHER_PSIPHON_CONFIG", next_value!()),
            "--psiphon-bind" => set("AETHER_PSIPHON_BIND", next_value!()),
            "--psiphon-http" => set("AETHER_PSIPHON_HTTP", next_value!()),
            "--psiphon-region" => set("AETHER_PSIPHON_REGION", next_value!()),
            "--psiphon-mode" => set("AETHER_PSIPHON_MODE", next_value!()),
            "--psiphon-cdn-ips" => set("AETHER_PSIPHON_CDN_IPS", next_value!()),
            "--psiphon-cdn-sni" => set("AETHER_PSIPHON_CDN_SNI", next_value!()),
            "--psiphon-cdn-sets" => set("AETHER_PSIPHON_CDN_SETS", next_value!()),
            "--psiphon-dir" => set("AETHER_PSIPHON_DIR", next_value!()),
            "--psiphon-bin" => set("AETHER_PSIPHON_BIN", next_value!()),
            "--psiphon-entries" | "--psiphon-server-entries" => {
                set("AETHER_PSIPHON_SERVER_ENTRIES", next_value!())
            }
            "--psiphon-ready-secs" => set("AETHER_PSIPHON_READY_SECS", next_value!()),
            "--psiphon-interface" => set("AETHER_PSIPHON_INTERFACE", next_value!()),
            "--psiphon-sponsor-id" => set("AETHER_PSIPHON_SPONSOR_ID", next_value!()),
            "--psiphon-channel-id" => set("AETHER_PSIPHON_PROPAGATION_CHANNEL_ID", next_value!()),
            "--psiphon-server-list" => set("AETHER_PSIPHON_SERVER_LIST", next_value!()),
            "--fwmark" | "--mark" => set("AETHER_MARK", next_value!()),
            "--tun" => set("AETHER_TUN", next_value!()),
            "--tun-addr" => set("AETHER_TUN_ADDR", next_value!()),
            "--exit-country" | "--exit-loc" => set("AETHER_EXIT_LOC", next_value!()),
            "--exit-check-secs" | "--exit-loc-secs" => set("AETHER_EXIT_LOC_SECS", next_value!()),
            "--stats" => set("AETHER_STATS", "1"),
            "--stats-secs" => set("AETHER_STATS_SECS", next_value!()),
            "--quick-reconnect" => set("AETHER_QUICK_RECONNECT", "1"),
            "--no-quick-reconnect" => set("AETHER_QUICK_RECONNECT", "0"),

            "-4" => set("AETHER_IP", "v4"),
            "-6" => set("AETHER_IP", "v6"),
            "--dual" => set("AETHER_IP", "both"),
            "--ip" => set("AETHER_IP", next_value!()),

            "--peer" => set("AETHER_PEER", next_value!()),
            "--wg-peer" => set("AETHER_WG_PEER", next_value!()),

            "--gool-outer" | "--wiw-outer" | "--outer-peer" => {
                set("AETHER_WIW_OUTER_PEER", next_value!())
            }
            "--gool-inner" | "--wiw-inner" | "--inner-peer" => {
                set("AETHER_WIW_INNER_PEER", next_value!())
            }
            "--gool-peers" | "--wiw-peers" => set("AETHER_WIW_PEERS", next_value!()),
            "--gool-scan" | "--wiw-scan" => set("AETHER_WIW_PEERS", "auto"),

            "--masque" => set("AETHER_PROTOCOL", "masque"),
            "--wg" | "--wireguard" | "--warp" => set("AETHER_PROTOCOL", "wg"),
            "--gool" | "--wiw" => set("AETHER_PROTOCOL", "gool"),
            "--gool-wg-peer" | "--gool-peer" => {
                set("AETHER_PROTOCOL", "gool");
                set("AETHER_GOOL_INNER", next_value!())
            }
            "--gool-classic" => {
                set("AETHER_PROTOCOL", "gool");
                set("AETHER_GOOL_MODE", "classic")
            }
            "--mim" | "--masque-in-masque" => set("AETHER_PROTOCOL", "mim"),
            "--mim-outer" => set("AETHER_MIM_OUTER_PEER", next_value!()),
            "--mim-inner" => set("AETHER_MIM_INNER_PEER", next_value!()),
            "--mim-peers" => set("AETHER_MIM_PEERS", next_value!()),
            "--mim-scan" => set("AETHER_MIM_PEERS", "auto"),
            "--protocol" => set("AETHER_PROTOCOL", next_value!()),

            "--scan" => set("AETHER_SCAN", next_value!()),
            "--turbo" => set("AETHER_SCAN", "turbo"),
            "--balanced" => set("AETHER_SCAN", "balanced"),
            "--thorough" => set("AETHER_SCAN", "thorough"),
            "--verified" | "--stealth" => set("AETHER_SCAN", "verified"),
            "--ironclad" => set("AETHER_SCAN", "ironclad"),

            "--noize" => set("AETHER_NOIZE", next_value!()),

            "--h2" | "--http2" => set("AETHER_MASQUE_HTTP2", "1"),
            "--h3" | "--quic" => set("AETHER_MASQUE_HTTP2", "0"),
            "--no-quic-v2" => set("AETHER_QUIC_V2", "0"),
            "--h2-peer" => set("AETHER_MASQUE_H2_PEER", next_value!()),
            "--masque-sni" => set("AETHER_MASQUE_SNI", next_value!()),
            "--ech" => set("AETHER_ECH", next_value!()),
            "--ech-dns" => set("AETHER_ECH_DNS", next_value!()),
            "--ech-domain" => set("AETHER_ECH_DOMAIN", next_value!()),
            "--no-data-check" => {
                set("AETHER_MASQUE_NO_DATA_CHECK", "1");
                set("AETHER_WG_NO_DATA_CHECK", "1");
            }
            "--validate-secs" => {
                let value = next_value!().clone();
                set("AETHER_MASQUE_VALIDATE_SECS", &value);
                set("AETHER_WG_VALIDATE_SECS", &value);
            }
            "--startup-secs" => set("AETHER_MASQUE_STARTUP_SECS", next_value!()),
            "--reconnect-secs" => {
                let value = next_value!().clone();
                set("AETHER_MASQUE_RECONNECT_SECS", &value);
                set("AETHER_WG_RECONNECT_SECS", &value);
            }
            "--dns" => set("AETHER_DNS", next_value!()),
            "--fragment" => set("AETHER_MASQUE_H2_FRAGMENT", "1"),
            "--fragment-size" => set("AETHER_MASQUE_H2_FRAGMENT_SIZE", next_value!()),
            "--fragment-delay-ms" | "--fragment-delay" => {
                set("AETHER_MASQUE_H2_FRAGMENT_DELAY", next_value!())
            }
            "--fragment-sni" => set("AETHER_MASQUE_H2_FRAGMENT_SNI", "1"),
            "--mtu" => set("AETHER_MASQUE_MTU", next_value!()),
            "--h2-keepalive-secs" => set("AETHER_MASQUE_H2_KEEPALIVE_SECS", next_value!()),
            "--h2-timeout-secs" | "--h2-keepalive-timeout-secs" => {
                set("AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS", next_value!())
            }

            "--wg-keepalive-secs" | "--keepalive" => set("AETHER_WG_KEEPALIVE", next_value!()),
            "--no-profile-retry" => set("AETHER_WG_NO_PROFILE_RETRY", "1"),
            "--wg-stale-secs" | "--stale-secs" => set("AETHER_WG_STALE_SECS", next_value!()),
            "--wg-cooldown-secs" | "--endpoint-cooldown-secs" => {
                set("AETHER_WG_ENDPOINT_COOLDOWN_SECS", next_value!())
            }

            "--config" => set("AETHER_CONFIG", next_value!()),
            "--wg-config" => set("AETHER_WG_CONFIG", next_value!()),
            "--masque-config" => set("AETHER_MASQUE_CONFIG", next_value!()),
            "--register" => set("AETHER_REGISTER", next_value!()),
            "--api-address" => set("AETHER_API_ADDRESS", next_value!()),
            "--api-sni" => set("AETHER_API_SNI", next_value!()),
            "--api-host" => set("AETHER_API_HOST", next_value!()),

            "--team" | "--organization" => set("AETHER_TEAM", next_value!()),
            "--access-id" => set("AETHER_ACCESS_CLIENT_ID", next_value!()),
            "--access-secret" => set("AETHER_ACCESS_CLIENT_SECRET", next_value!()),
            "--access-token" => set("AETHER_ACCESS_TOKEN", next_value!()),
            "--access-email" => set("AETHER_ACCESS_EMAIL", next_value!()),
            "--gateway" => set("AETHER_GATEWAY", "1"),

            "--route-block" => set("AETHER_ROUTE_BLOCK", next_value!()),
            "--route-direct" => set("AETHER_ROUTE_DIRECT", next_value!()),
            "--routes" => set("AETHER_ROUTES_FILE", next_value!()),

            "--tls-groups" => set("AETHER_TLS_GROUPS", next_value!()),
            "--tls-key-shares" => set("AETHER_TLS_KEY_SHARES", next_value!()),
            "--tls12-ciphers" | "--tls-ciphers" => set("AETHER_TLS_CIPHERS", next_value!()),
            "--tls13-ciphers" => set("AETHER_TLS13_CIPHERS", next_value!()),
            "--no-grease" | "--disable-grease" => set("AETHER_DISABLE_GREASE", "1"),
            "--grease-sigalgs" | "--enable-grease-sigalgs" => {
                set("AETHER_ENABLE_GREASE_SIGALGS", "1")
            }
            "--tls-sigalgs" => set("AETHER_TLS_SIGALGS", next_value!()),
            "--tls-cert-compress" | "--tls-cert-compression" => {
                set("AETHER_TLS_CERT_COMPRESSION", next_value!())
            }
            "--tls-alps" => set("AETHER_TLS_ALPS", next_value!()),
            "--tls-anchors" | "--tls-trust-anchors" => {
                set("AETHER_TLS_TRUST_ANCHORS", next_value!())
            }
            "--tls-padding" | "--tls-server-padding" => {
                set("AETHER_TLS_SERVER_PADDING", next_value!())
            }
            "--ech-grease" | "--enable-ech-grease" => set("AETHER_ENABLE_ECH_GREASE", "1"),
            "--no-ocsp" | "--disable-ocsp-stapling" => set("AETHER_DISABLE_OCSP_STAPLING", "1"),
            "--no-sct" | "--disable-sct" => set("AETHER_DISABLE_SCT", "1"),
            "--no-session-ticket" | "--disable-session-ticket" => {
                set("AETHER_DISABLE_SESSION_TICKET", "1")
            }
            "--no-ext-shuffle" | "--disable-extension-permutation" => {
                set("AETHER_DISABLE_EXTENSION_PERMUTATION", "1")
            }
            "--tls-verify" => set("AETHER_TLS_VERIFY", "1"),
            "--no-tls-verify" => set("AETHER_TLS_VERIFY", "0"),
            "--max-clients" => set("AETHER_MAX_CLIENTS", next_value!()),
            "--half-close-secs" => set("AETHER_HALF_CLOSE_SECS", next_value!()),
            "--tcp-keepalive-secs" => set("AETHER_TCP_KEEPALIVE_SECS", next_value!()),
            "--tcp-connect-secs" => set("AETHER_TCP_CONNECT_SECS", next_value!()),
            "--route-sniff-ms" => set("AETHER_ROUTE_SNIFF_MS", next_value!()),
            "--no-route-sniff" => set("AETHER_ROUTE_SNIFF", "0"),
            "--ironclad-port" => set("AETHER_IRONCLAD_PORT", next_value!()),
            "--no-reprovision" => set("AETHER_REPROVISION", "0"),
            "--perf" => set("AETHER_PERF_PROFILE", next_value!()),
            "--log-level" => set("AETHER_LOG_LEVEL", next_value!()),
            "--verbose" => set("AETHER_LOG_LEVEL", "debug"),

            other => {
                return Err(CliError::UnknownOption(other.to_string()).into());
            }
        }

        i += 1;
    }

    check_tun_conflicts()?;

    Ok(Parsed::Run)
}

/// A tun replaces socks5, so whatever can only be served through socks5 is
/// refused here rather than after an identity has been provisioned.
fn check_tun_conflicts() -> crate::error::Result<()> {
    if crate::settings::var("AETHER_TUN").is_err() {
        return Ok(());
    }

    for (key, flag, value) in [
        ("AETHER_TOR", "--tor-only", "only"),
        ("AETHER_PSIPHON", "--psiphon-only", "only"),
        ("AETHER_PROTOCOL", "--gool", "gool"),
        ("AETHER_PROTOCOL", "--mim", "mim"),
        ("AETHER_TEAM", "--team", "team"),
        ("AETHER_GATEWAY", "--gateway", "1"),
    ] {
        if crate::settings::var(key).as_deref() == Ok(value) {
            return Err(CliError::TunNeedsStack(flag.to_string()).into());
        }
    }

    if crate::settings::var("AETHER_EXIT_LOC").is_ok() {
        return Err(CliError::TunNeedsStack("--exit-country".to_string()).into());
    }

    Ok(())
}

fn set(key: &str, value: &str) {
    crate::settings::set(key, value);
}

fn append(key: &str, value: &str) {
    match crate::settings::var(key) {
        Ok(existing) if !existing.trim().is_empty() => {
            crate::settings::set(key, format!("{existing};{value}"))
        }
        _ => crate::settings::set(key, value),
    }
}
