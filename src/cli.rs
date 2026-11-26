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
    #[error("--tun cannot carry {0}: it replaces socks5 with a kernel interface, and this mode needs the userspace tcp stack that socks5 gives it")]
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

Run it with no options and it asks for what it needs: protocol, scan mode, IP
version. Every question has a flag, and passing it is what stops the question
being asked. Nothing is read from the environment.

  aether                                   answer the questions as they come
  aether --masque --turbo -4               nothing asked, straight to work
  aether --wg --thorough --noize gfw       classic wireguard on a strict network
  aether --gool --wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408
  aether --mim                             two masque hops, for a different exit

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --http-proxy <addr>      also expose an HTTP CONNECT proxy on this address
                           (off by default, e.g. 127.0.0.1:1820)
  --upstream <url>         dial out through a proxy already running here, e.g.
                           socks5://127.0.0.1:1080 or http://user:pass@host:8080;
                           tor and psiphon dial through it as well when no tunnel
                           carries them (tor takes a socks5 address only)
  --mark <n>               put this firewall mark (SO_MARK) on every socket aether
                           opens to the internet, e.g. 0xff, so a tun front end on
                           the same Linux router can let them past instead of
                           looping them back in (Linux and Android, needs root or
                           CAP_NET_ADMIN); a name is looked up outside the mark, so
                           without --upstream the calls to the WARP API take an IP
                           address only, see --api-address
  --tun <name>             carry the tunnel on a tun device of this name instead
                           of socks5, so the kernel owns tcp, udp and routing: send
                           traffic into the device and it goes through the tunnel
                           (needs root or CAP_NET_ADMIN and /dev/net/tun; --bind,
                           --http-proxy and --route-* belong to socks5 and are
                           ignored, and modes that need the userspace tcp stack,
                           like --gool, --mim and --tor-only, are refused)
  --tun-addr <a/p,...>     give the device these addresses instead of the ones
                           the tunnel assigned, e.g. 172.16.0.2/32
  --exit-loc <spec>        refuse a tunnel whose exit country is not wanted, checked
                           through the finished tunnel before socks5 serves and again
                           every minute after: !IR,AZ,RU blocks those, DE,SE allows
                           only those. Off unless you pass this flag: without it
                           nothing is looked up and no tunnel is refused
  --exit-loc-secs <n>      how often to recheck the exit country (default 60)
  --stats                  log how much has gone up and down and how long the
                           tunnel has been up (off by default)
  --stats-secs <n>         how often to log that line (default 60)
  --quick-reconnect        auto-accept reconnecting with the last known working gateway
  --no-quick-reconnect     always scan fresh, ignore any saved last-connection gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both IPv4 and IPv6
  --ip <v4|v6|both>        the same choice written out
  --peer <ip:port>         force a MASQUE/WireGuard peer, skip scanning
  --wg-peer <ip:port>      force a WireGuard peer (warp-in-warp outer), skip scanning

Protocol:
  --masque                 use MASQUE over QUIC/HTTP-3 (default)
  --wg, --wireguard, --warp
                           use classic WireGuard
  --gool, --wiw            use gool: a wireguard warp tunnel carried inside a
                           masque one. The wireguard hop is dialled from
                           inside warp, so cloudflare gives it another exit
                           than your own address would get. Its identity is
                           <masque config>-gool.toml: --register gool makes
                           it, and the tunnel registers one from inside warp
                           when there is none
  --gool-peer <ip:port>    the wireguard endpoint gool dials inside the tunnel
                           (default: the one its registration names, port 2408)
  --gool-classic           the older gool: wireguard tunneled in wireguard
  --mim, --masque-in-masque
                           use MASQUE-in-MASQUE: a masque tunnel carried inside
                           another one, which changes the address you come out
                           of the way gool does, on the same carrier for both
                           hops (HTTP/3 in HTTP/3, or --h2 for HTTP/2 in HTTP/2)
  --protocol <name>        masque | wg | gool | mim

Classic gool (WARP-in-WARP) endpoints:
  Naming any of these selects the classic gool. Both hops are found by the
  scan unless you name them here. The port is
  required: which port gets through is exactly what differs between networks,
  so none is assumed for you. Name one hop and the scan finds the other,
  keeping your address out of the sweep. The two hops must be different
  addresses, and naming one selects warp-in-warp on its own, so --gool
  alongside is optional.
  --wiw-outer <ip:port>    the outer hop, the one your network sees
  --wiw-inner <ip:port>    the inner hop, reached through the outer one
  --wiw-peers <out[,in]>   both hops in one value, or only the outer one
  --wiw-scan               scan for both, ignoring any endpoint already named

MASQUE-in-MASQUE endpoints:
  The outer hop is found by the scan and the inner one is picked for you, both
  unless you name them here. The port is required, and the two hops must be
  different addresses. Naming one selects masque-in-masque on its own.
  --mim-outer <ip:port>    the outer hop, the one your network sees
  --mim-inner <ip:port>    the inner hop, reached through the outer one
  --mim-peers <out[,in]>   both hops in one value, or only the outer one
  --mim-scan               find the outer hop by scanning, ignoring any endpoint
                           already named

Scan mode:
  --scan <mode>            turbo | balanced | thorough | verified | ironclad
  --turbo                  stop at the first candidate that answers
  --balanced               default: collect a few, keep the fastest
  --thorough               sweep whole ranges, for when everything looks blocked
  --verified               dial only the edges measured to answer connect-ip,
                           never a guessed neighbour. On --gool and --mim it also
                           keeps the two hops in separate ranges, which is what
                           moves the exit address; the plain modes are untouched
  --ironclad               open a real tunnel and make a real HTTP request per
                           candidate, so a gateway is only trusted once it has
                           genuinely carried traffic

Obfuscation:
  --noize <profile>        off | light | firewall | balanced | gfw | aggressive
                           firewall is the default for MASQUE, balanced for
                           WireGuard and gool; reach for gfw when the default
                           does not get through

MASQUE transport:
  --h2, --http2            use HTTP/2 (TCP) instead of HTTP/3 (QUIC)
  --h3, --quic             use HTTP/3 (QUIC), without asking
  --no-quic-v2             do not send the QUIC v2 version-negotiation opener
                           (it is on by default; it opens a path for HTTP/3 on
                           networks that block QUIC v1 but let QUIC v2 through)
  --h2-peer <ip:port>      override the peer used for the HTTP/2 transport
  --no-data-check          skip the end-to-end data-plane validation
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --startup-secs <n>       total MASQUE startup deadline (default 30)
  --reconnect-secs <n>     delay before reconnecting after a tunnel drop (default 2)
  --dns <list>             resolvers used inside the tunnel (default 1.1.1.1,1.0.0.1)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
                           and on the calls to the WARP API, whatever the
                           transport (off by default; it helps where a
                           firewall resets a whole ClientHello whose SNI ends
                           in cloudflareclient.com, as Iran's does)
  --fragment-size <n|a-b>  fragment chunk size in bytes (default 8-16)
  --fragment-delay <n|a-b> delay between fragments in ms (default 2-10)
  --fragment-sni           split the server name itself across two fragments
                           (off by default)
  --mtu <n>                the tunnel's MTU, 576 to 1500 (default 1280, or the
                           most an http/3 datagram carries)
  --h2-keepalive-secs <n>  HTTP/2 keepalive interval (default 15)
  --h2-keepalive-timeout-secs <n>
                           how long a keepalive may go unanswered (default 20)

TLS:
  the TLS handshakes of the tunnel and its setup, MASQUE over HTTP/2 and HTTP/3,
  the calls to the WARP API and the DoH lookup of --ech-dns, have Chrome's
  fingerprint as BoringSSL writes it, with what these change; certificates go
  unchecked, but for the MASQUE gateway's with --team or --tls-verify
  --masque-sni <name>      the server name the MASQUE handshakes, over HTTP/3 and
                           HTTP/2, put in their ClientHello (default
                           www.cloudflare.com; the WARP client sends
                           consumer-masque.cloudflareclient.com); the HTTP host,
                           the :authority of the CONNECT request, stays
                           cloudflareaccess.com. With --ech it is the name
                           inside the encrypted ClientHello
  --tls-verify             hold the certificate of the MASQUE gateway to the
                           pins aether carries (on by default with --team)
  --no-tls-verify          do not, even with --team
  --ech <auto|base64>      enable Encrypted Client Hello on the MASQUE handshakes
                           and the calls to the WARP API, with the key looked up
                           (auto) or given in base64; without a key it can
                           offer, neither goes ahead rather than send a name in
                           the clear. The DoH lookup of the key goes without it
  --ech-dns <url>          the resolver --ech auto asks for the key:
                           udp://ip[:port] or tcp://ip[:port], port 53 unless
                           given, or a DNS-over-HTTPS https:// URL, port 443
                           unless given (default udp://1.1.1.1). After the URL,
                           @address=<ip|name> sends the connection there and
                           @sni=<name> puts that name in the ClientHello; the
                           URL's host stays the HTTP host, e.g.
                           https://doq.dns4all.eu/dns-query@address=2.2.2.2@sni=google.com
  --ech-domain <name>      the domain whose key --ech auto takes
                           (default cloudflare-ech.com)
  --tls-ciphers <list>     TLS 1.2 cipher suites, listed after the TLS 1.3 ones,
                           which stay as they are; names separated by ':', e.g.
                           \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\"
                           (default Chrome's, \"ALL:!aPSK:!ECDSA+SHA1:!3DES\").
                           HTTP/3 lists none: QUIC offers TLS 1.3 alone
  --tls13-ciphers <list>   TLS 1.3 cipher suites, in order, standard names
                           separated by ':', e.g.
                           \"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256\"
                           (default Chrome's order: AES-GCM first on hardware
                           with AES instructions, ChaCha20 first elsewhere)
  --tls-groups <list>      TLS groups, in order (default \"P-256:X25519:P-384\")
  --tls-key-shares <list>  the groups that get a key share, in order, each one
                           of --tls-groups, in its order (default Chrome's: the
                           first group, and the first one of the other kind,
                           post-quantum or not)
  --disable-grease         leave out the GREASE values (RFC 8701) the cipher
                           suites, extensions, groups, key shares and versions
                           carry by default, as Chrome's do
  --enable-grease-sigalgs  put a GREASE value first among the signature
                           algorithms as well, as Chrome does (off by default)
  --tls-sigalgs <list>     signature algorithms, in order, by BoringSSL's names
                           separated by ':', e.g.
                           \"ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256\";
                           the server signs the handshake with one of them
                           (default BoringSSL's: Chrome's eight, then
                           rsa_pkcs1_sha1)
  --tls-cert-compression <list>
                           certificate compression offered, in order, of zlib,
                           brotli and zstd, e.g. \"brotli\" as Chrome offers it;
                           a certificate sent compressed is decompressed
                           (default none)
  --tls-alps <new|old>     offer ALPS for h2 and h3, under the codepoint Chrome
                           sends now (new, 0x44cd) or sent before (old, 0x4469,
                           as Chrome 120) (default none)
  --tls-trust-anchors <list>
                           trust anchor IDs asked for, in order, dotted,
                           separated by ':', e.g. \"11129.9.1:11129.9.4\"
                           (default none)
  --tls-server-padding <n> bytes of padding asked of the server, from 0 to
                           65535, as Chrome asks 6000 (default none)
  --enable-ech-grease      send a GREASE ECH extension when no ECH key is
                           offered, as Chrome and Firefox do (off by default)
  --disable-ocsp-stapling  leave out status_request (OCSP), which Chrome sends
  --disable-sct            leave out signed_certificate_timestamp, which Chrome
                           sends
  --disable-session-ticket leave out session_ticket, which Chrome sends
  --disable-extension-permutation
                           keep BoringSSL's one order of the extensions, where
                           Chrome's change on each handshake

WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (default 5)
  --no-profile-retry       don't retry other obfuscation profiles during scan
  --stale-secs <n>         silence on a wireguard tunnel before it counts as
                           dead (default 10)
  --endpoint-cooldown-secs <n>
                           how long an endpoint is left out of rescans once its
                           tunnel ended twice in a row, each time within five
                           minutes of starting (default 300)

Tor:
  Three ways to use tor, all needing a build made with the tor feature:
  cargo build --release --features tor

  --tor                    carry tor inside the tunnel: aether -> warp -> tor ->
                           internet. The usual proxy keeps the warp exit and a
                           second one, on --tor-bind, comes out of tor. Any
                           transport carries it, with nothing in between, so
                           --wg --tor has the wireguard tunnel carry tor itself
  --tor-reverse            the other way round: dial the tunnel through tor, so
                           warp is reached from a tor exit and your network never
                           sees warp. Tor carries tcp only and the wireguard
                           endpoints of warp answer on udp alone, so this runs
                           masque over http/2, gool's outer hop too, and
                           refuses --wg and --gool-classic
  --tor-only               no tunnel at all: the proxy on --bind is plain tor
  --tor-bind <addr>        where the tor proxy listens with --tor and
                           --tor-reverse (default 127.0.0.1:1820)
  --tor-http <addr>        also serve tor as an http/connect proxy here, for
                           clients that cannot speak socks5 (off by default)
  --tor-bridge-file <path> read bridge lines from this file, one per line, the
                           same shape torrc uses; blank lines and # are skipped
  --tor-relays <what>      running tor relays from onionoo, used as plain
                           bridges: auto (default, alongside bridgedb), only,
                           off, or a count such as 80. bridgedb hands out a
                           handful of bridges that are enumerated and blocked
                           early; onionoo lists every running relay, which is a
                           far larger pool to measure against
  --tor-relay-ports <set>  which relay ports to consider: web (default, only
                           80 and 443, the ports a restrictive firewall tends
                           to leave open) or any. the ports tor itself is known
                           for are always skipped
  --tor-dir <path>         where tor keeps its directory cache and state
                           (default <config>-tor beside the identity file)
  --tor-country <cc>       ask bridgedb for bridges of this country, e.g. ir
  --tor-check <host:port>  an address tor must reach before it counts as working
                           (default check.torproject.org:443)
  --tor-log <level>        how loud tor is: info, debug or trace
  --tor-direct-secs <n>    how long to try tor plainly before bridges (default 75)
  --tor-stall-secs <n>     give up on a bridge after this long with no headway,
                           however far it got (default 75)
  --tor-bridge-secs <n>    the longest any one bridge may take (default 360)

  --psiphon                carry psiphon inside the tunnel: aether -> warp ->
                           psiphon -> internet, served on --psiphon-bind
  --psiphon-reverse        the other way round: dial the tunnel through psiphon.
                           psiphon carries tcp only, so this runs masque over
                           http/2, gool's outer hop too, and refuses --wg and
                           --gool-classic
  --psiphon-only           no tunnel at all: the proxy on --bind is plain psiphon
  --psiphon-mode <shape>   auto (default, let psiphon pick), cdn (only fronted
                           meek through a cdn, for networks that block the rest)
                           or direct (no fronting)
  --psiphon-config <path>  a psiphon json config of your own, laid over the
                           built-in one. only needed to use different
                           credentials or server list settings
  --psiphon-cdn-ips <list> addresses to try as cdn fronting edges, comma or
                           space separated. left empty, the list built into
                           psiphon is used
  --psiphon-cdn-sni <list> server names to present to those edges
  --psiphon-cdn-sets <list>
                           which of the edge lists built into psiphon the
                           fronting scan tries: cloudflare, fastly, cloudfront,
                           psiphon-akamai, psiphon-bunny, vercel, github,
                           curated-fronting, legacy-android-overrides. left
                           empty, all of them; named beside --psiphon-cdn-ips,
                           they are tried after those addresses
  --psiphon-bind <addr>    where the psiphon proxy listens with --psiphon and
                           --psiphon-reverse (default 127.0.0.1:1821)
  --psiphon-http <addr>    also serve psiphon as an http/connect proxy here
  --psiphon-region <cc>    ask psiphon to leave from this country, e.g. DE. the
                           log lists what is on offer as AvailableEgressRegions
  --psiphon-dir <path>     where psiphon keeps its data (default
                           <config>-psiphon beside the identity file)
  --psiphon-bin <path>     the psiphon-tunnel-core binary to run, when it is not
                           next to aether, in ./pt, or on PATH
  --psiphon-server-entries <path>
                           a file of server entries psiphon starts with, in the
                           form the remote list unpacks to, so that the first
                           connection does not depend on downloading that list;
                           a fetched list is merged on top of it
  --psiphon-ready-secs <n> how long to wait for psiphon to tunnel (default 180)
  --psiphon-interface <name>
                           the interface psiphon listens on, instead of the one
                           the bind address names
  --psiphon-sponsor-id <id> the sponsor id psiphon presents
  --psiphon-channel-id <id> the propagation channel id psiphon presents
  --psiphon-server-list <url>
                           where psiphon fetches its remote server list

  On a network that blocks tor, aether fetches its own bridges from bridgedb and
  finds the pluggable transports already on this machine, tor browser's included.
  Nothing below is needed for that; it is there to override what it picks.

  --tor-bridges            go to bridges at once, without trying tor plainly first
  --no-tor-bridges         never use bridges, however blocked the network looks
  --tor-bridge <line>      a bridge line of your own, instead of the fetched ones.
                           Repeat it for more than one, e.g.
                           --tor-bridge \"obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0\"
  --tor-pt [name=]<path>   the pluggable transport binary a bridge needs, e.g.
                           --tor-pt /usr/bin/lyrebird (obfs4 is assumed) or
                           --tor-pt snowflake=/usr/bin/snowflake-client
  --tor-pt-dir <path>      another folder to look in for those binaries

Zero Trust (WARP for organizations):
  --team <name>            enrol into a Zero Trust organization by team name
  --access-id <id>         service token client id (headless enrolment)
  --access-secret <secret> service token client secret (headless enrolment)
  --access-email <addr>    sign in with a one-time code emailed to this address
  --access-token <jwt>     an enrolment token you already obtained by signing in
                           at https://<team>.cloudflareaccess.com/warp
  --gateway                send http and https through the organization's gateway
                           proxy so its filtering and logging apply (off by default:
                           it adds a hop inside the tunnel and logs your browsing)

Routing (which traffic goes where):
  --route-block <list>     never let these reach the network at all
  --route-direct <list>    send these straight out, bypassing the tunnel
  --routes <path>          load both lists from a file with [block] and [direct]
                           sections
                           list entries are comma or newline separated and may be:
                             example.com          the name and every subdomain
                             full:example.com     that exact name only
                             keyword:doubleclick  any name containing it
                             regexp:^ad[0-9]+     a regular expression
                             10.0.0.0/8           a network, or a bare address
                             port:25              a port, or port:3000-3010
                             private              lan, loopback and cgnat space
                           block is checked first, then direct, otherwise the
                           tunnel is used

Config files:
  --config <path>          base identity config path (default aether.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE
                           warp-in-warp adds a second identity of its own beside
                           the wireguard one, named <config>-secondary.toml
  --register <which>       register identities and exit, with no scan and no
                           tunnel: masque, wg, gool (masque and the wireguard
                           identity gool carries inside it, registered from
                           here rather than from inside warp), gool-classic
                           (both wireguard hops), mim (both masque hops) or all
                           five. Each new identity is saved only once WARP is
                           enabled on it. An identity file already
                           there is kept, never replaced; point the config paths
                           at new files to get new keys. With --tor-reverse or
                           --psiphon-reverse the registrations go through that
                           carrier whatever the protocol: they are https, which
                           tor and psiphon carry, so --wg and --gool-classic are
                           refused there only for the tunnel
  --api-address <ip|name[:port]>
                           where the calls to the WARP API, which register and
                           enroll the keys, go: port 443 unless one follows the
                           address, an IPv6 one then in brackets, e.g.
                           162.159.137.105 or [2606:4700:7::a29f:8969]:443
                           (default: the --api-sni name, on 443). With --mark
                           and no --upstream, an IP address only
  --api-sni <name>         the server name the ClientHello of those calls sends
                           (default: the --api-host name); with --ech, the name
                           inside the encrypted ClientHello
  --api-host <name>        the HTTP host of those calls, their Host or :authority
                           (default api.devices.cloudflare.com). With neither
                           --api-sni nor --api-host, an attempt that gets no
                           answer by that name, or a refusal of another server
                           than the API, goes by api.cloudflareclient.com next, and
                           the name the API answers by goes first for the rest
                           of the run. Cloudflare refuses a call whose server
                           name and host differ

Advanced:
  --perf <low|medium|high> force a resource profile instead of auto-detecting from cpu/ram
                           (low: routers/small boards, medium: typical desktop, high: servers)
  --max-clients <n>        proxy clients served at once; past it new ones wait for
                           a free slot (default by resources, 512 to 8192)
  --half-close-secs <n>    how long a connection the client has finished sending
                           on may sit silent before it is closed (default 30)
  --tcp-keepalive-secs <n> idle time before a keep-alive checks that the other
                           end of a connection is still there; three unanswered
                           ones close it (default 60)
  --tcp-connect-secs <n>   how long a connection through the tunnel may take to
                           open (default 30)
  --route-sniff-ms <n>     how long to wait for the first bytes that name the
                           server, which is what makes routing rules work behind
                           a tun front end (default 400)
  --no-route-sniff         stop reading the server name from those bytes
  --ironclad-port <n>      port the ironclad scan makes its real HTTP request to
                           (default 80)
  --no-reprovision         stop replacing an identity Cloudflare has refused with
                           a freshly registered one
  --log-level <level>      error | warn | info | debug | trace (default info)
                           info: connection stages, validation, reconnects, retries
                           debug: adds per-tunnel internals useful for troubleshooting
                           trace: everything, including per-packet noise
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
            "--psiphon-server-entries" => set("AETHER_PSIPHON_SERVER_ENTRIES", next_value!()),
            "--psiphon-ready-secs" => set("AETHER_PSIPHON_READY_SECS", next_value!()),
            "--psiphon-interface" => set("AETHER_PSIPHON_INTERFACE", next_value!()),
            "--psiphon-sponsor-id" => set("AETHER_PSIPHON_SPONSOR_ID", next_value!()),
            "--psiphon-channel-id" => set("AETHER_PSIPHON_PROPAGATION_CHANNEL_ID", next_value!()),
            "--psiphon-server-list" => set("AETHER_PSIPHON_SERVER_LIST", next_value!()),
            "--mark" => set("AETHER_MARK", next_value!()),
            "--tun" => set("AETHER_TUN", next_value!()),
            "--tun-addr" => set("AETHER_TUN_ADDR", next_value!()),
            "--exit-loc" => set("AETHER_EXIT_LOC", next_value!()),
            "--exit-loc-secs" => set("AETHER_EXIT_LOC_SECS", next_value!()),
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

            "--wiw-outer" | "--gool-outer" | "--outer-peer" => {
                set("AETHER_WIW_OUTER_PEER", next_value!())
            }
            "--wiw-inner" | "--gool-inner" | "--inner-peer" => {
                set("AETHER_WIW_INNER_PEER", next_value!())
            }
            "--wiw-peers" | "--gool-peers" => set("AETHER_WIW_PEERS", next_value!()),
            "--wiw-scan" | "--gool-scan" => set("AETHER_WIW_PEERS", "auto"),

            "--masque" => set("AETHER_PROTOCOL", "masque"),
            "--wg" | "--wireguard" | "--warp" => set("AETHER_PROTOCOL", "wg"),
            "--gool" | "--wiw" => set("AETHER_PROTOCOL", "gool"),
            "--gool-peer" => {
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
            "--fragment-delay" => set("AETHER_MASQUE_H2_FRAGMENT_DELAY", next_value!()),
            "--fragment-sni" => set("AETHER_MASQUE_H2_FRAGMENT_SNI", "1"),
            "--mtu" => set("AETHER_MASQUE_MTU", next_value!()),
            "--h2-keepalive-secs" => set("AETHER_MASQUE_H2_KEEPALIVE_SECS", next_value!()),
            "--h2-keepalive-timeout-secs" => {
                set("AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS", next_value!())
            }

            "--keepalive" => set("AETHER_WG_KEEPALIVE", next_value!()),
            "--no-profile-retry" => set("AETHER_WG_NO_PROFILE_RETRY", "1"),
            "--stale-secs" => set("AETHER_WG_STALE_SECS", next_value!()),
            "--endpoint-cooldown-secs" => set("AETHER_WG_ENDPOINT_COOLDOWN_SECS", next_value!()),

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
            "--tls-ciphers" => set("AETHER_TLS_CIPHERS", next_value!()),
            "--tls13-ciphers" => set("AETHER_TLS13_CIPHERS", next_value!()),
            "--disable-grease" => set("AETHER_DISABLE_GREASE", "1"),
            "--enable-grease-sigalgs" => set("AETHER_ENABLE_GREASE_SIGALGS", "1"),
            "--tls-sigalgs" => set("AETHER_TLS_SIGALGS", next_value!()),
            "--tls-cert-compression" => set("AETHER_TLS_CERT_COMPRESSION", next_value!()),
            "--tls-alps" => set("AETHER_TLS_ALPS", next_value!()),
            "--tls-trust-anchors" => set("AETHER_TLS_TRUST_ANCHORS", next_value!()),
            "--tls-server-padding" => set("AETHER_TLS_SERVER_PADDING", next_value!()),
            "--enable-ech-grease" => set("AETHER_ENABLE_ECH_GREASE", "1"),
            "--disable-ocsp-stapling" => set("AETHER_DISABLE_OCSP_STAPLING", "1"),
            "--disable-sct" => set("AETHER_DISABLE_SCT", "1"),
            "--disable-session-ticket" => set("AETHER_DISABLE_SESSION_TICKET", "1"),
            "--disable-extension-permutation" => set("AETHER_DISABLE_EXTENSION_PERMUTATION", "1"),
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
        return Err(CliError::TunNeedsStack("--exit-loc".to_string()).into());
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
