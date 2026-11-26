# Aether

Aether is a censorship circumvention client for heavily restricted networks. It finds a reachable WARP route, opens an encrypted tunnel, and serves it as a local SOCKS5 proxy — or as a `tun` device when the kernel should own the traffic.

It is built for networks where deep packet inspection, protocol fingerprinting, UDP throttling and endpoint blocking are the norm.

- **Automatic endpoint discovery** with end-to-end data-plane validation: a gateway is trusted only once it has carried traffic, not just once it answers a handshake.
- **Five transports**: MASQUE (HTTP/3 and HTTP/2), WireGuard, and three nested modes that get you a different exit address.
- **Obfuscation** profiles that reshape the WireGuard handshake, and optional TLS ClientHello fragmentation.
- **Chrome's TLS fingerprint**, tunable down to cipher suites, groups, key shares and GREASE.
- **Routing rules** by domain, address or port, matched from the TLS server name so they keep working behind a tun front end.
- **Tor and Psiphon**, either inside the tunnel or carrying it.
- **Zero Trust** enrolment for organizations.
- **Flags or prompts**: pass the flag and the question is never asked.

## Quick start

### Docker

The released artifact is the container image `ghcr.io/mehdisadeghidev/aether:latest`, published by a manual run of the `Build and Publish` workflow and tagged with the commit hash and `latest`.

> **The SOCKS5 proxy has no authentication.** Anyone who can reach the port can use your tunnel. Every command below publishes the port to `127.0.0.1` only. Do not replace it with `-p 1819:1819`: that listens on every interface of the host and turns the proxy into an open relay. If you need to serve other machines, put an authenticated front end in front of it and firewall the port.

The `-v aether-data:/data` volume keeps the generated WARP identity between runs. Without it, every start registers a brand new device and Cloudflare starts rate limiting your address.

```bash
# interactive: answer the prompts on first run
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data \
  ghcr.io/mehdisadeghidev/aether:latest

# no prompts
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data \
  ghcr.io/mehdisadeghidev/aether:latest --masque --balanced
```

#### A whole network through the tunnel

`--tun` gives Aether a device instead of a SOCKS port. The container must be able to create it, which means the host network, `/dev/net/tun` and `CAP_NET_ADMIN`; a container that publishes ports cannot do this, so nothing is published here:

```bash
docker run -d --name aether --restart always \
  --network host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v aether-data:/data \
  ghcr.io/mehdisadeghidev/aether:latest \
  --tun tun0 --fwmark 0xff --masque --h2 --stats
```

Traffic the kernel routes into `tun0` then goes through the tunnel, UDP and DNS included. On a router, mark the tunnel's own sockets with `--fwmark 0xff` and let that mark reach the internet directly, or the tunnel dials itself:

```bash
ip rule add fwmark 255 lookup main pref 100
ip rule add from 192.168.10.0/24 to 192.168.10.0/24 lookup main pref 1000
ip rule add from 192.168.10.0/24 lookup 100 pref 1010
ip route replace default dev tun0 table 100
nft add table ip aether
nft add chain ip aether post '{ type nat hook postrouting priority 100 ; }'
nft add rule ip aether post oifname "tun0" masquerade
```

The masquerade keeps the source address WARP assigned; without it the handshake succeeds and no data ever comes back. `--tun` replaces the SOCKS front end, so `--bind`, `--http-proxy` and `--routes` are ignored, and modes that need the userspace TCP stack it provides (`--gool`, `--gool-classic`, `--mim`, `--tor-only`, `--psiphon-only`, `--team`, `--gateway`, `--exit-country`) are refused at startup. So is `--tor`: a carrier inside the tunnel dials the socks5 listener it lives behind, and `--tun` never binds one; put it under the tunnel with `--tor-reverse`. `--psiphon` does work with a tun, differently: the tun's TCP is terminated by a stack of its own and each connection is dialled through Psiphon, which rides the tunnel like any other program on the machine, so TCP exits at a Psiphon exit while UDP keeps exiting at WARP.

#### Build the image yourself

```bash
docker build -t aether .
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data aether
```

### From source

Requirements: Rust (latest stable), a C/C++ compiler, CMake, and Go for the pluggable transports and Psiphon.

```bash
bash scripts/build-pt.sh linux amd64 pt
bash scripts/build-psiphon.sh linux amd64 pt
cargo build --release --locked --features tor
```

The binary is `target/release/aether`. The transports the `--tor*` modes need are written to `pt/`, which Aether looks for next to the binary.

### Running

With no arguments it asks for what it needs:

```bash
./target/release/aether
```

Every question has a flag, and passing the flag is what stops the question:

```bash
./target/release/aether --masque -4 --scan turbo --noize firewall
```

The proxy then listens on `127.0.0.1:1819`:

```bash
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

The reply contains `warp=on` when the request left through WARP.

## Protocols

| Flag | Transport | Exit address |
| --- | --- | --- |
| `--masque` | MASQUE over HTTP/3 or HTTP/2 (default) | WARP |
| `--wg` | WireGuard | WARP |
| `--gool` | WireGuard inside MASQUE | a second WARP exit |
| `--gool-classic` | WireGuard inside WireGuard | a second WARP exit |
| `--mim` | MASQUE inside MASQUE | a second WARP exit |

The nested modes exist for one reason: the inner hop is dialled from inside the outer tunnel, so Cloudflare sees the outer edge instead of your address and hands the inner tunnel a different exit IP.

### MASQUE (default)

Encapsulates traffic over HTTP/3 (QUIC) or HTTP/2 (TLS), so it resembles ordinary HTTPS. Use `--h2` where UDP is blocked or throttled.

### WireGuard

Fast and lightweight, for networks with less aggressive inspection. `--wg --noize gfw` is the pairing for a strict firewall.

### WireGuard over MASQUE (`--gool`)

Your network sees only the MASQUE hop. The MASQUE hop is found by the scan or named with `--peer`; the WireGuard hop is the endpoint its key names, on port 2408, unless `--gool-wg-peer` names another.

```bash
./target/release/aether --gool
```

### Nested WireGuard (`--gool-classic`)

The older gool: WireGuard inside WireGuard. Both hops are found by the scan unless you name them. The port is required — which port gets through is what differs between networks, so none is assumed. Name one hop and the scan finds the other, keeping your address out of the sweep.

```bash
./target/release/aether --gool-classic \
  --gool-outer 162.159.192.1:2408 --gool-inner 188.114.96.1:2408
```

### Nested MASQUE (`--mim`)

MASQUE inside MASQUE, on the same carrier for both hops: HTTP/3 in HTTP/3, or HTTP/2 in HTTP/2 with `--h2`. The outer hop is found by the scan and the inner one is picked for you, unless named with `--mim-outer` and `--mim-inner`.

```bash
./target/release/aether --mim
```

## Tor

Built with the `tor` feature, Aether carries an arti client and can combine it with the tunnel three ways:

| Mode | Flag | Path | Exit address |
| --- | --- | --- | --- |
| Tor through the tunnel | `--tor` | you → WARP → Tor → internet | a Tor exit |
| The tunnel through Tor | `--tor-reverse` | you → Tor → WARP → internet | a WARP exit |
| Tor alone | `--tor-only` | you → Tor → internet | a Tor exit |

```bash
./target/release/aether --masque --tor
```

With `--tor` the proxy on `127.0.0.1:1819` keeps the WARP exit, and a second one on `127.0.0.1:1820` comes out of Tor. Any transport can carry it — `--masque`, `--wg`, `--gool`, `--mim` — so `--wg --tor` has the WireGuard tunnel carry Tor directly.

The other direction cannot: Tor carries TCP only, and WARP's WireGuard endpoints answer on UDP alone. `--tor-reverse` therefore runs MASQUE over HTTP/2 (for `--gool`, its MASQUE hop) and refuses `--wg` and `--gool-classic`.

Where Tor is blocked, `--tor-reverse` and `--tor-only` fetch their own bridges from bridgedb and run them through the pluggable transports in `pt/`, so there is nothing to install and nothing to paste in.

## Psiphon

Psiphon needs no build feature; the `psiphon-tunnel-core` binary is enough, found next to `aether`, in `./pt`, or on `PATH`.

| Mode | Flag | Path | Exit address |
| --- | --- | --- | --- |
| Psiphon through the tunnel | `--psiphon` | you → WARP → Psiphon → internet | a Psiphon exit |
| The tunnel through Psiphon | `--psiphon-reverse` | you → Psiphon → WARP → internet | a WARP exit |
| Psiphon alone | `--psiphon-only` | you → Psiphon → internet | a Psiphon exit |

```bash
./target/release/aether --psiphon
```

As with Tor, the chained mode serves the WARP exit on `--bind` and a second proxy on `--psiphon-bind`; that is the socks5 front end it dials the tunnel through, and with `--tun` there is none, so it dials out as any other program on the machine does and the tun's TCP is handed to it instead: same exit, no proxy needed. `--psiphon-reverse` carries TCP only, so it runs MASQUE over HTTP/2 and refuses `--wg` and `--gool-classic`. `--psiphon-mode cdn` keeps Psiphon on meek through a CDN, for networks that block everything else.

## Exit countries

`--exit-country` refuses a tunnel whose exit is in the wrong place. The check runs through the finished tunnel before the proxy serves, then again every `--exit-check-secs`:

```bash
./target/release/aether --masque --exit-country '!IR,AZ,RU'   # block these
./target/release/aether --masque --exit-country 'DE,SE'       # allow only these
```

Without the flag nothing is looked up and no tunnel is refused.

## Routing rules

Split traffic by name, address or port:

```bash
./target/release/aether --masque \
  --route-block 'private,port:25' \
  --route-direct 'example.com,10.0.0.0/8'
```

Or keep both lists in a file and load it with `--routes routes.conf` — one entry per line, `#` for comments:

```ini
[block]
private
keyword:doubleclick
port:25

[direct]
example.com
full:internal.example.com
10.0.0.0/8
```

Entries are comma or newline separated, and may be:

| Entry | Matches |
| --- | --- |
| `example.com` | the name and every subdomain |
| `full:example.com` | that exact name only |
| `keyword:doubleclick` | any name containing it |
| `regexp:^ad[0-9]+` | a regular expression |
| `10.0.0.0/8` | a network, or a bare address |
| `port:25`, `port:3000-3010` | a port, or a range |
| `private` | LAN, loopback and CGNAT space |

`block` is checked first, then `direct`; anything else goes through the tunnel.

## Zero Trust

For organizations with a WARP deployment, enrol by team name. A team needs one way to sign in:

| Sign-in | Flags |
| --- | --- |
| Service token | `--access-id <id> --access-secret <secret>` |
| Email one-time code | `--access-email <addr>` |
| Token you already hold | `--access-token <jwt>`, from signing in at `https://<team>.cloudflareaccess.com/warp` |

```bash
./target/release/aether --team myteam --masque --access-id <id> --access-secret <secret>
```

`--gateway` sends HTTP and HTTPS through the organization's gateway proxy so its filtering and logging apply.

## Flags

`aether help` prints this reference, in the same order, with the longer notes.

### Front end

| Flag | What it does | Default |
| --- | --- | --- |
| `--bind <addr>` | SOCKS5 listen address | `127.0.0.1:1819` |
| `--http-proxy <addr>` | also serve an HTTP CONNECT proxy | off |
| `--tun <name>` | carry the tunnel on this tun device instead of SOCKS5 | off |
| `--tun-addr <a/p,...>` | addresses to give the device | the tunnel's |
| `--upstream <url>` | dial out through an existing proxy (`socks5://`, `http://`) | direct |
| `--fwmark <n>` | `SO_MARK` on every socket Aether opens | none |
| `--exit-country <spec>` | refuse exits outside the spec | off |
| `--exit-check-secs <n>` | how often to recheck the exit country | `60` |
| `--stats` | log bytes up/down and uptime | off |
| `--stats-secs <n>` | how often to log that line | `60` |
| `--quick-reconnect` | reuse the last working gateway without asking | ask |
| `--no-quick-reconnect` | always scan fresh, ignore the saved gateway | — |
| `-4` | scan and connect over IPv4 only | default |
| `-6` | scan and connect over IPv6 only | |
| `--dual` | scan and connect over both | |
| `--ip <v4\|v6\|both>` | the same choice written out | |
| `--peer <ip:port>` | force the peer, skip the scan | scan |
| `--wg-peer <ip:port>` | force the WireGuard peer, skip the scan | scan |

### Protocol and endpoints

| Flag | What it does | Default |
| --- | --- | --- |
| `--masque` | MASQUE over QUIC/HTTP-3 | default |
| `--wg` | classic WireGuard | |
| `--gool` | WireGuard carried inside MASQUE | |
| `--gool-classic` | WireGuard carried inside WireGuard | |
| `--mim` | MASQUE carried inside MASQUE | |
| `--protocol <name>` | `masque` \| `wg` \| `gool` \| `mim` | |
| `--gool-wg-peer <ip:port>` | the WireGuard endpoint dialled inside the tunnel | registration, port 2408 |
| `--gool-outer <ip:port>` | classic gool outer hop | scan |
| `--gool-inner <ip:port>` | classic gool inner hop | scan |
| `--gool-peers <out[,in]>` | both classic gool hops in one value | scan |
| `--gool-scan` | scan for both, ignoring any endpoint named | — |
| `--mim-outer <ip:port>` | outer MASQUE hop | scan |
| `--mim-inner <ip:port>` | inner MASQUE hop | picked for you |
| `--mim-peers <out[,in]>` | both hops in one value | scan |
| `--mim-scan` | find the outer hop by scanning | — |

### Scan mode

| Flag | What it does | Default |
| --- | --- | --- |
| `--scan <mode>` | `turbo` \| `balanced` \| `thorough` \| `verified` \| `ironclad` | `balanced` |
| `--turbo` | stop at the first candidate that answers | |
| `--balanced` | collect a few, keep the fastest | |
| `--thorough` | sweep whole ranges, when everything looks blocked | |
| `--verified` | measured edges only, never a guessed neighbour; on `--gool` and `--mim` the two hops also stay in separate ranges | |
| `--ironclad` | a real tunnel and a real HTTP request per candidate | |

### Obfuscation

| Flag | What it does | Default |
| --- | --- | --- |
| `--noize <profile>` | `off` \| `light` \| `firewall` \| `balanced` \| `gfw` \| `aggressive` | `firewall` for MASQUE, `balanced` for WireGuard and gool |

Reach for `gfw` when the default profile does not get through.

### Transport

| Flag | What it does | Default |
| --- | --- | --- |
| `--h2` | use HTTP/2 (TCP) instead of HTTP/3 (QUIC) | HTTP/3 |
| `--h3` | use HTTP/3 without asking | |
| `--no-quic-v2` | do not send the QUIC v2 opener | sent |
| `--h2-peer <ip:port>` | override the peer used by the HTTP/2 transport | scan |
| `--h2-keepalive-secs <n>` | HTTP/2 keepalive interval | `15` |
| `--h2-timeout-secs <n>` | how long a keepalive may go unanswered | `20` |
| `--masque-sni <name>` | server name in the MASQUE ClientHello | `www.cloudflare.com` |
| `--dns <list>` | resolvers used inside the tunnel | `1.1.1.1,1.0.0.1` |
| `--mtu <n>` | tunnel MTU, 576 to 1500 | `1280` |
| `--startup-secs <n>` | total MASQUE startup deadline | `30` |
| `--validate-secs <n>` | data-plane validation window | `10` |
| `--no-data-check` | skip data-plane validation | off |
| `--reconnect-secs <n>` | delay before reconnecting after a drop | `2` |
| `--fragment` | fragment the ClientHello on HTTP/2 and on the WARP API calls | off |
| `--fragment-size <n\|a-b>` | fragment size in bytes | `8-16` |
| `--fragment-delay-ms <n\|a-b>` | delay between fragments | `2-10` |
| `--fragment-sni` | split the server name itself across two fragments | off |

### TLS

The tunnel's handshakes, MASQUE over HTTP/2 and HTTP/3, the WARP API calls and the DoH lookup of `--ech-dns` carry Chrome's fingerprint as BoringSSL writes it, with what these change. Certificates go unchecked, except the MASQUE gateway's with `--team` or `--tls-verify`.

| Flag | What it does | Default |
| --- | --- | --- |
| `--tls-verify` | hold the MASQUE gateway's certificate to Aether's pins | on with `--team` |
| `--no-tls-verify` | do not, even with `--team` | |
| `--ech <auto\|base64>` | offer Encrypted Client Hello, with the key looked up or given | off |
| `--ech-dns <url>` | resolver `--ech auto` asks for the key | `udp://1.1.1.1` |
| `--ech-domain <name>` | domain whose key `--ech auto` takes | `cloudflare-ech.com` |
| `--tls12-ciphers <list>` | TLS 1.2 suites, after the TLS 1.3 ones | Chrome's |
| `--tls13-ciphers <list>` | TLS 1.3 suites, in order | Chrome's order |
| `--tls-groups <list>` | TLS groups, in order | `P-256:X25519:P-384` |
| `--tls-key-shares <list>` | groups that get a key share, in order | Chrome's |
| `--tls-sigalgs <list>` | signature algorithms, in order | Chrome's eight |
| `--no-grease` | leave out the GREASE values (RFC 8701) | GREASE sent |
| `--grease-sigalgs` | GREASE first among the signature algorithms | off |
| `--tls-cert-compress <list>` | certificate compression offered (`zlib`, `brotli`, `zstd`) | none |
| `--tls-alps <new\|old>` | offer ALPS for h2 and h3 | none |
| `--tls-anchors <list>` | trust anchor IDs asked for | none |
| `--tls-padding <n>` | bytes of padding asked of the server, 0 to 65535 | none |
| `--ech-grease` | send a GREASE ECH extension when no key is offered | off |
| `--no-ocsp` | leave out `status_request` | sent |
| `--no-sct` | leave out `signed_certificate_timestamp` | sent |
| `--no-session-ticket` | leave out `session_ticket` | sent |
| `--no-ext-shuffle` | keep one fixed extension order | shuffled |

### WireGuard

| Flag | What it does | Default |
| --- | --- | --- |
| `--wg-keepalive-secs <n>` | persistent keepalive interval | `5` |
| `--no-profile-retry` | do not retry other obfuscation profiles during a scan | retried |
| `--wg-stale-secs <n>` | silence before the tunnel counts as dead | `10` |
| `--wg-cooldown-secs <n>` | how long an endpoint sits out of rescans after two tunnels ended within five minutes of starting | `300` |

### Tor

| Flag | What it does | Default |
| --- | --- | --- |
| `--tor` | Tor inside the tunnel | |
| `--tor-reverse` | the tunnel through Tor | |
| `--tor-only` | Tor alone, no tunnel | |
| `--tor-bind <addr>` | where Tor listens with `--tor` and `--tor-reverse` | `127.0.0.1:1820` |
| `--tor-http <addr>` | also serve Tor as an HTTP CONNECT proxy | off |
| `--tor-bridge-file <path>` | read bridge lines from a file, one per line, as torrc writes them | |
| `--tor-relays <what>` | running onionoo relays as plain bridges: `auto`, `only`, `off`, or a count | `auto` |
| `--tor-relay-ports <set>` | `web` (80 and 443) or `any` | `web` |
| `--tor-dir <path>` | Tor's directory cache and state | `<config>-tor` |
| `--tor-country <cc>` | ask bridgedb for bridges of this country | |
| `--tor-check <host:port>` | an address Tor must reach to count as working | `check.torproject.org:443` |
| `--tor-log <level>` | `info`, `debug` or `trace` | `info` |
| `--tor-direct-secs <n>` | how long to try Tor plainly before bridges | `75` |
| `--tor-stall-secs <n>` | give up on a bridge after this long with no headway | `75` |
| `--tor-bridge-secs <n>` | the longest any one bridge may take | `360` |
| `--tor-bridges` | go to bridges at once, without trying Tor plainly | |
| `--no-tor-bridges` | never use bridges | |
| `--tor-bridge <line>` | a bridge line of your own; repeat for more than one | |
| `--tor-pt [name=]<path>` | the pluggable transport binary a bridge needs | |
| `--tor-pt-dir <path>` | another folder to look in for those binaries | |

### Psiphon

| Flag | What it does | Default |
| --- | --- | --- |
| `--psiphon` | Psiphon inside the tunnel | |
| `--psiphon-reverse` | the tunnel through Psiphon | |
| `--psiphon-only` | Psiphon alone, no tunnel | |
| `--psiphon-mode <shape>` | `auto`, `cdn` (meek through a CDN only) or `direct` | `auto` |
| `--psiphon-config <path>` | your own Psiphon JSON config, laid over the built-in one | |
| `--psiphon-cdn-ips <list>` | addresses to try as CDN fronting edges | built-in list |
| `--psiphon-cdn-sni <list>` | server names to present to those edges | |
| `--psiphon-cdn-sets <list>` | which built-in edge lists to try | all |
| `--psiphon-bind <addr>` | where Psiphon listens with `--psiphon` and `--psiphon-reverse` | `127.0.0.1:1821` |
| `--psiphon-http <addr>` | also serve Psiphon as an HTTP CONNECT proxy | off |
| `--psiphon-region <cc>` | ask Psiphon to leave from this country | |
| `--psiphon-dir <path>` | where Psiphon keeps its data | `<config>-psiphon` |
| `--psiphon-bin <path>` | the `psiphon-tunnel-core` binary | next to `aether`, `./pt`, `PATH` |
| `--psiphon-entries <path>` | server entries to start with, so the first connection need not download the list | |
| `--psiphon-ready-secs <n>` | how long to wait for Psiphon to tunnel | `180` |
| `--psiphon-interface <name>` | the interface Psiphon listens on | the bind address's |
| `--psiphon-sponsor-id <id>` | sponsor id Psiphon presents | |
| `--psiphon-channel-id <id>` | propagation channel id Psiphon presents | |
| `--psiphon-server-list <url>` | where Psiphon fetches its remote server list | |

### Zero Trust

| Flag | What it does | Default |
| --- | --- | --- |
| `--team <name>` | enrol into a Zero Trust organization by team name | |
| `--access-id <id>` | service token client id (headless enrolment) | |
| `--access-secret <secret>` | service token client secret (headless enrolment) | |
| `--access-email <addr>` | sign in with a one-time code emailed here | |
| `--access-token <jwt>` | an enrolment token you already hold | |
| `--gateway` | send HTTP and HTTPS through the organization's gateway proxy | off |

### Routing

| Flag | What it does | Default |
| --- | --- | --- |
| `--route-block <list>` | never let these reach the network at all | |
| `--route-direct <list>` | send these straight out, bypassing the tunnel | |
| `--routes <path>` | load both lists from a file with `[block]` and `[direct]` sections | |

### Config and identities

| Flag | What it does | Default |
| --- | --- | --- |
| `--config <path>` | base identity config | `aether.toml` |
| `--wg-config <path>` | identity config for WireGuard | |
| `--masque-config <path>` | identity config for MASQUE | |
| `--register <which>` | register identities and exit: `masque`, `wg`, `gool`, `gool-classic`, `mim` or `all` | |
| `--api-address <ip\|name[:port]>` | where the WARP API calls go | `--api-sni`, port 443 |
| `--api-sni <name>` | server name in the ClientHello of those calls | `--api-host` |
| `--api-host <name>` | the HTTP host of those calls | `api.devices.cloudflare.com` |

### Advanced

| Flag | What it does | Default |
| --- | --- | --- |
| `--perf <low\|medium\|high>` | force a resource profile instead of detecting from CPU and RAM | auto |
| `--max-clients <n>` | proxy clients served at once | by resources, 512 to 8192 |
| `--half-close-secs <n>` | how long a half-closed connection may sit silent | `30` |
| `--tcp-keepalive-secs <n>` | idle time before a keepalive probes the other end | `60` |
| `--tcp-connect-secs <n>` | how long a connection through the tunnel may take to open | `30` |
| `--route-sniff-ms <n>` | how long to wait for the bytes that name the server | `400` |
| `--no-route-sniff` | stop reading the server name from those bytes | |
| `--ironclad-port <n>` | port the ironclad scan makes its real HTTP request to | `80` |
| `--no-reprovision` | stop replacing an identity Cloudflare has refused | replaced |
| `--log-level <level>` | `error` \| `warn` \| `info` \| `debug` \| `trace` | `info` |
| `--verbose` | shortcut for `--log-level debug` | |

## Environment

Aether reads nothing from the environment. Every setting comes from a flag, or from a prompt when the flag is absent.

## License

See the LICENSE file for licensing information.
