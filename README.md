# Aether

<a href="https://trendshift.io/repositories/112657" target="_blank"><img src="https://trendshift.io/api/badge/repositories/112657" alt="CluvexStudio%2FAether | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>

Telegram: https://t.me/CluvexStudio

Aether is a censorship circumvention client designed for heavily restricted networks. It automatically discovers reachable routes, establishes an encrypted tunnel, and exposes a local SOCKS5 proxy for your applications.

Unlike traditional VPN clients, Aether is built for environments where Deep Packet Inspection (DPI), protocol fingerprinting, UDP throttling, and endpoint blocking are common.

## Features

- Automatic endpoint discovery, with end-to-end data-plane validation so a gateway is only trusted once it actually passes traffic, not just once it answers the handshake
- MASQUE (HTTP/3 & HTTP/2), with optional TLS ClientHello fragmentation on HTTP/2
- WireGuard support
- WireGuard over MASQUE (`--gool`), a WireGuard tunnel inside a MASQUE one for a different exit address
- Nested WireGuard mode (`--gool-classic`), with both hops discovered by the scan or given by hand
- Nested MASQUE mode (`--mim`), a masque tunnel inside another one for a different exit address
- Traffic obfuscation
- Routing rules by domain, address, or port, matched from the TLS server name so they keep working behind a tun front end
- Upstream proxy support, so Aether can dial out through another VPN or proxy already running on the machine
- Optional Tor exit (`--tor`), with Tor carried inside the tunnel, so the exit address is a Tor exit
- Automatic reconnection, and quick-reconnect to your last known-good gateway to skip rescanning
- Local SOCKS5 proxy, or a `tun` device when the kernel should own TCP, UDP and routing (`--tun`)
- Command-line flags, environment variables, or interactive prompts — your choice

## Docker

The released artifact is a container image, `ghcr.io/cluvexstudio/aether:latest`. It is built on every push to `main` and every `v*` tag.

> **The SOCKS5 proxy has no authentication.** Anyone who can reach the port can use your tunnel. Every command below publishes the port to `127.0.0.1` only, so it stays reachable from your own machine and nothing else. Do not replace it with `-p 1819:1819`, because that form listens on every interface of the host and turns the proxy into an open relay. If you genuinely need to serve other machines, put an authenticated front end in front of it and firewall the port.

The `-v aether-data:/data` volume keeps the generated WARP identity between runs. Without it every start registers a brand new device, and Cloudflare begins rate limiting your address.

Pull and run (interactive mode is required for initial setup):

```bash
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data ghcr.io/cluvexstudio/aether:latest
```

Skip the prompts by providing environment variables:

```bash
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data \
  -e AETHER_PROTOCOL=masque \
  -e AETHER_SCAN=balanced \
  ghcr.io/cluvexstudio/aether:latest
```

### A whole network through the tunnel

Passing `--tun` gives Aether a device instead of a SOCKS port. The container needs to create it, which means the host network, `/dev/net/tun` and `CAP_NET_ADMIN`; a container that publishes ports cannot do this, so nothing is published and the proxy is not exposed at all:

```bash
docker run -d --name aether --restart always \
  --network host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v aether-data:/data \
  -e AETHER_TUN=tun0 \
  -e AETHER_MARK=0xff \
  -e AETHER_PROTOCOL=masque \
  -e AETHER_MASQUE_HTTP2=1 \
  -e AETHER_STATS=1 \
  ghcr.io/cluvexstudio/aether:latest
```

Traffic that the kernel routes into `tun0` then goes through the tunnel, UDP and DNS included. On a router, mark the tunnel's own sockets with `--mark 0xff` and let that mark reach the internet directly, or the tunnel dials itself:

```bash
ip rule add fwmark 255 lookup main pref 100
ip rule add from 192.168.10.0/24 to 192.168.10.0/24 lookup main pref 1000
ip rule add from 192.168.10.0/24 lookup 100 pref 1010
ip route replace default dev tun0 table 100
nft add table ip aether
nft add chain ip aether post '{ type nat hook postrouting priority 100 ; }'
nft add rule ip aether post oifname "tun0" masquerade
```

The masquerade keeps the source address one WARP assigned; without it the handshake succeeds and no data ever comes back. `--tun` replaces the SOCKS front end, so `--bind`, `--http-proxy` and `--routes` are ignored, and modes that need the userspace TCP stack it provides (`--gool`, `--mim`, `--tor-only`, `--psiphon-only`, `--team`, `--gateway`, `--exit-loc`) are refused at startup.

### Build the image yourself

```bash
docker build -t aether .
docker run -it -p 127.0.0.1:1819:1819 -v aether-data:/data aether
```

## Build

### Requirements

- Rust, the latest stable release
- C/C++ compiler
- CMake
- Go, for the pluggable transports and psiphon

The `quiche` repository must be placed alongside `aether`:

```text
<repo>/
  aether/
  quiche/
```

Build from the repository root; the Cargo manifest is `aether/Cargo.toml`, so enter that directory first:

```bash
cd aether
bash ../scripts/build-pt.sh linux amd64 pt
bash ../scripts/build-psiphon.sh linux amd64 pt
cargo build --release --locked --features tor
```

Binary, relative to the repository root:

```text
aether/target/release/aether
```

The transports the `--tor*` modes need are written to `aether/pt`, which Aether looks for next to the binary.

## Usage

Run with no arguments and answer the prompts:

```bash
./aether/target/release/aether
```

Or skip the prompts with flags:

```bash
./aether/target/release/aether --masque -4 --scan turbo --noize firewall
```

Every prompt has a flag and an environment variable equivalent. Run `aether help` (or `--help`) for the full list — every flag, every variable, and what each one does.

After startup, a SOCKS5 proxy is available at `127.0.0.1:1819`:

```bash
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

The output contains `warp=on` when the request left through WARP.

## Supported Protocols

### MASQUE (Recommended)

Encapsulates traffic over HTTP/3 (QUIC) or HTTP/2 (TLS), making it resemble ordinary HTTPS traffic.

### WireGuard

Fast and lightweight transport for networks with less aggressive inspection.

### Nested MASQUE (`--mim`)

A MASQUE tunnel carried inside another MASQUE tunnel. The inner hop is dialled from inside the outer one, so Cloudflare sees the outer edge instead of your address and hands the inner tunnel a different exit IP — the same idea as `gool`, with a MASQUE tunnel inside instead of a WireGuard one. Both hops use HTTP/3, or both use HTTP/2 with `--h2`.

```bash
./aether/target/release/aether --mim
```

### WireGuard over MASQUE (`--gool`)

A WireGuard tunnel carried inside a MASQUE tunnel. Your network sees only the MASQUE hop; the WireGuard hop is dialled from inside it, so Cloudflare sees the MASQUE edge instead of your address and hands the WireGuard tunnel a different exit IP. The MASQUE hop is found by the scan or named with `--peer`; the WireGuard hop is the endpoint its key names, on port 2408, unless `--gool-peer` names another.

```bash
./aether/target/release/aether --gool
```

### Nested WireGuard (`--gool-classic`)

The older gool: a WireGuard tunnel running inside another WireGuard tunnel, providing an additional encryption layer.

Its two hops are found by the scan by default. If you already know addresses that work on your network, name them instead with `--wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408`, or both at once with `--wiw-peers 162.159.192.1:2408,188.114.96.1:2408`. The port is required — which port gets through is what differs between networks, so none is assumed. Give only one and the scan finds the other.

## Tor

Built with the `tor` feature, Aether carries a Tor implementation (arti) and can combine it with the tunnel three ways:

| Mode | Flag | Path | Exit address |
| --- | --- | --- | --- |
| Tor through the tunnel | `--tor` | you → WARP → Tor → internet | a Tor exit |
| The tunnel through Tor | `--tor-reverse` | you → Tor → WARP → internet | a WARP exit |
| Tor alone | `--tor-only` | you → Tor → internet | a Tor exit |

```bash
./aether/target/release/aether --masque --tor
```

With `--tor` the usual proxy on `127.0.0.1:1819` keeps the WARP exit and a second one on `127.0.0.1:1820` comes out of Tor. Because Tor rides inside the tunnel, a network that blocks Tor never sees it. Any transport can carry it — `--masque` over HTTP/3 or HTTP/2, `--wg`, `--gool`, `--mim` — with nothing in between: `--wg --tor` has the WireGuard tunnel carry Tor directly. The other direction cannot do that, because Tor carries TCP only and WARP's WireGuard endpoints answer on UDP alone, so `--tor-reverse` runs MASQUE over HTTP/2 (for `--gool`, its MASQUE hop) and refuses `--wg` and `--gool-classic`. `--tor-reverse` and `--tor-only` reach Tor directly, and where Tor is blocked they fetch their own bridges from bridgedb and run them through the pluggable transports in the `pt/` folder, so there is nothing to install and nothing to paste in.

## Repository layout

```text
aether/         the crate
quiche/         vendored QUIC/HTTP-3 library, a path dependency
scripts/        build helpers: pluggable transports, psiphon, h2 benchmark
Dockerfile      the released image
```

## Credits

Developed by **CluvexStudio**. :))

MASQUE support is built on top of Cloudflare's **Quiche** library.

## Contributing

> **Experienced network developers and protocol engineers are welcome to contribute.**

> **Please keep the codebase clean, maintainable, and well-engineered. Low-quality or vibe-coded contributions will not be accepted.**

## Donate

If Aether has been useful to you, consider supporting its development:

- **TRX (Tron):** `TRxVSHcoADZnBfztFmFb2TQopusAwWYEVR`
- **BTC:** `bc1qnjnvzsa5avgj7n0uy383cv5zdxfjnvvp257egm`
- **TON:** `UQAH75bXaaRUhZMwiF0ZujOXFDDmvLSPASKoOsWF0HNasiaM`

## License

See the LICENSE file for licensing information.
