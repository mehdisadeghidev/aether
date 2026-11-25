# Put a whole network behind Aether on VyOS

[OpenWrt as a service](OPENWRT.en.md) ends with a SOCKS5 proxy: every client has
to speak SOCKS. This guide does something different. Aether gets a `tun` device,
so the kernel owns TCP, UDP and routing, and the router sends a LAN through WARP
by routing it into that device. Clients change nothing, and DNS, UDP and anything
that cannot use a SOCKS proxy go through the tunnel too.

Aether runs in a container, because VyOS starts containers from its own config:
`/config` survives reboots and upgrades, and nothing has to be started by hand.
When you finish, `tun0` carries the tunnel, `192.168.10.0/24` goes through it, and
a trace from any client prints `warp=on`.

## What you need

- VyOS 1.4 or newer, x86_64, with root access. The released image is amd64 only.
- `/dev/net/tun` on the router. `ls -l /dev/net/tun` must exist; if it does not,
  load the kernel module with `modprobe tun`.
- The WARP identity in `/config/aether`, kept across upgrades. Those files are
  this device's Cloudflare login; deleting them makes Cloudflare see a new device.
- A LAN to route. This guide uses `192.168.10.0/24`; change it everywhere.

## Put `--tun` in the container

`aether help` must list `--tun`. A version without it serves SOCKS only, so build
or pull one that has it first.

```bash
configure
set container name aether image 'ghcr.io/cluvexstudio/aether:latest'
set container name aether allow-host-networks
set container name aether restart always
set container name aether memory 1024
set container name aether stop-timeout 5
set container name aether capability net-admin

# a tun device and the node to create it on
set container name aether device tun source '/dev/net/tun'
set container name aether device tun destination '/dev/net/tun'

# the identity, in the only place that survives a reboot
set container name aether volume data source '/config/aether'
set container name aether volume data destination '/data'

set container name aether environment AETHER_CONFIG value '/data/aether.toml'
set container name aether environment AETHER_TUN value 'tun0'
set container name aether environment AETHER_MARK value '0xff'
set container name aether environment AETHER_PROTOCOL value 'masque'
set container name aether environment AETHER_MASQUE_HTTP2 value '1'
set container name aether environment AETHER_SCAN value 'balanced'
set container name aether environment AETHER_IP value 'v4'
set container name aether environment AETHER_NOIZE value 'firewall'
set container name aether environment AETHER_QUICK_RECONNECT value '1'
set container name aether environment AETHER_STATS value '1'
set container name aether environment AETHER_PERF_PROFILE value 'low'
commit
```

`capability net-admin` is what lets it create the device and put a mark on its
own sockets. `allow-host-networks` puts the container in the router's network
namespace, which is the point: `tun0` then belongs to the router.

Two of those settings matter more than they look:

- `AETHER_MARK=0xff` marks the sockets Aether opens to the internet. The routing
  below lets a marked packet out directly, so the tunnel never enters itself.
  Without it you get a loop, not a tunnel.
- `AETHER_STATS=1` logs how much has gone up and down. With a tun there is no
  SOCKS port to poke, so this line and the device counters are how you tell the
  tunnel is carrying anything.

`--tun` replaces SOCKS5 entirely, so `AETHER_SOCKS`, `--http-proxy`, `--routes`
and the other SOCKS settings are ignored. Modes that need the userspace TCP stack
the SOCKS front end provides (`--gool`, `--mim`, `--tor-only`, `--psiphon-only`,
`--team`, `--gateway`, `--exit-loc`) are refused at startup instead of failing
later.

## Send the LAN through it

The device does not exist when a config is committed, so these routes cannot be
VyOS config. Put them in the boot hook, and re-apply them when the container is
restarted and the device comes back with a new index.

```bash
cat >/config/scripts/vyos-postconfig-bootup.script <<'EOF'
#!/bin/sh
# Route the LAN through aether's tun and nothing else.

apply() {
  ip rule add fwmark 255 lookup main pref 100
  ip rule add from 192.168.10.0/24 to 192.168.10.0/24 lookup main pref 1000
  ip rule add from 192.168.10.0/24 lookup 100 pref 1010

  ip route replace default dev tun0 table 100
  # keeps table 100 answering when the device is gone: no route, no leak
  ip route replace unreachable default metric 1000 table 100

  nft flush chain ip aether post 2>/dev/null
  nft list table ip aether >/dev/null 2>&1 || {
    nft add table ip aether
    nft add chain ip aether post '{ type nat hook postrouting priority 100 ; }'
  }
  nft add rule ip aether post oifname "tun0" masquerade
}

# re-apply whenever the device comes back, e.g. after a container restart
last=
while :; do
  index=$(cat /sys/class/net/tun0/ifindex 2>/dev/null)
  if [ -n "$index" ] && [ "$index" != "$last" ]; then
    last=$index
    apply
  fi
  sleep 5
done
EOF
chmod 755 /config/scripts/vyos-postconfig-bootup.script
```

What each line buys:

- `fwmark 255` beats everything else, so Aether's own packets leave through the
  WAN. `255` is `0xff`, the value in `AETHER_MARK`.
- `from LAN to LAN` stays on the main table: clients talking to each other, to the
  router, or to a server on another VLAN never enter the tunnel.
- everything else from the LAN looks in table `100`, which is `tun0`.
- the `unreachable` route is the kill switch. If the tunnel dies the device
  disappears but the rule still matches table `100`, so traffic is dropped
  instead of falling back to the WAN.
- `masquerade` on `tun0` makes Aether's WARP address the source. WARP drops
  packets whose source is not the address it assigned; without this rule the
  handshake works and no data ever comes back, which is the failure this guide
  wastes the most time on.

Reboot, or run the hook once by hand:

```bash
/config/scripts/vyos-postconfig-bootup.script &
sleep 6
ip rule show
ip route show table 100
```

## Check that it works

On the router:

```bash
ip -s link show tun0
journalctl -u vyos-container-aether -f
```

The log should reach `[+] tun tun0 is up, 1500 byte mtu` and then the tunnel's own
`[+]` lines. From a client on the LAN, with no proxy configured:

```bash
curl -sS -m 20 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|warp)='
dig +short @1.1.1.1 example.com
```

`warp=on` and an answer from `dig` mean TCP and UDP both travel through WARP.
`ip -s link show tun0` should now show packets in both directions growing.

## When something does not work

| Symptom | Cause |
| --- | --- |
| `cannot open /dev/net/tun` | the device was not passed into the container, or the module is not loaded |
| `cannot attach tun0: Operation not permitted` | `capability net-admin` is missing |
| handshake succeeds, no data, counters flat | no `masquerade` on `tun0`, so WARP drops the packets |
| Aether reconnects in a loop | the tunnel's own traffic goes into `tun0`: the mark rule is missing or the mark differs from `AETHER_MARK` |
| clients keep their old IP | traffic still leaves the WAN, so `ip rule show` and `ip route show table 100` were not applied |
| WARP rejects the address | pass `AETHER_TUN_ADDR=172.16.0.2/32` to give the device the address yourself, or turn WARP's own family off with `AETHER_IP=v4` |

The router's own traffic is not routed into the tunnel by this setup, only the
LAN's. That is deliberate: it keeps the WAN usable when the tunnel is down.

## Turn it off

```bash
configure
delete container name aether
commit
```

Then restore the hook, or empty it:

```bash
: >/config/scripts/vyos-postconfig-bootup.script
ip rule del fwmark 255 lookup main pref 100
ip rule del from 192.168.10.0/24 to 192.168.10.0/24 lookup main pref 1000
ip rule del from 192.168.10.0/24 lookup 100 pref 1010
ip route flush table 100
nft delete table ip aether
```
