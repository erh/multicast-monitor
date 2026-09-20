# multicast-monitor

One static binary (`mcastwatch`) that watches multicast discovery chatter on a LAN, keeps
per-host history, serves a dashboard, and shouts when a device starts
misbehaving. No database, no agent, no stack.

Watches mDNS (5353), SSDP (1900), NetBIOS (137/138), WS-Discovery (3702) and
ARP. Answers "who is flooding my network right now" and "was this box already
bad three weeks ago".

## Install

Quickest, on the box that will run it:

```bash
curl -fsSL https://raw.githubusercontent.com/erh/multicast-monitor/main/install.sh \
  | sudo bash -s -- eno1
```

That pulls the right binary for the architecture, installs the systemd unit and
starts it on `eno1`. Dashboard on `http://<host>:8088/`.

From source (Go 1.21+, nothing to fetch — stdlib only):

```bash
git clone https://github.com/erh/multicast-monitor
cd multicast-monitor
make test
sudo make install
sudo systemctl enable --now mcastwatch@eno1
```

Releases are cut by pushing a tag; CI builds static amd64, arm64 and armv6
binaries and attaches them to the release:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-i` | — | interface to watch (required) |
| `-listen` | `:8088` | dashboard address |
| `-state` | `/var/lib/mcastwatch/state.json.gz` | snapshot path |
| `-warn` | `0.5` | pkt/s per host to mark chatty |
| `-crit` | `2.0` | pkt/s per host to mark broken and alert |
| `-alert-cmd` | — | shell command run on breach |
| `-alert-cooldown` | `30m` | minimum gap between alerts per host |
| `-save-interval` | `5m` | snapshot frequency |
| `-no-resolve` | false | skip reverse DNS |

## Alerting

Threshold breaches always hit the journal:

```
mcastwatch: ALERT 10.1.2.31 (hp-color-mfp.lan) at 11.30 pkt/s — mdns HP-ColorLJ._ipp._tcp.local
```

`-alert-cmd` runs any shell command with the details in the environment
(`MW_HOST`, `MW_HOSTNAME`, `MW_MAC`, `MW_PPS`, `MW_PROTO`, `MW_NAME`,
`MW_PACKETS_24H`). Slack:

```bash
-alert-cmd 'curl -s -XPOST -H "Content-type: application/json" \
  -d "{\"text\":\"mDNS flood: $MW_HOSTNAME ($MW_HOST) at $MW_PPS pkt/s — $MW_NAME\"}" \
  https://hooks.slack.com/services/XXX'
```

Email via `mail`, a webhook, an ntfy push — anything that runs in a shell.

## Reading it

The `Top name` column is the useful one. Per-host packet rates tell you *who*;
the repeated service name tells you *what is broken*:

| Name | Usually means |
|---|---|
| `_companion-link._tcp` / `_airplay._tcp` | Apple device with stuck Continuity/AirPlay state |
| `_ipp._tcp` / `_pdl-datastream._tcp` | Printer, often an HP or Brother with a firmware bug |
| `_googlecast._tcp` | Chromecast or Google Home re-announcing |
| `_esphomelib._tcp` | Home Assistant discovery loop |
| `_sonos._tcp` / SSDP | Sonos, usually fine unless it's constant |
| `_crestron._tcp` | Control processor doing service discovery |

Rough baselines per source: under 0.2 pkt/s is normal, 0.5–2 is chatty,
sustained above 2 means something is stuck in a loop, above 10 is your Wi-Fi
problem. Multicast goes out at the lowest basic rate on Wi-Fi, so a *wired*
device spraying 20 pkt/s costs airtime on every AP in the broadcast domain.

## API

```bash
curl -s localhost:8088/api/hosts | jq '.[] | select(.pps_now > 1)'
curl -s 'localhost:8088/api/host?key=10.1.2.31' | jq .names
```

## What it sees and what it doesn't

It sees everything in its own broadcast domain, including wireless clients,
because APs bridge them onto the same L2. It does **not** see other VLANs. For
those, either run one instance per VLAN subinterface or put the box on a trunk
port and run `mcastwatch@eno1.20` alongside `mcastwatch@eno1`.

If UniFi's mDNS repeater is on, traffic from other VLANs reappears here sourced
from the original device, so you'll see the offender but understate its true
rate. Check `Settings → Networks → (VLAN) → Multicast DNS` before concluding
anything about volume.

## Design notes

About 1,100 lines of stdlib Go (plus 340 of tests), no external modules, `CGO_ENABLED=0`, so the
binary is fully static and drops onto any Linux box with no libpcap.

- **Kernel BPF filter.** The filter is attached with `SO_ATTACH_FILTER` before
  the socket is bound, so non-discovery traffic is dropped in the kernel and
  never copied to userspace. CPU cost is negligible even on a busy link. The
  bytecode table in `capture.go` is verbatim output from
  `tcpdump -dd -i eth0 '<filter>'` — regenerate it the same way if you want to
  watch different ports.
- **Two-resolution history.** Per-minute buckets for 24h, per-hour for 90 days,
  in fixed ring buffers. A few MB resident regardless of uptime, and no
  retention policy to tune.
- **State is one gzipped JSON file**, written atomically every 5 minutes and on
  shutdown. Restarts don't lose history. Delete the file to reset.
- **Unprivileged.** `DynamicUser=yes` with ambient `CAP_NET_RAW`. It never runs
  as root.

Memory is bounded by host count, not traffic: ~18 KB per host. A thousand
talkers is under 20 MB.

## Limits worth knowing

- Counts packets, not bytes-on-air. A 1500-byte mDNS response costs far more
  airtime than a 60-byte query; the rate column treats them alike.
- No per-VLAN tagging. Frames arriving tagged are counted, but the VLAN ID
  isn't recorded — run a separate instance per subinterface if you need that
  split out.
- Reverse DNS only. Devices without PTR records show as bare IPs; the mDNS name
  column is usually more identifying anyway.
