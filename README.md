# SDN-Based Automated Intrusion Detection and Mitigation System

Proof-of-concept system that detects network threats (SYN floods, port scans)
via Suricata and automatically installs OpenFlow drop/rate-limit rules on an
SDN backbone switch through a Ryu controller.

## Prerequisites

- Linux (tested on Linux Mint 22)
- [Mininet](http://mininet.org/)
- [Open vSwitch](https://www.openvswitch.org/) (system-wide, not in venv)
- [Suricata](https://suricata.io/) >= 6 (system-wide, not in venv)
- Python >= 3.12
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Setup

```bash
git clone <repo-url>
cd sdn_threat_detection
```

### Option A: uv (recommended)

```bash
uv sync
```

### Option B: pip

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # linters, test runner
```

### Verify system tools

```bash
ovs-vsctl --version
suricata --build-info
mn --version
```

## Usage

### Running the Full Demo

```bash
sudo ./src/scripts/start.sh
```

This will:

1. Clean any stale Mininet/Suricata state.
2. Start the Ryu controller in the background.
3. Launch the Mininet topology, configure OVS mirror + VLANs, start Suricata.
4. Drop into the Mininet CLI.

### Visualizing the Topology Only

```bash
.venv/bin/python3 src/scripts/visualize_topo.py
```

This opens the topology graph in a Matplotlib window without starting Ryu,
Mininet runtime services, or Suricata.

### Simulating Attacks

From the Mininet CLI:

```bash
# SYN flood (200 pps for 30 seconds)
mininet> hacker .venv/bin/python3 src/scripts/syn_flood.py 10.0.3.10 -d 30 -p 200

# Port scan (ports 1-1024)
mininet> hacker .venv/bin/python3 src/scripts/port_scan.py 10.0.3.10 -s 1 -e 1024

# ICMP flood (200 pps for 30 seconds)
mininet> hacker .venv/bin/python3 src/scripts/icmp_flood.py 10.0.3.10 -d 30 -p 200

# UDP flood to DNS port 53 (200 pps for 30 seconds)
mininet> hacker .venv/bin/python3 src/scripts/udp_flood.py 10.0.3.10 -P 53 -d 30 -p 200

# Horizontal scan (one port, many hosts)
mininet> hacker .venv/bin/python3 src/scripts/horizontal_scan.py -P 22 10.0.3.10 10.0.3.20 10.0.3.30

# ARP spoofing pattern (provide live victim MAC addresses from Mininet)
mininet> hacker .venv/bin/python3 src/scripts/arp_spoof.py --victim-a-ip 10.0.3.10 --victim-a-mac <MAC_A> --victim-b-ip 10.0.3.20 --victim-b-mac <MAC_B> -d 30 -p 10

# MAC flooding pattern (ARP-broadcast heavy)
mininet> hacker .venv/bin/python3 src/scripts/mac_flood.py -i hacker-eth0 -T 10.0.3.10 -d 30 -p 500

# SSH brute-force traffic-pattern stub (repeated TCP connect attempts only)
mininet> hacker .venv/bin/python3 src/scripts/ssh_bruteforce_stub.py 10.0.3.10 -a 200 -r 10
```

Within seconds, Suricata should write alerts under `logs/`, the Ryu controller
tails `logs/eve.json`, and may install mitigation on the backbone switch
`s1_omurga`. The subsection below explains how to verify each layer in detail.

### Verifying detection and mitigation

Detection and enforcement are separate in this design:

- **Suricata** listens on the mirrored interface (`mirror0` in `ids/suricata.yaml`)
  and only **logs** alerts. It does not drop packets on the live path (passive
  IDS, not inline IPS).
- **Ryu** reads those alerts and, for known signature IDs, sends **OpenFlow 1.3**
  `FlowMod` / `MeterMod` messages to **`s1_omurga`** (datapath id `1`). That is
  the actual mitigation: drop or rate-limit traffic matching the attacker
  source IPv4 on the Internet VLAN (`15`).

Treat verification as three layers: Suricata logs, controller logs, then the
switch pipeline.

#### 1. Suricata: proof the IDS saw the traffic

All paths below are relative to the **project root** (the directory from which
you run `sudo ./src/scripts/start.sh`). `start.sh` truncates some logs on each
run so you see a clean slice for that session.

| Log file | Role |
|----------|------|
| `logs/eve.json` | JSON lines: `event_type: "alert"` records with `src_ip`, `dest_ip`, `proto`, `alert.signature_id`, etc. Best source for automation and for matching what the controller reads. |
| `logs/fast.log` | One line per alert (classic Suricata fast log). Quick human scan (`tail -f`, `grep`). |
| `logs/suricata.log` | Engine and stats messages at the configured log level. |
| `logs/suricata_stderr.log` | Startup/runtime errors from the Suricata process. |

**Examples** (from another terminal, repo root, while or after an attack):

```bash
# Follow new EVE lines (alerts are JSON objects, one per line)
tail -f logs/eve.json

# If jq is installed: show recent alert signatures and SIDs
grep '"event_type":"alert"' logs/eve.json | tail -n 5 | jq -c '{sid: .alert.signature_id, sig: .alert.signature, src: .src_ip, dst: .dest_ip}'
```

If `eve.json` and `fast.log` show alerts but nothing happens on the switch,
Suricata is fine; continue with layers 2 and 3.

#### 2. Ryu: proof the controller reacted

`start.sh` starts Ryu with `--log-file logs/ryu.log`. After Suricata appends a
matching alert to `logs/eve.json`, the controller should log:

- An **`ALERT:`** line with signature text, source, destination, and SID.
- Either **`DROP rule installed`** or **`RATE-LIMIT rule installed`** (from
  `FlowManager`), depending on the SID mapping in `src/controller/alert_parser.py`.

**Examples:**

```bash
tail -f logs/ryu.log
grep -E 'ALERT:|DROP rule|RATE-LIMIT rule' logs/ryu.log
```

**Mitigation mapping** (only SIDs listed in `_SID_ACTION_MAP` in
`src/controller/alert_parser.py` trigger OpenFlow mitigation): SYN flood, ICMP
flood, UDP flood, MAC flooding, and HTTP rate abuse use **rate limit**; port
scan, horizontal scan, ARP spoofing, SSH brute-force stub, HTTP SQLi URI, and
web port scan use **drop**.

**Duplicate alerts** from the same `src_ip` are ignored until the mitigation
**hard timeout** elapses (300 seconds by default in `FlowManager`), so you may
see one controller action per attacker IP per window even if Suricata logs many
alerts.

**If Ryu logs `ALERT` but never installs a rule**, check for **`s1_omurga (dpid=1) not connected`** in `logs/ryu.log`. Mitigation is only applied to that
datapath.

#### 3. Open vSwitch: proof the data plane has the rules

Logs can show intent; **`ovs-ofctl`** shows what OVS actually holds. Run as
**root** from any working directory:

```bash
ovs-ofctl -O OpenFlow13 dump-flows s1_omurga
ovs-ofctl -O OpenFlow13 dump-meters s1_omurga
```

- **Drop mitigation**: look for flows with **priority `100`** (mitigation
  priority), match fields including **`ipv4_src=<attacker>`** and VLAN matching
  the Internet zone, with **no forwarding actions** (packets matching that flow
  are not output).
- **Rate-limit mitigation**: the same style of match at priority `100`, plus
  **`dump-meters`** should list a **meter** referenced from the flow (controller
  installs a drop band at a configured kbps rate).

Compare before and after an attack: new high-priority flows or meters should
appear when mitigation triggers and disappear after the flow **hard timeout**
unless traffic keeps the entries relevant.

#### 4. End-to-end sanity check

From Mininet, after mitigation (especially **drop**), traffic **from the blocked
source** toward monitored targets may stall or fail while the rule is active;
after several minutes (default hard timeout), behavior should return unless new
alerts arrive.

### Stopping

Type `exit` in the Mininet CLI. The `start.sh` EXIT trap kills Suricata,
the Ryu controller, and runs `mn -c`.

## Development

### With uv

```bash
uv run ruff check
uv run ty check
uv run pytest
```

### With pip (inside activated venv)

```bash
ruff check
ty check
pytest
```
