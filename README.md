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
python3 src/scripts/visualize_topology.py
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
```

Within seconds, Suricata writes an alert to `logs/eve.json`, the Ryu
controller picks it up, and installs a mitigation rule on s1_omurga. You can
verify with:

```bash
# In another terminal (as root)
ovs-ofctl -O OpenFlow13 dump-flows s1_omurga
ovs-ofctl -O OpenFlow13 dump-meters s1_omurga
```

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
