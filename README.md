# SDN-Based Automated Intrusion Detection and Mitigation System

Proof-of-concept system that detects network threats (SYN floods, port scans)
via Suricata and automatically installs OpenFlow drop/rate-limit rules on an
SDN backbone switch through a Ryu controller.

## Prerequisites

- Linux (tested on Linux Mint 22)
- [Mininet](http://mininet.org/) (system-wide)
- [Open vSwitch](https://www.openvswitch.org/)
- [Suricata](https://suricata.io/) >= 6
- Python >= 3.12
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Setup

```bash
git clone <repo-url> && cd bitirme

# Install Python dependencies into a virtual environment
uv sync

# Verify system tools
ovs-vsctl --version
suricata --build-info | head -5
mn --version
```

Mininet is installed system-wide and is not a pip package in the venv. If
`ty check` reports unresolved mininet imports, this is expected (the venv
does not inherit system site-packages by default).

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

```bash
# Lint
uv run ruff check src/ tests/

# Type check
uv run ty check

# Run tests
uv run pytest
```
