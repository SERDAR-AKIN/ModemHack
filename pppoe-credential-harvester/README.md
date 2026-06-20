# PPPoE Credential Harvester

A network security tool that captures PPPoE usernames and passwords from modems during WAN reconnection. It impersonates a PPPoE access concentrator, negotiates the LCP handshake, and forces the modem to send PAP credentials in plaintext.

Built with Scapy. VLAN 0 (802.1Q Priority Tagging) aware. Single-file architecture. Tested on Turkcell ZTE H3600P modems.

## Requirements

- Linux (tested on Ubuntu/Debian-based distributions)
- Python 3.6+
- [scapy](https://scapy.net/) (`pip install scapy`)
- Root access (raw sockets required for L2 frame injection)
- Ethernet port connected to the modem's WAN port

## How It Works

PPPoE has two stages: **discovery** and **session**. The harvester handles both.

### Protocol Flow

```
Modem                     Harvester
  |                          |
  |--- PADI (broadcast) ---->|  Discovery: modem looks for a server
  |<---- PADO (unicast) -----|  Harvester replies as access concentrator
  |--- PADR (unicast) ----->|  Modem requests session
  |<---- PADS (session) -----|  Session established, session ID assigned
  |                          |
  |<--- LCP Configure-Req ---|  Harvester initiates LCP negotiation
  |--- LCP Configure-Ack --->|  Modem agrees on MRU, Magic Number
  |<-- LCP Configure-Req ----|  Modem sends its own LCP request
  |--- LCP Configure-Ack --->|  Harvester acknowledges
  |                          |
  |<-- PAP Authenticate-Req -|  Harvester requests PAP auth
  |-- PAP Authenticate-Ack ->|  Modem sends credentials (plaintext)
  |                          |
  [+] Captured: username / password
```

### Phase Details

1. **PADI (PPPoE Active Discovery Initiation)** - The modem broadcasts a PADI frame on the network looking for a PPPoE access concentrator. The harvester receives this and prepares to respond.

2. **PADO (PPPoE Active Discovery Offer)** - The harvester sends a PADO back to the modem, claiming to be a valid access concentrator.

3. **PADR (PPPoE Active Discovery Request)** - The modem accepts the offer and sends a PADR to request a session.

4. **PADS (PPPoE Active Discovery Session-confirmation)** - The harvester assigns a session ID and sends PADS, establishing the PPP session.

5. **LCP (Link Control Protocol)** - The harvester initiates LCP negotiation. Both sides exchange Configure-Requests and Configure-Acks to agree on parameters like MRU (Maximum Receive Unit) and Magic Numbers. This handshake is critical: without correct LCP responses, the modem will time out and restart discovery.

6. **PAP (Password Authentication Protocol)** - Once LCP is open, the harvester requests PAP authentication. The modem responds with its username and password in cleartext. The harvester acknowledges the credentials and logs them.

## Protocol Details

### VLAN 0 / 802.1Q Priority Tagging

Many modems tag outgoing PPPoE frames with an 802.1Q header carrying VLAN ID 0. This is **Priority Tagging**, not a real VLAN assignment. The tag sets Ethernet priority (CoS) without isolating traffic to a specific VLAN.

Standard PPPoE tools like `rp-pppoe` strip or ignore these tags, causing them to miss modem traffic entirely. This harvester operates at the raw Ethernet frame level, preserving and handling VLAN 0 tags so no packets are lost.

### Raw Sockets (Layer 2)

The tool uses `sendp()` (Scapy's L2 frame injection) instead of `send()` (L3). This bypasses the kernel's IP stack entirely, which is essential because:

- PPPoE frames are Ethernet type `0x8863` (discovery) and `0x8864` (session), not IP
- VLAN tags sit between the MAC header and the EtherType field
- The kernel would drop or mishandle these frames on a standard network interface

Root access is required for raw socket operations.

### Why PAP and Not CHAP

PPPoE supports two authentication protocols: PAP and CHAP. CHAP is more secure because it uses a challenge-response mechanism that never sends the password over the wire. The harvester deliberately offers only PAP during LCP option negotiation. When PAP is the only offered method, the modem falls back to it and transmits the password in plaintext.

This is not a vulnerability in PPPoE itself. It is a design feature of PAP: the protocol sends credentials as cleartext by definition. CHAP would prevent this capture entirely.

## Quick Start

1. **Install dependency:**
   ```bash
   pip install scapy
   ```

2. **Cable connection:**
   Connect your computer's ethernet port to the modem's **WAN** port.

3. **Run the tool:**
   ```bash
   sudo ./run.sh                # Default interface (enp8s0)
   sudo ./run.sh eth0           # Custom interface
   ```

   Or directly with Python:
   ```bash
   sudo python3 src/harvester.py
   sudo python3 src/harvester.py -i eth0 -t 120
   ```

4. **Trigger:**
   Reboot the modem. Credentials appear within seconds.

## Project Structure

```
pppoe-credential-harvester/
├── src/
│   └── harvester.py          # Main tool (VLAN-aware PPPoE harvester)
├── docs/
│   └── TECH_JOURNEY.md       # Technical development history and obstacles
├── logs/                     # Captured credentials (auto-created)
├── run.sh                    # Convenience launcher
├── README.md                 # This file
├── RUN_GUIDE.md              # Detailed usage guide
└── .gitignore
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-i`, `--interface` | `enp8s0` | Ethernet interface to listen on |
| `-t`, `--timeout` | `180` | Timeout in seconds (0 = unlimited) |

## Technical Summary

Standard PPPoE servers (like rp-pppoe) often fail with modern modems. This tool succeeds where they do not through three key techniques:

- **VLAN 0 Awareness:** Captures Priority Tagged (802.1Q VLAN 0) packets from modems at the raw Ethernet layer, preventing frame loss.
- **LCP Handshake Simulation:** Negotiates connection parameters (MRU, Magic Number) correctly to transition the modem to the authentication phase.
- **PAP Forced Authentication:** Refuses more secure auth methods, forcing the modem to send credentials as cleartext.

## Warning

This tool is intended for educational use and password recovery on your own devices only. Unauthorized use against networks or devices you do not own is illegal and unethical. The author assumes no responsibility for misuse.
