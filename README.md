# ModemHack — PPPoE Credential Harvester

A network security tool that captures PPPoE usernames and passwords from modems during WAN reconnection. It impersonates a PPPoE access concentrator (BRAS), negotiates the LCP handshake, and forces the modem to send PAP credentials in plaintext.

**Stack:** Python 3 + Scapy · VLAN 0 (802.1Q Priority Tagging) aware · Tested on **Turkcell ZTE H3600P**

## Quick Start

```bash
pip install scapy
sudo ./pppoe-credential-harvester/run.sh eth0
# Reboot the target modem — credentials appear within seconds
```

## How It Works

```
Modem                     Harvester
  |                          |
  |--- PADI (broadcast) ---->|  "Anyone out there?"
  |<---- PADO (unicast) -----|  "I am a BRAS, authenticate with me"
  |--- PADR (unicast) ----->|  "Okay, start a session"
  |<---- PADS (session) -----|  Session 0x5555 established
  |                          |
  |<--- LCP Conf-Req (PAP) --|  "Use PAP authentication"
  |--- LCP Conf-Ack -------->|  Modem agrees
  |--- PAP Auth-Req --------->|  Username + password (cleartext)
  |                          |
  ═══ credentials captured ═══
```

## Why This Exists

Standard PPPoE servers (rp-pppoe, pppoe-server) fail with modern modems because:

- Modems tag discovery packets with **VLAN 0** (802.1Q Priority Tagging) that the kernel strips before PPPoE daemons see them
- Kernel VLAN processing is driver-dependent and unpredictable
- LCP handshake must be perfectly timed and acknowledged

This tool bypasses the kernel's network stack entirely — raw L2 frame capture and injection via Scapy.

## Documentation

| Document | Description |
|----------|-------------|
| [README](pppoe-credential-harvester/README.md) | Full project overview, protocol details, requirements |
| [Run Guide](pppoe-credential-harvester/RUN_GUIDE.md) | Usage guide, troubleshooting (8 scenarios), `run.sh` internals |
| [Technical Architecture](pppoe-credential-harvester/docs/TECH_JOURNEY.md) | 4 ADR-style challenges, hex-level protocol analysis, RFC references |

## Warning

This tool is intended for **educational use and password recovery on your own devices only**. Unauthorized use against networks or devices you do not own is illegal.
