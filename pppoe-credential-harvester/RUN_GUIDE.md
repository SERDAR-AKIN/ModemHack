# PPPoE Credential Harvester - Run Guide & Protocol Walkthrough

This document explains how to run the tool and describes the automatic routing logic flow (the PPPoE lifecycle) that makes credential capture possible.

## Prerequisites

- **Physical connection:** Connect your computer's Ethernet port directly to the modem's **WAN** port using a standard Ethernet cable. Do not use the modem's LAN ports.
- **No internet required on the target machine:** The machine does not need a working internet connection during capture (though internet is needed for installing dependencies).
- **Root / sudo access:** The tool requires raw socket access for L2 packet injection. All commands must be run with `sudo`.
- **Scapy dependency:** Install the only external dependency:
  ```bash
  pip install scapy
  ```

## Quick Start

Navigate to the project directory and run:

```bash
sudo chmod +x run.sh
sudo ./run.sh                  # Default interface (enp8s0)
sudo ./run.sh eth0             # Specify a different interface
```

Or run directly with Python:

```bash
sudo python3 src/harvester.py                      # Default interface
sudo python3 src/harvester.py -i eth0              # Different interface
sudo python3 src/harvester.py -i enp8s0 -t 120     # 2-minute timeout
sudo python3 src/harvester.py -t 0                 # No timeout (wait indefinitely)
```

## Interface Selection

Linux uses predictable network interface names. Common conventions:

- `enp8s0` — PCI-based Ethernet interface (common on modern systems, this is the default)
- `eth0` — Legacy naming convention (common on older or virtualized systems)
- `enpXsY` — Varies by hardware slot

To list available interfaces on your system:

```bash
ip link
```

Look for interfaces in a state other than `LOOPBACK` (usually `UP` or `DOWN`). Pass the chosen interface via the `-i` flag or as the first argument to `run.sh`.

## Triggering the Capture

When you see the message `[!] HAZIR! Modemi şimdi yeniden başlatın.` printed to the console:

1. Unplug the modem's power cable and wait about 10 seconds.
2. Plug the power cable back in.
3. The modem will initiate a WAN reconnection. Within approximately 1 minute, the credentials should appear on screen.

The capture begins immediately. The tool listens for PPPoE discovery packets (PADI). If no modem activity is detected within the timeout period, the tool exits gracefully.

## Understanding the Output

The tool prints progress messages with a prefix convention:

| Prefix | Meaning |
|--------|---------|
| `[*]` | Informational status message |
| `[+]` | Success (credential captured) |
| `[!]` | Warning or critical action required |

Key console messages and what they mean:

- `[!] HAZIR! Modemi şimdi yeniden başlatın.` — The tool is ready and listening. Reboot the modem now. (Console messages are kept in Turkish to match the source code output.)
- `PADI Yakalandı` — A PPPoE Active Discovery Initiation packet was captured from the modem ("Is anyone out there?").
- `PADO Gönderildi (VLAN 0 Response)` — The tool sent a PPPoE Active Discovery Offer back, posing as a BRAS (Telekom central office).
- `PADR Yakalandı` — The modem accepted the offer with a PPPoE Active Discovery Request.
- `PADS Gönderildi (Session ID: ...)` — Session confirmation sent; a PPPoE session is now established.
- `LCP Config-Request (ID: ...)` — Link Control Protocol handshake in progress (MRU negotiation, Magic Number exchange).
- `LCP ACK İletildi` — LCP configuration acknowledged.
- `PAP Auth Talebi Gönderildi` — PAP authentication request transmitted, forcing the modem to send credentials in clear text.
- `PPPoE KİMLİK BİLGİLERİ YAKALANDI!` — PAP credentials captured successfully.
- `Kullanıcı Adı: ... / Şifre: ...` — The extracted username and password printed to the console.
- `[+] Sonuçlar kaydedildi: ...` — Credentials successfully saved to the logs directory.
- `[!] Zaman aşımı (...s). Şifre yakalanamadı.` — Timeout reached without capturing credentials.

### Output Files

When credentials are captured, they are:

- Printed to the console in real time.
- Saved as a JSON file in the `logs/` directory with a timestamp-based filename.

## What `run.sh` Does Behind the Scenes

The `run.sh` bootstrapping script automates several pre-flight steps before launching the harvester:

1. **Root privilege check** — Verifies the script is running with `sudo`. Exits with an error message if not.
2. **Interface validation** — Confirms the specified interface exists via `ip link show`. On failure, it lists available interfaces.
3. **Dependency check** — Attempts to import `scapy` via Python. If missing, it automatically installs it with `pip3 install scapy --quiet`.
4. **NetworkManager isolation** — Runs `nmcli device set <interface> managed no` to prevent NetworkManager from interfering with the raw socket capture.
5. **Interface activation** — Brings the interface up with `ip link set <interface> up`.
6. **Launches the harvester** — Calls `python3 src/harvester.py -i <interface>`.
7. **Cleanup on exit** — Restores NetworkManager management of the interface (`nmcli device set <interface> managed yes`) so normal networking resumes.

## Automatic Routing Logic Flow (Protocol Walkthrough)

The tool exploits the modem's WAN reconnection sequence by impersonating a BRAS (Broadband Remote Access Server). The 7-step flow:

1. **Interface Preparation** — `run.sh` disables NetworkManager on the target interface and brings it up.
2. **PADI Capture (Discovery)** — The modem broadcasts "Is anyone out there?" (PPPoE Active Discovery Initiation). The harvester captures this packet, even when wrapped in VLAN 0 (802.1Q priority tagging).
3. **PADO Response (Offer)** — The tool replies "I am a BRAS (Telecom central office), send me your password" (PPPoE Active Discovery Offer).
4. **PADS Confirmation (Session)** — The modem acknowledges and opens a PPPoE session (PPPoE Active Discovery Session-confirmation).
5. **LCP Negotiation** — Both sides agree on link parameters (MRU, Magic Number, protocol options).
6. **PAP Extraction** — The tool forces the modem to authenticate using PAP, which sends the password in **clear text**.
7. **Credential Capture** — The captured username and password are printed to the console and saved to a JSON file in `logs/`. The program then terminates.

## Troubleshooting

- **PADI not being captured:** Make sure the Ethernet cable is connected to the modem's **WAN** port (not a LAN port) and that the modem is actively rebooting. Some modems take 30-60 seconds after power-on to emit PADI packets.
- **Interface not found:** Run `ip link` to list all available interfaces. You may need to pass a different interface name via the `-i` flag. Common names include `eth0`, `enp8s0`, `enp2s0`, `ens33` (VM), or `eth1`.
- **Permission denied:** The tool requires root access for raw sockets. Always run with `sudo`. If you see "Operation not permitted", you are not running as root.
- **Scapy not installed / ImportError:** Install it with `pip install scapy`. If you are using a virtual environment, activate it first. On some systems, you may need `pip3` instead of `pip`.
- **VLAN issues:** The tool handles VLAN 0 (802.1Q priority tagged) packets at the raw Ethernet level. If you suspect the modem is using a different VLAN ID, verify with `tcpdump -i <interface> -e vlan`.
- **Timeout:** Use `-t 0` to run in indefinite wait mode. Some modems take longer than the default 180 seconds to reconnect.
- **No output after a long wait:** Verify that NetworkManager is not interfering (the `run.sh` script handles this automatically if used). If running the Python script directly, run `nmcli device set <interface> managed no` before starting.
- **Multiple modems or networks in range:** The tool captures the first PADI it sees. In a shared environment, ensure only the target modem is connected.
