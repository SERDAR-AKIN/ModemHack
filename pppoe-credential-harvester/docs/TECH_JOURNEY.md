# Technical Architecture: PPPoE Credential Harvester

**Document type:** Technical Challenges & Resolutions
**Application:** `pppoe-credential-harvester/src/harvester.py` (260 lines)
**Target device:** Turkcell ZTE H3600P (fiber/DSL modem)
**Target environment:** Linux (raw L2 sockets via Scapy)
**Dependencies:** scapy only

---

## Challenge 1: Invisible Discovery Packets (VLAN 0 Priority Tagging)

### Problem
The target modem (MAC `zte_2d:bd:ad`) wraps its PPPoE Active Discovery
Initiation (PADI) packets in an 802.1Q header with VLAN ID 0 (Priority
Tagging). Standard Linux PPPoE servers (e.g. `rp-pppoe`, `pppoe-server`)
bind to the Ethernet type `0x8863` (PPPoE Discovery) at the kernel level.
When the kernel's VLAN subsystem processes the 802.1Q header, it strips the
tag and routes the inner PPPoE frame to a VLAN interface, not the raw
Ethernet socket the PPPoE daemon listens on. The daemon never sees these
packets and therefore never responds.

The modem's PADI frames have this structure:
```
MAC dst: ff:ff:ff:ff:ff:ff
MAC src: zte_2d:bd:ad
EtherType: 0x8100 (802.1Q)
  └─ VLAN: 0, Priority: 0-7, CFI: 0
     EtherType: 0x8863 (PPPoE Discovery)
       └─ PPPoED code=0x09 (PADI)
```

### Root Cause
The kernel expects VLAN-tagged traffic to be handled by VLAN sub-interfaces
(e.g. `eth0.0`). Even with `rp_filter` disabled, the `pppoe-server` socket
listening for EtherType `0x8863` receives frames *after* the VLAN layer
either strips or drops them. Priority Tagging (VLAN 0) is particularly
tricky: some drivers forward the untagged inner frame, some do not, and the
behavior varies by NIC and driver version. The modem uses VLAN 0 not for
network segmentation but for priority signaling, which means standard
server implementations do not anticipate it.

### Solution
Bypass the kernel's network stack entirely. Use Scapy's L2 raw socket
(`conf.L3socket` / `L2RawSocket`) to capture and inject frames at the
Ethernet layer, before any VLAN processing occurs. The harvester:

1. Sniffs raw Ethernet frames with `scapy.sniff()` on the physical
   interface (line 225).
2. Inspects each frame for a `Dot1Q` layer (line 70).
3. Extracts the VLAN ID and priority code point (PCP) from the 802.1Q tag
   (lines 68-72).
4. Constructs all responses with the **same** `Dot1Q(vlan=vlan_id,
   prio=prio)` header, so the modem sees a consistent tag (lines 84, 97,
   117, 131).

### Implementation
The `_get_vlan_info()` method (lines 68-72) and the `Dot1Q` inclusion in
every `sendp()` call (lines 86, 99, 120, 134) implement this approach.
All outbound frames use `sendp()` (L2) instead of `send()` (L3) to avoid
kernel IP stack interference. This is a hard requirement documented in the
project anti-patterns.

---

## Challenge 2: Zero-Length PPPoED Tag Field

### Problem
When constructing PPPoE Discovery packets manually, the `PPPoED` layer's
`len` field was set to 0. The modem silently discarded these packets. This
affected both PADO (response to PADI, line 85) and PADS (response to PADR,
line 98) responses.

The PPPoED header format requires:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  VER | TYPE  |      CODE     |          SESSION_ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           LENGTH              |          payload...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The `LENGTH` field specifies the length of the payload **only** (not the
entire frame). Scapy's `PPPoED` class does not auto-compute this field
when the layer is constructed programmatically; it must be set explicitly.

### Root Cause
Scapy's `PPPoED` layer defaults `len` to 0 when instantiated directly via
`PPPoED(code=..., sessionid=..., len=...)`. The PPPoED specification
(RFC 2516) requires this field to reflect the exact byte count of the
Tag payload that follows the 6-byte PPPoED header. A value of 0 causes
the receiver to interpret the payload as empty, so the modem discards the
entire Discovery response.

### Solution
Compute the tag payload length dynamically before constructing the
`PPPoED` header. The tag bytes are assembled first via `get_tag()` calls,
then the total length is passed to `PPPoED(len=...)`.

### Implementation
The tag-assembly logic at lines 80-85 and 93-98 demonstrates this
pattern:

```python
tags = self.get_tag(0x0101, "BRAS") + self.get_tag(0x0102, "")
tags += self._extract_host_cookie(bytes(pkt[PPPoED].payload))
resp = (Ether(...) /
        Dot1Q(...) /
        PPPoED(code=0x07, sessionid=0, len=len(tags)))   # explicit length
sendp(bytes(resp) + tags, ...)   # tags appended as raw bytes
```

The tags are appended as raw bytes (`bytes(resp) + tags`) rather than
embedded as a Scapy layer, giving full control over the wire format. The
`get_tag()` helper (lines 50-55) packs each tag as `[type:2][len:2][value]`
using `struct.pack("!HH", tag_type, len(tag_value))`.

Because the `len` field is populated before transmission, the modem
correctly parses the Tag payload and proceeds to the next Discovery phase.

---

## Challenge 3: LCP Handshake Loop (Stalled at Authentication Phase)

### Problem
After the PPPoE Discovery phase completes (PADI / PADO / PADR / PADS), the
modem enters the PPP Link Control Protocol (LCP) negotiation. The modem
sends repeated LCP Configure-Requests (code=0x01) with incremental
Identifier fields. If the harvester does not respond with proper
Configure-Acks (code=0x02), the modem retransmits indefinitely at
decreasing intervals and never transitions to the Authentication phase.
Without completing LCP, the modem never sends the PAP Authenticate-Request
that contains the credential payload.

The modem's LCP Configure-Request includes options such as:
- MRU (Maximum Receive Unit, option 0x01)
- Authentication Protocol (option 0x03, value 0xc023 for PAP)
- Magic Number (option 0x05)

The packet flow when things go wrong:
```
Modem ──LCP Conf-Req(ID=1)──> Server
Modem <──(no response)── Server
Modem ──LCP Conf-Req(ID=2)──> Server (retransmit)
Modem ──LCP Conf-Req(ID=3)──> Server (retransmit)
... loop continues until timeout ...
```

### Root Cause
The LCP state machine (RFC 1661) requires a strict request/acknowledge
exchange before the link transitions to the Network-Layer Protocol phase.
The server must:
1. Acknowledge each valid Configure-Request from the peer with a
   Configure-Ack (code=0x02) matching the same Identifier.
2. Optionally send its own Configure-Request to request authentication
   via PAP (protocol 0xc023).

Without (1), the modem's LCP `REQ-SENT` state never transitions to
`OPENED`. Without (2), the modem assumes the server does not require
authentication and either skips PAP or attempts CHAP instead.

### Solution
Implement a two-part LCP handler:

**Part A: Acknowledge modem requests.** For each incoming LCP
Configure-Request (code=0x01), extract the Identifier and length, then
echo the exact payload back with code set to 0x02 (Configure-Ack). Track
the last acknowledged ID to avoid duplicate ACKs on retransmissions.

**Part B: Proactively request PAP authentication.** After acknowledging
the modem's request, send an LCP Configure-Request that includes:
- MRU = 1492 (standard PPPoE MTU)
- Authentication Protocol = PAP (0xc023)
- Magic Number = random 32-bit value (line 42)

This forces the modem to enter the Authentication phase using PAP, which
transmits the username and password as cleartext (no encryption or
challenge-response).

### Implementation
The `_handle_lcp()` method (lines 102-136) implements both parts:

**Part A (lines 111-122):**
```python
lcp_payload = struct.pack("!BBH", 0x02, lcp_id, lcp_len) + raw_ppp[4:lcp_len]
```
Takes the original Configure-Request payload, replaces the first byte
(code) with `0x02` (Configure-Ack), and sends it wrapped in PPP
(proto=0xc021) over the established PPPoE session.

**Part B (lines 125-136):**
```python
# MRU(1492) + Auth(PAP) + MagicNumber(random)
opts = b"\x01\x04\x05\xd4\x03\x04\xc0\x23\x05\x06" + magic_bytes
lcp_req_payload = struct.pack("!BBH", 0x01, 0x01, 4 + len(opts)) + opts
```
Sends a fresh Configure-Request with PAP as the required authentication
protocol. The `sent_lcp` flag (line 43) ensures this is transmitted only
once per session to avoid infinite loops.

The response path structure mirrors the Discovery path: Ethernet header,
Dot1Q (VLAN 0), PPPoE session header, PPP protocol field, then the raw
LCP payload. All via `sendp()`.

---

## Challenge 4: Credential Extraction from PAP Frames

### Problem
Once LCP negotiation completes and PAP is selected, the modem transmits its
credentials via a PAP Authenticate-Request frame. This frame arrives on the
PPPoE session channel (EtherType `0x8864`) with PPP protocol `0xc023` and
PAP code `0x01`. The payload is a simple type-length-value structure:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  CODE (=0x01) |     ID        |          LENGTH             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  USERNAME_LEN  |  USERNAME...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  PASSWORD_LEN  |  PASSWORD...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Solution
Parse the raw PPP payload byte-by-byte using struct offsets. Scapy does not
always auto-detect `PPP_PAP_Request` on VLAN-tagged PPPoE sessions, so the
handler falls back to raw byte extraction from `bytes(pkt[PPP].payload)`.

### Implementation
The `_handle_pap()` method (lines 138-158) handles extraction:

```python
p_data = bytes(pkt[PPP].payload)   # fallback extraction
u_len = p_data[4]                  # username length byte
user = p_data[5:5 + u_len]         # username bytes
p_len = p_data[5 + u_len]          # password length byte
password = p_data[6 + u_len:6 + u_len + p_len]  # password bytes
```

Credentials are logged to a timestamped JSON file in `logs/` via
`_save_credentials()` (lines 160-176). The tool exits cleanly after a
successful capture.

---

## Architecture Summary

### Protocol Flow (Success Path)

```
Modem                          Harvester
  │                                │
  │── PADI (VLAN 0, code=0x09) ──>│  Discovery: "any BRAS available?"
  │<── PADO (code=0x07, VLAN 0) ──│  Response: "yes, at this MAC"
  │── PADR (code=0x19, VLAN 0) ──>│  Request: "start session"
  │<── PADS (code=0x65, SID) ─────│  Confirm: "session 0x5555 open"
  │                                │
  │── LCP Conf-Req (0xc021) ─────>│  LCP: "negotiate parameters"
  │<── LCP Conf-Ack ──────────────│  Acknowledge modem params
  │<── LCP Conf-Req (w/ PAP) ─────│  Request: "authenticate via PAP"
  │── LCP Conf-Ack ──────────────>│
  │                                │
  │── PAP Auth-Req (0xc023) ─────>│  Authentication: CLEARTEXT
  │                                │  ** credentials captured **
```

### Key Design Decisions

| Decision | Rationale | Location |
|----------|-----------|----------|
| L2 raw socket via Scapy | Kernel VLAN processing drops VLAN 0 PPPoE frames | `sniff()`, line 225 |
| `sendp()` over `send()` | Must inject at L2 to preserve 802.1Q tags | All outbound frames |
| Manual `struct.pack` for tags | Scapy PPPoED auto-packing is unreliable for Discovery Tags | `get_tag()`, line 50 |
| Random magic number (32-bit) | Required by LCP per RFC 1661; prevents duplicate detection issues | Line 42 |
| Session ID hardcoded to `0x5555` | Arbitrary; any valid 16-bit value works if unique on the LAN | Line 31 |
| Synchronous sniff loop | Scapy's `sniff()` is blocking by design; async adds complexity with no benefit | Line 225 |
| VLAN 0 is assumed, not negotiated | All observed modems use Priority Tagging; configurable via code changes | Lines 68-72 |
