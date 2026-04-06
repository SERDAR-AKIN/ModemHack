#!/bin/bash

# Renkler
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}   PPPoE Credential Harvester - AUTO FLOW    ${NC}"
echo -e "${GREEN}=============================================${NC}"

# 1. Root Yetkisi Kontrolü
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Lütfen bu betiği sudo ile çalıştırın.${NC}"
  exit 1
fi

# 2. Arayüz Parametresi (varsayılan: enp8s0)
INTERFACE="${1:-enp8s0}"
echo -e "[*] Kullanılan Arayüz: ${GREEN}$INTERFACE${NC}"

# 3. Arayüz Varlık Kontrolü
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo -e "${RED}[!] Arayüz bulunamadı: $INTERFACE${NC}"
    echo -e "${YELLOW}[*] Mevcut arayüzler:${NC}"
    ip -o link show | awk '{print "    " $2}'
    exit 1
fi

# 4. Bağımlılık Kontrolü (Scapy)
python3 -c "import scapy" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Scapy bulunamadı. Kuruluyor...${NC}"
    pip3 install scapy --quiet
fi

# 5. NetworkManager Müdahalesini Engelle
echo -e "[*] NetworkManager arayüzden çekiliyor..."
nmcli device set "$INTERFACE" managed no 2>/dev/null
ip link set "$INTERFACE" up

# 6. Harvester'ı Başlat
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo -e "${GREEN}[!] HAZIR! Modemi şimdi yeniden başlatın.${NC}"
echo -e "[*] Dinleme başlıyor..."
python3 "$SCRIPT_DIR/src/harvester.py" -i "$INTERFACE"

# 7. Temizlik: NetworkManager'a arayüzü geri ver
echo -e "[*] NetworkManager'a arayüz geri veriliyor..."
nmcli device set "$INTERFACE" managed yes 2>/dev/null
echo -e "${GREEN}[*] Temizlik tamamlandı.${NC}"
