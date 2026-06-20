#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}   PPPoE Credential Harvester - AUTO FLOW    ${NC}"
echo -e "${GREEN}=============================================${NC}"

# 1. Root Privilege Check
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}[!] Please run this script with sudo.${NC}"
  exit 1
fi

# 2. Interface Parameter (default: enp8s0)
INTERFACE="${1:-enp8s0}"
echo -e "[*] Using interface: ${GREEN}$INTERFACE${NC}"

# 3. Interface Existence Check
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo -e "${RED}[!] Interface not found: $INTERFACE${NC}"
    echo -e "${YELLOW}[*] Available interfaces:${NC}"
    ip -o link show | awk '{print "    " $2}'
    exit 1
fi

# 4. Dependency Check (Scapy)
python3 -c "import scapy" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Scapy not found. Installing...${NC}"
    pip3 install scapy --quiet
fi

# 5. Prevent NetworkManager Interference
echo -e "[*] Disconnecting NetworkManager from interface..."
nmcli device set "$INTERFACE" managed no 2>/dev/null
ip link set "$INTERFACE" up

# 6. Launch Harvester
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo -e "${GREEN}[!] READY! Reboot the modem now.${NC}"
echo -e "[*] Listening started..."
python3 "$SCRIPT_DIR/src/harvester.py" -i "$INTERFACE"

# 7. Cleanup: Restore interface to NetworkManager
echo -e "[*] Restoring interface to NetworkManager..."
nmcli device set "$INTERFACE" managed yes 2>/dev/null
echo -e "${GREEN}[*] Cleanup complete.${NC}"
