#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
SCRIPT1_URL="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt1.sh"
SCRIPT2_URL="https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt2.sh"

# Show title
clear
echo ""
echo -e "${BLUE}===============================================================${NC}"
echo -e "${CYAN}           ESIMFREEGB FAST DNS INSTALLER${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo -e "${WHITE}                  SCRIPT BY ESIM FREE GB${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[✗] Run as root: sudo bash $0${NC}"
    exit 1
fi

# Installation
echo -e "${GREEN}──────────────────────────────────────────────────────────────${NC}"
echo -e "${WHITE}             STARTING INSTALLATION${NC}"
echo -e "${GREEN}──────────────────────────────────────────────────────────────${NC}"
echo ""

# Function to install
install() {
    local num=$1
    local url=$2
    
    echo -e "${BLUE}[→] Installing Script $num...${NC}"
    echo -e "${YELLOW}    URL: $url${NC}"
    
    if curl -fsSL "$url" -o /tmp/install$num.sh; then
        echo -e "${GREEN}    [✓] Downloaded${NC}"
        chmod +x /tmp/install$num.sh
        
        echo ""
        if bash /tmp/install$num.sh; then
            echo -e "${GREEN}    [✓] Installation complete${NC}"
        else
            echo -e "${YELLOW}    [!] Installation finished with warnings${NC}"
        fi
        
        rm -f /tmp/install$num.sh
        return 0
    else
        echo -e "${RED}    [✗] Download failed${NC}"
        return 1
    fi
}

# Install script 1
echo ""
install 1 "$SCRIPT1_URL"
if [ $? -ne 0 ]; then
    echo -e "${RED}[✗] Installation failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}──────────────────────────────────────────────────────────────${NC}"
echo ""

# Install script 2
install 2 "$SCRIPT2_URL"
if [ $? -ne 0 ]; then
    echo -e "${RED}[✗] Installation failed${NC}"
    exit 1
fi

# Completion
echo ""
echo -e "${GREEN}──────────────────────────────────────────────────────────────${NC}"
echo -e "${WHITE}           INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}──────────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "${CYAN}===============================================================${NC}"
echo -e "${WHITE}          WELCOME TO TANZANIA!${NC}"
echo -e "${CYAN}===============================================================${NC}"
echo ""
echo -e "${GREEN}[✓] SlowDNS Server installed${NC}"
echo -e "${GREEN}[✓] EDNS Proxy configured${NC}"
echo -e "${GREEN}[✓] System ready${NC}"
echo ""
echo -e "${YELLOW}Script 1: $SCRIPT1_URL${NC}"
echo -e "${YELLOW}Script 2: $SCRIPT2_URL${NC}"
echo ""
echo -e "${BLUE}Thank you for using ESIMFREEGB SlowDNS Script${NC}"
echo ""
