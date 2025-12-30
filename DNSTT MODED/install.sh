#!/bin/bash
# COMPLETE SLOWDNS INSTALLER
echo "Installing SlowDNS with Python implementation..."

# Download the Python script
wget https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/moded-slowdns.py -O /tmp/slowdns.py

# Download config (optional)
wget https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/config.ini -O /tmp/config.ini 2>/dev/null || true

# Run installation
sudo python3 /tmp/slowdns.py --install#
