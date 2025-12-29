#!/bin/bash

echo "🗑️  Uninstalling SlowDNS..."

# Stop services
systemctl stop server-sldns edns-proxy 2>/dev/null || true
systemctl disable server-sldns edns-proxy 2>/dev/null || true

# Remove services
rm -f /etc/systemd/system/server-sldns.service
rm -f /etc/systemd/system/edns-proxy.service

# Remove files
rm -rf /etc/slowdns
rm -f /usr/local/bin/edns-proxy

# Reload systemd
systemctl daemon-reload

echo "✅ SlowDNS uninstalled successfully"
