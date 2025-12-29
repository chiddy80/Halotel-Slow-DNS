
### ⌛ FAST DNS HALOTEL TANZANIA 🇹🇿
```bash
apt update && apt install -y curl dos2unix && \
curl -fsSL "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/moded-slowdns%20.sh" -o moded-slowdns.sh && \
dos2unix moded-slowdns.sh && \
chmod +x moded-slowdns.sh && \
./moded-slowdns.sh


# Modern SlowDNS Installer (Rust)

A high-performance, modern SlowDNS installer written in Rust. Features professional installation, systemd integration, and optimized networking.

## Features

- 🚀 **High Performance**: Compiled native Rust code
- 🛡️ **Safe**: Memory-safe with proper error handling
- 📦 **Complete**: Full SlowDNS + EDNS proxy setup
- 🔧 **Configurable**: Easy to customize settings
- 📊 **Professional**: Clean UI with progress indicators
- 🐧 **Cross-platform**: Works on Ubuntu & Debian

## Quick Start

### Prerequisites
- Rust 1.70+ (install via rustup)
- Root access
- Ubuntu/Debian system

### Installation

1. **Clone and build:**
```bash
git clone https://github.com/yourusername/slowdns-rust-installer.git
cd slowdns-rust-installer
cargo build --release
