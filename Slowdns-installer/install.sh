#!/bin/bash
set -e

echo "🚀 Installing SlowDNS Rust Installer..."

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# Clone or copy files
echo "Building installer..."
cargo build --release

echo "Installation complete!"
echo "Run with: sudo ./target/release/slowdns-installer"
