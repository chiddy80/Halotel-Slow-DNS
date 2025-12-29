#!/bin/bash
# Install prerequisites for SlowDNS Rust installer

set -e

echo "📦 Installing prerequisites..."

# Update system
apt-get update

# Install required packages
apt-get install -y \
    curl \
    wget \
    gcc \
    build-essential \
    iptables \
    openssh-server \
    systemd \
    net-tools \
    iproute2

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

echo "✅ Prerequisites installed successfully!"
