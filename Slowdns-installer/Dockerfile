FROM rust:latest as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    iptables \
    gcc \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/slowdns-installer /usr/local/bin/
COPY resources/ /usr/local/share/slowdns/

RUN chmod +x /usr/local/bin/slowdns-installer

ENTRYPOINT ["slowdns-installer"]
