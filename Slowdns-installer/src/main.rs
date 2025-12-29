use anyhow::{Context, Result};
use colored::*;
use libc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const GITHUB_BASE: &str =
    "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED";

const SSH_PORT: u16 = 22;
const SLOWDNS_PORT: u16 = 5300;
const EDNS_PORT: u16 = 53;
const MTU: u16 = 1800;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemInfo {
    ip: String,
    os: String,
    arch: String,
    kernel: String,
}

fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} failed", cmd);
    }
    Ok(())
}

fn get_ip() -> String {
    let out = Command::new("hostname").arg("-I").output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("127.0.0.1")
        .to_string()
}

fn detect_system() -> Result<SystemInfo> {
    let os = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("PRETTY_NAME="))
        .unwrap_or("PRETTY_NAME=Linux")
        .replace("PRETTY_NAME=", "")
        .replace('"', "");

    let arch = String::from_utf8(Command::new("uname").arg("-m").output()?.stdout)?;
    let kernel = String::from_utf8(Command::new("uname").arg("-r").output()?.stdout)?;

    Ok(SystemInfo {
        ip: get_ip(),
        os,
        arch: arch.trim().to_string(),
        kernel: kernel.trim().to_string(),
    })
}

fn download(url: &str, dest: &str) -> Result<()> {
    println!("  → {}", url);
    run("curl", &["-fsSL", url, "-o", dest])?;
    Ok(())
}

fn main() -> Result<()> {
    if !is_root() {
        anyhow::bail!("Run as root");
    }

    let sys = detect_system()?;

    println!("{}", "MODERN SLOWDNS INSTALLER".bright_cyan());
    println!("IP: {}", sys.ip);
    println!("OS: {}", sys.os);
    println!("ARCH: {}", sys.arch);
    println!("KERNEL: {}", sys.kernel);

    print!("Enter DNS name (example: dns.example.com): ");
    io::stdout().flush()?;
    let mut nameserver = String::new();
    io::stdin().read_line(&mut nameserver)?;
    let nameserver = nameserver.trim();
    if nameserver.is_empty() {
        anyhow::bail!("Nameserver required");
    }

    println!("{}", "Installing SlowDNS…".cyan());

    fs::create_dir_all("/etc/slowdns")?;
    download(
        &format!("{}/dnstt-server", GITHUB_BASE),
        "/etc/slowdns/dnstt-server",
    )?;
    run("chmod", &["+x", "/etc/slowdns/dnstt-server"])?;

    download(
        &format!("{}/server.key", GITHUB_BASE),
        "/etc/slowdns/server.key",
    )?;
    download(
        &format!("{}/server.pub", GITHUB_BASE),
        "/etc/slowdns/server.pub",
    )?;

    let service = format!(
        r#"[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=/etc/slowdns/dnstt-server -udp :{} -mtu {} -privkey-file /etc/slowdns/server.key {} 127.0.0.1:{}
Restart=always

[Install]
WantedBy=multi-user.target
"#,
        SLOWDNS_PORT, MTU, nameserver, SSH_PORT
    );

    fs::write("/etc/systemd/system/server-sldns.service", service)?;

    println!("{}", "Enabling services…".cyan());
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "server-sldns"])?;
    run("systemctl", &["restart", "server-sldns"])?;

    println!("{}", "Installing EDNS proxy…".cyan());
    run("systemctl", &["enable", "edns-proxy"])?;
    run("systemctl", &["restart", "edns-proxy"])?;

    thread::sleep(Duration::from_secs(2));

    println!("\n{}", "INSTALLATION COMPLETE".green());
    println!("DNS Server: {}", nameserver);
    println!("SlowDNS Port: {}", SLOWDNS_PORT);
    println!("EDNS Port: {}", EDNS_PORT);
    println!("\nPublic Key:\n{}", fs::read_to_string("/etc/slowdns/server.pub")?);

    Ok(())
}
