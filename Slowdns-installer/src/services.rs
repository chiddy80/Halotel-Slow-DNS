use anyhow::{Context, Result};
use std::fs;
use std::process::Command;

pub fn backup_ssh_config() -> Result<()> {
    let ssh_config_path = "/etc/ssh/sshd_config";
    if fs::metadata(ssh_config_path).is_ok() {
        let backup_path = format!("{}.backup", ssh_config_path);
        fs::copy(ssh_config_path, backup_path)?;
    }
    Ok(())
}

pub fn configure_ssh(port: u16) -> Result<()> {
    let config = format!(
        r#"Port {port}
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
AllowTcpForwarding yes
GatewayPorts yes
Compression delayed
Subsystem sftp /usr/lib/openssh/sftp-server
MaxSessions 100
MaxStartups 100:30:200
LoginGraceTime 30
UseDNS no"#,
        port = port
    );
    
    fs::write("/etc/ssh/sshd_config", config)?;
    run_command("systemctl", &["restart", "ssh"])?;
    
    Ok(())
}

pub fn create_slowdns_service(nameserver: &str, slowdns_port: u16, mtu: u16, ssh_port: u16) -> Result<()> {
    let service = format!(
        r#"[Unit]
Description=SlowDNS Server
After=network.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :{slowdns_port} -mtu {mtu} -privkey-file /etc/slowdns/server.key {nameserver} 127.0.0.1:{ssh_port}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target"#,
        slowdns_port = slowdns_port,
        mtu = mtu,
        nameserver = nameserver,
        ssh_port = ssh_port
    );
    
    fs::write("/etc/systemd/system/server-sldns.service", service)?;
    Ok(())
}

pub fn create_edns_service() -> Result<()> {
    let service = r#"[Unit]
Description=EDNS Proxy
After=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target"#;
    
    fs::write("/etc/systemd/system/edns-proxy.service", service)?;
    Ok(())
}

pub fn compile_edns_proxy() -> Result<()> {
    // Write C source
    let c_source = include_str!("../resources/edns_proxy.c");
    fs::write("/tmp/edns_proxy.c", c_source)?;
    
    // Compile
    run_command("gcc", &[
        "-O3", 
        "-march=native", 
        "-pipe",
        "/tmp/edns_proxy.c",
        "-o", 
        "/usr/local/bin/edns-proxy"
    ])?;
    
    run_command("chmod", &["+x", "/usr/local/bin/edns-proxy"])?;
    
    // Cleanup
    let _ = fs::remove_file("/tmp/edns_proxy.c");
    
    Ok(())
}

pub fn start_service(service: &str) -> Result<()> {
    run_command("systemctl", &["enable", service])?;
    run_command("systemctl", &["start", service])?;
    Ok(())
}

pub fn verify_service_status(service: &str) -> Result<()> {
    let output = Command::new("systemctl")
        .args(&["is-active", service])
        .output()
        .context("Failed to check service status")?;
    
    let status = String::from_utf8_lossy(&output.stdout).trim();
    if status == "active" {
        println!("  {} {} is active", "✓".green(), service);
        Ok(())
    } else {
        println!("  {} {} is not active", "⚠".yellow(), service);
        Err(anyhow::anyhow!("Service {} not active", service))
    }
}

fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to execute {}", cmd))?;
    
    if !status.success() {
        return Err(anyhow::anyhow!("Command failed: {} {:?}", cmd, args));
    }
    
    Ok(())
}
