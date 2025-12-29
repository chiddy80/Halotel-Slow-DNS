use anyhow::{Context, Result};
use colored::*;
use reqwest;
use std::collections::HashMap;
use std::process::Command;

pub async fn get_system_info() -> Result<HashMap<String, String>> {
    let mut info = HashMap::new();
    
    // Get external IP
    let ip = get_external_ip().await.unwrap_or_else(|_| {
        get_local_ip().unwrap_or_else(|_| "127.0.0.1".to_string())
    });
    info.insert("IP".to_string(), ip);
    
    // Get OS info
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if line.starts_with("PRETTY_NAME=") {
                let os = line.trim_start_matches("PRETTY_NAME=").trim_matches('"');
                info.insert("OS".to_string(), os.to_string());
                break;
            }
        }
    }
    
    // Get architecture
    if let Ok(output) = Command::new("uname").arg("-m").output() {
        let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info.insert("Architecture".to_string(), arch);
    }
    
    // Get kernel
    if let Ok(output) = Command::new("uname").arg("-r").output() {
        let kernel = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info.insert("Kernel".to_string(), kernel);
    }
    
    Ok(info)
}

pub async fn get_external_ip() -> Result<String> {
    let client = reqwest::Client::new();
    let response = client.get("https://api.ipify.org")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .context("Failed to get external IP")?;
    
    Ok(response.text().await?)
}

pub fn get_local_ip() -> Result<String> {
    let output = Command::new("hostname")
        .arg("-I")
        .output()
        .context("Failed to get local IP")?;
    
    let ip = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();
    
    Ok(ip)
}

pub async fn download_file(url: &str, destination: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client.get(url)
        .send()
        .await
        .with_context(|| format!("Failed to download {}", url))?;
    
    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to download: {}", response.status()));
    }
    
    let content = response.bytes().await?;
    std::fs::write(destination, content)
        .with_context(|| format!("Failed to write to {}", destination))?;
    
    Ok(())
}

pub fn configure_firewall(ssh_port: u16, slowdns_port: u16, dns_port: u16) -> Result<()> {
    // Flush existing rules
    run_command("iptables", &["-F"])?;
    run_command("iptables", &["-X"])?;
    run_command("iptables", &["-t", "nat", "-F"])?;
    run_command("iptables", &["-t", "nat", "-X"])?;
    
    // Set policies
    for policy in &["INPUT", "FORWARD", "OUTPUT"] {
        run_command("iptables", &["-P", policy, "ACCEPT"])?;
    }
    
    // Add rules
    let rules = vec![
        vec!["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        vec!["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        vec!["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        vec!["-A", "INPUT", "-p", "tcp", "--dport", &ssh_port.to_string(), "-j", "ACCEPT"],
        vec!["-A", "INPUT", "-p", "udp", "--dport", &slowdns_port.to_string(), "-j", "ACCEPT"],
        vec!["-A", "INPUT", "-p", "udp", "--dport", &dns_port.to_string(), "-j", "ACCEPT"],
        vec!["-A", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "ACCEPT"],
        vec!["-A", "OUTPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "ACCEPT"],
        vec!["-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
        vec!["-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"],
    ];
    
    for rule in rules {
        run_command("iptables", &rule)?;
    }
    
    // Disable IPv6
    std::fs::write("/etc/sysctl.d/99-disable-ipv6.conf", "net.ipv6.conf.all.disable_ipv6 = 1")?;
    run_command("sysctl", &["-p", "/etc/sysctl.d/99-disable-ipv6.conf"])?;
    
    Ok(())
}

pub fn stop_conflicting_services() -> Result<()> {
    run_command("systemctl", &["stop", "systemd-resolved"])?;
    run_command("systemctl", &["disable", "systemd-resolved"])?;
    
    // Kill any process on port 53
    let _ = Command::new("fuser")
        .args(&["-k", "53/udp"])
        .output();
    
    Ok(())
}

pub async fn check_port_listening(port: u16) -> Result<()> {
    let output = Command::new("ss")
        .args(&["-ulpn", "sport", "=", &port.to_string()])
        .output()
        .context("Failed to check listening ports")?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    if output_str.contains(&port.to_string()) {
        println!("  {} Port {} is listening", "✓".green(), port);
        Ok(())
    } else {
        println!("  {} Port {} is not listening", "⚠".yellow(), port);
        Err(anyhow::anyhow!("Port {} not listening", port))
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
