//! Firewall configuration - Equivalent to iptables commands

use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use std::str;

/// Firewall configuration
pub struct Firewall {
    rules: Vec<FirewallRule>,
}

/// Firewall rule type
enum RuleType {
    Accept,
    Drop,
    Reject,
}

/// Firewall rule
struct FirewallRule {
    rule_type: RuleType,
    chain: String,
    protocol: Option<String>,
    port: Option<u16>,
    source: Option<String>,
    destination: Option<String>,
    interface: Option<String>,
    state: Option<String>,
}

impl Firewall {
    /// Create new firewall config
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }
    
    /// Configure firewall - Equivalent to all iptables commands in bash
    pub async fn configure(&self) -> Result<()> {
        // Flush existing rules
        self.flush_rules()?;
        
        // Set default policies
        self.set_default_policies()?;
        
        // Add essential rules
        self.add_essential_rules()?;
        
        // Disable IPv6
        self.disable_ipv6()?;
        
        Ok(())
    }
    
    /// Flush rules - Equivalent to iptables -F
    fn flush_rules(&self) -> Result<()> {
        let commands = vec![
            vec!["-F"],
            vec!["-X"],
            vec!["-t", "nat", "-F"],
            vec!["-t", "nat", "-X"],
        ];
        
        for args in commands {
            self.run_iptables(&args)?;
        }
        
        Ok(())
    }
    
    /// Set default policies - Equivalent to iptables -P
    fn set_default_policies(&self) -> Result<()> {
        for policy in ["INPUT", "FORWARD", "OUTPUT"] {
            self.run_iptables(&["-P", policy, "ACCEPT"])?;
        }
        Ok(())
    }
    
    /// Add essential rules - All the iptables -A commands
    fn add_essential_rules(&self) -> Result<()> {
        let rules = vec![
            // Loopback
            vec!["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            vec!["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            
            // Established connections
            vec!["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            
            // SSH
            vec!["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
            
            // SlowDNS
            vec!["-A", "INPUT", "-p", "udp", "--dport", "5300", "-j", "ACCEPT"],
            
            // DNS
            vec!["-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            
            // Localhost
            vec!["-A", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "ACCEPT"],
            vec!["-A", "OUTPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "ACCEPT"],
            
            // ICMP
            vec!["-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
            
            // Invalid
            vec!["-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"],
        ];
        
        for rule in rules {
            self.run_iptables(&rule)?;
        }
        
        Ok(())
    }
    
    /// Disable IPv6 - Equivalent to echo 1 > /proc/sys/net/ipv6/...
    fn disable_ipv6(&self) -> Result<()> {
        // Write to proc
        std::fs::write(
            "/proc/sys/net/ipv6/conf/all/disable_ipv6",
            "1"
        ).context("Failed to disable IPv6")?;
        
        // Also update sysctl
        std::fs::write(
            "/etc/sysctl.d/99-slowdns-ipv6.conf",
            "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1"
        )?;
        
        Command::new("sysctl")
            .args(["-p", "/etc/sysctl.d/99-slowdns-ipv6.conf"])
            .status()?;
        
        Ok(())
    }
    
    /// Run iptables command
    fn run_iptables(&self, args: &[&str]) -> Result<()> {
        let output = Command::new("iptables")
            .args(args)
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .context("Failed to run iptables command")?;
        
        if !output.status.success() {
            let stderr = str::from_utf8(&output.stderr)
                .unwrap_or("Unknown error");
            return Err(anyhow::anyhow!("iptables failed: {}", stderr));
        }
        
        Ok(())
    }
}
