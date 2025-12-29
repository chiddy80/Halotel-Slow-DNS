//! Configuration - Equivalent to bash variables

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Main configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ssh_port: u16,
    pub slowdns_port: u16,
    pub edns_port: u16,
    pub mtu: u16,
    pub github_base: String,
    pub github_backup: String,
    pub install_dir: String,
    pub log_file: String,
}

/// Installation steps
#[derive(Debug, Clone)]
pub enum InstallationStep {
    ConfigureSSH,
    SetupSlowDNS,
    CreateServices,
    CompileEDNSProxy,
    ConfigureFirewall,
    StartServices,
}

impl std::fmt::Display for InstallationStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::ConfigureSSH => "Configure OpenSSH",
            Self::SetupSlowDNS => "Setup SlowDNS",
            Self::CreateServices => "Create Services",
            Self::CompileEDNSProxy => "Compile EDNS Proxy",
            Self::ConfigureFirewall => "Configure Firewall",
            Self::StartServices => "Start Services",
        };
        write!(f, "{}", text)
    }
}

impl Config {
    /// Load configuration
    pub fn load() -> anyhow::Result<Self> {
        let config = Self {
            ssh_port: 22,
            slowdns_port: 5300,
            edns_port: 53,
            mtu: 1800,
            github_base: "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED".to_string(),
            github_backup: "https://github.com/chiddy80/Halotel-Slow-DNS/raw/main/DNSTT%20MODED".to_string(),
            install_dir: "/etc/slowdns".to_string(),
            log_file: "/var/log/slowdns-installer.log".to_string(),
        };
        
        Ok(config)
    }
    
    /// Save configuration
    pub fn save(&self) -> anyhow::Result<()> {
        let config_dir = Path::new("/etc/slowdns");
        if !config_dir.exists() {
            fs::create_dir_all(config_dir)?;
        }
        
        let config_path = config_dir.join("config.json");
        let config_json = serde_json::to_string_pretty(self)?;
        fs::write(config_path, config_json)?;
        
        Ok(())
    }
}
