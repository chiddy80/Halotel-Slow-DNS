use std::fs;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::path::Path;
use std::time::Duration;
use std::thread;
use std::collections::HashMap;
use colored::*;
use reqwest;
use serde::{Deserialize, Serialize};
use tokio;
use anyhow::{Result, Context};

// Configuration
const CONFIG: Config = Config {
    ssh_port: 22,
    slowdns_port: 5300,
    edns_port: 53,
    mtu: 1800,
    github_base: "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED",
};

// Data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    ssh_port: u16,
    slowdns_port: u16,
    edns_port: u16,
    mtu: u16,
    github_base: &'static str,
}

#[derive(Debug)]
struct SystemInfo {
    ip: String,
    os: String,
    arch: String,
    kernel: String,
}

#[derive(Debug)]
struct InstallationStatus {
    ssh_configured: bool,
    slowdns_installed: bool,
    edns_compiled: bool,
    firewall_setup: bool,
    services_running: bool,
}

struct ModernSlowDNSInstaller {
    config: Config,
    system_info: SystemInfo,
    status: InstallationStatus,
    nameserver: String,
}

impl ModernSlowDNSInstaller {
    fn new() -> Result<Self> {
        // Check root privileges
        if !Self::is_root() {
            return Err(anyhow::anyhow!("Please run this script as root"));
        }

        // Detect system info
        let system_info = Self::detect_system_info()?;

        Ok(Self {
            config: CONFIG,
            system_info,
            status: InstallationStatus {
                ssh_configured: false,
                slowdns_installed: false,
                edns_compiled: false,
                firewall_setup: false,
                services_running: false,
            },
            nameserver: String::new(),
        })
    }

    fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }

    fn detect_system_info() -> Result<SystemInfo> {
        // Get external IP
        let ip = reqwest::blocking::get("https://api.ipify.org")
            .and_then(|r| r.text())
            .unwrap_or_else(|_| {
                let output = Command::new("hostname")
                    .arg("-I")
                    .output()
                    .unwrap();
                String::from_utf8_lossy(&output.stdout)
                    .split_whitespace()
                    .next()
                    .unwrap_or("127.0.0.1")
                    .to_string()
            });

        // Get OS info
        let os = if Path::new("/etc/os-release").exists() {
            let content = fs::read_to_string("/etc/os-release")?;
            content
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"'))
                .unwrap_or("Unknown")
                .to_string()
        } else {
            "Unknown".to_string()
        };

        let arch = Command::new("uname")
            .arg("-m")
            .output()?
            .stdout
            .trim()
            .to_string();

        let kernel = Command::new("uname")
            .arg("-r")
            .output()?
            .stdout
            .trim()
            .to_string();

        Ok(SystemInfo { ip, os, arch, kernel })
    }

    fn display_banner(&self) {
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════╗".cyan());
        println!("{}", "║          🚀 MODERN SLOWDNS INSTALLATION SCRIPT           ║".cyan());
        println!("{}", "║            Built with Rust for Performance               ║".cyan());
        println!("{}", "║                 Ubuntu & Debian Compatible               ║".cyan());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".cyan());
        println!();
    }

    fn display_system_info(&self) {
        println!("{}", "📦 SYSTEM INFORMATION".bold().cyan());
        println!("{}", "═".repeat(50).cyan());
        
        let info = vec![
            ("🌐 Server IP".green(), self.system_info.ip.clone()),
            ("💻 OS".green(), self.system_info.os.clone()),
            ("🏗️  Architecture".green(), self.system_info.arch.clone()),
            ("🐧 Kernel".green(), self.system_info.kernel.clone()),
        ];

        for (label, value) in info {
            println!("  {}: {}", label, value.bright_white());
        }
        println!();
    }

    async fn prompt_nameserver(&mut self) -> Result<()> {
        println!("{}", "Enter nameserver configuration:".bold().white());
        println!("{}", "┌──────────────────────────────────────────────────────────┐".cyan());
        println!("{}", "│ Default: dns.example.com                                │".cyan());
        println!("{}", "│ Example: tunnel.yourdomain.com                          │".cyan());
        println!("{}", "└──────────────────────────────────────────────────────────┘".cyan());
        println!();
        
        print!("{}", "Enter nameserver: ".bold().white());
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        self.nameserver = input.trim().to_string();
        if self.nameserver.is_empty() {
            self.nameserver = "dns.example.com".to_string();
        }
        
        Ok(())
    }

    fn configure_ssh(&mut self) -> Result<()> {
        println!("{}", "🔧 STEP 1: CONFIGURE OPENSSH".bold().cyan());
        
        // Backup original SSH config
        let ssh_config_path = "/etc/ssh/sshd_config";
        let backup_path = format!("{}.backup-{}", ssh_config_path, chrono::Local::now().format("%Y%m%d-%H%M%S"));
        
        if Path::new(ssh_config_path).exists() {
            fs::copy(ssh_config_path, &backup_path)
                .context("Failed to backup SSH config")?;
            println!("  {} SSH configuration backed up", "✓".green());
        }

        // Create optimized SSH configuration
        let ssh_config = format!(
            "# ============================================================================\n\
            # SLOWDNS OPTIMIZED SSH CONFIGURATION\n\
            # ============================================================================\n\
            Port {}\n\
            Protocol 2\n\
            PermitRootLogin yes\n\
            PubkeyAuthentication yes\n\
            PasswordAuthentication yes\n\
            PermitEmptyPasswords no\n\
            ChallengeResponseAuthentication no\n\
            UsePAM yes\n\
            X11Forwarding no\n\
            PrintMotd no\n\
            PrintLastLog yes\n\
            TCPKeepAlive yes\n\
            ClientAliveInterval 60\n\
            ClientAliveCountMax 3\n\
            AllowTcpForwarding yes\n\
            GatewayPorts yes\n\
            Compression delayed\n\
            Subsystem sftp /usr/lib/openssh/sftp-server\n\
            MaxSessions 100\n\
            MaxStartups 100:30:200\n\
            LoginGraceTime 30\n\
            UseDNS no\n\
            AddressFamily inet\n\
            SyslogFacility AUTH\n\
            LogLevel INFO\n",
            self.config.ssh_port
        );

        fs::write(ssh_config_path, ssh_config)
            .context("Failed to write SSH config")?;

        // Restart SSH service
        self.execute_command("systemctl", &["restart", "ssh"], "Restarting SSH service")?;
        
        self.status.ssh_configured = true;
        println!("  {} OpenSSH configured on port {}", "✓".green(), self.config.ssh_port);
        
        Ok(())
    }

    async fn setup_slowdns(&mut self) -> Result<()> {
        println!("{}", "📦 STEP 2: SETUP SLOWDNS".bold().cyan());
        
        // Create directory
        let slowdns_dir = "/etc/slowdns";
        fs::create_dir_all(slowdns_dir)
            .context("Failed to create SlowDNS directory")?;
        
        println!("  {} SlowDNS directory created", "✓".green());

        // Download binary
        let binary_url = format!("{}/dnstt-server", self.config.github_base);
        let binary_path = format!("{}/dnstt-server", slowdns_dir);
        
        self.download_file(&binary_url, &binary_path, "SlowDNS binary").await?;
        
        // Set executable permissions
        Command::new("chmod")
            .arg("+x")
            .arg(&binary_path)
            .output()
            .context("Failed to set executable permissions")?;

        // Download keys
        let key_url = format!("{}/server.key", self.config.github_base);
        let pub_url = format!("{}/server.pub", self.config.github_base);
        
        self.download_file(&key_url, &format!("{}/server.key", slowdns_dir), "server.key").await?;
        self.download_file(&pub_url, &format!("{}/server.pub", slowdns_dir), "server.pub").await?;

        self.status.slowdns_installed = true;
        println!("  {} SlowDNS components installed", "✓".green());
        
        Ok(())
    }

    async fn download_file(&self, url: &str, dest: &str, description: &str) -> Result<()> {
        print!("  Downloading {}... ", description);
        io::stdout().flush()?;
        
        let response = reqwest::get(url).await
            .with_context(|| format!("Failed to download {}", url))?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to download: {}", response.status()));
        }
        
        let content = response.bytes().await
            .context("Failed to read response")?;
        
        fs::write(dest, content)
            .with_context(|| format!("Failed to write to {}", dest))?;
        
        println!("{}", "✓".green());
        Ok(())
    }

    fn create_slowdns_service(&self) -> Result<()> {
        println!("{}", "⚙️  STEP 3: CREATE SLOWDNS SERVICE".bold().cyan());
        
        let service_content = format!(
            "# ============================================================================\n\
            # SLOWDNS SERVICE CONFIGURATION\n\
            # ============================================================================\n\
            [Unit]\n\
            Description=SlowDNS Server\n\
            Description=High-performance DNS tunnel server\n\
            After=network.target sshd.service\n\
            Wants=network-online.target\n\n\
            [Service]\n\
            Type=simple\n\
            ExecStart=/etc/slowdns/dnstt-server -udp :{} -mtu {} -privkey-file /etc/slowdns/server.key {} 127.0.0.1:{}\n\
            Restart=always\n\
            RestartSec=5\n\
            User=root\n\
            LimitNOFILE=65536\n\
            LimitCORE=infinity\n\
            TimeoutStartSec=0\n\
            Environment=\"RUST_LOG=info\"\n\
            StandardOutput=journal\n\
            StandardError=journal\n\n\
            [Install]\n\
            WantedBy=multi-user.target\n",
            self.config.slowdns_port,
            self.config.mtu,
            self.nameserver,
            self.config.ssh_port
        );

        fs::write("/etc/systemd/system/server-sldns.service", service_content)
            .context("Failed to create SlowDNS service")?;

        println!("  {} SlowDNS service created", "✓".green());
        
        Ok(())
    }

    fn compile_edns_proxy(&mut self) -> Result<()> {
        println!("{}", "🔨 STEP 4: COMPILE EDNS PROXY".bold().cyan());
        
        // Install build dependencies if needed
        if !self.command_exists("gcc") {
            self.execute_command("apt-get", &["update"], "Updating package list")?;
            self.execute_command("apt-get", &["install", "-y", "gcc", "build-essential"], "Installing build tools")?;
        }

        // Create optimized C code
        let edns_source = include_str!("edns_proxy.c");
        let source_path = "/tmp/edns_proxy.c";
        fs::write(source_path, edns_source)
            .context("Failed to write EDNS source code")?;

        // Compile with optimizations
        print!("  Compiling EDNS proxy with O3 optimizations... ");
        io::stdout().flush()?;
        
        let compile_status = Command::new("gcc")
            .args(&["-O3", "-march=native", "-pipe", "-std=c11", "-D_GNU_SOURCE"])
            .arg(source_path)
            .arg("-o")
            .arg("/usr/local/bin/edns-proxy")
            .arg("-lpthread")
            .status()
            .context("Failed to compile EDNS proxy")?;

        if compile_status.success() {
            Command::new("chmod")
                .arg("+x")
                .arg("/usr/local/bin/edns-proxy")
                .output()
                .context("Failed to set executable permissions")?;
            
            println!("{}", "✓".green());
        } else {
            println!("{}", "✗".red());
            return Err(anyhow::anyhow!("EDNS proxy compilation failed"));
        }

        // Create EDNS service
        let edns_service = include_str!("edns_service.service");
        fs::write("/etc/systemd/system/edns-proxy.service", edns_service)
            .context("Failed to create EDNS service")?;

        self.status.edns_compiled = true;
        println!("  {} EDNS Proxy compiled and configured", "✓".green());
        
        Ok(())
    }

    fn configure_firewall(&mut self) -> Result<()> {
        println!("{}", "🛡️  STEP 5: CONFIGURE FIREWALL".bold().cyan());
        
        // Flush existing rules
        self.execute_command("iptables", &["-F"], "Flushing iptables rules")?;
        self.execute_command("iptables", &["-X"], "Deleting user-defined chains")?;
        self.execute_command("iptables", &["-t", "nat", "-F"], "Flushing NAT rules")?;
        self.execute_command("iptables", &["-t", "nat", "-X"], "Deleting NAT chains")?;
        
        // Set default policies
        for policy in ["INPUT", "FORWARD", "OUTPUT"] {
            self.execute_command("iptables", &["-P", policy, "ACCEPT"], 
                &format!("Setting {} policy to ACCEPT", policy))?;
        }
        
        // Essential rules
        let rules = vec![
            (vec!["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], "Allow loopback"),
            (vec!["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], "Allow loopback output"),
            (vec!["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], "Allow established"),
            (vec!["-A", "INPUT", "-p", "tcp", "--dport", &self.config.ssh_port.to_string(), "-j", "ACCEPT"], "Allow SSH"),
            (vec!["-A", "INPUT", "-p", "udp", "--dport", &self.config.slowdns_port.to_string(), "-j", "ACCEPT"], "Allow SlowDNS"),
            (vec!["-A", "INPUT", "-p", "udp", "--dport", &self.config.edns_port.to_string(), "-j", "ACCEPT"], "Allow DNS"),
            (vec!["-A", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "ACCEPT"], "Allow localhost"),
            (vec!["-A", "OUTPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "ACCEPT"], "Allow localhost output"),
            (vec!["-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"], "Allow ICMP"),
            (vec!["-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP"], "Drop invalid"),
        ];
        
        for (args, desc) in rules {
            self.execute_command("iptables", &args, desc)?;
        }
        
        // Disable IPv6 if not needed
        let disable_ipv6 = "net.ipv6.conf.all.disable_ipv6 = 1";
        fs::write("/etc/sysctl.d/99-disable-ipv6.conf", disable_ipv6)
            .context("Failed to disable IPv6")?;
        
        self.execute_command("sysctl", &["-p", "/etc/sysctl.d/99-disable-ipv6.conf"], "Applying IPv6 disable")?;
        
        // Stop conflicting DNS services
        self.execute_command("systemctl", &["stop", "systemd-resolved"], "Stopping systemd-resolved")?;
        self.execute_command("systemctl", &["disable", "systemd-resolved"], "Disabling systemd-resolved")?;
        
        // Kill any process on port 53
        let _ = Command::new("fuser")
            .args(&["-k", "53/udp"])
            .output();
        
        self.status.firewall_setup = true;
        println!("  {} Firewall and network configured", "✓".green());
        
        Ok(())
    }

    fn start_services(&mut self) -> Result<()> {
        println!("{}", "🚀 STEP 6: START SERVICES".bold().cyan());
        
        // Reload systemd
        self.execute_command("systemctl", &["daemon-reload"], "Reloading systemd")?;
        
        // Start and enable services
        let services = vec!["server-sldns", "edns-proxy"];
        
        for service in services {
            self.execute_command("systemctl", &["enable", service], &format!("Enabling {}", service))?;
            self.execute_command("systemctl", &["start", service], &format!("Starting {}", service))?;
            
            // Verify service is running
            thread::sleep(Duration::from_secs(2));
            
            let status = Command::new("systemctl")
                .args(&["is-active", service])
                .output()
                .context("Failed to check service status")?;
            
            if status.status.success() {
                println!("  {} {} service started", "✓".green(), service);
            } else {
                println!("  {} {} service may need attention", "⚠".yellow(), service);
            }
        }
        
        self.status.services_running = true;
        println!("  {} All services started", "✓".green());
        
        Ok(())
    }

    fn display_summary(&self) {
        println!();
        println!("{}", "🎉 INSTALLATION COMPLETE".bold().cyan());
        println!("{}", "═".repeat(50).cyan());
        
        let summary = vec![
            ("🌐 Server IP".green(), self.system_info.ip.clone()),
            ("🔐 SSH Port".green(), self.config.ssh_port.to_string()),
            ("🚀 SlowDNS Port".green(), self.config.slowdns_port.to_string()),
            ("📡 EDNS Port".green(), self.config.edns_port.to_string()),
            ("📦 MTU Size".green(), self.config.mtu.to_string()),
            ("🏷️  Nameserver".green(), self.nameserver.clone()),
        ];
        
        for (label, value) in summary {
            println!("  {}: {}", label, value.bright_white());
        }
        
        println!();
        println!("{}", "🔧 VERIFICATION COMMANDS".bold().cyan());
        println!("  {}", "dig @{} {}".bright_green(), self.system_info.ip, self.nameserver);
        println!("  {}", "nslookup {} {}".bright_green(), self.nameserver, self.system_info.ip);
        println!("  {}", "systemctl status server-sldns".bright_green());
        println!("  {}", "systemctl status edns-proxy".bright_green());
        
        println!();
        println!("{}", "💡 PERFORMANCE TIPS".bold().cyan());
        println!("  • MTU {} is optimal for most networks", self.config.mtu);
        println!("  • Monitor logs: journalctl -u server-sldns -f");
        println!("  • Check connections: ss -ulpn | grep ':53\\|:5300'");
        
                
        // Show public key
        let pubkey_path = "/etc/slowdns/server.pub";
        if let Ok(content) = fs::read_to_string(pubkey_path) {
            println!();
            println!("{}", "🔑 PUBLIC KEY".bold().cyan());
            println!("{}", content.trim());
        }
    }

    fn execute_command(&self, cmd: &str, args: &[&str], description: &str) -> Result<()> {
        print!("  {}... ", description);
        io::stdout().flush()?;
        
        let output = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("Failed to execute {} command", cmd))?;
        
        if output.status.success() {
            println!("{}", "✓".green());
            Ok(())
        } else {
            println!("{}", "✗".red());
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("Command failed: {}", stderr))
        }
    }

    fn command_exists(&self, cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    async fn verify_installation(&self) -> Result<()> {
        println!();
        println!("{}", "🔍 VERIFICATION".bold().cyan());
        
        // Check port listening
        let ports = vec![
            (self.config.edns_port, "EDNS Proxy"),
            (self.config.slowdns_port, "SlowDNS"),
        ];
        
        for (port, service) in ports {
            let output = Command::new("ss")
                .args(&["-ulpn", "sport", "=", &port.to_string()])
                .output()
                .context("Failed to check listening ports")?;
            
            if String::from_utf8_lossy(&output.stdout).contains(&port.to_string()) {
                println!("  {} {} on port {}", "✓".green(), service, port);
            } else {
                println!("  {} {} not listening on port {}", "⚠".yellow(), service, port);
            }
        }
        
        // Check service status
        let services = vec!["server-sldns", "edns-proxy"];
        for service in services {
            let status = Command::new("systemctl")
                .args(&["is-active", service])
                .output()
                .context("Failed to check service status")?;
            
            if status.status.success() {
                println!("  {} {} is active", "✓".green(), service);
            } else {
                println!("  {} {} is not active", "⚠".yellow(), service);
            }
        }
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize colored output
    colored::control::set_override(true);
    
    match ModernSlowDNSInstaller::new() {
        Ok(mut installer) => {
            installer.display_banner();
            installer.display_system_info();
            
            installer.prompt_nameserver().await?;
            
            // Run installation steps
            if let Err(e) = installer.configure_ssh() {
                eprintln!("{} Failed to configure SSH: {}", "✗".red(), e);
                return Ok(());
            }
            
            if let Err(e) = installer.setup_slowdns().await {
                eprintln!("{} Failed to setup SlowDNS: {}", "✗".red(), e);
                return Ok(());
            }
            
            if let Err(e) = installer.create_slowdns_service() {
                eprintln!("{} Failed to create SlowDNS service: {}", "✗".red(), e);
                return Ok(());
            }
            
            if let Err(e) = installer.compile_edns_proxy() {
                eprintln!("{} Failed to compile EDNS proxy: {}", "✗".red(), e);
                return Ok(());
            }
            
            if let Err(e) = installer.configure_firewall() {
                eprintln!("{} Failed to configure firewall: {}", "✗".red(), e);
                return Ok(());
            }
            
            if let Err(e) = installer.start_services() {
                eprintln!("{} Failed to start services: {}", "✗".red(), e);
                return Ok(());
            }
            
            // Show summary
            installer.display_summary();
            installer.verify_installation().await?;
            
            println!();
            println!("{}", "✅ INSTALLATION COMPLETED SUCCESSFULLY".bold().green());
            println!("{}", format!("📞 Support: @esimfreegb").yellow());
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            return Ok(());
        }
    }
    
    Ok(())
}
```
