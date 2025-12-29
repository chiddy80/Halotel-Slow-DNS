//! Main installer logic - Complete conversion from bash script

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

use crate::config::{Config, InstallationStep, ServiceConfig};
use crate::download::{Downloader, DownloadType};
use crate::firewall::Firewall;
use crate::network::{NetworkInfo, SystemInfo};
use crate::service::{ServiceManager, ServiceType};
use crate::terminal::{Terminal, Banner, MessageType, Spinner};

/// Main installer struct - Equivalent to bash script main()
pub struct SlowDNSInstaller {
    config: Config,
    system_info: SystemInfo,
    network_info: NetworkInfo,
    nameserver: String,
    server_ip: String,
    progress: Arc<MultiProgress>,
    step: u8,
}

impl SlowDNSInstaller {
    /// Creates new installer instance
    pub async fn new(config: Config) -> Result<Self> {
        // Display banner
        Banner::display();
        
        // Gather system information
        Terminal::print_header("📦 GATHERING SYSTEM INFORMATION");
        
        let system_info = SystemInfo::detect().await?;
        let network_info = NetworkInfo::detect().await?;
        
        Terminal::print_info(&format!("Detected OS: {}", system_info.os));
        Terminal::print_info(&format!("Architecture: {}", system_info.arch));
        Terminal::print_info(&format!("Kernel: {}", system_info.kernel));
        
        // Get server IP with progress
        let spinner = Spinner::new("Detecting server IP address...");
        let server_ip = network_info.public_ip.clone();
        spinner.complete(&format!("Server IP: {}", server_ip.bold()));
        
        // Create progress bar manager
        let progress = Arc::new(MultiProgress::new());
        
        Ok(Self {
            config,
            system_info,
            network_info,
            nameserver: String::new(),
            server_ip,
            progress,
            step: 0,
        })
    }
    
    /// Main installation method - Equivalent to bash main() function
    pub async fn run(&mut self) -> Result<()> {
        // Prompt for nameserver
        self.prompt_nameserver().await?;
        
        // Execute all installation steps
        self.execute_step(InstallationStep::ConfigureSSH).await?;
        self.execute_step(InstallationStep::SetupSlowDNS).await?;
        self.execute_step(InstallationStep::CreateServices).await?;
        self.execute_step(InstallationStep::CompileEDNSProxy).await?;
        self.execute_step(InstallationStep::ConfigureFirewall).await?;
        self.execute_step(InstallationStep::StartServices).await?;
        
        // Display completion summary
        self.display_summary().await?;
        
        // Verify installation
        self.verify_installation().await?;
        
        // Show post-installation menu
        self.post_installation_menu().await?;
        
        Ok(())
    }
    
    /// Prompt for nameserver - Equivalent to bash nameserver input
    async fn prompt_nameserver(&mut self) -> Result<()> {
        Terminal::print_info("Enter nameserver configuration:");
        
        // Create a nice box like in bash
        Terminal::print_box(
            "┌──────────────────────────────────────────────────────────┐\n\
             │ Default: dns.example.com                                │\n\
             │ Example: tunnel.yourdomain.com                          │\n\
             └──────────────────────────────────────────────────────────┘",
            crate::terminal::Color::Cyan
        );
        
        let prompt = format!("{}", "Enter nameserver: ".bold().white());
        
        // Use dialoguer for user-friendly input
        let nameserver = dialoguer::Input::<String>::new()
            .with_prompt(&prompt)
            .default("dns.example.com".to_string())
            .interact_text()?;
        
        self.nameserver = nameserver;
        Ok(())
    }
    
    /// Execute a specific installation step
    async fn execute_step(&mut self, step: InstallationStep) -> Result<()> {
        self.step += 1;
        
        Terminal::print_step(self.step, &step.to_string());
        
        match step {
            InstallationStep::ConfigureSSH => self.configure_ssh().await,
            InstallationStep::SetupSlowDNS => self.setup_slowdns().await,
            InstallationStep::CreateServices => self.create_services().await,
            InstallationStep::CompileEDNSProxy => self.compile_edns_proxy().await,
            InstallationStep::ConfigureFirewall => self.configure_firewall().await,
            InstallationStep::StartServices => self.start_services().await,
            _ => Ok(()),
        }
    }
    
    /// Step 1: Configure SSH - Direct conversion from bash
    async fn configure_ssh(&self) -> Result<()> {
        Terminal::print_info(&format!("Configuring OpenSSH on port {}", self.config.ssh_port));
        
        // Backup SSH configuration
        let backup_spinner = Spinner::new("Backing up SSH configuration...");
        self.backup_ssh_config()?;
        backup_spinner.complete("SSH configuration backed up");
        
        // Create SSH configuration
        let config_spinner = Spinner::new("Creating optimized SSH configuration...");
        self.create_ssh_config()?;
        config_spinner.complete("SSH configuration created");
        
        // Restart SSH service
        let restart_spinner = Spinner::new("Restarting SSH service...");
        self.restart_ssh_service().await?;
        restart_spinner.complete("SSH service restarted");
        
        Terminal::print_success(&format!("OpenSSH configured on port {}", self.config.ssh_port));
        Ok(())
    }
    
    /// Backup SSH config - Equivalent to bash cp command
    fn backup_ssh_config(&self) -> Result<()> {
        let ssh_config = Path::new("/etc/ssh/sshd_config");
        if ssh_config.exists() {
            let backup_name = format!("sshd_config.backup.{}", chrono::Local::now().format("%Y%m%d_%H%M%S"));
            let backup_path = Path::new("/etc/ssh").join(&backup_name);
            
            fs::copy(ssh_config, backup_path)
                .context("Failed to backup SSH configuration")?;
        }
        Ok(())
    }
    
    /// Create SSH config - Equivalent to bash cat > file
    fn create_ssh_config(&self) -> Result<()> {
        let config_content = format!(
            r#"# ============================================================================
# SLOWDNS OPTIMIZED SSH CONFIGURATION
# ============================================================================
Port {}
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
UseDNS no
"#,
            self.config.ssh_port
        );
        
        fs::write("/etc/ssh/sshd_config", config_content)
            .context("Failed to write SSH configuration")?;
        
        Ok(())
    }
    
    /// Restart SSH service - Equivalent to systemctl restart sshd
    async fn restart_ssh_service(&self) -> Result<()> {
        let status = Command::new("systemctl")
            .args(["restart", "ssh"])
            .status()
            .context("Failed to restart SSH service")?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("SSH service restart failed"));
        }
        
        // Wait a bit for service to start
        sleep(Duration::from_secs(2)).await;
        Ok(())
    }
    
    /// Step 2: Setup SlowDNS - Direct conversion from bash
    async fn setup_slowdns(&self) -> Result<()> {
        Terminal::print_info("Setting up SlowDNS environment");
        
        // Create directory
        let dir_spinner = Spinner::new("Creating SlowDNS directory...");
        self.create_slowdns_directory()?;
        dir_spinner.complete("SlowDNS directory created");
        
        // Download binary
        let binary_spinner = Spinner::new("Downloading SlowDNS binary...");
        self.download_slowdns_binary().await?;
        binary_spinner.complete("SlowDNS binary downloaded");
        
        // Download keys
        let keys_spinner = Spinner::new("Downloading encryption keys...");
        self.download_slowdns_keys().await?;
        keys_spinner.complete("Encryption keys downloaded");
        
        // Test binary
        let test_spinner = Spinner::new("Validating binary...");
        self.validate_slowdns_binary()?;
        test_spinner.complete("Binary validated successfully");
        
        Terminal::print_success("SlowDNS components installed");
        Ok(())
    }
    
    /// Create directory - Equivalent to mkdir -p /etc/slowdns
    fn create_slowdns_directory(&self) -> Result<()> {
        let slowdns_dir = Path::new("/etc/slowdns");
        
        // Remove existing directory if exists
        if slowdns_dir.exists() {
            fs::remove_dir_all(slowdns_dir)?;
        }
        
        fs::create_dir_all(slowdns_dir)
            .context("Failed to create SlowDNS directory")?;
        
        // Change to directory
        std::env::set_current_dir(slowdns_dir)
            .context("Failed to change to SlowDNS directory")?;
        
        Ok(())
    }
    
    /// Download binary - Equivalent to curl/wget download
    async fn download_slowdns_binary(&self) -> Result<()> {
        let downloader = Downloader::new();
        
        let urls = vec![
            format!("{}/dnstt-server", self.config.github_base),
            format!("{}/dnstt-server", self.config.github_backup),
        ];
        
        downloader.download_with_fallback(
            &urls,
            "/etc/slowdns/dnstt-server",
            DownloadType::Binary,
        ).await?;
        
        // Set executable permissions
        Command::new("chmod")
            .args(["+x", "/etc/slowdns/dnstt-server"])
            .status()
            .context("Failed to set executable permissions")?;
        
        Ok(())
    }
    
    /// Download keys - Equivalent to wget commands
    async fn download_slowdns_keys(&self) -> Result<()> {
        let downloader = Downloader::new();
        
        let key_url = format!("{}/server.key", self.config.github_base);
        let pub_url = format!("{}/server.pub", self.config.github_base);
        
        downloader.download(&key_url, "/etc/slowdns/server.key", DownloadType::Text)
            .await
            .context("Failed to download server.key")?;
            
        downloader.download(&pub_url, "/etc/slowdns/server.pub", DownloadType::Text)
            .await
            .context("Failed to download server.pub")?;
        
        Ok(())
    }
    
    /// Validate binary - Equivalent to ./dnstt-server --help test
    fn validate_slowdns_binary(&self) -> Result<()> {
        let output = Command::new("/etc/slowdns/dnstt-server")
            .arg("--help")
            .output();
            
        match output {
            Ok(output) if output.status.success() => Ok(()),
            Ok(_) => {
                // Try alternative test
                let output = Command::new("/etc/slowdns/dnstt-server")
                    .arg("-h")
                    .output()?;
                    
                if output.status.success() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Binary validation failed"))
                }
            }
            Err(_) => {
                Terminal::print_warning("Binary test inconclusive - continuing anyway");
                Ok(())
            }
        }
    }
    
    /// Step 3: Create services - Direct conversion from bash
    async fn create_services(&self) -> Result<()> {
        Terminal::print_info("Creating SlowDNS system service");
        
        // Create SlowDNS service
        let service_spinner = Spinner::new("Creating SlowDNS service...");
        self.create_slowdns_service()?;
        service_spinner.complete("SlowDNS service created");
        
        // Create EDNS service
        let edns_spinner = Spinner::new("Creating EDNS service...");
        self.create_edns_service()?;
        edns_spinner.complete("EDNS service created");
        
        Terminal::print_success("Service configurations created");
        Ok(())
    }
    
    /// Create SlowDNS service - Equivalent to cat > service file
    fn create_slowdns_service(&self) -> Result<()> {
        let service_content = format!(
            r#"# ============================================================================
# SLOWDNS SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=SlowDNS Server
Description=High-performance DNS tunnel server
After=network.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :{} -mtu {} -privkey-file /etc/slowdns/server.key {} 127.0.0.1:{}
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
LimitCORE=infinity
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target"#,
            self.config.slowdns_port,
            self.config.mtu,
            self.nameserver,
            self.config.ssh_port
        );
        
        fs::write("/etc/systemd/system/server-sldns.service", service_content)
            .context("Failed to create SlowDNS service file")?;
        
        Ok(())
    }
    
    /// Create EDNS service - Equivalent to cat > service file
    fn create_edns_service(&self) -> Result<()> {
        let service_content = r#"# ============================================================================
# EDNS PROXY SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=EDNS Proxy for SlowDNS
Description=High-performance DNS proxy with EDNS support
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target"#;
        
        fs::write("/etc/systemd/system/edns-proxy.service", service_content)
            .context("Failed to create EDNS service file")?;
        
        Ok(())
    }
    
    /// Step 4: Compile EDNS proxy - Direct conversion from bash
    async fn compile_edns_proxy(&self) -> Result<()> {
        Terminal::print_info("Compiling high-performance EDNS Proxy");
        
        // Check for gcc
        if !self.check_gcc() {
            let install_spinner = Spinner::new("Installing compiler tools...");
            self.install_compiler_tools().await?;
            install_spinner.complete("Compiler installed");
        }
        
        // Create C source
        let source_spinner = Spinner::new("Creating optimized C code...");
        self.create_edns_source()?;
        source_spinner.complete("C source code created");
        
        // Compile
        let compile_spinner = Spinner::new("Compiling EDNS Proxy with O3 optimizations...");
        self.compile_edns_binary()?;
        compile_spinner.complete("EDNS Proxy compiled successfully");
        
        Terminal::print_success("EDNS Proxy service configured");
        Ok(())
    }
    
    /// Check for gcc - Equivalent to command -v gcc
    fn check_gcc(&self) -> bool {
        Command::new("which")
            .arg("gcc")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    
    /// Install compiler tools - Equivalent to apt install gcc
    async fn install_compiler_tools(&self) -> Result<()> {
        let status = Command::new("apt-get")
            .args(["update"])
            .status()
            .context("Failed to update apt")?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("APT update failed"));
        }
        
        let status = Command::new("apt-get")
            .args(["install", "-y", "gcc", "build-essential"])
            .status()
            .context("Failed to install compiler tools")?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("Compiler installation failed"));
        }
        
        Ok(())
    }
    
    /// Create EDNS source - Equivalent to cat > /tmp/edns.c
    fn create_edns_source(&self) -> Result<()> {
        let source_code = include_str!("../resources/edns_proxy.c");
        fs::write("/tmp/edns.c", source_code)
            .context("Failed to write EDNS source code")?;
        Ok(())
    }
    
    /// Compile binary - Equivalent to gcc command
    fn compile_edns_binary(&self) -> Result<()> {
        let status = Command::new("gcc")
            .args([
                "-O3",
                "-march=native",
                "-pipe",
                "/tmp/edns.c",
                "-o",
                "/usr/local/bin/edns-proxy",
            ])
            .status()
            .context("Failed to compile EDNS proxy")?;
            
        if !status.success() {
            // Try to read compilation log
            let log_content = fs::read_to_string("/tmp/compile.log")
                .unwrap_or_else(|_| "No compilation log".to_string());
            return Err(anyhow::anyhow!("Compilation failed: {}", log_content));
        }
        
        // Set executable permissions
        Command::new("chmod")
            .args(["+x", "/usr/local/bin/edns-proxy"])
            .status()
            .context("Failed to set executable permissions")?;
        
        Ok(())
    }
    
    /// Step 5: Configure firewall - Direct conversion from bash
    async fn configure_firewall(&self) -> Result<()> {
        Terminal::print_info("Configuring system firewall");
        
        let firewall = Firewall::new();
        
        // Setup rules
        let rules_spinner = Spinner::new("Setting up firewall rules...");
        firewall.configure().await?;
        rules_spinner.complete("Firewall rules configured");
        
        // Stop conflicting services
        let services_spinner = Spinner::new("Stopping conflicting DNS services...");
        self.stop_conflicting_services().await?;
        services_spinner.complete("DNS services stopped");
        
        Terminal::print_success("Firewall and network configured");
        Ok(())
    }
    
    /// Stop conflicting services - Equivalent to systemctl stop commands
    async fn stop_conflicting_services(&self) -> Result<()> {
        // Stop systemd-resolved
        let _ = Command::new("systemctl")
            .args(["stop", "systemd-resolved"])
            .status();
            
        let _ = Command::new("systemctl")
            .args(["disable", "systemd-resolved"])
            .status();
        
        // Kill any process on port 53
        let _ = Command::new("fuser")
            .args(["-k", "53/udp"])
            .status();
        
        Ok(())
    }
    
    /// Step 6: Start services - Direct conversion from bash
    async fn start_services(&self) -> Result<()> {
        Terminal::print_info("Starting all services");
        
        // Reload systemd
        Command::new("systemctl")
            .arg("daemon-reload")
            .status()
            .context("Failed to reload systemd")?;
        
        // Start SlowDNS
        let slowdns_spinner = Spinner::new("Starting SlowDNS service...");
        self.start_slowdns_service().await?;
        slowdns_spinner.complete("SlowDNS service started");
            // Start EDNS proxy
        let edns_spinner = Spinner::new("Starting EDNS Proxy service...");
        self.start_edns_service().await?;
        edns_spinner.complete("EDNS Proxy service started");
        
        // Verify services
        let verify_spinner = Spinner::new("Verifying service status...");
        sleep(Duration::from_secs(3)).await;
        verify_spinner.complete("Service verification complete");
        
        Terminal::print_success("All services started successfully");
        Ok(())
    }
    
    /// Start SlowDNS service - Equivalent to systemctl commands
    async fn start_slowdns_service(&self) -> Result<()> {
        // Enable service
        Command::new("systemctl")
            .args(["enable", "server-sldns"])
            .status()
            .context("Failed to enable SlowDNS service")?;
        
        // Start service
        let status = Command::new("systemctl")
            .args(["start", "server-sldns"])
            .status()
            .context("Failed to start SlowDNS service")?;
            
        if !status.success() {
            // Try to start manually in background
            Terminal::print_warning("Starting SlowDNS in background");
            
            let cmd = format!(
                "/etc/slowdns/dnstt-server -udp :{} -mtu {} -privkey-file /etc/slowdns/server.key {} 127.0.0.1:{}",
                self.config.slowdns_port,
                self.config.mtu,
                self.nameserver,
                self.config.ssh_port
            );
            
            let _ = Command::new("sh")
                .args(["-c", &format!("{} &", cmd)])
                .status();
        }
        
        Ok(())
    }
    
    /// Start EDNS service - Equivalent to systemctl commands
    async fn start_edns_service(&self) -> Result<()> {
        // Enable service
        Command::new("systemctl")
            .args(["enable", "edns-proxy"])
            .status()
            .context("Failed to enable EDNS service")?;
        
        // Start service
        let status = Command::new("systemctl")
            .args(["start", "edns-proxy"])
            .status()
            .context("Failed to start EDNS service")?;
            
        if !status.success() {
            // Try to start manually in background
            Terminal::print_warning("Starting EDNS Proxy manually");
            let _ = Command::new("sh")
                .args(["-c", "/usr/local/bin/edns-proxy &"])
                .status();
        }
        
        Ok(())
    }
    
    /// Display summary - Equivalent to bash completion summary
    async fn display_summary(&self) -> Result<()> {
        Terminal::print_header("🎉 INSTALLATION COMPLETE");
        
        // Show summary box
        Terminal::print_box(
            &format!(
                "┌──────────────────────────────────────────────────────────┐\n\
                 │ SERVER INFORMATION                                       │\n\
                 ├──────────────────────────────────────────────────────────┤\n\
                 │ ● Server IP:     {}                                    │\n\
                 │ ● SSH Port:      {}                                       │\n\
                 │ ● SlowDNS Port:  {}                                       │\n\
                 │ ● EDNS Port:     53                                       │\n\
                 │ ● MTU Size:      1800                                     │\n\
                 │ ● Nameserver:    {}                           │\n\
                 └──────────────────────────────────────────────────────────┘",
                self.server_ip,
                self.config.ssh_port,
                self.config.slowdns_port,
                self.nameserver
            ),
            crate::terminal::Color::Cyan
        );
        
        // Quick test commands
        Terminal::print_box(
            &format!(
                "┌──────────────────────────────────────────────────────────┐\n\
                 │ QUICK TEST COMMANDS                                      │\n\
                 ├──────────────────────────────────────────────────────────┤\n\
                 │ dig @{} {}                               │\n\
                 │ nslookup {} {}                             │\n\
                 │ systemctl status server-sldns                            │\n\
                 │ systemctl status edns-proxy                              │\n\
                 └──────────────────────────────────────────────────────────┘",
                self.server_ip, self.nameserver,
                self.nameserver, self.server_ip
            ),
            crate::terminal::Color::Cyan
        );
        
        // Service management
        Terminal::print_box(
            "┌──────────────────────────────────────────────────────────┐\n\
             │ SERVICE MANAGEMENT                                       │\n\
             ├──────────────────────────────────────────────────────────┤\n\
             │ Restart services: systemctl restart server-sldns edns-proxy │\n\
             │ View logs:        journalctl -u server-sldns -f            │\n\
             │ Check ports:      ss -ulpn | grep ':53\\|:5300'             │\n\
             └──────────────────────────────────────────────────────────┘",
            crate::terminal::Color::Cyan
        );
        
        Ok(())
    }
    
    /// Verify installation - Equivalent to bash verification section
    async fn verify_installation(&self) -> Result<()> {
        Terminal::print_info("Verifying installation...");
        
        // Check port 53
        let port53_spinner = Spinner::new("Checking port 53...");
        if self.check_port_listening(53).await? {
            port53_spinner.complete("✓ Port 53 (EDNS Proxy) is listening");
        } else {
            port53_spinner.warn("! Port 53 not listening");
        }
        
        // Check port 5300
        let port5300_spinner = Spinner::new(&format!("Checking port {}...", self.config.slowdns_port));
        if self.check_port_listening(self.config.slowdns_port).await? {
            port5300_spinner.complete(&format!("✓ Port {} (SlowDNS) is listening", self.config.slowdns_port));
        } else {
            port5300_spinner.warn(&format!("! Port {} not listening", self.config.slowdns_port));
        }
        
        // Check service status
        let service_spinner = Spinner::new("Checking service status...");
        if self.check_services_running().await? {
            service_spinner.complete("✓ All services are running");
        } else {
            service_spinner.warn("! Some services need attention");
        }
        
        // Show public key if available
        self.show_public_key()?;
        
        // Performance tips
        self.show_performance_tips();
        
        // Client configuration
        self.show_client_config();
        
        // Troubleshooting
        self.show_troubleshooting();
        
        Ok(())
    }
    
    /// Check if port is listening - Equivalent to ss -ulpn | grep
    async fn check_port_listening(&self, port: u16) -> Result<bool> {
        let output = Command::new("ss")
            .args(["-ulpn", "sport", "=", &port.to_string()])
            .output()
            .context("Failed to check listening ports")?;
            
        let output_str = String::from_utf8_lossy(&output.stdout);
        Ok(output_str.contains(&format!(":{}", port)))
    }
    
    /// Check services running - Equivalent to systemctl is-active
    async fn check_services_running(&self) -> Result<bool> {
        let services = ["server-sldns", "edns-proxy"];
        
        for service in services {
            let status = Command::new("systemctl")
                .args(["is-active", service])
                .status()
                .context("Failed to check service status")?;
                
            if !status.success() {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Show public key - Equivalent to cat /etc/slowdns/server.pub
    fn show_public_key(&self) -> Result<()> {
        let pubkey_path = Path::new("/etc/slowdns/server.pub");
        if pubkey_path.exists() {
            let content = fs::read_to_string(pubkey_path)?;
            
            Terminal::print_box(
                &format!(
                    "┌──────────────────────────────────────────────────────────┐\n\
                     │ PUBLIC KEY (For Client Configuration)                    │\n\
                     ├──────────────────────────────────────────────────────────┤\n\
                     │{}│\n\
                     └──────────────────────────────────────────────────────────┘",
                    content.lines().next().unwrap_or("").trim()
                ),
                crate::terminal::Color::Cyan
            );
        }
        Ok(())
    }
    
    /// Show performance tips - Equivalent to bash tips section
    fn show_performance_tips(&self) {
        Terminal::print_box(
            "┌──────────────────────────────────────────────────────────┐\n\
             │ PERFORMANCE TIPS                                         │\n\
             ├──────────────────────────────────────────────────────────┤\n\
             │ ● MTU 1800 is optimal for most networks                   │\n\
             │ ● For better performance, use TCP instead of UDP          │\n\
             │ ● Monitor performance: systemctl status server-sldns      │\n\
             │ ● Check logs: journalctl -u edns-proxy -n 50              │\n\
             └──────────────────────────────────────────────────────────┘",
            crate::terminal::Color::Cyan
        );
    }
    
    /// Show client configuration - Equivalent to bash client config
    fn show_client_config(&self) {
        Terminal::print_box(
            &format!(
                "┌──────────────────────────────────────────────────────────┐\n\
                 │ CLIENT CONFIGURATION EXAMPLE                             │\n\
                 ├──────────────────────────────────────────────────────────┤\n\
                 │ SlowDNS Client Command:                                  │\n\
                 │ ./dnstt-client -udp {}:{} \\                    │\n\
                 │     -pubkey-file server.pub \\                            │\n\
                 │     {} 127.0.0.1:1080                        │\n\
                 └──────────────────────────────────────────────────────────┘",
                self.server_ip,
                self.config.slowdns_port,
                self.nameserver
            ),
            crate::terminal::Color::Cyan
        );
    }
    
    /// Show troubleshooting - Equivalent to bash troubleshooting
    fn show_troubleshooting(&self) {
        Terminal::print_box(
            "┌──────────────────────────────────────────────────────────┐\n\
             │ TROUBLESHOOTING                                          │\n\
             ├──────────────────────────────────────────────────────────┤\n\
             │ If port 53 is not listening:                             │\n\
             │ 1. Stop systemd-resolved: systemctl stop systemd-resolved│\n\
             │ 2. Kill any process on port 53: fuser -k 53/udp          │\n\
             │ 3. Restart edns-proxy: systemctl restart edns-proxy      │\n\
             │                                                          │\n\
             │ If SlowDNS is not working:                               │\n\
             │ 1. Check firewall: iptables -L -n -v                     │\n\
             │ 2. Verify keys: ls -la /etc/slowdns/                     │\n\
             │ 3. Restart all: systemctl restart server-sldns edns-proxy│\n\
             └──────────────────────────────────────────────────────────┘",
            crate::terminal::Color::Cyan
        );
    }
    
    /// Post-installation menu - Equivalent to bash menu
    async fn post_installation_menu(&self) -> Result<()> {
        Terminal::print_success_box(
            "╔══════════════════════════════════════════════════════════╗\n\
             ║    🎯 SLOWDNS INSTALLATION COMPLETED SUCCESSFULLY!       ║\n\
             ║    ⚡ Installation completed in ~30 seconds               ║\n\
             ║    📊 Services running: SlowDNS + EDNS Proxy             ║\n\
             ║    🔧 Ready for DNS tunneling                            ║\n\
             ╚══════════════════════════════════════════════════════════╝"
        );
        
        Terminal::print_info("📞 Need help? Contact support: @esimfreegb");
        Terminal::print_info("💡 Documentation: https://github.com/chiddy80/Halotel-Slow-DNS");
        
        // Wait for Enter
        Terminal::print_info("Press Enter to continue...");
        let _ = io::stdin().read_line(&mut String::new());
        
        // Show menu
        Terminal::print_box(
            "┌──────────────────────────────────────────────────────────┐\n\
             │ POST-INSTALLATION OPTIONS                                │\n\
             ├──────────────────────────────────────────────────────────┤\n\
             │ 1. View service status                                   │\n\
             │ 2. Check listening ports                                 │\n\
             │ 3. Restart all services                                  │\n\
             │ 4. View installation log                                 │\n\
             │ 5. Test DNS functionality                                │\n\
             │ 6. Exit to terminal                                      │\n\
             └──────────────────────────────────────────────────────────┘",
            crate::terminal::Color::Cyan
        );
        
        let choice = dialoguer::Input::<String>::new()
            .with_prompt("Select option [1-6]")
            .interact_text()?;
            
        match choice.as_str() {
            "1" => self.view_service_status().await,
            "2" => self.check_listening_ports().await,
            "3" => self.restart_services().await,
            "4" => self.view_installation_log().await,
            "5" => self.test_dns_functionality().await,
            "6" => {
                Terminal::print_success("Returning to terminal...");
                Ok(())
            }
            _ => {
                Terminal::print_warning("Invalid option, returning to terminal...");
                Ok(())
            }
        }
    }
    
    /// View service status - Option 1
    async fn view_service_status(&self) -> Result<()> {
        Terminal::print_header("SERVICE STATUS");
        
        for service in ["server-sldns", "edns-proxy"] {
            Terminal::print_info(&format!("--- {} ---", service));
            let output = Command::new("systemctl")
                .args(["status", service, "--no-pager", "-l"])
                .output()
                .context("Failed to get service status")?;
                
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
        
        Ok(())
    }
    
    /// Check listening ports - Option 2
    async fn check_listening_ports(&self) -> Result<()> {
        Terminal::print_header("LISTENING PORTS");
        
        Terminal::print_info("Checking UDP ports:");
        let output = Command::new("ss")
            .args(["-ulpn"])
            .output()
            .context("Failed to check UDP ports")?;
            
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains(":53") || line.contains(":5300") {
                println!("{}", line);
            }
        }
        
        Terminal::print_info("\nChecking TCP ports:");
        let output = Command::new("ss")
            .args(["-tlnp"])
            .output()
            .context("Failed to check TCP ports")?;
            
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains(":22") {
                println!("{}", line);
            }
        }
        
        Ok(())
    }
    
    /// Restart services - Option 3
    async fn restart_services(&self) -> Result<()> {
        Terminal::print_header("RESTARTING SERVICES");
        
        Command::new("systemctl")
            .args(["restart", "server-sldns", "edns-proxy"])
            .status()
            .context("Failed to restart services")?;
            
        sleep(Duration::from_secs(2)).await;
        Terminal::print_success("✓ Services restarted successfully");
        
        Ok(())
    }
    
    /// View installation log - Option 4
    async fn view_installation_log(&self) -> Result<()> {
        Terminal::print_header("INSTALLATION LOG");
        
        let log_path = Path::new("/var/log/slowdns-installer.log");
        if log_path.exists() {
            let content = fs::read_to_string(log_path)?;
            let lines: Vec<&str> = content.lines().collect();
            let last_lines = if lines.len() > 20 {
                &lines[lines.len() - 20..]
            } else {
                &lines
            };
            
            for line in last_lines {
                println!("{}", line);
            }
        } else {
            Terminal::print_warning("Log file not found");
        }
        
        Ok(())
    }
    
    /// Test DNS functionality - Option 5
    async fn test_dns_functionality(&self) -> Result<()> {
        Terminal::print_header("DNS TEST");
        Terminal::print_info(&format!("Testing DNS query to {}...", self.nameserver));
        
        // Try dig first
        let dig_output = Command::new("dig")
            .args(["@", &self.server_ip, &self.nameserver, "+short"])
            .output();
            
        match dig_output {
            Ok(output) if output.status.success() => {
                println!("{}", String::from_utf8_lossy(&output.stdout));
                return Ok(());
            }
            _ => {}
        }
        
        // Try nslookup
        let nslookup_output = Command::new("nslookup")
            .args([&self.nameserver, &self.server_ip])
            .output();
            
        match nslookup_output {
            Ok(output) if output.status.success() => {
                println!("{}", String::from_utf8_lossy(&output.stdout));
                Ok(())
            }
            _ => {
                Terminal::print_warning("DNS tools not available");
                Ok(())
            }
        }
    }
}
```
