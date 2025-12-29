use anyhow::{Context, Result};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

use crate::network;
use crate::service;
use crate::utils;

pub struct ModernSlowDNSInstaller {
    config: Config,
    nameserver: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub ssh_port: u16,
    pub slowdns_port: u16,
    pub edns_port: u16,
    pub mtu: u16,
    pub github_base: String,
}

impl ModernSlowDNSInstaller {
    pub async fn new() -> Result<Self> {
        let config = Config {
            ssh_port: 22,
            slowdns_port: 5300,
            edns_port: 53,
            mtu: 1800,
            github_base: "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED".to_string(),
        };

        Ok(Self {
            config,
            nameserver: String::new(),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Display system info
        self.display_system_info().await?;

        // Get nameserver from user
        self.prompt_nameserver()?;

        // Step 1: Configure SSH
        self.configure_ssh()?;

        // Step 2: Setup SlowDNS
        self.setup_slowdns().await?;

        // Step 3: Create services
        self.create_services()?;

        // Step 4: Compile EDNS proxy
        self.compile_edns_proxy()?;

        // Step 5: Configure firewall
        self.configure_firewall()?;

        // Step 6: Start services
        self.start_services()?;

        // Display summary
        self.display_summary()?;

        // Verify installation
        self.verify_installation().await?;

        Ok(())
    }

    async fn display_system_info(&self) -> Result<()> {
        println!("{}", "📦 SYSTEM INFORMATION".bold().cyan());
        println!("{}", "═".repeat(50).cyan());

        let info = network::get_system_info().await?;
        
        for (label, value) in info {
            println!("  {}: {}", label.green(), value.bright_white());
        }
        println!();

        Ok(())
    }

    fn prompt_nameserver(&mut self) -> Result<()> {
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

    fn configure_ssh(&self) -> Result<()> {
        println!("{}", "🔧 STEP 1: CONFIGURE OPENSSH".bold().cyan());
        
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Backing up SSH configuration...");
        service::backup_ssh_config()?;
        pb.finish_and_clear();
        println!("  {} SSH configuration backed up", "✓".green());

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Configuring SSH...");
        service::configure_ssh(self.config.ssh_port)?;
        pb.finish_and_clear();
        println!("  {} SSH configured on port {}", "✓".green(), self.config.ssh_port);
        
        Ok(())
    }

    async fn setup_slowdns(&self) -> Result<()> {
        println!("{}", "📦 STEP 2: SETUP SLOWDNS".bold().cyan());
        
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Creating directories...");
        fs::create_dir_all("/etc/slowdns")?;
        pb.finish_and_clear();
        println!("  {} SlowDNS directory created", "✓".green());

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Downloading SlowDNS binary...");
        network::download_file(
            &format!("{}/dnstt-server", self.config.github_base),
            "/etc/slowdns/dnstt-server"
        ).await?;
        pb.finish_and_clear();
        println!("  {} SlowDNS binary downloaded", "✓".green());

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Downloading keys...");
        network::download_file(
            &format!("{}/server.key", self.config.github_base),
            "/etc/slowdns/server.key"
        ).await?;
        
        network::download_file(
            &format!("{}/server.pub", self.config.github_base),
            "/etc/slowdns/server.pub"
        ).await?;
        pb.finish_and_clear();
        println!("  {} Keys downloaded", "✓".green());

        // Set permissions
        utils::set_executable("/etc/slowdns/dnstt-server")?;
        
        Ok(())
    }

    fn create_services(&self) -> Result<()> {
        println!("{}", "⚙️  STEP 3: CREATE SERVICES".bold().cyan());
        
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Creating SlowDNS service...");
        service::create_slowdns_service(
            &self.nameserver,
            self.config.slowdns_port,
            self.config.mtu,
            self.config.ssh_port
        )?;
        pb.finish_and_clear();
        println!("  {} SlowDNS service created", "✓".green());

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Creating EDNS service...");
        service::create_edns_service()?;
        pb.finish_and_clear();
        println!("  {} EDNS service created", "✓".green());
        
        Ok(())
    }

    fn compile_edns_proxy(&self) -> Result<()> {
        println!("{}", "🔨 STEP 4: COMPILE EDNS PROXY".bold().cyan());
        
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Checking for gcc...");
        if !utils::command_exists("gcc") {
            pb.set_message("Installing build tools...");
            utils::install_packages(&["gcc", "build-essential"])?;
        }
        pb.finish_and_clear();
        println!("  {} Build tools verified", "✓".green());

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Compiling EDNS proxy...");
        service::compile_edns_proxy()?;
        pb.finish_and_clear();
        println!("  {} EDNS proxy compiled", "✓".green());
        
        Ok(())
    }

    fn configure_firewall(&self) -> Result<()> {
        println!("{}", "🛡️  STEP 5: CONFIGURE FIREWALL".bold().cyan());
        
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Configuring firewall rules...");
        network::configure_firewall(
            self.config.ssh_port,
            self.config.slowdns_port,
            self.config.edns_port
        )?;
        pb.finish_and_clear();
        println!("  {} Firewall configured", "✓".green());

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Stopping conflicting services...");
        network::stop_conflicting_services()?;
        pb.finish_and_clear();
        println!("  {} Conflicting services stopped", "✓".green());
        
        Ok(())
    }

    fn start_services(&self) -> Result<()> {
        println!("{}", "🚀 STEP 6: START SERVICES".bold().cyan());
        
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        pb.set_message("Reloading systemd...");
        utils::reload_systemd()?;
        pb.finish_and_clear();

        let services = ["server-sldns", "edns-proxy"];
        
        for service in services.iter() {
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap());
            pb.enable_steady_tick(Duration::from_millis(100));
            
            pb.set_message(&format!("Starting {}...", service));
            service::start_service(service)?;
            sleep(Duration::from_secs(1)).await;
            pb.finish_and_clear();
            println!("  {} {} started", "✓".green(), service);
        }
        
        Ok(())
    }

    fn display_summary(&self) -> Result<()> {
        println!();
        println!("{}", "🎉 INSTALLATION COMPLETE".bold().cyan());
        println!("{}", "═".repeat(50).cyan());
        
        // Get system IP
        let sys_info = futures::executor::block_on(network::get_system_info())?;
        let ip = sys_info.get("IP").unwrap_or(&"Unknown".to_string()).clone();
        
        println!("  {}: {}", "🌐 Server IP".green(), ip.bright_white());
        println!("  {}: {}", "🔐 SSH Port".green(), self.config.ssh_port.to_string().bright_white());
        println!("  {}: {}", "🚀 SlowDNS Port".green(), self.config.slowdns_port.to_string().bright_white());
        println!("  {}: {}", "📡 EDNS Port".green(), self.config.edns_port.to_string().bright_white());
        println!("  {}: {}", "📦 MTU Size".green(), self.config.mtu.to_string().bright_white());
        println!("  {}: {}", "🏷️ Nameserver".green(), self.nameserver.bright_white());
        
        Ok(())
    }

    async fn verify_installation(&self) -> Result<()> {
        println!();
        println!("{}", "🔍 VERIFICATION".bold().cyan());
        
        // Check ports
        network::check_port_listening(self.config.edns_port).await?;
        network::check_port_listening(self.config.slowdns_port).await?;
        
        // Check services
        service::verify_service_status("server-sldns")?;
        service::verify_service_status("edns-proxy")?;
        
        println!("  {} Installation verified successfully", "✓".green());
        
        Ok(())
    }
}
