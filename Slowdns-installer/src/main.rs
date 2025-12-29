use anyhow::Result;
use colored::*;
use log::{error, info};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::process;

mod installer;
mod network;
mod service;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    TermLogger::init(
        simplelog::LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // Check for root privileges
    if !utils::is_root() {
        eprintln!("{}", "✗ Please run this script as root".red());
        process::exit(1);
    }

    // Display banner
    display_banner();

    // Create installer instance
    let installer = installer::ModernSlowDNSInstaller::new().await?;

    // Run installation
    if let Err(e) = installer.run().await {
        error!("Installation failed: {}", e);
        process::exit(1);
    }

    Ok(())
}

fn display_banner() {
    println!();
    println!("{}", "╔══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║          🚀 MODERN SLOWDNS INSTALLATION SCRIPT           ║".cyan());
    println!("{}", "║            Built with Rust for Performance               ║".cyan());
    println!("{}", "║                 Ubuntu & Debian Compatible               ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".cyan());
    println!();
}
