//! Modern SlowDNS Installer - Complete Rust implementation
//! Converts all bash functionality to high-performance Rust

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

mod installer;
mod network;
mod service;
mod firewall;
mod terminal;
mod download;
mod config;

use config::{Config, InstallationStep};
use terminal::{Terminal, Banner, MessageType};

#[tokio::main]
async fn main() -> Result<()> {
    // Set panic hook for better error messages
    std::panic::set_hook(Box::new(|panic_info| {
        Terminal::print_error(&format!("Panic: {}", panic_info));
        process::exit(1);
    }));

    // Check root privileges
    if !terminal::is_root() {
        Terminal::print_error("This installer must be run as root (sudo)");
        process::exit(1);
    }

    // Initialize configuration
    let config = Config::load()?;
    
    // Create installer instance
    let installer = installer::SlowDNSInstaller::new(config).await?;
    
    // Run the installation
    match installer.run().await {
        Ok(_) => {
            Terminal::print_success("Installation completed successfully!");
            process::exit(0);
        }
        Err(e) => {
            Terminal::print_error(&format!("Installation failed: {}", e));
            process::exit(1);
        }
    }
}
