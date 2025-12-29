//! Service management - Equivalent to systemctl commands

use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use std::str;

/// Service manager
pub struct ServiceManager;

impl ServiceManager {
    /// Check if service exists
    pub fn service_exists(name: &str) -> bool {
        Command::new("systemctl")
            .args(["list-unit-files", "--type=service"])
            .output()
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.contains(name)
            })
            .unwrap_or(false)
    }
    
    /// Check if service is active
    pub fn is_service_active(name: &str) -> Result<bool> {
        let output = Command::new("systemctl")
            .args(["is-active", name])
            .output()
            .context("Failed to check service status")?;
        
        Ok(output.status.success())
    }
    
    /// Enable service
    pub fn enable_service(name: &str) -> Result<()> {
        let status = Command::new("systemctl")
            .args(["enable", name])
            .status()
            .with_context(|| format!("Failed to enable service: {}", name))?;
        
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to enable service: {}", name));
        }
        
        Ok(())
    }
    
    /// Start service
    pub fn start_service(name: &str) -> Result<()> {
        let status = Command::new("systemctl")
            .args(["start", name])
            .status()
            .with_context(|| format!("Failed to start service: {}", name))?;
        
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to start service: {}", name));
        }
        
        Ok(())
    }
    
    /// Restart service
    pub fn restart_service(name: &str) -> Result<()> {
        let status = Command::new("systemctl")
            .args(["restart", name])
            .status()
            .with_context(|| format!("Failed to restart service: {}", name))?;
        
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to restart service: {}", name));
        }
        
        Ok(())
    }
    
    /// Stop service
    pub fn stop_service(name: &str) -> Result<()> {
        let status = Command::new("systemctl")
            .args(["stop", name])
            .status()
            .with_context(|| format!("Failed to stop service: {}", name))?;
        
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to stop service: {}", name));
        }
        
        Ok(())
    }
    
    /// Get service status
    pub fn get_service_status(name: &str) -> Result<String> {
        let output = Command::new("systemctl")
            .args(["status", name, "--no-pager"])
            .output()
            .with_context(|| format!("Failed to get status for service: {}", name))?;
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    /// Reload systemd
    pub fn reload_systemd() -> Result<()> {
        let status = Command::new("systemctl")
            .arg("daemon-reload")
            .status()
            .context("Failed to reload systemd")?;
        
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to reload systemd"));
        }
        
        Ok(())
    }
}
