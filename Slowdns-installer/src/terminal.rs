//! Complete terminal UI - Equivalent to all bash print functions

use colored::*;
use indicatif::{ProgressBar, ProgressStyle, Spinner as IndicatifSpinner};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

/// Terminal colors matching bash script
pub enum Color {
    Red,
    Green,
    Yellow,
    Blue,
    Purple,
    Cyan,
    White,
}

/// Message types for consistent formatting
pub enum MessageType {
    Success,
    Error,
    Warning,
    Info,
    Step,
}

/// Terminal utilities - Replaces all bash print functions
pub struct Terminal;

impl Terminal {
    /// Check if running as root - Equivalent to $EUID check
    pub fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }
    
    /// Print banner - Equivalent to print_banner()
    pub fn print_banner() {
        print!("\x1B[2J\x1B[1;1H"); // Clear screen
        println!("{}", "╔══════════════════════════════════════════════════════════╗".cyan());
        println!("{}", "║          🚀 MODERN SLOWDNS INSTALLATION SCRIPT           ║".cyan());
        println!("{}", "║            Fast & Professional Configuration             ║".white());
        println!("{}", "║                Optimized for Performance                 ║".yellow());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".cyan());
        println!();
    }
    
    /// Print header - Equivalent to print_header()
    pub fn print_header(text: &str) {
        println!("\n{}", "══════════════════════════════════════════════════════════".purple());
        println!("{}", text.bold().cyan());
        println!("{}", "══════════════════════════════════════════════════════════".purple());
    }
    
    /// Print step - Equivalent to print_step()
    pub fn print_step(step: u8, text: &str) {
        println!("\n{} {}", "┌─".blue(), format!("STEP {}", step).bold().cyan());
        println!("{}", "│".blue());
        println!("  {} {}", "ℹ".cyan().bold(), text.cyan());
    }
    
    /// Print step end - Equivalent to print_step_end()
    pub fn print_step_end() {
        println!("{} {}", "└─".blue(), "✓ Completed".green());
    }
    
    /// Print box - Equivalent to print_box()
    pub fn print_box(content: &str, color: Color) {
        let color_code = match color {
            Color::Red => "31",
            Color::Green => "32",
            Color::Yellow => "33",
            Color::Blue => "34",
            Color::Purple => "35",
            Color::Cyan => "36",
            Color::White => "37",
        };
        
        println!("\x1B[{}m{}\x1B[0m", color_code, content);
    }
    
    /// Print success - Equivalent to print_success()
    pub fn print_success(text: &str) {
        println!("  {} {}", "✓".green().bold(), text.green());
    }
    
    /// Print error - Equivalent to print_error()
    pub fn print_error(text: &str) {
        eprintln!("  {} {}", "✗".red().bold(), text.red());
    }
    
    /// Print warning - Equivalent to print_warning()
    pub fn print_warning(text: &str) {
        println!("  {} {}", "!".yellow().bold(), text.yellow());
    }
    
    /// Print info - Equivalent to print_info()
    pub fn print_info(text: &str) {
        println!("  {} {}", "ℹ".cyan().bold(), text.cyan());
    }
    
    /// Print success box - For final message
    pub fn print_success_box(content: &str) {
        println!("\n{}", content.green().bold());
    }
    
    /// Show progress - Equivalent to show_progress()
    pub fn show_progress<F, T>(task: F, message: &str) -> T
    where
        F: FnOnce() -> T,
    {
        let spinner = Spinner::new(message);
        let result = task();
        spinner.complete("Done");
        result
    }
}

/// Spinner for progress - Equivalent to show_progress()
pub struct Spinner {
    pb: ProgressBar,
    message: String,
}

impl Spinner {
    pub fn new(message: &str) -> Self {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));
        
        Self {
            pb,
            message: message.to_string(),
        }
    }
    
    pub fn complete(self, message: &str) {
        self.pb.finish_with_message(message.to_string());
    }
    
    pub fn warn(self, message: &str) {
        self.pb.finish_with_message(message.yellow().to_string());
    }
    
    pub fn error(self, message: &str) {
        self.pb.finish_with_message(message.red().to_string());
    }
}

/// Banner display
pub struct Banner;

impl Banner {
    pub fn display() {
        Terminal::print_banner();
    }
}
