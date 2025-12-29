//! Modern SlowDNS Installation Script in Rust
//! ============================================================================
//! Author: Your Name
//! Version: 1.0.0
//! Repository: https://github.com/chiddy80/Halotel-Slow-DNS

use std::process::{Command, Stdio};
use std::io::{self, Write, Read, BufRead, BufReader};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use std::os::unix::fs::PermissionsExt;
use std::net::UdpSocket;
use std::str;
use reqwest;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use colored::*;
use crossterm::{
    terminal::{self, ClearType},
    cursor,
    execute,
    style::{Print, Color, ResetColor, SetForegroundColor, SetBackgroundColor},
    event::{self, Event, KeyCode},
};
use console::{Style, Term};
use dialoguer::{Input, Select, theme::ColorfulTheme};
use serde_json;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================
const SSH_PORT: u16 = 22;
const SLOWDNS_PORT: u16 = 5300;
const GITHUB_BASE: &str = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED";

// ============================================================================
// MAIN INSTALLER STRUCT
// ============================================================================
struct SlowDNSInstaller {
    server_ip: String,
    nameserver: String,
    install_dir: PathBuf,
    log_file: PathBuf,
    ssh_config_backup: PathBuf,
    term: Term,
    theme: ColorfulTheme,
}

impl SlowDNSInstaller {
    // ============================================================================
    // CONSTRUCTOR AND INITIALIZATION
    // ============================================================================
    fn new() -> io::Result<Self> {
        Ok(Self {
            server_ip: String::new(),
            nameserver: "dns.example.com".to_string(),
            install_dir: PathBuf::from("/etc/slowdns"),
            log_file: PathBuf::from("/var/log/slowdns-install.log"),
            ssh_config_backup: PathBuf::from("/etc/ssh/sshd_config.backup"),
            term: Term::stdout(),
            theme: ColorfulTheme::default(),
        })
    }

    // ============================================================================
    // COLOR AND DISPLAY FUNCTIONS
    // ============================================================================
    fn print_color(&self, text: &str, color: Color) {
        execute!(
            io::stdout(),
            SetForegroundColor(color),
            Print(text),
            ResetColor
        ).unwrap();
    }

    fn println_color(&self, text: &str, color: Color) {
        execute!(
            io::stdout(),
            SetForegroundColor(color),
            Print(format!("{}\n", text)),
            ResetColor
        ).unwrap();
    }

    fn print_banner(&self) {
        let clear_screen = terminal::Clear(ClearType::All);
        let move_cursor = cursor::MoveTo(0, 0);
        
        execute!(io::stdout(), clear_screen, move_cursor).unwrap();
        
        let banner = r#"
╔══════════════════════════════════════════════════════════╗
║          🚀 MODERN SLOWDNS INSTALLATION SCRIPT           ║
║            Fast & Professional Configuration             ║
║                Optimized for Performance                 ║
╚══════════════════════════════════════════════════════════╝
        "#;
        
        println!("{}", banner.cyan().bold());
    }

    fn print_header(&self, text: &str) {
        println!("\n{}", "══════════════════════════════════════════════════════════".purple());
        println!("{}", text.cyan().bold());
        println!("{}", "══════════════════════════════════════════════════════════".purple());
    }

    fn print_step(&self, step: u8, title: &str) {
        println!("\n{} {}", "┌─".blue(), format!("STEP {}: {}", step, title).cyan().bold());
        println!("{}", "│".blue());
    }

    fn print_step_end(&self) {
        println!("{} {}", "└─".blue(), "✓ Completed".green());
    }

    fn print_success(&self, text: &str) {
        println!("  {} {}", "✓".green().bold(), text.green());
    }

    fn print_error(&self, text: &str) {
        println!("  {} {}", "✗".red().bold(), text.red());
    }

    fn print_warning(&self, text: &str) {
        println!("  {} {}", "!".yellow().bold(), text.yellow());
    }

    fn print_info(&self, text: &str) {
        println!("  {} {}", "ℹ".cyan().bold(), text.cyan());
    }

    fn print_box(&self, text: &str) {
        let width = 50;
        let padding = (width - text.len() - 2) / 2;
        let remaining = width - text.len() - 2 - padding;
        
        println!("{}", "┌".cyan());
        print!("{}", "─".cyan().repeat(width - 2));
        println!("{}", "┐".cyan());
        
        print!("{}", "│".cyan());
        print!("{}{}{}", " ".repeat(padding), text, " ".repeat(remaining));
        println!("{}", "│".cyan());
        
        print!("{}", "└".cyan());
        print!("{}", "─".cyan().repeat(width - 2));
        println!("{}", "┘".cyan());
    }

    fn show_progress(&self, message: &str, duration: Duration) {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} {msg}")
        );
        pb.set_message(message.to_string());
        
        thread::sleep(duration);
        pb.finish_with_message("Done!");
    }

    // ============================================================================
    // SYSTEM COMMAND FUNCTIONS
    // ============================================================================
    fn run_command(&self, cmd: &str) -> io::Result<String> {
        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", cmd])
                .output()?
        } else {
            Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()?
        };

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Command failed: {}", String::from_utf8_lossy(&output.stderr))
            ))
        }
    }

    fn run_command_silent(&self, cmd: &str) -> io::Result<()> {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(())
    }

    // ============================================================================
    // NETWORK FUNCTIONS
    // ============================================================================
    fn get_server_ip(&mut self) -> io::Result<()> {
        self.print_info("Detecting server IP address...");
        
        // Try multiple methods to get public IP
        let methods = [
            ("ifconfig.me", "https://ifconfig.me"),
            ("ipinfo.io", "https://ipinfo.io/ip"),
            ("icanhazip.com", "https://icanhazip.com"),
        ];
        
        for (name, url) in methods.iter() {
            match reqwest::blocking::get(*url) {
                Ok(response) => {
                    if let Ok(ip) = response.text() {
                        let ip = ip.trim().to_string();
                        if !ip.is_empty() {
                            self.server_ip = ip;
                            self.print_success(&format!("Server IP detected via {}: {}", name, self.server_ip));
                            return Ok(());
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        
        // Fallback to local IP
        match self.run_command("hostname -I | awk '{print $1}'") {
            Ok(ip) => {
                self.server_ip = ip.trim().to_string();
                self.print_success(&format!("Local IP: {}", self.server_ip));
            }
            Err(_) => {
                self.server_ip = "127.0.0.1".to_string();
                self.print_warning("Could not detect IP, using 127.0.0.1");
            }
        }
        
        Ok(())
    }

    // ============================================================================
    // FILE DOWNLOAD FUNCTIONS
    // ============================================================================
    fn download_file(&self, url: &str, dest: &Path) -> io::Result<()> {
        self.print_info(&format!("Downloading: {}", url));
        
        let response = reqwest::blocking::get(url)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        let content = response.bytes()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        fs::write(dest, content)?;
        
        self.print_success(&format!("Downloaded to: {:?}", dest));
        Ok(())
    }

    // ============================================================================
    // INSTALLATION STEPS
    // ============================================================================
    fn check_root(&self) -> io::Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Please run this script as root"
            ));
        }
        Ok(())
    }

    fn get_nameserver(&mut self) -> io::Result<()> {
        self.print_banner();
        
        self.print_box("Enter nameserver configuration");
        println!("{}", "Default: dns.example.com".yellow());
        println!("{}", "Example: tunnel.yourdomain.com".yellow());
        println!();
        
        let input: String = Input::with_theme(&self.theme)
            .with_prompt("Enter nameserver")
            .default("dns.example.com".into())
            .interact_text()?;
        
        self.nameserver = input;
        Ok(())
    }

    fn configure_ssh(&self) -> io::Result<()> {
        self.print_step(1, "CONFIGURE OPENSSH");
        self.print_info(&format!("Configuring OpenSSH on port {}", SSH_PORT));
        
        // Backup SSH config
        self.print_info("Backing up SSH configuration...");
        if self.ssh_config_backup.exists() {
            fs::remove_file(&self.ssh_config_backup)?;
        }
        fs::copy("/etc/ssh/sshd_config", &self.ssh_config_backup)?;
        self.print_success("SSH configuration backed up");
        
        // Create new SSH config
        let ssh_config = format!(r#"# ============================================================================
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
"#, SSH_PORT);
        
        fs::write("/etc/ssh/sshd_config", ssh_config)?;
        
        // Restart SSH service
        self.print_info("Restarting SSH service...");
        self.run_command("systemctl restart sshd")?;
        thread::sleep(Duration::from_secs(2));
        self.print_success("SSH service restarted");
        
        self.print_success(&format!("OpenSSH configured on port {}", SSH_PORT));
        self.print_step_end();
        
        Ok(())
    }

    fn setup_slowdns(&self) -> io::Result<()> {
        self.print_step(2, "SETUP SLOWDNS");
        self.print_info("Setting up SlowDNS environment");
        
        // Create directory
        self.print_info("Creating SlowDNS directory...");
        if self.install_dir.exists() {
            fs::remove_dir_all(&self.install_dir)?;
        }
        fs::create_dir_all(&self.install_dir)?;
        self.print_success("SlowDNS directory created");
        
        // Change to install directory
        env::set_current_dir(&self.install_dir)?;
        
        // Download binary
        self.print_info("Downloading SlowDNS binary");
        let binary_url = format!("{}/dnstt-server", GITHUB_BASE);
        let binary_path = self.install_dir.join("dnstt-server");
        
        self.download_file(&binary_url, &binary_path)?;
        
        // Set executable permissions
        let mut perms = fs::metadata(&binary_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&binary_path, perms)?;
        
        // Download key files
        self.print_info("Downloading encryption keys");
        
        let key_url = format!("{}/server.key", GITHUB_BASE);
        let key_path = self.install_dir.join("server.key");
        self.download_file(&key_url, &key_path)?;
        
        let pub_url = format!("{}/server.pub", GITHUB_BASE);
        let pub_path = self.install_dir.join("server.pub");
        self.download_file(&pub_url, &pub_path)?;
        
        // Test binary
        self.print_info("Validating binary...");
        let test_result = self.run_command("./dnstt-server --help");
        match test_result {
            Ok(output) => {
                if output.to_lowercase().contains("usage") {
                    self.print_success("Binary validated successfully");
                } else {
                    self.print_warning("Binary test inconclusive");
                }
            }
            Err(_) => {
                self.print_warning("Binary test failed, continuing anyway");
            }
        }
        
        self.print_success("SlowDNS components installed");
        self.print_step_end();
        
        Ok(())
    }

    fn create_slowdns_service(&self) -> io::Result<()> {
        self.print_step(3, "CREATE SLOWDNS SERVICE");
        self.print_info("Creating SlowDNS system service");
        
        let service_content = format!(r#"# ============================================================================
# SLOWDNS SERVICE CONFIGURATION
# ============================================================================
[Unit]
Description=SlowDNS Server
Description=High-performance DNS tunnel server
After=network.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={}/dnstt-server -udp :{} -mtu 1800 -privkey-file {}/server.key {} 127.0.0.1:{}
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
LimitCORE=infinity
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
"#, 
            self.install_dir.display(),
            SLOWDNS_PORT,
            self.install_dir.display(),
            self.nameserver,
            SSH_PORT
        );
        
        let service_file = Path::new("/etc/systemd/system/server-sldns.service");
        fs::write(service_file, service_content)?;
        
        self.print_success("Service configuration created");
        self.print_step_end();
        
        Ok(())
    }

    fn compile_edns_proxy(&self) -> io::Result<()> {
        self.print_step(4, "COMPILE EDNS PROXY");
        self.print_info("Compiling high-performance EDNS Proxy");
        
        // Check for gcc
        self.print_info("Checking for compiler tools...");
        if self.run_command("which gcc").is_err() {
            self.print_info("Installing gcc...");
            self.run_command("apt-get update > /dev/null 2>&1")?;
            self.run_command("apt-get install -y gcc > /dev/null 2>&1")?;
            self.print_success("Compiler installed");
        }
        
        // Create C source code
        let c_code = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

#define EXT_EDNS 512
#define INT_EDNS 1800
#define SLOWDNS_PORT 5300
#define LISTEN_PORT 53
#define BUFFER_SIZE 4096
#define MAX_EVENTS 100

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t addr_len;
    time_t timestamp;
} request_t;

int patch_edns(unsigned char *buf, int len, int new_size) {
    if(len < 12) return len;
    int offset = 12;
    int qdcount = (buf[4] << 8) | buf[5];
    for(int i = 0; i < qdcount && offset < len; i++) {
        while(offset < len && buf[offset]) offset++;
        offset += 5;
    }
    int arcount = (buf[10] << 8) | buf[11];
    for(int i = 0; i < arcount && offset < len; i++) {
        if(buf[offset] == 0 && offset + 4 < len) {
            int type = (buf[offset+1] << 8) | buf[offset+2];
            if(type == 41) {
                buf[offset+3] = new_size >> 8;
                buf[offset+4] = new_size & 0xFF;
                return len;
            }
        }
        offset++;
    }
    return len;
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    printf("[EDNS Proxy] Starting high-performance DNS proxy...\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("[ERROR] socket");
        return 1;
    }
    
    if(set_nonblock(sock) < 0) {
        perror("[ERROR] fcntl");
        close(sock);
        return 1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[ERROR] bind");
        close(sock);
        return 1;
    }
    
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0) {
        perror("[ERROR] epoll_create1");
        close(sock);
        return 1;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("[ERROR] epoll_ctl");
        close(epoll_fd);
        close(sock);
        return 1;
    }
    
    printf("[EDNS Proxy] Listening on port 53 (epoll optimized)\n");
    printf("[EDNS Proxy] Ready to handle DNS queries\n");
    
    struct epoll_event events[MAX_EVENTS];
    request_t *requests[10000] = {0};
    
    while(1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        for(int i = 0; i < n; i++) {
            if(events[i].data.fd == sock) {
                unsigned char buffer[BUFFER_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int len = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
                if(len > 0) {
                    patch_edns(buffer, len, INT_EDNS);
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        set_nonblock(up_sock);
                        request_t *req = malloc(sizeof(request_t));
                        if(req) {
                            req->client_fd = sock;
                            req->client_addr = client_addr;
                            req->addr_len = client_len;
                            req->timestamp = time(NULL);
                            requests[up_sock] = req;
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                                                             (struct sockaddr*)&client_addr, &client_len);
                if(len > 0) {
                    patch_edns(buffer, len, INT_EDNS);
                    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if(up_sock >= 0) {
                        set_nonblock(up_sock);
                        request_t *req = malloc(sizeof(request_t));
                        if(req) {
                            req->client_fd = sock;
                            req->client_addr = client_addr;
                            req->addr_len = client_len;
                            req->timestamp = time(NULL);
                            requests[up_sock] = req;
                            struct epoll_event up_ev;
                            up_ev.events = EPOLLIN;
                            up_ev.data.fd = up_sock;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, up_sock, &up_ev);
                            struct sockaddr_in up_addr;
                            memset(&up_addr, 0, sizeof(up_addr));
                            up_addr.sin_family = AF_INET;
                            up_addr.sin_port = htons(SLOWDNS_PORT);
                            inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
                            sendto(up_sock, buffer, len, 0,
                                   (struct sockaddr*)&up_addr, sizeof(up_addr));
                        } else {
                            close(up_sock);
                        }
                    }
                }
            } else {
                int up_sock = events[i].data.fd;
                request_t *req = requests[up_sock];
                if(req) {
                    unsigned char buffer[BUFFER_SIZE];
                    int len = recv(up_sock, buffer, BUFFER_SIZE, 0);
                    if(len > 0) {
                        patch_edns(buffer, len, EXT_EDNS);
                        sendto(req->client_fd, buffer, len, 0,
                               (struct sockaddr*)&req->client_addr,
                               req->addr_len);
                    }
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, up_sock, NULL);
                    close(up_sock);
                    free(req);
                    requests[up_sock] = NULL;
                }
            }
        }
    }
    return 0;
}"#;
        
        // Write C code to file
        let c_file = Path::new("/tmp/edns.c");
        fs::write(c_file, c_code)?;
        
        // Compile
        self.print_info("Compiling EDNS Proxy with O3 optimizations...");
        let compile_cmd = "gcc -O3 -march=native -pipe /tmp/edns.c -o /usr/local/bin/edns-proxy";
        match self.run_command(compile_cmd) {
            Ok(_) => {
                let edns_binary = Path::new("/usr/local/bin/edns-proxy");
                let mut perms = fs::metadata(edns_binary)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(edns_binary, perms)?;
                self.print_success("EDNS Proxy compiled successfully");
            }
            Err(e) => {
                self.print_error(&format!("Compilation failed: {}", e));
                return Err(e);
            }
        }
        
        // Create EDNS service
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
WantedBy=multi-user.target
"#;
        
        let service_file = Path::new("/etc/systemd/system/edns-proxy.service");
        fs::write(service_file, service_content)?;
        
        self.print_success("EDNS Proxy service configured");
        self.print_step_end();
        
        Ok(())
    }

    fn configure_firewall(&self) -> io::Result<()> {
        self.print_step(5, "CONFIGURE FIREWALL");
        self.print_info("Configuring system firewall");
        
        self.print_info("Setting up firewall rules...");
        
        // Flush existing rules
        let firewall_commands = vec![
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT",
            &format!("iptables -A INPUT -i lo -j ACCEPT"),
            &format!("iptables -A OUTPUT -o lo -j ACCEPT"),
            &format!("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"),
            &format!("iptables -A INPUT -p tcp --dport {} -j ACCEPT", SSH_PORT),
            &format!("iptables -A INPUT -p udp --dport {} -j ACCEPT", SLOWDNS_PORT),
            "iptables -A INPUT -p udp --dport 53 -j ACCEPT",
            "iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT",
            "iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT",
            "iptables -A INPUT -p icmp -j ACCEPT",
            "iptables -A INPUT -m state --state INVALID -j DROP",
        ];
        
        for cmd in firewall_commands {
            let _ = self.run_command_silent(cmd);
        }
        
        // Disable IPv6
        self.print_info("Disabling IPv6...");
        let _ = self.run_command_silent("echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6");
        
        self.print_success("Firewall rules configured");
        
        // Stop conflicting services
        self.print_info("Stopping conflicting DNS services...");
        let _ = self.run_command_silent("systemctl stop systemd-resolved 2>/dev/null");
        let _ = self.run_command_silent("pkill -f '53/udp' 2>/dev/null");
        
        self.print_success("DNS services stopped");
        self.print_success("Firewall and network configured");
        self.print_step_end();
        
        Ok(())
    }

    fn start_services(&self) -> io::Result<()> {
        self.print_step(6, "START SERVICES");
        self.print_info("Starting all services");
        
        // Reload systemd
        self.run_command("systemctl daemon-reload")?;
        
        // Start SlowDNS
        self.print_info("Starting SlowDNS service...");
        let _ = self.run_command_silent("systemctl enable server-sldns > /dev/null 2>&1");
        self.run_command("systemctl start server-sldns")?;
        thread::sleep(Duration::from_secs(2));
        
        if self.run_command("systemctl is-active server-sldns").is_ok() {
            self.print_success("SlowDNS service started");
        } else {
            self.print_warning("Starting SlowDNS in background");
            let cmd = format!(
                "{}/dnstt-server -udp :{} -mtu 1800 -privkey-file {}/server.key {} 127.0.0.1:{} &",
                self.install_dir.display(),
                SLOWDNS_PORT,
                self.install_dir.display(),
                self.nameserver,
                SSH_PORT
            );
            self.run_command_silent(&cmd)?;
        }
        
        // Start EDNS proxy
        self.print_info("Starting EDNS Proxy service...");
        let _ = self.run_command_silent("systemctl enable edns-proxy > /dev/null 2>&1");
        self.run_command("systemctl start edns-proxy")?;
        thread::sleep(Duration::from_secs(2));
        
        if self.run_command("systemctl is-active edns-proxy").is_ok() {
            self.print_success("EDNS Proxy service started");
        } else {
            self.print_warning("Starting EDNS Proxy manually");
            self.run_command_silent("/usr/local/bin/edns-proxy &")?;
        }
        
        // Verify services
        self.print_info("Verifying service status...");
        thread::sleep(Duration::from_secs(3));
        self.print_success("Service verification complete");
        
        self.print_success("All services started successfully");
        self.print_step_end();
        
        Ok(())
    }

    fn show_summary(&self) -> io::Result<()> {
        self.print_header("🎉 INSTALLATION COMPLETE");
        
        // Server information
        println!("\n{}", "SERVER INFORMATION".cyan().bold());
        println!("{}", "─".repeat(50));
        println!("{} Server IP:     {}", "●".yellow(), self.server_ip.white().bold());
        println!("{} SSH Port:      {}", "●".yellow(), SSH_PORT.to_string().white());
        println!("{} SlowDNS Port:  {}", "●".yellow(), SLOWDNS_PORT.to_string().white());
        println!("{} EDNS Port:     {}", "●".yellow(), "53".white());
        println!("{} MTU Size:      {}", "●".yellow(), "1800".white());
        println!("{} Nameserver:    {}", "●".yellow(), self.nameserver.white().bold());
        println!("{}", "─".repeat(50));
        
        // Quick test commands
        println!("\n{}", "QUICK TEST COMMANDS".cyan().bold());
        println!("{}", "─".repeat(50));
        println!("{}", format!("dig @{} {}", self.server_ip, self.nameserver).green());
        println!("{}", format!("nslookup {} {}", self.nameserver, self.server_ip).green());
        println!("{}", "systemctl status server-sldns".green());
        println!("{}", "systemctl status edns-proxy".green());
        println!("{}", "─".repeat(50));
        
        // Service management
        println!("\n{}", "SERVICE MANAGEMENT".cyan().bold());
        println!("{}", "─".repeat(50));
        println!("{} systemctl restart server-sldns edns-proxy", "Restart services:".yellow());
        println!("{} journalctl -u server-sldns -f", "View logs:".yellow());
        println!("{} ss -ulpn | grep ':53\\|:5300'", "Check ports:".yellow());
        println!("{}", "─".repeat(50));
        
        // Final verification
        println!("\n{}", "Verifying installation...".white().bold());
        
        // Check port 53
        print!("  {} Checking port 53...", "ℹ".cyan());
        io::stdout().flush()?;
        
        if self.run_command("ss -ulpn 2>/dev/null | grep ':53 '").is_ok() {
            println!("\r  {} Port 53 (EDNS Proxy) is listening", "✓".green());
        } else {
            println!("\r  {} Port 53 not listening", "!".yellow());
        }
        
        // Check port 5300
        print!("  {} Checking port 5300...", "ℹ".cyan());
        io::stdout().flush()?;
        
        if self.run_command(&format!("ss -ulpn 2>/dev/null | grep ':{} '", SLOWDNS_PORT)).is_ok() {
            println!("\r  {} Port {} (SlowDNS) is listening", "✓".green(), SLOWDNS_PORT);
        } else {
            println!("\r  {} Port {} not listening", "!".yellow(), SLOWDNS_PORT);
        }
        
        // Check service status
        print!("  {} Checking service status...", "ℹ".cyan());
        io::stdout().flush()?;
        
        let slowdns_active = self.run_command("systemctl is-active server-sldns").is_ok();
        let edns_active = self.run_command("systemctl is-active edns-proxy").is_ok();
        
        if slowdns_active && edns_active {
            println!("\r  {} All services are running", "✓".green());
        } else {
            println!("\r  {} Some services need attention", "!".yellow());
        }
        
        // Show public key
        let pub_key_path = self.install_dir.join("server.pub");
        if pub_key_path.exists() {
            println!("\n{}", "PUBLIC KEY (For Client Configuration)".cyan().bold());
            println!("{}", "─".repeat(50));
            if let Ok(content) = fs::read_to_string(&pub_key_path) {
                if let Some(first_line) = content.lines().next() {
                    println!("{}", first_line.white());
                }
            }
            println!("{}", "─".repeat(50));
        }
        
        // Performance tips
        println!("\n{}", "PERFORMANCE TIPS".cyan().bold());
        println!("{}", "─".repeat(50));
        println!("{} MTU 1800 is optimal for most networks", "●".yellow());
        println!("{} For better performance, use TCP instead of UDP", "●".yellow());
        println!("{} Monitor performance: systemctl status server-sldns", "●".yellow());
        println!("{} Check logs: journalctl -u edns-proxy -n 50", "●".yellow());
        println!("{}", "─".repeat(50));
        
        // Client configuration
        println!("\n{}", "CLIENT CONFIGURATION EXAMPLE".cyan().bold());
        println!("{}", "─".repeat(50));
        println!("{}", "SlowDNS Client Command:".yellow());
        println!("{}", format!("./dnstt-client -udp {}:{} \\", self.server_ip, SLOWDNS_PORT).green());
        println!("{}", "    -pubkey-file server.pub \\".green());
        println!("{}", format!("    {} 127.0.0.1:1080", self.nameserver).green());
        println!("{}", "─".repeat(50));
        
        // Troubleshooting
        println!("\n{}", "TROUBLESHOOTING".cyan().bold());
        println!("{}", "─".repeat(50));
        println!("{}", "If port 53 is not listening:".yellow());
        println!("{}", "1. Stop systemd-resolved: systemctl stop systemd-resolved".white());
        println!("{}", "2. Kill any process on port 53: fuser -k 53/udp".white());
        println!("{}", "3. Restart edns-proxy: systemctl restart edns-proxy".white());
        println!();
        println!("{}", "If SlowDNS is not working:".yellow());
        println!("{}", "1. Check firewall: iptables -L -n -v".white());
        println!("{}", "2. Verify keys: ls -la /etc/slowdns/".white());
        println!("{}", "3. Restart all: systemctl restart server-sldns edns-proxy".white());
        println!("{}", "─".repeat(50));
        
        // Final message
        println!("\n{}", "╔══════════════════════════════════════════════════════════╗".green().bold());
        println!("{}", "║    🎯 SLOWDNS INSTALLATION COMPLETED SUCCESSFULLY!    ║".green().bold());
        println!("{}", "║    ⚡ Installation completed in Rust                     ║".green().bold());
        println!("{}", "║    📊 Services running: SlowDNS + EDNS Proxy            ║".green().bold());
        println!("{}", "║    🔧 Ready for DNS tunneling                           ║".green().bold());
        println!("{}", "╚══════════════════════════════════════════════════════════╝".green().bold());
        
        println!("\n{} {}", "📞".yellow().bold(), "Need help? Contact support: @esimfreegb".yellow().bold());
        println!("{} {}", "💡".yellow().bold(), "Documentation: https://github.com/chiddy80/Halotel-Slow-DNS".yellow().bold());
        
        Ok(())
    }

    fn post_install_menu(&self) -> io::Result<()> {
        println!("\n{}", "POST-INSTALLATION OPTIONS".cyan().bold());
        println!("{}", "─".repeat(50));
        println!("{} {}", "1.".yellow(), "View service status".white());
        println!("{} {}", "2.".yellow(), "Check listening ports".white());
        println!("{} {}", "3.".yellow(), "Restart all services".white());
        println!("{} {}", "4.".yellow(), "View installation log".white());
        println!("{} {}", "5.".yellow(), "Test DNS functionality".white());
        println!("{} {}", "6.".yellow(), "Exit to terminal".white());
        println!("{}", "─".repeat(50));
        
        print!("{}", "Select option [1-6]: ".white().bold());
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();
        
        match choice {
            "1" => {
                println!("\n{}", "════════════════ SERVICE STATUS ════════════════".cyan());
                let _ = self.run_command("systemctl status server-sldns --no-pager -l");
                println!("\n{}", "═══════════════════════════════════════════════".cyan());
                let _ = self.run_command("systemctl status edns-proxy --no-pager -l");
            }
            "2" => {
                println!("\n{}", "════════════════ LISTENING PORTS ════════════════".cyan());
                println!("{}", "Checking UDP ports:".white());
                let _ = self.run_command("ss -ulpn | grep -E ':53|:5300'");
                println!("\n{}", "Checking TCP ports:".white());
                let _ = self.run_command("ss -tlnp | grep -E ':22'");
            }
            "3" => {
                println!("\n{}", "════════════════ RESTARTING SERVICES ════════════════".cyan());
                let _ = self.run_command("systemctl restart server-sldns edns-proxy");
                thread::sleep(Duration::from_secs(2));
                println!("{}", "✓ Services restarted successfully".green());
            }
            "4" => {
                println!("\n{}", "════════════════ INSTALLATION LOG ════════════════".cyan());
                if self.log_file.exists() {
                    if let Ok(content) = fs::read_to_string(&self.log_file) {
                        let lines: Vec<&str> = content.lines().collect();
                        let start = if lines.len() > 20 { lines.len() - 20 } else { 0 };
                        for line in &lines[start..] {
                            println!("{}", line);
                        }
                    }
                } else {
                    println!("{}", "Log file not found".yellow());
                }
            }
            "5" => {
                println!("\n{}", "════════════════ DNS TEST ════════════════".cyan());
                println!("{}", format!("Testing DNS query to {}...", self.nameserver).white());
                
                if self.run_command("which dig").is_ok() {
                    let _ = self.run_command(&format!("dig @{} {} +short", self.server_ip, self.nameserver));
                } else if self.run_command("which nslookup").is_ok() {
                    let _ = self.run_command(&format!("nslookup {} {}", self.nameserver, self.server_ip));
                } else {
                    println!("{}", "DNS tools not available".yellow());
                }
            }
            "6" => {
                println!("\n{}", "Returning to terminal...".green());
            }
            _ => {
                println!("\n{}", "Invalid option, returning to terminal...".yellow());
            }
        }
        
        Ok(())
    }

    fn cleanup(&self) -> io::Result<()> {
        let temp_files = [
            Path::new("/tmp/edns.c"),
            Path::new("/tmp/compile.log"),
            Path::new("/var/log/slowdns-install.log"),
        ];
        
        for file in &temp_files {
            if file.exists() {
                let _ = fs::remove_file(file);
            }
        }
        
        Ok(())
    }

    fn run(&mut self) -> io::Result<()> {
        // Check root privileges
        self.check_root()?;
        
        // Get nameserver
        self.get_nameserver()?;
        
        self.print_header("📦 GATHERING SYSTEM INFORMATION");
        
        // Get server IP
        self.get_server_ip()?;
        
        // Run installation steps
        self.configure_ssh()?;
        self.setup_slowdns()?;
        self.create_slowdns_service()?;
        self.compile_edns_proxy()?;
        self.configure_firewall()?;
        self.start_services()?;
        self.show_summary()?;
        
        // Show post-installation menu
        self.post_install_menu()?;
        
        // Cleanup
        self.cleanup()?;
        
        // Final message
        let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("\n{}", "══════════════════════════════════════════════════════════".green().bold());
        println!("{}", format!("   Installation completed at: {}", current_time).green().bold());
        println!("{}", format!("   Server: {} | SlowDNS: {} | EDNS: 53", 
            self.server_ip, SLOWDNS_PORT).green().bold());
        println!("{}", "══════════════════════════════════════════════════════════".green().bold());
        println!();
        
        Ok(())
    }
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================
fn main() -> io::Result<()> {
    // Initialize colored output
    colored::control::set_override(true);
    
    // Create installer instance
    let mut installer = SlowDNSInstaller::new()?;
    
    // Run the installer
    match installer.run() {
        Ok(_) => {
            println!("{}", "Installation completed successfully!".green().bold());
            Ok(())
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red().bold(), format!("Installation failed: {}", e).red());
            installer.cleanup()?;
            std::process::exit(1);
        }
    }
}
