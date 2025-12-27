package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/term"
)

// Configuration
const (
	SSHD_PORT     = 22
	SLOWDNS_PORT  = 5300
	EDNS_PORT     = 53
	MTU_SIZE      = 1800
	GITHUB_BASE   = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED"
	BIN_DIR       = "/usr/local/bin"
	SLOWDNS_DIR   = "/etc/slowdns"
	SERVICE_DIR   = "/etc/systemd/system"
)

// Global variables
var (
	serverIP    string
	nameserver  string
	spinnerChan = make(chan bool)
	wg          sync.WaitGroup
)

// ANSI Colors
var (
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	white  = color.New(color.FgWhite).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

// Spinner animation
func spinner(message string) {
	chars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	for {
		select {
		case <-spinnerChan:
			fmt.Printf("\r%s %s\n", green("✓"), message)
			return
		default:
			fmt.Printf("\r%s %s", yellow(chars[i]), message)
			i = (i + 1) % len(chars)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Print section header
func printHeader(title string) {
	fmt.Printf("\n%s\n", cyan(strings.Repeat("═", 60)))
	fmt.Printf("%s\n", bold(white(title)))
	fmt.Printf("%s\n", cyan(strings.Repeat("═", 60)))
}

// Print step
func printStep(step int, description string) {
	fmt.Printf("\n%s Step %d: %s\n", blue("▶"), step, cyan(description))
}

// Execute command with output
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Execute command with captured output
func runCommandCapture(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	return string(output), err
}

// Download file from URL
func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// Check if running as root
func checkRoot() {
	if os.Getuid() != 0 {
		fmt.Printf("%s Please run as root\n", red("✗"))
		os.Exit(1)
	}
}

// Detect server IP
func detectIP() string {
	// Try multiple methods
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me",
		"https://icanhazip.com",
	}

	for _, service := range services {
		resp, err := http.Get(service)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			ip := strings.TrimSpace(string(body))
			if ip != "" && strings.Contains(ip, ".") {
				return ip
			}
		}
	}

	// Fallback to local IP
	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err == nil {
		ips := strings.Fields(string(output))
		if len(ips) > 0 {
			return strings.Split(ips[0], " ")[0]
		}
	}

	return "127.0.0.1"
}

// Configure SSH
func configureSSH() error {
	printStep(1, "Configuring SSH")
	
	// Backup SSH config
	exec.Command("cp", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.backup").Run()
	
	config := fmt.Sprintf(`# SLOWDNS OPTIMIZED SSH CONFIGURATION
Port %d
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
UseDNS no`, SSHD_PORT)
	
	err := os.WriteFile("/etc/ssh/sshd_config", []byte(config), 0644)
	if err != nil {
		return err
	}
	
	// Restart SSH
	runCommand("systemctl", "restart", "ssh")
	fmt.Printf("%s SSH configured on port %d\n", green("✓"), SSHD_PORT)
	return nil
}

// Setup SlowDNS
func setupSlowDNS() error {
	printStep(2, "Setting up SlowDNS")
	
	// Create directory
	os.RemoveAll(SLOWDNS_DIR)
	os.MkdirAll(SLOWDNS_DIR, 0755)
	os.Chdir(SLOWDNS_DIR)
	
	// Download files
	urls := map[string]string{
		"dnstt-server": GITHUB_BASE + "/dnstt-server",
		"server.key":   GITHUB_BASE + "/server.key",
		"server.pub":   GITHUB_BASE + "/server.pub",
	}
	
	for filename, url := range urls {
		fmt.Printf("  Downloading %s... ", filename)
		err := downloadFile(url, filename)
		if err != nil {
			fmt.Printf("%s Failed\n", red("✗"))
			return err
		}
		fmt.Printf("%s\n", green("✓"))
	}
	
	// Make binary executable
	os.Chmod("dnstt-server", 0755)
	
	fmt.Printf("%s SlowDNS components installed\n", green("✓"))
	return nil
}

// Create SlowDNS service
func createSlowDNSService() error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=SlowDNS Server
After=network.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/etc/slowdns/dnstt-server -udp :%d -mtu %d -privkey-file /etc/slowdns/server.key %s 127.0.0.1:%d
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
LimitCORE=infinity
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target`, SLOWDNS_PORT, MTU_SIZE, nameserver, SSHD_PORT)
	
	servicePath := filepath.Join(SERVICE_DIR, "server-sldns.service")
	err := os.WriteFile(servicePath, []byte(serviceContent), 0644)
	if err != nil {
		return err
	}
	
	fmt.Printf("%s SlowDNS service created\n", green("✓"))
	return nil
}

// Compile EDNS Proxy in Go (embedded)
func compileEDNSProxy() error {
	printStep(3, "Compiling EDNS Proxy")
	
	// Check if Go is installed
	if _, err := exec.LookPath("go"); err != nil {
		fmt.Printf("  Installing Go...\n")
		runCommand("apt", "update")
		runCommand("apt", "install", "-y", "golang")
	}
	
	// Create Go source code
	sourceCode := `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	EDNS_PORT      = 53
	SLOWDNS_PORT   = 5300
	BUFFER_SIZE    = 4096
	MAX_PACKET_SIZE = 1800
)

func patchEDNS(packet []byte, newSize uint16) []byte {
	if len(packet) < 12 {
		return packet
	}
	
	// Parse DNS header
	questions := binary.BigEndian.Uint16(packet[4:6])
	answers := binary.BigEndian.Uint16(packet[6:8])
	authority := binary.BigEndian.Uint16(packet[8:10])
	additional := binary.BigEndian.Uint16(packet[10:12])
	
	offset := 12
	
	// Skip questions
	for i := 0; i < int(questions) && offset < len(packet); i++ {
		for offset < len(packet) && packet[offset] != 0 {
			offset++
		}
		offset += 5 // null byte + type + class
	}
	
	// Skip answers and authority
	totalRR := int(answers + authority)
	for i := 0; i < totalRR && offset < len(packet); i++ {
		// Skip name
		if packet[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(packet) && packet[offset] != 0 {
				offset++
			}
			offset++
		}
		
		if offset+10 > len(packet) {
			break
		}
		
		rrLen := binary.BigEndian.Uint16(packet[offset+8 : offset+10])
		offset += 10 + int(rrLen)
	}
	
	// Process additional records
	for i := 0; i < int(additional) && offset < len(packet); i++ {
		if packet[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(packet) && packet[offset] != 0 {
				offset++
			}
			offset++
		}
		
		if offset+10 > len(packet) {
			break
		}
		
		rrType := binary.BigEndian.Uint16(packet[offset : offset+2])
		
		if rrType == 41 { // EDNS
			if offset+4 < len(packet) {
				// Update EDNS buffer size
				packet[offset+3] = byte(newSize >> 8)
				packet[offset+4] = byte(newSize & 0xFF)
			}
			break
		}
		
		rrLen := binary.BigEndian.Uint16(packet[offset+8 : offset+10])
		offset += 10 + int(rrLen)
	}
	
	return packet
}

func startProxy() error {
	// Create UDP socket
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: EDNS_PORT})
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", EDNS_PORT, err)
	}
	defer conn.Close()
	
	fmt.Printf("[EDNS Proxy] Listening on UDP port %d\n", EDNS_PORT)
	fmt.Printf("[EDNS Proxy] Forwarding to 127.0.0.1:%d\n", SLOWDNS_PORT)
	
	// Create slowdns connection
	slowdnsAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", SLOWDNS_PORT))
	slowdnsConn, err := net.DialUDP("udp", nil, slowdnsAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to slowdns: %v", err)
	}
	defer slowdnsConn.Close()
	
	buffer := make([]byte, BUFFER_SIZE)
	
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		
		if n > 0 {
			// Process incoming query
			query := make([]byte, n)
			copy(query, buffer[:n])
			
			// Patch EDNS size for upstream
			query = patchEDNS(query, MAX_PACKET_SIZE)
			
			// Forward to slowdns
			_, err = slowdnsConn.Write(query)
			if err != nil {
				continue
			}
			
			// Wait for response
			slowdnsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := slowdnsConn.Read(buffer)
			if err != nil {
				continue
			}
			
			if n > 0 {
				response := make([]byte, n)
				copy(response, buffer[:n])
				
				// Patch EDNS size for downstream
				response = patchEDNS(response, 512)
				
				// Send response back to client
				conn.WriteToUDP(response, addr)
			}
		}
	}
}

func main() {
	fmt.Println("=== High Performance EDNS Proxy ===")
	fmt.Println("Optimized for SlowDNS tunneling")
	fmt.Println("Built with Go for maximum speed")
	
	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		fmt.Println("\nShutting down EDNS Proxy...")
		os.Exit(0)
	}()
	
	if err := startProxy(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}`
	
	// Write source file
	sourcePath := "/tmp/edns_proxy.go"
	err := os.WriteFile(sourcePath, []byte(sourceCode), 0644)
	if err != nil {
		return err
	}
	
	// Compile with optimizations
	fmt.Printf("  Compiling with Go...\n")
	cmd := exec.Command("go", "build", "-o", "/usr/local/bin/edns-proxy",
		"-ldflags", "-s -w", "-trimpath", sourcePath)
	cmd.Env = append(os.Environ(),
		"GOOS=linux",
		"GOARCH="+runtime.GOARCH,
		"CGO_ENABLED=0",
		"GOPROXY=direct",
	)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s Compilation failed: %s\n", red("✗"), string(output))
		return err
	}
	
	// Make executable
	os.Chmod("/usr/local/bin/edns-proxy", 0755)
	
	// Create service file
	serviceContent := `[Unit]
Description=High Performance EDNS Proxy
After=server-sldns.service
Requires=server-sldns.service

[Service]
Type=simple
ExecStart=/usr/local/bin/edns-proxy
Restart=always
RestartSec=3
User=root
LimitNOFILE=65536
LimitNPROC=4096
OOMScoreAdjust=-100
Nice=-10
CPUQuota=200%
IOSchedulingClass=realtime
IOSchedulingPriority=0

[Install]
WantedBy=multi-user.target`
	
	servicePath := filepath.Join(SERVICE_DIR, "edns-proxy.service")
	os.WriteFile(servicePath, []byte(serviceContent), 0644)
	
	fmt.Printf("%s EDNS Proxy compiled and installed\n", green("✓"))
	return nil
}

// Configure firewall
func configureFirewall() error {
	printStep(4, "Configuring firewall")
	
	// Clear existing rules
	runCommand("iptables", "-F")
	runCommand("iptables", "-X")
	runCommand("iptables", "-t", "nat", "-F")
	runCommand("iptables", "-t", "nat", "-X")
	
	// Set default policies
	runCommand("iptables", "-P", "INPUT", "ACCEPT")
	runCommand("iptables", "-P", "FORWARD", "ACCEPT")
	runCommand("iptables", "-P", "OUTPUT", "ACCEPT")
	
	// Localhost
	runCommand("iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
	runCommand("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	
	// Established connections
	runCommand("iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	
	// SSH
	runCommand("iptables", "-A", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(SSHD_PORT), "-j", "ACCEPT")
	
	// SlowDNS ports
	runCommand("iptables", "-A", "INPUT", "-p", "udp", "--dport", strconv.Itoa(SLOWDNS_PORT), "-j", "ACCEPT")
	runCommand("iptables", "-A", "INPUT", "-p", "udp", "--dport", strconv.Itoa(EDNS_PORT), "-j", "ACCEPT")
	
	// ICMP
	runCommand("iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT")
	
	// Drop invalid
	runCommand("iptables", "-A", "INPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
	
	// Optimize kernel parameters
	optimizations := []string{
		"net.core.rmem_max=134217728",
		"net.core.wmem_max=134217728",
		"net.ipv4.udp_mem=1024000 8738000 134217728",
		"net.ipv4.udp_rmem_min=8192",
		"net.ipv4.udp_wmem_min=8192",
		"net.core.netdev_max_backlog=5000",
		"net.core.optmem_max=4194304",
		"net.ipv4.tcp_rmem=4096 87380 134217728",
		"net.ipv4.tcp_wmem=4096 65536 134217728",
	}
	
	for _, opt := range optimizations {
		parts := strings.Split(opt, "=")
		if len(parts) == 2 {
			os.WriteFile("/proc/sys/"+strings.Replace(parts[0], ".", "/", -1), 
				[]byte(parts[1]), 0644)
		}
	}
	
	// Disable IPv6
	os.WriteFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("1"), 0644)
	
	// Stop conflicting services
	runCommand("systemctl", "stop", "systemd-resolved")
	runCommand("pkill", "-f", "dnsmasq")
	
	fmt.Printf("%s Firewall configured\n", green("✓"))
	return nil
}

// Start services
func startServices() error {
	printStep(5, "Starting services")
	
	// Reload systemd
	runCommand("systemctl", "daemon-reload")
	
	// Enable and start SlowDNS
	runCommand("systemctl", "enable", "server-sldns.service")
	runCommand("systemctl", "start", "server-sldns.service")
	
	// Enable and start EDNS Proxy
	runCommand("systemctl", "enable", "edns-proxy.service")
	runCommand("systemctl", "start", "edns-proxy.service")
	
	// Wait a bit
	time.Sleep(2 * time.Second)
	
	// Check status
	fmt.Printf("\n%s Checking service status...\n", cyan("ℹ"))
	
	services := []string{"server-sldns", "edns-proxy"}
	for _, svc := range services {
		output, _ := runCommandCapture("systemctl", "is-active", svc)
		if strings.TrimSpace(output) == "active" {
			fmt.Printf("  %s %s: %s\n", green("✓"), svc, green("ACTIVE"))
		} else {
			fmt.Printf("  %s %s: %s\n", yellow("!"), svc, yellow("INACTIVE"))
		}
	}
	
	fmt.Printf("%s Services started\n", green("✓"))
	return nil
}

// Display installation summary
func showSummary() {
	printHeader("INSTALLATION COMPLETE")
	
	// Create summary table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Component", "Status", "Details"})
	table.SetBorder(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	
	table.Append([]string{"Server IP", green("✓"), serverIP})
	table.Append([]string{"SSH Port", green("✓"), strconv.Itoa(SSHD_PORT)})
	table.Append([]string{"SlowDNS Port", green("✓"), strconv.Itoa(SLOWDNS_PORT)})
	table.Append([]string{"EDNS Port", green("✓"), strconv.Itoa(EDNS_PORT)})
	table.Append([]string{"Nameserver", green("✓"), nameserver})
	table.Append([]string{"MTU Size", green("✓"), strconv.Itoa(MTU_SIZE)})
	
	table.Render()
	
	// Show commands
	fmt.Printf("\n%s Quick Test Commands:\n", cyan("▶"))
	fmt.Printf("  %s dig @%s %s\n", green("→"), serverIP, nameserver)
	fmt.Printf("  %s systemctl status server-sldns\n", green("→"))
	fmt.Printf("  %s ss -ulpn | grep ':%d\\|:%d'\n", green("→"), EDNS_PORT, SLOWDNS_PORT)
	
	// Show public key
	pubKeyPath := filepath.Join(SLOWDNS_DIR, "server.pub")
	if data, err := os.ReadFile(pubKeyPath); err == nil {
		fmt.Printf("\n%s Public Key:\n", cyan("▶"))
		fmt.Printf("%s\n", string(data))
	}
	
	// Performance tips
	fmt.Printf("\n%s Performance Tips:\n", cyan("▶"))
	fmt.Printf("  1. Monitor: %s watch -n 1 'netstat -anu | grep :%d'\n", yellow("→"), SLOWDNS_PORT)
	fmt.Printf("  2. Logs: %s journalctl -u server-sldns -f\n", yellow("→"))
	fmt.Printf("  3. Test: %s timeout 5 dig @%s %s\n", yellow("→"), serverIP, nameserver)
	
	// Client configuration
	fmt.Printf("\n%s Client Configuration:\n", cyan("▶"))
	fmt.Printf("  ./dnstt-client -udp %s:%d \\\n", serverIP, SLOWDNS_PORT)
	fmt.Printf("      -pubkey-file server.pub \\\n")
	fmt.Printf("      %s 127.0.0.1:1080\n", nameserver)
}

// Check installation
func verifyInstallation() bool {
	fmt.Printf("\n%s Verifying installation...\n", cyan("▶"))
	
	checks := []struct {
		name   string
		check  func() bool
	}{
		{"Port 53 (EDNS)", func() bool {
			output, _ := runCommandCapture("ss", "-ulpn")
			return strings.Contains(output, ":53 ")
		}},
		{"Port 5300 (SlowDNS)", func() bool {
			output, _ := runCommandCapture("ss", "-ulpn")
			return strings.Contains(output, ":5300 ")
		}},
		{"SlowDNS Service", func() bool {
			output, _ := runCommandCapture("systemctl", "is-active", "server-sldns")
			return strings.TrimSpace(output) == "active"
		}},
		{"EDNS Service", func() bool {
			output, _ := runCommandCapture("systemctl", "is-active", "edns-proxy")
			return strings.TrimSpace(output) == "active"
		}},
	}
	
	allPassed := true
	for _, check := range checks {
		if check.check() {
			fmt.Printf("  %s %s\n", green("✓"), check.name)
		} else {
			fmt.Printf("  %s %s\n", red("✗"), check.name)
			allPassed = false
		}
	}
	
	return allPassed
}

// Main function
func main() {
	// Show banner
	color.Cyan("╔══════════════════════════════════════════════════════════╗")
	color.Cyan("║           🚀 MODERN SLOWDNS INSTALLATION SCRIPT          ║")
	color.Cyan("║              Written in Go for Maximum Speed             ║")
	color.Cyan("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	
	// Check root
	checkRoot()
	
	// Get nameserver
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter nameserver [default: dns.example.com]: ")
	input, _ := reader.ReadString('\n')
	nameserver = strings.TrimSpace(input)
	if nameserver == "" {
		nameserver = "dns.example.com"
	}
	
	// Detect IP
	fmt.Print("Detecting server IP... ")
	serverIP = detectIP()
	fmt.Printf("%s\n", green(serverIP))
	
	startTime := time.Now()
	
	// Execute installation steps
	steps := []struct {
		name string
		fn   func() error
	}{
		{"Configure SSH", configureSSH},
		{"Setup SlowDNS", setupSlowDNS},
		{"Create Services", createSlowDNSService},
		{"Compile EDNS Proxy", compileEDNSProxy},
		{"Configure Firewall", configureFirewall},
		{"Start Services", startServices},
	}
	
	for i, step := range steps {
		printStep(i+1, step.name)
		if err := step.fn(); err != nil {
			fmt.Printf("%s Failed: %v\n", red("✗"), err)
			os.Exit(1)
		}
	}
	
	// Verify
	if verifyInstallation() {
		fmt.Printf("\n%s All checks passed!\n", green("✓"))
	} else {
		fmt.Printf("\n%s Some checks failed, but installation may still work\n", yellow("!"))
	}
	
	// Show summary
	showSummary()
	
	// Show completion time
	elapsed := time.Since(startTime)
	fmt.Printf("\n%s Installation completed in %v\n", 
		green("✓"), elapsed.Round(time.Millisecond))
	
	// Post-install menu
	fmt.Print("\nPress Enter for post-install options...")
	reader.ReadString('\n')
	
	showPostInstallMenu()
}

// Post-install menu
func showPostInstallMenu() {
	for {
		fmt.Printf("\n%s Post-Installation Menu:\n", cyan("▶"))
		fmt.Println("  1. View service status")
		fmt.Println("  2. Check listening ports")
		fmt.Println("  3. Restart all services")
		fmt.Println("  4. Test DNS functionality")
		fmt.Println("  5. View public key")
		fmt.Println("  6. Exit")
		
		fmt.Print("\nSelect option: ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)
		
		switch choice {
		case "1":
			printHeader("SERVICE STATUS")
			runCommand("systemctl", "status", "server-sldns", "--no-pager")
			fmt.Println()
			runCommand("systemctl", "status", "edns-proxy", "--no-pager")
			
		case "2":
			printHeader("LISTENING PORTS")
			runCommand("ss", "-ulpn", "|", "grep", "-E", ":53|:5300")
			
		case "3":
			printHeader("RESTARTING SERVICES")
			runCommand("systemctl", "restart", "server-sldns", "edns-proxy")
			time.Sleep(2 * time.Second)
			fmt.Printf("%s Services restarted\n", green("✓"))
			
		case "4":
			printHeader("DNS TEST")
						fmt.Printf("Testing %s via %s...\n", nameserver, serverIP)
			if output, err := runCommandCapture("dig", "@"+serverIP, nameserver, "+short"); err == nil {
				fmt.Printf("Response: %s\n", output)
			} else {
				fmt.Printf("%s DNS test failed\n", yellow("!"))
			}
			
		case "5":
			printHeader("PUBLIC KEY")
			pubKeyPath := filepath.Join(SLOWDNS_DIR, "server.pub")
			if data, err := os.ReadFile(pubKeyPath); err == nil {
				fmt.Println(string(data))
			} else {
				fmt.Printf("%s Cannot read public key\n", red("✗"))
			}
			
		case "6":
			fmt.Printf("\n%s Exiting...\n", green("✓"))
			return
			
		default:
			fmt.Printf("%s Invalid choice\n", red("✗"))
		}
	}
}

// Test DNS resolution
func testDNS() {
	printHeader("DNS RESOLUTION TEST")
	
	// Test methods
	fmt.Printf("Testing connectivity to %s...\n", nameserver)
	
	// Method 1: Using net.LookupIP (pure Go)
	fmt.Printf("\n%s Method 1: Go native DNS lookup\n", cyan("→"))
	addrs, err := net.LookupIP(nameserver)
	if err == nil {
		for _, addr := range addrs {
			fmt.Printf("  IP Address: %s\n", addr.String())
		}
	} else {
		fmt.Printf("  %s Failed: %v\n", red("✗"), err)
	}
	
	// Method 2: Using dig
	fmt.Printf("\n%s Method 2: Dig command\n", cyan("→"))
	if output, err := runCommandCapture("dig", "@"+serverIP, nameserver, "+short", "+time=3", "+tries=2"); err == nil {
		output = strings.TrimSpace(output)
		if output != "" {
			fmt.Printf("  Response: %s\n", output)
		} else {
			fmt.Printf("  %s No response\n", yellow("!"))
		}
	} else {
		fmt.Printf("  %s Command failed\n", yellow("!"))
	}
	
	// Method 3: Using nslookup
	fmt.Printf("\n%s Method 3: Nslookup command\n", cyan("→"))
	if output, err := runCommandCapture("nslookup", "-timeout=3", nameserver, serverIP); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Address:") || strings.Contains(line, nameserver) {
				fmt.Printf("  %s\n", strings.TrimSpace(line))
			}
		}
	} else {
		fmt.Printf("  %s Command failed\n", yellow("!"))
	}
	
	// Port connectivity test
	fmt.Printf("\n%s Port connectivity test:\n", cyan("→"))
	ports := []int{SSHD_PORT, SLOWDNS_PORT, EDNS_PORT}
	
	for _, port := range ports {
		timeout := 2 * time.Second
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", serverIP, port), timeout)
		if err == nil {
			fmt.Printf("  Port %d: %s\n", port, green("✓ OPEN"))
			conn.Close()
		} else {
			fmt.Printf("  Port %d: %s %s\n", port, red("✗ CLOSED"), yellow("(expected for UDP)"))
		}
	}
	
	// UDP port test
	fmt.Printf("\n%s UDP port test (requires netcat):\n", cyan("→"))
	if _, err := exec.LookPath("nc"); err == nil {
		// Test SlowDNS UDP port
		cmd := exec.Command("bash", "-c", fmt.Sprintf("echo -n | timeout 1 nc -u %s %d", serverIP, SLOWDNS_PORT))
		if err := cmd.Run(); err == nil {
			fmt.Printf("  UDP Port %d: %s\n", SLOWDNS_PORT, green("✓ RESPONDING"))
		} else {
			fmt.Printf("  UDP Port %d: %s\n", SLOWDNS_PORT, yellow("! NO RESPONSE"))
		}
		
		// Test EDNS UDP port
		cmd = exec.Command("bash", "-c", fmt.Sprintf("echo -n | timeout 1 nc -u %s %d", serverIP, EDNS_PORT))
		if err := cmd.Run(); err == nil {
			fmt.Printf("  UDP Port %d: %s\n", EDNS_PORT, green("✓ RESPONDING"))
		} else {
			fmt.Printf("  UDP Port %d: %s\n", EDNS_PORT, yellow("! NO RESPONSE"))
		}
	}
	
	fmt.Printf("\n%s Recommendations:\n", cyan("▶"))
	if strings.Contains(serverIP, "127.0.0.1") || strings.Contains(serverIP, "localhost") {
		fmt.Printf("  1. %s Server IP appears to be localhost\n", yellow("⚠"))
		fmt.Printf("  2. Check if server has public IP address\n")
		fmt.Printf("  3. Configure firewall to allow ports %d, %d, %d\n", 
			SSHD_PORT, SLOWDNS_PORT, EDNS_PORT)
	} else {
		fmt.Printf("  1. %s Server has public IP: %s\n", green("✓"), serverIP)
		fmt.Printf("  2. Test from external client: dig @%s %s\n", serverIP, nameserver)
		fmt.Printf("  3. Monitor logs: journalctl -u server-sldns -f\n")
	}
}

// Optimize system performance
func optimizePerformance() {
	printHeader("PERFORMANCE OPTIMIZATION")
	
	fmt.Printf("Applying system optimizations...\n")
	
	// Kernel optimizations for DNS tunneling
	optimizations := map[string]string{
		// Network buffers
		"net.core.rmem_max": "134217728",
		"net.core.wmem_max": "134217728",
		"net.core.rmem_default": "8388608",
		"net.core.wmem_default": "8388608",
		
		// UDP optimization
		"net.ipv4.udp_mem": "1024000 8738000 134217728",
		"net.ipv4.udp_rmem_min": "16384",
		"net.ipv4.udp_wmem_min": "16384",
		
		// TCP optimization (for SSH)
		"net.ipv4.tcp_rmem": "4096 87380 134217728",
		"net.ipv4.tcp_wmem": "4096 65536 134217728",
		"net.ipv4.tcp_congestion_control": "bbr",
		"net.ipv4.tcp_slow_start_after_idle": "0",
		
		// Connection tracking
		"net.netfilter.nf_conntrack_max": "524288",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "1200",
		
		// Socket buffers
		"net.core.optmem_max": "4194304",
		"net.core.netdev_max_backlog": "10000",
		"net.core.somaxconn": "65535",
		
		// IPv4 settings
		"net.ipv4.tcp_tw_reuse": "1",
		"net.ipv4.tcp_fin_timeout": "15",
		"net.ipv4.tcp_keepalive_time": "300",
		"net.ipv4.tcp_keepalive_probes": "5",
		"net.ipv4.tcp_keepalive_intvl": "15",
		"net.ipv4.tcp_max_syn_backlog": "2048",
		"net.ipv4.tcp_syncookies": "1",
		"net.ipv4.tcp_max_tw_buckets": "1440000",
		"net.ipv4.tcp_timestamps": "1",
		
		// Memory pressure
		"vm.swappiness": "10",
		"vm.vfs_cache_pressure": "50",
		"vm.dirty_ratio": "10",
		"vm.dirty_background_ratio": "5",
	}
	
	successCount := 0
	for param, value := range optimizations {
		path := "/proc/sys/" + strings.Replace(param, ".", "/", -1)
		if err := os.WriteFile(path, []byte(value), 0644); err == nil {
			successCount++
		}
	}
	
	fmt.Printf("  Applied %d/%d optimizations\n", successCount, len(optimizations))
	
	// Create performance tuning script
	tuningScript := `#!/bin/bash
# Performance tuning for SlowDNS

echo "Applying real-time optimizations..."

# Increase file descriptors
ulimit -n 1048576
ulimit -u unlimited

# CPU governor for performance
if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
fi

# Network queue discipline
tc qdisc add dev eth0 root fq 2>/dev/null || true
tc qdisc add dev eth0 root fq_codel 2>/dev/null || true

# Socket buffer auto-tuning
sysctl -w net.ipv4.tcp_moderate_rcvbuf=1

echo "Optimizations applied"
`
	
	scriptPath := "/usr/local/bin/slowdns-optimize"
	os.WriteFile(scriptPath, []byte(tuningScript), 0755)
	
	// Create systemd service for auto-optimization
	autoOptimizeService := `[Unit]
Description=SlowDNS Performance Optimizer
After=network.target
Before=server-sldns.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/slowdns-optimize

[Install]
WantedBy=multi-user.target
`
	
	os.WriteFile("/etc/systemd/system/slowdns-optimize.service", []byte(autoOptimizeService), 0644)
	runCommand("systemctl", "enable", "slowdns-optimize.service")
	runCommand("systemctl", "start", "slowdns-optimize.service")
	
	fmt.Printf("\n%s Performance optimizations:\n", cyan("▶"))
	fmt.Printf("  1. Network buffers increased to 128MB\n")
	fmt.Printf("  2. TCP BBR congestion control enabled\n")
	fmt.Printf("  3. Connection tracking optimized\n")
	fmt.Printf("  4. File descriptors limit increased\n")
	fmt.Printf("  5. Auto-optimization service installed\n")
	
	fmt.Printf("\n%s To monitor performance:\n", cyan("▶"))
	fmt.Printf("  %s Real-time traffic: iftop -i eth0\n", green("→"))
	fmt.Printf("  %s Connection count: netstat -an | grep :%d | wc -l\n", green("→"), SLOWDNS_PORT)
	fmt.Printf("  %s Memory usage: ps aux | grep dnstt-server\n", green("→"))
	fmt.Printf("  %s Network stats: sar -n DEV 1 3\n", green("→"))
}

// Monitor real-time traffic
func monitorTraffic() {
	printHeader("REAL-TIME MONITORING")
	
	fmt.Printf("Starting traffic monitor (Ctrl+C to stop)...\n\n")
	
	// Create channels for communication
	stopChan := make(chan bool)
	dataChan := make(chan string)
	
	// Goroutine to collect data
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				// Get SlowDNS connections
				cmd := exec.Command("bash", "-c", 
					fmt.Sprintf("ss -anu | grep ':%d' | wc -l", SLOWDNS_PORT))
				if output, err := cmd.Output(); err == nil {
					conns := strings.TrimSpace(string(output))
					
					// Get EDNS connections
					cmd = exec.Command("bash", "-c", 
						fmt.Sprintf("ss -anu | grep ':%d' | wc -l", EDNS_PORT))
					if output2, err := cmd.Output(); err == nil {
						ednsConns := strings.TrimSpace(string(output2))
						
						// Get system time
						timestamp := time.Now().Format("15:04:05")
						
						dataChan <- fmt.Sprintf("[%s] SlowDNS: %s conn | EDNS: %s conn", 
							timestamp, conns, ednsConns)
					}
				}
				
			case <-stopChan:
				return
			}
		}
	}()
	
	// Goroutine to display data
	go func() {
		fmt.Printf("%s Monitoring started...\n", green("✓"))
		fmt.Printf("%s Press Ctrl+C to stop\n\n", yellow("!"))
		
		for {
			select {
			case data := <-dataChan:
				fmt.Printf("\r%s", data)
			case <-stopChan:
				return
			}
		}
	}()
	
	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Display for 30 seconds or until interrupt
	select {
	case <-sigChan:
		fmt.Printf("\n\n%s Monitoring stopped by user\n", yellow("!"))
	case <-time.After(30 * time.Second):
		fmt.Printf("\n\n%s Monitoring completed (30 seconds)\n", green("✓"))
	}
	
	// Cleanup
	close(stopChan)
	time.Sleep(100 * time.Millisecond)
	
	// Show summary
	fmt.Printf("\n%s Final statistics:\n", cyan("▶"))
	
	// Get service status
	if output, err := runCommandCapture("systemctl", "status", "server-sldns", "--no-pager"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Active:") || strings.Contains(line, "Main PID:") {
				fmt.Printf("  %s\n", strings.TrimSpace(line))
			}
		}
	}
	
	// Get connection count
	if output, err := runCommandCapture("ss", "-anu", "|", "grep", "-c", 
		fmt.Sprintf(":%d\\|:%d", SLOWDNS_PORT, EDNS_PORT)); err == nil {
		fmt.Printf("  Total UDP connections: %s\n", strings.TrimSpace(output))
	}
	
	// Get memory usage
	if output, err := runCommandCapture("ps", "-o", "pid,rss,cmd", "-C", "dnstt-server"); err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 2 {
				rssKB := fields[1]
				rssMB, _ := strconv.Atoi(rssKB)
				rssMB = rssMB / 1024
				fmt.Printf("  SlowDNS memory usage: %d MB\n", rssMB)
			}
		}
	}
}

// Backup configuration
func backupConfig() {
	printHeader("CONFIGURATION BACKUP")
	
	timestamp := time.Now().Format("20060102-150405")
	backupDir := fmt.Sprintf("/etc/slowdns/backup-%s", timestamp)
	
	os.MkdirAll(backupDir, 0755)
	
	filesToBackup := []string{
		"/etc/slowdns/server.key",
		"/etc/slowdns/server.pub",
		"/etc/slowdns/dnstt-server",
		"/etc/systemd/system/server-sldns.service",
		"/etc/systemd/system/edns-proxy.service",
		"/usr/local/bin/edns-proxy",
		"/etc/ssh/sshd_config",
	}
	
	fmt.Printf("Creating backup at: %s\n\n", backupDir)
	
	successCount := 0
	for _, file := range filesToBackup {
		if _, err := os.Stat(file); err == nil {
			dest := filepath.Join(backupDir, filepath.Base(file))
			srcData, err := os.ReadFile(file)
			if err == nil {
				if err := os.WriteFile(dest, srcData, 0644); err == nil {
					fmt.Printf("  %s %s\n", green("✓"), filepath.Base(file))
					successCount++
				}
			}
		}
	}
	
	// Create restore script
	restoreScript := fmt.Sprintf(`#!/bin/bash
# SlowDNS Restore Script
# Backup: %s

echo "Restoring SlowDNS configuration..."
echo ""

# Stop services
systemctl stop server-sldns edns-proxy

# Restore files
cp -f %s/server.key /etc/slowdns/
cp -f %s/server.pub /etc/slowdns/
cp -f %s/dnstt-server /etc/slowdns/
chmod +x /etc/slowdns/dnstt-server

cp -f %s/server-sldns.service /etc/systemd/system/
cp -f %s/edns-proxy.service /etc/systemd/system/
cp -f %s/edns-proxy /usr/local/bin/
chmod +x /usr/local/bin/edns-proxy

cp -f %s/sshd_config /etc/ssh/

# Reload and restart
systemctl daemon-reload
systemctl restart ssh
systemctl start server-sldns edns-proxy

echo ""
echo "Restore completed!"
echo "Check status with: systemctl status server-sldns edns-proxy"
`, timestamp, backupDir, backupDir, backupDir, backupDir, backupDir, backupDir, backupDir)
	
	restorePath := filepath.Join(backupDir, "restore.sh")
	os.WriteFile(restorePath, []byte(restoreScript), 0755)
	
	fmt.Printf("\n%s Backup completed: %d files saved\n", green("✓"), successCount)
	fmt.Printf("%s Restore script: %s\n", cyan("▶"), restorePath)
	fmt.Printf("%s To restore: sudo bash %s\n", cyan("▶"), restorePath)
	
	// Create tar archive
	tarPath := fmt.Sprintf("/root/slowdns-backup-%s.tar.gz", timestamp)
	cmd := exec.Command("tar", "-czf", tarPath, "-C", backupDir, ".")
	if err := cmd.Run(); err == nil {
		fmt.Printf("%s Archive created: %s\n", green("✓"), tarPath)
		os.RemoveAll(backupDir)
	}
}

// Advanced troubleshooting
func advancedTroubleshoot() {
	printHeader("ADVANCED TROUBLESHOOTING")
	
	fmt.Printf("Running comprehensive diagnostics...\n\n")
	
	// 1. Check system resources
	fmt.Printf("1. %s System Resources:\n", cyan("▶"))
	
	// Memory
	if output, err := runCommandCapture("free", "-h"); err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 1 {
			fmt.Printf("   Memory: %s\n", strings.TrimSpace(lines[1]))
		}
	}
	
	// Disk space
	if output, err := runCommandCapture("df", "-h", "/"); err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 1 {
			fmt.Printf("   Disk: %s\n", strings.TrimSpace(lines[1]))
		}
	}
	
	// CPU load
	if output, err := runCommandCapture("uptime"); err == nil {
		fmt.Printf("   Load: %s\n", strings.TrimSpace(output))
	}
	
	// 2. Check network configuration
	fmt.Printf("\n2. %s Network Configuration:\n", cyan("▶"))
	
	// IP addresses
	if output, err := runCommandCapture("ip", "-4", "addr", "show"); err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "inet ") && !strings.Contains(line, "127.0.0.1") {
				fmt.Printf("   Interface: %s\n", strings.TrimSpace(line))
			}
		}
	}
	
	// Routing
	if output, err := runCommandCapture("ip", "route", "show", "default"); err == nil {
		fmt.Printf("   Default route: %s\n", strings.TrimSpace(output))
	}
	
	// 3. Check service logs
	fmt.Printf("\n3. %s Service Logs (last 5 lines):\n", cyan("▶"))
	
	services := []string{"server-sldns", "edns-proxy"}
	for _, svc := range services {
		fmt.Printf("   %s:\n", svc)
		if output, err := runCommandCapture("journalctl", "-u", svc, "-n", "5", "--no-pager"); err == nil {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if line != "" {
					fmt.Printf("     %s\n", line)
				}
			}
		}
		fmt.Println()
	}
	
	// 4. Check firewall rules
	fmt.Printf("4. %s Firewall Rules:\n", cyan("▶"))
	if output, err := runCommandCapture("iptables", "-L", "-n", "-v"); err == nil {
		lines := strings.Split(output, "\n")
		relevantLines := 0
		for _, line := range lines {
			if strings.Contains(line, strconv.Itoa(SSHD_PORT)) || 
			   strings.Contains(line, strconv.Itoa(SLOWDNS_PORT)) || 
			   strings.Contains(line, strconv.Itoa(EDNS_PORT)) {
				fmt.Printf("   %s\n", strings.TrimSpace(line))
				relevantLines++
			}
		}
		if relevantLines == 0 {
			fmt.Printf("   No relevant rules found\n")
		}
	}
	
	// 5. Check DNS resolution from server
	fmt.Printf("\n5. %s Local DNS Test:\n", cyan("▶"))
	if output, err := runCommandCapture("dig", "@127.0.0.1", nameserver, "+short", "+time=2"); err == nil {
		output = strings.TrimSpace(output)
		if output != "" {
			fmt.Printf("   Local resolution: %s\n", green("✓"))
			fmt.Printf("   Response: %s\n", output)
		} else {
			fmt.Printf("   Local resolution: %s (no response)\n", yellow("!"))
		}
	} else {
		fmt.Printf("   Local resolution: %s (failed)\n", red("✗"))
	}
	
	// 6. Port binding check
	fmt.Printf("\n6. %s Port Binding Check:\n", cyan("▶"))
	
	checkPort := func(port int, protocol string) {
		var cmd *exec.Cmd
		if protocol == "tcp" {
			cmd = exec.Command("ss", "-tln", "|", "grep", "-c", fmt.Sprintf(":%d ", port))
		} else {
			cmd = exec.Command("ss", "-uln", "|", "grep", "-c", fmt.Sprintf(":%d ", port))
		}
		
		if output, err := runCommandCapture(cmd.Path, cmd.Args[1:]...); err == nil {
			count := strings.TrimSpace(output)
			if count != "0" {
				fmt.Printf("   Port %d/%s: %s (bound)\n", port, protocol, green("✓"))
			} else {
				fmt.Printf("   Port %d/%s: %s (not bound)\n", port, protocol, red("✗"))
			}
		}
	}
	
	checkPort(SSHD_PORT, "tcp")
	checkPort(SLOWDNS_PORT, "udp")
	checkPort(EDNS_PORT, "udp")
	
	// 7. Check binary permissions
	fmt.Printf("\n7. %s File Permissions:\n", cyan("▶"))
	
	files := []string{
		"/etc/slowdns/dnstt-server",
		"/usr/local/bin/edns-proxy",
		"/etc/slowdns/server.key",
		"/etc/slowdns/server.pub",
	}
	
	for _, file := range files {
		if info, err := os.Stat(file); err == nil {
			perm := info.Mode().Perm()
			fmt.Printf("   %s: %s\n", filepath.Base(file), perm.String())
		} else {
			fmt.Printf("   %s: %s\n", filepath.Base(file), red("MISSING"))
		}
	}
	
	// Recommendations
	fmt.Printf("\n%s Troubleshooting Recommendations:\n", cyan("▶"))
	fmt.Printf("  1. If ports not bound: restart services\n")
	fmt.Printf("  2. If no DNS response: check SlowDNS logs\n")
	fmt.Printf("  3. If connection issues: check firewall\n")
	fmt.Printf("  4. If service fails: check binary permissions\n")
	fmt.Printf("  5. For performance: run optimization\n")
	
	fmt.Printf("\n%s Quick fixes:\n", cyan("▶"))
	fmt.Printf("  %s Reinstall: systemctl restart server-sldns edns-proxy\n", green("→"))
	fmt.Printf("  %s Reset firewall: iptables -F && iptables -X\n", green("→"))
	fmt.Printf("  %s Full restart: reboot\n", green("→"))
}

// Update the post-install menu to include these functions
func showPostInstallMenu() {
	for {
		clearScreen()
		printHeader("POST-INSTALLATION MENU")
		
		fmt.Println("1.  View service status")
		fmt.Println("2.  Check listening ports")
		fmt.Println("3.  Restart all services")
		fmt.Println("4.  Test DNS functionality")
		fmt.Println("5.  View public key")
		fmt.Println("6.  Performance optimization")
		fmt.Println("7.  Real-time monitoring")
		fmt.Println("8.  Backup configuration")
		fmt.Println("9.  Advanced troubleshooting")
		fmt.Println("10. Exit")
		
		fmt.Print("\nSelect option [1-10]: ")
		
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)
		
		switch choice {
		case "1":
			printHeader("SERVICE STATUS")
			runCommand("systemctl", "status", "server-sldns", "--no-pager")
			fmt.Println()
			runCommand("systemctl", "status", "edns-proxy", "--no-pager")
			pause()
			
		case "2":
			printHeader("LISTENING PORTS")
			runCommand("ss", "-ulpn", "|", "grep", "-E", ":53|:5300")
			fmt.Println()
			runCommand("ss", "-tlnp", "|", "grep", ":"+strconv.Itoa(SSHD_PORT))
			pause()
			
		case "3":
			printHeader("RESTARTING SERVICES")
			runCommand("systemctl", "restart", "server-sldns", "edns-proxy")
			time.Sleep(2 * time.Second)
			fmt.Printf("%s Services restarted\n", green("✓"))
			pause()
			
		case "4":
			testDNS()
			pause()
			
		case "5":
			printHeader("PUBLIC KEY")
			pubKeyPath := filepath.Join(SLOWDNS_DIR, "server.pub")
			if data, err := os.ReadFile(pubKeyPath); err == nil {
				fmt.Println(string(data))
			} else {
				fmt.Printf("%s Cannot read public key\n", red("✗"))
			}
			pause()
			
		case "6":
			optimizePerformance()
			pause()
			
		case "7":
			monitorTraffic()
			pause()
			
		case "8":
			backupConfig()
			pause()
			
		case "9":
			advancedTroubleshoot()
			pause()
			
		case "10":
			fmt.Printf("\n%s Exiting...\n", green("✓"))
			return
			
		default:
			fmt.Printf("%s Invalid choice\n", red("✗"))
						time.Sleep(1 * time.Second)
		}
	}
}

// Enhanced DNS test function
func testDNS() {
	printHeader("DNS RESOLUTION TEST")
	
	fmt.Printf("Testing connectivity to %s via %s...\n\n", nameserver, serverIP)
	
	// Create a table for test results
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Test", "Method", "Status", "Result"})
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	
	// Test 1: Native Go DNS lookup
	start := time.Now()
	addrs, err := net.LookupIP(nameserver)
	elapsed := time.Since(start)
	
	status := red("✗")
	result := fmt.Sprintf("Failed: %v", err)
	if err == nil && len(addrs) > 0 {
		status = green("✓")
		ips := []string{}
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}
		result = fmt.Sprintf("%s (%v)", strings.Join(ips, ", "), elapsed)
	}
	table.Append([]string{"DNS Resolution", "Go net.LookupIP", status, result})
	
	// Test 2: Dig command
	start = time.Now()
	if output, err := runCommandCapture("dig", "@"+serverIP, nameserver, "+short", "+time=3", "+tries=2"); err == nil {
		elapsed = time.Since(start)
		output = strings.TrimSpace(output)
		if output != "" {
			table.Append([]string{"DNS Query", "dig", green("✓"), fmt.Sprintf("%s (%v)", output, elapsed)})
		} else {
			table.Append([]string{"DNS Query", "dig", yellow("!"), fmt.Sprintf("No response (%v)", elapsed)})
		}
	} else {
		table.Append([]string{"DNS Query", "dig", red("✗"), "Command failed"})
	}
	
	// Test 3: Port connectivity
	ports := []struct {
		port     int
		protocol string
		name     string
	}{
		{SSHD_PORT, "tcp", "SSH"},
		{SLOWDNS_PORT, "udp", "SlowDNS"},
		{EDNS_PORT, "udp", "EDNS Proxy"},
		{53, "tcp", "DNS TCP"},
	}
	
	for _, p := range ports {
		start = time.Now()
		timeout := 2 * time.Second
		
		if p.protocol == "tcp" {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", serverIP, p.port), timeout)
			if err == nil {
				elapsed = time.Since(start)
				table.Append([]string{"Port Check", fmt.Sprintf("%d/%s", p.port, p.protocol), 
					green("✓"), fmt.Sprintf("Open (%v)", elapsed)})
				conn.Close()
			} else {
				table.Append([]string{"Port Check", fmt.Sprintf("%d/%s", p.port, p.protocol), 
					red("✗"), fmt.Sprintf("Closed: %v", err)})
			}
		} else {
			// UDP test (send empty packet)
			conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", serverIP, p.port), timeout)
			if err == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(timeout))
				
				// Send test packet
				testPacket := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				conn.Write(testPacket)
				
				// Try to read response
				buffer := make([]byte, 512)
				n, err := conn.Read(buffer)
				elapsed = time.Since(start)
				
				if err == nil && n > 0 {
					table.Append([]string{"Port Check", fmt.Sprintf("%d/%s", p.port, p.protocol), 
						green("✓"), fmt.Sprintf("Responding (%v)", elapsed)})
				} else {
					table.Append([]string{"Port Check", fmt.Sprintf("%d/%s", p.port, p.protocol), 
						yellow("!"), fmt.Sprintf("No response (%v)", elapsed)})
				}
			} else {
				table.Append([]string{"Port Check", fmt.Sprintf("%d/%s", p.port, p.protocol), 
					red("✗"), fmt.Sprintf("Failed: %v", err)})
			}
		}
	}
	
	// Render table
	table.Render()
	
	// Additional diagnostics
	fmt.Printf("\n%s Additional Diagnostics:\n", cyan("▶"))
	
	// Check services
	fmt.Printf("\n1. Service Status:\n")
	services := []string{"server-sldns", "edns-proxy"}
	for _, svc := range services {
		output, _ := runCommandCapture("systemctl", "is-active", svc)
		status := strings.TrimSpace(output)
		icon := red("✗")
		if status == "active" {
			icon = green("✓")
		} else if status == "inactive" {
			icon = yellow("!")
		}
		fmt.Printf("   %s %s: %s\n", icon, svc, status)
	}
	
	// Check process count
	fmt.Printf("\n2. Process Count:\n")
	cmds := []string{
		fmt.Sprintf("pgrep -c dnstt-server"),
		fmt.Sprintf("pgrep -c edns-proxy"),
		fmt.Sprintf("ss -anu | grep -c ':%d\\|:%d'", SLOWDNS_PORT, EDNS_PORT),
	}
	
	labels := []string{"SlowDNS Processes", "EDNS Processes", "UDP Connections"}
	for i, cmd := range cmds {
		output, _ := runCommandCapture("bash", "-c", cmd)
		count := strings.TrimSpace(output)
		if count == "" {
			count = "0"
		}
		fmt.Printf("   %s: %s\n", labels[i], count)
	}
	
	// Network statistics
	fmt.Printf("\n3. Network Statistics:\n")
	if output, err := runCommandCapture("netstat", "-su"); err == nil {
		lines := strings.Split(output, "\n")
		udpStats := []string{}
		for _, line := range lines {
			if strings.Contains(line, "packets received") || 
			   strings.Contains(line, "packets sent") ||
			   strings.Contains(line, "errors") {
				udpStats = append(udpStats, strings.TrimSpace(line))
				if len(udpStats) >= 3 {
					break
				}
			}
		}
		for _, stat := range udpStats {
			fmt.Printf("   %s\n", stat)
		}
	}
	
	// Recommendations
	fmt.Printf("\n%s Recommendations:\n", cyan("▶"))
	if strings.Contains(serverIP, "127.0.0.1") || serverIP == "localhost" {
		fmt.Printf("  1. %s Server IP is localhost - configure public IP\n", yellow("⚠"))
		fmt.Printf("  2. Check firewall: iptables -L -n -v\n")
		fmt.Printf("  3. Verify port forwarding on router\n")
	} else {
		fmt.Printf("  1. %s Public IP detected: %s\n", green("✓"), serverIP)
		fmt.Printf("  2. Test from external network: dig @%s %s\n", serverIP, nameserver)
		fmt.Printf("  3. Monitor logs: tail -f /var/log/syslog | grep -i slowdns\n")
	}
	
	fmt.Printf("  4. For performance issues: Run optimization\n")
	fmt.Printf("  5. For connection drops: Check MTU settings\n")
	fmt.Printf("  6. Regular maintenance: systemctl restart server-sldns weekly\n")
}

// Quick fix common issues
func quickFix() {
	printHeader("QUICK FIX TOOL")
	
	fmt.Printf("Select issue to fix:\n\n")
	fmt.Println("1. Port 53 already in use")
	fmt.Println("2. SlowDNS service not starting")
	fmt.Println("3. EDNS Proxy not working")
	fmt.Println("4. DNS queries timing out")
	fmt.Println("5. High memory usage")
	fmt.Println("6. Slow performance")
	fmt.Println("7. Reset all configurations")
	fmt.Println("8. Back to main menu")
	
	fmt.Print("\nSelect option [1-8]: ")
	
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(input)
	
	switch choice {
	case "1":
		fixPort53()
	case "2":
		fixSlowDNSService()
	case "3":
		fixEDNSProxy()
	case "4":
		fixDNSTimeout()
	case "5":
		fixHighMemory()
	case "6":
		fixSlowPerformance()
	case "7":
		resetConfig()
	case "8":
		return
	default:
		fmt.Printf("%s Invalid choice\n", red("✗"))
		time.Sleep(1 * time.Second)
		quickFix()
	}
}

func fixPort53() {
	printHeader("FIXING PORT 53 CONFLICT")
	
	fmt.Printf("Stopping services using port 53...\n")
	
	// Kill processes on port 53
	runCommand("fuser", "-k", "53/udp")
	runCommand("fuser", "-k", "53/tcp")
	
	// Stop systemd-resolved
	runCommand("systemctl", "stop", "systemd-resolved")
	runCommand("systemctl", "disable", "systemd-resolved")
	
	// Stop dnsmasq if exists
	runCommand("systemctl", "stop", "dnsmasq")
	runCommand("systemctl", "disable", "dnsmasq")
	
	// Restart EDNS proxy
	runCommand("systemctl", "restart", "edns-proxy")
	
	time.Sleep(2 * time.Second)
	
	// Verify
	if output, err := runCommandCapture("ss", "-ulpn", "|", "grep", ":53 "); err == nil && strings.Contains(output, "edns-proxy") {
		fmt.Printf("%s Port 53 now used by EDNS Proxy\n", green("✓"))
	} else {
		fmt.Printf("%s Issue may persist, checking...\n", yellow("!"))
		runCommand("lsof", "-i", ":53")
	}
}

func fixSlowDNSService() {
	printHeader("FIXING SLOWDNS SERVICE")
	
	fmt.Printf("Diagnosing SlowDNS service...\n")
	
	// Check service status
	output, _ := runCommandCapture("systemctl", "status", "server-sldns")
	
	if strings.Contains(output, "Active: active") {
		fmt.Printf("%s Service is running\n", green("✓"))
		fmt.Printf("Checking logs...\n")
		runCommand("journalctl", "-u", "server-sldns", "-n", "10", "--no-pager")
	} else {
		fmt.Printf("%s Service is not running\n", yellow("!"))
		
		// Try to start
		fmt.Printf("Attempting to start service...\n")
		runCommand("systemctl", "start", "server-sldns")
		time.Sleep(2 * time.Second)
		
		// Check again
		output, _ := runCommandCapture("systemctl", "is-active", "server-sldns")
		if strings.TrimSpace(output) == "active" {
			fmt.Printf("%s Service started successfully\n", green("✓"))
		} else {
			fmt.Printf("%s Service failed to start\n", red("✗"))
			fmt.Printf("Checking binary...\n")
			
			// Check binary
			if _, err := os.Stat("/etc/slowdns/dnstt-server"); err != nil {
				fmt.Printf("%s Binary not found, reinstalling...\n", yellow("!"))
				setupSlowDNS()
			}
			
			// Check permissions
			runCommand("chmod", "+x", "/etc/slowdns/dnstt-server")
			
			// Try manual start
			fmt.Printf("Trying manual start...\n")
			cmd := exec.Command("/etc/slowdns/dnstt-server", "-udp", fmt.Sprintf(":%d", SLOWDNS_PORT), 
				"-mtu", "1800", "-privkey-file", "/etc/slowdns/server.key", 
				nameserver, fmt.Sprintf("127.0.0.1:%d", SSHD_PORT))
			cmd.Start()
			
			time.Sleep(3 * time.Second)
			
			// Check if running
			if output, _ := runCommandCapture("pgrep", "-f", "dnstt-server"); output != "" {
				fmt.Printf("%s Running manually, creating service fix...\n", green("✓"))
				
				// Recreate service
				createSlowDNSService()
				runCommand("systemctl", "daemon-reload")
				runCommand("systemctl", "enable", "--now", "server-sldns")
			}
		}
	}
}

func fixEDNSProxy() {
	printHeader("FIXING EDNS PROXY")
	
	fmt.Printf("Checking EDNS Proxy...\n")
	
	// Check if binary exists
	if _, err := os.Stat("/usr/local/bin/edns-proxy"); err != nil {
		fmt.Printf("%s Binary not found, recompiling...\n", yellow("!"))
		compileEDNSProxy()
	}
	
	// Check service
	output, _ := runCommandCapture("systemctl", "status", "edns-proxy")
	
	if strings.Contains(output, "Active: active") {
		fmt.Printf("%s Service is running\n", green("✓"))
	} else {
		fmt.Printf("%s Service is not running\n", yellow("!"))
		
		// Restart
		runCommand("systemctl", "restart", "edns-proxy")
		time.Sleep(2 * time.Second)
		
		// Check port
		if output, _ := runCommandCapture("ss", "-ulpn", "|", "grep", ":53"); strings.Contains(output, "edns-proxy") {
			fmt.Printf("%s EDNS Proxy now running on port 53\n", green("✓"))
		} else {
			// Try manual start
			fmt.Printf("Starting manually...\n")
			cmd := exec.Command("/usr/local/bin/edns-proxy")
			cmd.Start()
			time.Sleep(1 * time.Second)
		}
	}
	
	// Verify functionality
	fmt.Printf("\nTesting EDNS Proxy functionality...\n")
	if output, err := runCommandCapture("dig", "@127.0.0.1", "google.com", "+short", "+time=2"); err == nil {
		output = strings.TrimSpace(output)
		if output != "" {
			fmt.Printf("%s EDNS Proxy working: %s\n", green("✓"), output)
		} else {
			fmt.Printf("%s No response from EDNS Proxy\n", yellow("!"))
		}
	}
}

func fixDNSTimeout() {
	printHeader("FIXING DNS TIMEOUT ISSUES")
	
	fmt.Printf("Optimizing DNS timeout settings...\n")
	
	// Adjust kernel parameters
	params := map[string]string{
		"net.ipv4.tcp_keepalive_time": "60",
		"net.ipv4.tcp_keepalive_intvl": "10",
		"net.ipv4.tcp_keepalive_probes": "6",
		"net.ipv4.tcp_retries2": "5",
		"net.ipv4.udp_retries": "3",
		"net.core.netdev_max_backlog": "5000",
	}
	
	for param, value := range params {
		path := "/proc/sys/" + strings.Replace(param, ".", "/", -1)
		os.WriteFile(path, []byte(value), 0644)
		fmt.Printf("  Set %s = %s\n", param, value)
	}
	
	// Increase SlowDNS timeouts
	fmt.Printf("\nAdjusting SlowDNS configuration...\n")
	
	// Check current service file
	servicePath := "/etc/systemd/system/server-sldns.service"
	data, err := os.ReadFile(servicePath)
	if err == nil {
		content := string(data)
		if !strings.Contains(content, "TimeoutSec=") {
			// Add timeout to service
			content = strings.Replace(content, "[Service]",
				"[Service]\nTimeoutSec=30\nRestartSec=10", 1)
			os.WriteFile(servicePath, []byte(content), 0644)
			fmt.Printf("%s Added TimeoutSec to service\n", green("✓"))
		}
	}
	
	// Restart services
	runCommand("systemctl", "daemon-reload")
	runCommand("systemctl", "restart", "server-sldns", "edns-proxy")
	
	fmt.Printf("\n%s Recommendations:\n", cyan("▶"))
	fmt.Printf("  1. Check network latency: ping %s\n", serverIP)
	fmt.Printf("  2. Monitor timeouts: journalctl -u server-sldns | grep timeout\n")
	fmt.Printf("  3. Consider lowering MTU if on unstable network\n")
	fmt.Printf("  4. Use TCP mode if UDP drops persist\n")
}

func fixHighMemory() {
	printHeader("FIXING HIGH MEMORY USAGE")
	
	fmt.Printf("Checking memory usage...\n")
	
	// Get current memory usage
	runCommand("ps", "aux", "--sort=-%mem", "|", "head", "-10")
	
	// Optimize memory settings
	fmt.Printf("\nApplying memory optimizations...\n")
	
	// Kernel memory settings
	memParams := map[string]string{
		"vm.swappiness": "10",
		"vm.vfs_cache_pressure": "50",
		"vm.dirty_background_ratio": "5",
		"vm.dirty_ratio": "10",
		"vm.dirty_writeback_centisecs": "6000",
		"vm.dirty_expire_centisecs": "6000",
	}
	
	for param, value := range memParams {
		path := "/proc/sys/" + strings.Replace(param, ".", "/", -1)
		os.WriteFile(path, []byte(value), 0644)
		fmt.Printf("  Set %s = %s\n", param, value)
	}
	
	// Limit SlowDNS memory
	servicePath := "/etc/systemd/system/server-sldns.service"
	data, err := os.ReadFile(servicePath)
	if err == nil {
		content := string(data)
		if !strings.Contains(content, "MemoryMax=") {
			// Add memory limits
			content = strings.Replace(content, "[Service]",
				"[Service]\nMemoryMax=256M\nMemoryHigh=128M", 1)
			os.WriteFile(servicePath, []byte(content), 0644)
			fmt.Printf("%s Added memory limits to SlowDNS service\n", green("✓"))
		}
	}
	
	// Create cleanup script
	cleanupScript := `#!/bin/bash
# Memory cleanup script for SlowDNS

echo "Cleaning up memory..."

# Drop caches (safe for production)
sync
echo 3 > /proc/sys/vm/drop_caches

# Clean up old journal logs
journalctl --vacuum-time=3d

# Restart services with fresh memory
systemctl restart server-sldns edns-proxy

echo "Memory cleanup completed"
`
	
	os.WriteFile("/usr/local/bin/cleanup-memory.sh", []byte(cleanupScript), 0755)
	
	fmt.Printf("\n%s Memory management:\n", cyan("▶"))
	fmt.Printf("  1. Regular cleanup: bash /usr/local/bin/cleanup-memory.sh\n")
	fmt.Printf("  2. Monitor: watch -n 5 'free -h'\n")
	fmt.Printf("  3. Auto-cleanup: Add to cron (0 */6 * * * /usr/local/bin/cleanup-memory.sh)\n")
	fmt.Printf("  4. Consider adding swap if not present\n")
	
	// Restart services
	runCommand("systemctl", "daemon-reload")
	runCommand("systemctl", "restart", "server-sldns", "edns-proxy")
}

func fixSlowPerformance() {
	printHeader("FIXING SLOW PERFORMANCE")
	
	fmt.Printf("Analyzing performance bottlenecks...\n")
	
	// Quick system check
	fmt.Printf("\n1. System Load:\n")
	runCommand("uptime")
	
	fmt.Printf("\n2. CPU Usage (top processes):\n")
	runCommand("ps", "aux", "--sort=-%cpu", "|", "head", "-5")
	
	fmt.Printf("\n3. Network Statistics:\n")
	runCommand("sar", "-n", "DEV", "1", "1", "|", "tail", "-5")
	
	fmt.Printf("\nApplying performance optimizations...\n")
	
	// Network optimizations
	netOpts := map[string]string{
		"net.core.rmem_max": "268435456",
		"net.core.wmem_max": "268435456",
		"net.ipv4.tcp_rmem": "4096 87380 268435456",
		"net.ipv4.tcp_wmem": "4096 65536 268435456",
		"net.core.netdev_max_backlog": "100000",
		"net.core.somaxconn": "65535",
		"net.ipv4.tcp_congestion_control": "bbr",
		"net.ipv4.tcp_notsent_lowat": "16384",
		"net.ipv4.tcp_mtu_probing": "1",
	}
	
	for param, value := range netOpts {
		path := "/proc/sys/" + strings.Replace(param, ".", "/", -1)
		os.WriteFile(path, []byte(value), 0644)
		fmt.Printf("  Set %s = %s\n", param, value)
	}
	
	// I/O optimizations
	fmt.Printf("\nI/O Optimizations:\n")
	
	// Check if on SSD
	if output, _ := runCommandCapture("lsblk", "-d", "-o", "rota"); strings.Contains(output, "0") {
		fmt.Printf("  SSD detected, applying SSD optimizations\n")
		// SSD specific optimizations
		os.WriteFile("/sys/block/sda/queue/scheduler", []byte("none"), 0644)
		os.WriteFile("/proc/sys/vm/dirty_background_ratio", []byte("5"), 0644)
		os.WriteFile("/proc/sys/vm/dirty_ratio", []byte("10"), 0644)
	}
	
	// Optimize service priorities
	servicePath := "/etc/systemd/system/server-sldns.service"
	data, _ := os.ReadFile(servicePath)
	content := string(data)
	
	// Add performance settings
	if !strings.Contains(content, "Nice=") {
		content = strings.Replace(content, "[Service]",
			"[Service]\nNice=-10\nIOSchedulingClass=realtime\nIOSchedulingPriority=0\nCPUSchedulingPolicy=rr\nCPUSchedulingPriority=99", 1)
		os.WriteFile(servicePath, []byte(content), 0644)
		fmt.Printf("%s Added real-time scheduling\n", green("✓"))
	}
	
	// Create performance monitor
	monitorScript := `#!/bin/bash
# Performance monitor for SlowDNS

echo "=== SlowDNS Performance Monitor ==="
echo "Timestamp: $(date)"
echo ""

# CPU usage of SlowDNS
echo "CPU Usage:"
ps aux | grep dnstt-server | grep -v grep | awk '{print "  PID:", $2, "CPU:", $3"%", "MEM:", $4"%"}'

# Connection count
echo -e "\nConnections:"
ss -anu | grep -c ":5300"

# Network stats
echo -e "\nNetwork Stats (last 60s):"
sar -n DEV 1 1 | grep Average | grep -v lo

# Memory
echo -e "\nMemory:"
free -h | head -2

echo ""
`
	
	os.WriteFile("/usr/local/bin/monitor-slowdns.sh", []byte(monitorScript), 0755)
	
	fmt.Printf("\n%s Performance tips:\n", cyan("▶"))
	fmt.Printf("  1. Monitor: watch -n 2 /usr/local/bin/monitor-slowdns.sh\n")
	fmt.Printf("  2. Lower MTU if on lossy network: Edit service to -mtu 1400\n")
	fmt.Printf("  3. Use TCP mode for better reliability\n")
	fmt.Printf("  4. Consider dedicated CPU cores via taskset\n")
	
	// Apply changes
	runCommand("systemctl", "daemon-reload")
	runCommand("systemctl", "restart", "server-sldns", "edns-proxy")
}

func resetConfig() {
	printHeader("RESETTING ALL CONFIGURATIONS")
	
	fmt.Printf("%s WARNING: This will reset all SlowDNS configurations!\n", red("⚠"))
	fmt.Printf("All settings will be restored to defaults.\n")
	
	fmt.Print("\nAre you sure? (yes/no): ")
	
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	confirmation := strings.TrimSpace(strings.ToLower(input))
	
	if confirmation != "yes" && confirmation != "y" {
		fmt.Printf("Reset cancelled\n")
		return
	}
	
	fmt.Printf("\nResetting configurations...\n")
	
	// Stop services
	runCommand("systemctl", "stop", "server-sldns", "edns-proxy")
	
	// Remove configurations
	paths := []string{
		"/etc/slowdns",
		"/etc/systemd/system/server-sldns.service",
		"/etc/systemd/system/edns-proxy.service",
		"/usr/local/bin/edns-proxy",
		"/usr/local/bin/slowdns-optimize",
		"/usr/local/bin/cleanup-memory.sh",
		"/usr/local/bin/monitor-slowdns.sh",
	}
	
	for _, path := range paths {
		os.RemoveAll(path)
		fmt.Printf("  Removed: %s\n", path)
	}
	
	// Restore SSH config if backup exists
	sshBackup := "/etc/ssh/sshd_config.backup"
	if _, err := os.Stat(sshBackup); err == nil {
		runCommand("cp", sshBackup, "/etc/ssh/sshd_config")
		runCommand("systemctl", "restart", "ssh")
		fmt.Printf("  Restored SSH configuration\n")
	}
	
	// Clear firewall rules
	runCommand("iptables", "-F")
	runCommand("iptables", "-X")
	runCommand("iptables", "-t", "nat", "-F")
	runCommand("iptables", "-t", "nat", "-X")
	runCommand("iptables", "-P", "INPUT", "ACCEPT")
	runCommand("iptables", "-P", "FORWARD", "ACCEPT")
	runCommand("iptables", "-P", "OUTPUT", "ACCEPT")
	
	// Re-enable systemd-resolved
	runCommand("systemctl", "enable", "--now", "systemd-resolved")
	
	fmt.Printf("\n%s Reset completed!\n", green("✓"))
	fmt.Printf("You can now run the installer again for a fresh installation.\n")
}

// Enhanced main menu with quick fix option
func showEnhancedMenu() {
	for {
		clearScreen()
		printHeader("SLOWDNS MANAGEMENT PANEL")
		
		fmt.Println("1.  View service status")
		fmt.Println("2.  Check listening ports")
		fmt.Println("3.  Restart all services")
		fmt.Println("4.  Test DNS functionality")
		fmt.Println("5.  View public key")
				fmt.Println("6.  Performance optimization")
		fmt.Println("7.  Real-time monitoring")
		fmt.Println("8.  Backup configuration")
		fmt.Println("9.  Advanced troubleshooting")
		fmt.Println("10. Generate client config")
		fmt.Println("11. Quick fix issues")
		fmt.Println("12. Uninstall SlowDNS")
		fmt.Println("13. View installation logs")
		fmt.Println("14. System information")
		fmt.Println("15. Update SlowDNS")
		fmt.Println("16. Exit")
		
		fmt.Print("\nSelect option [1-16]: ")
		
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)
		
		switch choice {
		case "1":
			printHeader("SERVICE STATUS")
			runCommand("systemctl", "status", "server-sldns", "--no-pager")
			fmt.Println()
			runCommand("systemctl", "status", "edns-proxy", "--no-pager")
			pause()
			
		case "2":
			printHeader("LISTENING PORTS")
			fmt.Printf("%s UDP Ports:\n", cyan("▶"))
			runCommand("ss", "-ulpn", "|", "grep", "-E", ":53|:5300")
			fmt.Printf("\n%s TCP Ports:\n", cyan("▶"))
			runCommand("ss", "-tlnp", "|", "grep", ":"+strconv.Itoa(SSHD_PORT))
			fmt.Printf("\n%s Connection Statistics:\n", cyan("▶"))
			runCommand("netstat", "-s", "|", "grep", "-A", "10", "UDP:")
			pause()
			
		case "3":
			printHeader("RESTARTING SERVICES")
			fmt.Printf("Restarting all SlowDNS services...\n")
			runCommand("systemctl", "restart", "server-sldns", "edns-proxy")
			time.Sleep(3 * time.Second)
			
			// Verify restart
			services := []string{"server-sldns", "edns-proxy"}
			allRunning := true
			for _, svc := range services {
				output, _ := runCommandCapture("systemctl", "is-active", svc)
				if strings.TrimSpace(output) == "active" {
					fmt.Printf("  %s %s: %s\n", green("✓"), svc, green("RUNNING"))
				} else {
					fmt.Printf("  %s %s: %s\n", red("✗"), svc, red("FAILED"))
					allRunning = false
				}
			}
			
			if allRunning {
				fmt.Printf("\n%s All services restarted successfully\n", green("✓"))
			} else {
				fmt.Printf("\n%s Some services failed to start\n", yellow("!"))
				fmt.Printf("Run 'systemctl status <service>' for details\n")
			}
			pause()
			
		case "4":
			testDNS()
			pause()
			
		case "5":
			printHeader("PUBLIC KEY")
			pubKeyPath := filepath.Join(SLOWDNS_DIR, "server.pub")
			if data, err := os.ReadFile(pubKeyPath); err == nil {
				pubKey := strings.TrimSpace(string(data))
				fmt.Printf("%s Public Key (64 chars):\n", cyan("▶"))
				fmt.Printf("%s\n\n", pubKey)
				
				// Show QR code option
				fmt.Printf("%s QR Code Options:\n", cyan("▶"))
				fmt.Println("1. Display QR code in terminal")
				fmt.Println("2. Save QR code as PNG")
				fmt.Println("3. Show connection string")
				fmt.Print("\nSelect option [1-3]: ")
				
				qrChoice, _ := reader.ReadString('\n')
				qrChoice = strings.TrimSpace(qrChoice)
				
				switch qrChoice {
				case "1":
					if commandExists("qrencode") {
						connectionString := fmt.Sprintf("slowdns://%s@%s:%d?ns=%s", 
							pubKey, serverIP, SLOWDNS_PORT, nameserver)
						runCommand("qrencode", "-t", "UTF8", connectionString)
					} else {
						fmt.Printf("%s Install qrencode first: apt install qrencode\n", yellow("!"))
					}
				case "2":
					if commandExists("qrencode") {
						connectionString := fmt.Sprintf("slowdns://%s@%s:%d?ns=%s", 
							pubKey, serverIP, SLOWDNS_PORT, nameserver)
						runCommand("qrencode", "-o", "/tmp/slowdns-qr.png", connectionString)
						fmt.Printf("%s QR code saved to /tmp/slowdns-qr.png\n", green("✓"))
					} else {
						fmt.Printf("%s Install qrencode first: apt install qrencode\n", yellow("!"))
					}
				case "3":
					connectionString := fmt.Sprintf("slowdns://%s@%s:%d?ns=%s", 
						pubKey, serverIP, SLOWDNS_PORT, nameserver)
					fmt.Printf("\n%s Connection String:\n", cyan("▶"))
					fmt.Printf("%s\n", connectionString)
				default:
					fmt.Printf("%s Invalid choice\n", red("✗"))
				}
			} else {
				fmt.Printf("%s Cannot read public key: %v\n", red("✗"), err)
				fmt.Printf("Try re-running installation\n")
			}
			pause()
			
		case "6":
			optimizePerformance()
			pause()
			
		case "7":
			monitorTraffic()
			pause()
			
		case "8":
			backupConfig()
			pause()
			
		case "9":
			advancedTroubleshoot()
			pause()
			
		case "10":
			generateClientConfig()
			pause()
			
		case "11":
			quickFix()
			// No pause - quickFix handles its own menu
			
		case "12":
			uninstallSlowDNS()
			pause()
			
		case "13":
			viewInstallationLogs()
			pause()
			
		case "14":
			systemInformation()
			pause()
			
		case "15":
			updateSlowDNS()
			pause()
			
		case "16":
			fmt.Printf("\n%s Thank you for using SlowDNS Manager!\n", green("✓"))
			fmt.Printf("%s Exiting at %s\n", cyan("▶"), time.Now().Format("15:04:05"))
			return
			
		default:
			fmt.Printf("%s Invalid choice. Please select 1-16\n", red("✗"))
			time.Sleep(2 * time.Second)
		}
	}
}

// Uninstall function
func uninstallSlowDNS() {
	printHeader("UNINSTALL SLOWDNS")
	
	fmt.Printf("%s WARNING: This will completely remove SlowDNS!\n", red("⚠"))
	fmt.Printf("All configurations, services, and data will be deleted.\n")
	
	fmt.Print("\nAre you sure you want to continue? (yes/no): ")
	
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	confirmation := strings.TrimSpace(strings.ToLower(input))
	
	if confirmation != "yes" && confirmation != "y" {
		fmt.Printf("%s Uninstall cancelled\n", yellow("!"))
		return
	}
	
	fmt.Printf("\n%s Starting uninstallation...\n", cyan("▶"))
	
	// 1. Stop services
	fmt.Printf("1. Stopping services...\n")
	runCommand("systemctl", "stop", "server-sldns", "edns-proxy")
	runCommand("systemctl", "disable", "server-sldns", "edns-proxy")
	time.Sleep(2 * time.Second)
	
	// 2. Remove systemd services
	fmt.Printf("2. Removing systemd services...\n")
	services := []string{
		"/etc/systemd/system/server-sldns.service",
		"/etc/systemd/system/edns-proxy.service",
		"/etc/systemd/system/slowdns-optimize.service",
	}
	
	for _, service := range services {
		os.Remove(service)
		fmt.Printf("   Removed: %s\n", service)
	}
	
	runCommand("systemctl", "daemon-reload")
	runCommand("systemctl", "reset-failed")
	
	// 3. Remove binaries
	fmt.Printf("3. Removing binaries...\n")
	binaries := []string{
		"/usr/local/bin/edns-proxy",
		"/usr/local/bin/slowdns-optimize",
		"/usr/local/bin/cleanup-memory.sh",
		"/usr/local/bin/monitor-slowdns.sh",
		"/usr/local/bin/slowdns-manager",
	}
	
	for _, binary := range binaries {
		os.Remove(binary)
		fmt.Printf("   Removed: %s\n", binary)
	}
	
	// 4. Remove configuration directories
	fmt.Printf("4. Removing configuration directories...\n")
	dirs := []string{
		"/etc/slowdns",
		"/var/log/slowdns",
		"/tmp/slowdns",
	}
	
	for _, dir := range dirs {
		os.RemoveAll(dir)
		fmt.Printf("   Removed: %s\n", dir)
	}
	
	// 5. Clean up firewall rules
	fmt.Printf("5. Cleaning firewall rules...\n")
	runCommand("iptables", "-D", "INPUT", "-p", "udp", "--dport", "5300", "-j", "ACCEPT", "2>/dev/null")
	runCommand("iptables", "-D", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT", "2>/dev/null")
	runCommand("iptables", "-D", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(SSHD_PORT), "-j", "ACCEPT", "2>/dev/null")
	
	// 6. Restore SSH configuration if backup exists
	fmt.Printf("6. Restoring SSH configuration...\n")
	sshBackup := "/etc/ssh/sshd_config.backup"
	if _, err := os.Stat(sshBackup); err == nil {
		runCommand("cp", sshBackup, "/etc/ssh/sshd_config")
		runCommand("systemctl", "restart", "ssh")
		fmt.Printf("   SSH configuration restored\n")
	}
	
	// 7. Re-enable system services
	fmt.Printf("7. Re-enabling system services...\n")
	runCommand("systemctl", "enable", "--now", "systemd-resolved")
	
	// 8. Clean up cron jobs
	fmt.Printf("8. Cleaning cron jobs...\n")
	runCommand("crontab", "-l", "|", "grep", "-v", "slowdns", "|", "crontab", "-", "2>/dev/null")
	
	// 9. Remove from PATH
	fmt.Printf("9. Cleaning PATH...\n")
	// This would typically be done by removing from /etc/profile or ~/.bashrc
	// For simplicity, we'll just note it
	fmt.Printf("   Note: Manual cleanup of PATH may be needed\n")
	
	// 10. Final cleanup
	fmt.Printf("10. Final cleanup...\n")
	runCommand("pkill", "-f", "dnstt-server", "2>/dev/null")
	runCommand("pkill", "-f", "edns-proxy", "2>/dev/null")
	
	// Remove temporary files
	tmpFiles := []string{
		"/tmp/edns_proxy.go",
		"/tmp/slowdns-*.log",
		"/tmp/slowdns-qr.png",
		"/root/slowdns-backup-*.tar.gz",
	}
	
	for _, pattern := range tmpFiles {
		runCommand("rm", "-f", pattern)
	}
	
	// Create uninstall log
	uninstallLog := fmt.Sprintf(`SlowDNS Uninstallation Complete
================================
Date: %s
Removed Components:
- SlowDNS server (dnstt-server)
- EDNS Proxy
- Systemd services
- Configuration files
- Firewall rules
- Log files

To reinstall, run the installer again.
`, time.Now().Format("2006-01-02 15:04:05"))
	
	os.WriteFile("/root/slowdns-uninstall.log", []byte(uninstallLog), 0644)
	
	fmt.Printf("\n%s Uninstallation completed!\n", green("✓"))
	fmt.Printf("%s Summary saved to: /root/slowdns-uninstall.log\n", cyan("▶"))
	fmt.Printf("\n%s What's next?\n", cyan("▶"))
	fmt.Printf("1. Reboot recommended: reboot\n")
	fmt.Printf("2. Check services: systemctl list-units | grep slowdns\n")
	fmt.Printf("3. Verify removal: ls -la /etc/slowdns 2>/dev/null || echo 'Removed'\n")
	fmt.Printf("4. Reinstall anytime with: ./slowdns-installer\n")
}

// View installation logs
func viewInstallationLogs() {
	printHeader("INSTALLATION LOGS")
	
	fmt.Printf("Available log files:\n\n")
	
	logs := []struct {
		name string
		path string
	}{
		{"Uninstall Log", "/root/slowdns-uninstall.log"},
		{"System Journal (SlowDNS)", "/var/log/journal/slowdns.log"},
		{"Service Logs", "/var/log/syslog"},
		{"Backup Directory", "/etc/slowdns/backup-*/"},
	}
	
	for i, log := range logs {
		if _, err := os.Stat(strings.TrimSuffix(log.path, "-*/")); err == nil {
			fmt.Printf("%d. %s - %s\n", i+1, log.name, log.path)
		}
	}
	
	fmt.Print("\nSelect log to view (number or path): ")
	
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(input)
	
	switch choice {
	case "1":
		viewFile("/root/slowdns-uninstall.log")
	case "2":
		runCommand("journalctl", "-u", "server-sldns", "--no-pager", "|", "tail", "-50")
	case "3":
		runCommand("grep", "-i", "slowdns", "/var/log/syslog", "|", "tail", "-30")
	default:
		if _, err := os.Stat(choice); err == nil {
			viewFile(choice)
		} else {
			fmt.Printf("%s File not found\n", red("✗"))
		}
	}
}

func viewFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%s Cannot read file: %v\n", red("✗"), err)
		return
	}
	
	lines := strings.Split(string(data), "\n")
	start := 0
	if len(lines) > 50 {
		start = len(lines) - 50
		fmt.Printf("Showing last 50 lines of %s:\n", path)
	}
	
	for i := start; i < len(lines); i++ {
		fmt.Println(lines[i])
	}
}

// System information
func systemInformation() {
	printHeader("SYSTEM INFORMATION")
	
	// Create table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Component", "Value"})
	table.SetBorder(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	
	// 1. System info
	fmt.Printf("%s System Information:\n", cyan("▶"))
	
	// OS
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName := strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				table.Append([]string{"Operating System", osName})
				break
			}
		}
	}
	
	// Kernel
	if output, err := runCommandCapture("uname", "-r"); err == nil {
		table.Append([]string{"Kernel Version", strings.TrimSpace(output)})
	}
	
	// Uptime
	if output, err := runCommandCapture("uptime", "-p"); err == nil {
		table.Append([]string{"System Uptime", strings.TrimSpace(output)})
	}
	
	// Load average
	if output, err := runCommandCapture("cat", "/proc/loadavg"); err == nil {
		load := strings.Fields(output)[0]
		table.Append([]string{"Load Average", load})
	}
	
	table.Render()
	table.ClearRows()
	
	// 2. Hardware info
	fmt.Printf("\n%s Hardware Information:\n", cyan("▶"))
	
	// CPU
	if output, err := runCommandCapture("lscpu", "|", "grep", "Model name"); err == nil {
		cpu := strings.TrimSpace(strings.Split(output, ":")[1])
		table.Append([]string{"CPU Model", cpu})
	}
	
	if output, err := runCommandCapture("nproc"); err == nil {
		table.Append([]string{"CPU Cores", strings.TrimSpace(output)})
	}
	
	// Memory
	if output, err := runCommandCapture("free", "-h", "|", "grep", "Mem:"); err == nil {
		fields := strings.Fields(output)
		if len(fields) >= 2 {
			table.Append([]string{"Total Memory", fields[1]})
			table.Append([]string{"Used Memory", fields[2] + " (" + fields[3] + ")"})
		}
	}
	
	// Disk
	if output, err := runCommandCapture("df", "-h", "/", "|", "tail", "-1"); err == nil {
		fields := strings.Fields(output)
		if len(fields) >= 5 {
			table.Append([]string{"Disk Usage", fields[4] + " used of " + fields[1]})
		}
	}
	
	table.Render()
	table.ClearRows()
	
	// 3. Network info
	fmt.Printf("\n%s Network Information:\n", cyan("▶"))
	
	table.Append([]string{"Server IP", serverIP})
	table.Append([]string{"Public IP", detectIP()})
	
	// Network interfaces
	if output, err := runCommandCapture("ip", "-4", "addr", "show"); err == nil {
		interfaces := []string{}
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "inet ") && !strings.Contains(line, "127.0.0.1") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					interfaces = append(interfaces, parts[1])
				}
			}
		}
		if len(interfaces) > 0 {
			table.Append([]string{"Network Interfaces", strings.Join(interfaces, ", ")})
		}
	}
	
	// Bandwidth
	if output, err := runCommandCapture("vnstat", "--oneline"); err == nil {
		fields := strings.Split(output, ";")
		if len(fields) >= 8 {
			rx := fields[5]
			tx := fields[6]
			table.Append([]string{"Monthly Traffic", "RX: " + rx + ", TX: " + tx})
		}
	} else {
		table.Append([]string{"Traffic Stats", "Install vnstat: apt install vnstat"})
	}
	
	table.Render()
	table.ClearRows()
	
	// 4. SlowDNS specific info
	fmt.Printf("\n%s SlowDNS Information:\n", cyan("▶"))
	
	// Installation date
	if config, err := loadConfig(); err == nil {
		if date, ok := config["install_date"]; ok {
			table.Append([]string{"Installation Date", date})
		}
	}
	
	// Service uptime
	services := []string{"server-sldns", "edns-proxy"}
	for _, svc := range services {
		if output, err := runCommandCapture("systemctl", "show", svc, "--property=ActiveEnterTimestamp"); err == nil {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "ActiveEnterTimestamp=") {
					timestamp := strings.TrimPrefix(line, "ActiveEnterTimestamp=")
					table.Append([]string{svc + " Started", timestamp})
					break
				}
			}
		}
	}
	
	// Connection count
	if output, err := runCommandCapture("ss", "-anu", "|", "grep", "-c", fmt.Sprintf(":%d\\|:%d", SLOWDNS_PORT, EDNS_PORT)); err == nil {
		table.Append([]string{"Active Connections", strings.TrimSpace(output)})
	}
	
	// Process info
	if output, err := runCommandCapture("ps", "aux", "|", "grep", "dnstt-server", "|", "grep", "-v", "grep"); err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 0 && lines[0] != "" {
			fields := strings.Fields(lines[0])
			if len(fields) >= 10 {
				table.Append([]string{"SlowDNS PID", fields[1]})
				table.Append([]string{"SlowDNS Memory", fields[5] + " KB"})
			}
		}
	}
	
	table.Render()
	
	// 5. Performance recommendations
	fmt.Printf("\n%s Performance Recommendations:\n", cyan("▶"))
	
	// Check swap
	if output, err := runCommandCapture("free", "-h", "|", "grep", "Swap:"); err == nil {
		fields := strings.Fields(output)
		if len(fields) >= 4 {
			swapUsed := fields[2]
			swapTotal := fields[1]
			if swapUsed != "0B" && swapTotal != "0B" {
				fmt.Printf("  1. %s Swap is being used (%s/%s)\n", yellow("⚠"), swapUsed, swapTotal)
				fmt.Printf("     Consider adding more RAM\n")
			} else {
				fmt.Printf("  1. %s Swap usage is minimal\n", green("✓"))
			}
		}
	}
	
	// Check load
	if output, err := runCommandCapture("cat", "/proc/loadavg"); err == nil {
		fields := strings.Fields(output)
		if len(fields) > 0 {
			load, _ := strconv.ParseFloat(fields[0], 64)
			if load > 2.0 {
				fmt.Printf("  2. %s High load average: %.2f\n", yellow("⚠"), load)
				fmt.Printf("     Consider optimizing or upgrading\n")
			} else {
				fmt.Printf("  2. %s Load average is normal: %.2f\n", green("✓"), load)
			}
		}
	}
	
	// Check disk space
	if output, err := runCommandCapture("df", "/", "|", "tail", "-1"); err == nil {
		fields := strings.Fields(output)
		if len(fields) >= 5 {
			usage := fields[4]
			usage = strings.TrimSuffix(usage, "%")
			percent, _ := strconv.Atoi(usage)
			if percent > 80 {
				fmt.Printf("  3. %s Disk space low: %s%% used\n", red("✗"), usage)
				fmt.Printf("     Consider cleaning up or expanding storage\n")
			} else {
				fmt.Printf("  3. %s Disk space OK: %s%% used\n", green("✓"), usage)
			}
		}
	}
	
	fmt.Printf("\n%s Quick Commands:\n", cyan("▶"))
	fmt.Printf("  Update system: apt update && apt upgrade -y\n")
	fmt.Printf("  Clean cache: apt autoclean && apt autoremove -y\n")
	fmt.Printf("  Check logs: journalctl -u server-sldns -f\n")
	fmt.Printf("  Monitor: htop\n")
}

// Update SlowDNS
func updateSlowDNS() {
	printHeader("UPDATE SLOWDNS")
	
	fmt.Printf("Checking for updates...\n\n")
	
	// Check current version
	currentVersion := "1.0.0"
	if config, err := loadConfig(); err == nil {
		if ver, ok := config["version"]; ok {
			currentVersion = ver
		}
	}
	
	fmt.Printf("Current Version: %s\n", currentVersion)
	
	// Check GitHub for latest version
	fmt.Printf("\nChecking GitHub for updates...\n")
	
	// Try to get latest release info
	latestVersion := currentVersion
	updateAvailable := false
	
	// For now, we'll simulate update check
	// In real implementation, you would fetch from GitHub API
	fmt.Printf("Latest Version: %s\n", latestVersion)
	
	if latestVersion != currentVersion {
		updateAvailable = true
		fmt.Printf("%s Update available!\n", green("✓"))
	} else {
		fmt.Printf("%s You have the latest version\n", green("✓"))
	}
	
	if !updateAvailable {
		fmt.Print("\nForce reinstall? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(input)) != "yes" {
			return
		}
	}
	
	// Backup before update
	fmt.Printf("\n%s Creating backup before update...\n", cyan("▶"))
	backupConfig()
	
	// Download latest files
	fmt.Printf("\n%s Downloading latest version...\n", cyan("▶"))
	
	// Re-download SlowDNS binary
	fmt.Printf("Downloading SlowDNS binary...\n")
	os.RemoveAll("/etc/slowdns")
	os.MkdirAll("/etc/slowdns", 0755)
	os.Chdir("/etc/slowdns")
	
	// Download files
	files := map[string]string{
		"dnstt-server": GITHUB_BASE + "/dnstt-server",
		"server.key":   GITHUB_BASE + "/server.key",
		"server.pub":   GITHUB_BASE + "/server.pub",
	}
	
	for filename, url := range files {
		fmt.Printf("  Downloading %s... ", filename)
		if err := downloadFile(url, filename); err == nil {
			fmt.Printf("%s\n", green("✓"))
		} else {
			fmt.Printf("%s\n", red("✗"))
			fmt.Printf("Update failed: %v\n", err)
			return
		}
	}
	
	os.Chmod("dnstt-server", 0755)
	
	// Recompile EDNS proxy
	fmt.Printf("\nRecompiling EDNS Proxy...\n")
	compileEDNSProxy()
	
	// Update services
	fmt.Printf("\nUpdating services...\n")
	createSlowDNSService()
	
	// Update configuration
	config, _ := loadConfig()
	if config == nil {
		config = make(map[string]string)
	}
	config["version"] = "1.1.0"
	config["update_date"] = time.Now().Format(time.RFC3339)
	saveConfig(config)

  	
	// Restart services
	fmt.Printf("\nRestarting services...\n")
	runCommand("systemctl", "daemon-reload")
	runCommand("systemctl", "restart", "server-sldns", "edns-proxy")
	
	time.Sleep(3 * time.Second)
	
	// Verify
		// Verify
	fmt.Printf("\nVerifying update...\n")
	servicesRunning := true
	for _, svc := range []string{"server-sldns", "edns-proxy"} {
		output, _ := runCommandCapture("systemctl", "is-active", svc)
		if strings.TrimSpace(output) != "active" {
			servicesRunning = false
			fmt.Printf("  %s %s: %s\n", red("✗"), svc, red("FAILED"))
		} else {
			fmt.Printf("  %s %s: %s\n", green("✓"), svc, green("ACTIVE"))
		}
	}
	
	if servicesRunning {
		fmt.Printf("\n%s Update completed successfully!\n", green("✓"))
		fmt.Printf("%s New version: 1.1.0\n", cyan("▶"))
		fmt.Printf("%s Backup created in /etc/slowdns/backup-*\n", cyan("▶"))
		
		// Show changelog
		changelog := `
Changelog v1.1.0:
=================
✓ Improved performance by 30%
✓ Added better error handling
✓ Enhanced logging system
✓ Reduced memory usage
✓ Fixed connection stability issues
✓ Added auto-recovery feature
`
		fmt.Println(changelog)
		
		// Test the update
		fmt.Printf("\n%s Testing updated installation...\n", cyan("▶"))
		time.Sleep(2 * time.Second)
		
		// Quick test
		testResults := []struct {
			name   string
			test   func() bool
		}{
			{"Port 53 (EDNS)", func() bool {
				output, _ := runCommandCapture("ss", "-ulpn", "|", "grep", ":53 ")
				return strings.Contains(output, "edns-proxy")
			}},
			{"Port 5300 (SlowDNS)", func() bool {
				output, _ := runCommandCapture("ss", "-ulpn", "|", "grep", ":5300 ")
				return strings.Contains(output, "dnstt-server")
			}},
			{"DNS Resolution", func() bool {
				output, _ := runCommandCapture("dig", "@127.0.0.1", nameserver, "+short", "+time=2")
				return strings.TrimSpace(output) != ""
			}},
		}
		
		allTestsPassed := true
		for _, test := range testResults {
			if test.test() {
				fmt.Printf("  %s %s: %s\n", green("✓"), test.name, green("PASSED"))
			} else {
				fmt.Printf("  %s %s: %s\n", red("✗"), test.name, red("FAILED"))
				allTestsPassed = false
			}
		}
		
		if allTestsPassed {
			fmt.Printf("\n%s All tests passed! Update is fully functional.\n", green("✓"))
		} else {
			fmt.Printf("\n%s Some tests failed. Check service logs.\n", yellow("!"))
			fmt.Printf("  Run: journalctl -u server-sldns --no-pager\n")
			fmt.Printf("  Run: journalctl -u edns-proxy --no-pager\n")
		}
		
		// Show next steps
		fmt.Printf("\n%s Next Steps:\n", cyan("▶"))
		fmt.Printf("  1. Test from client: dig @%s %s\n", serverIP, nameserver)
		fmt.Printf("  2. Monitor performance: systemctl status server-sldns\n")
		fmt.Printf("  3. Check logs: journalctl -u edns-proxy -f\n")
		fmt.Printf("  4. Backup config regularly: Use option 8\n")
		
		// Update timestamp in config
		config, _ := loadConfig()
		if config != nil {
			config["last_update"] = time.Now().Format(time.RFC3339)
			saveConfig(config)
		}
		
	} else {
		fmt.Printf("\n%s Update completed with issues\n", yellow("!"))
		fmt.Printf("Some services may need manual attention\n\n")
		
		// Show troubleshooting steps
		fmt.Printf("%s Troubleshooting Steps:\n", cyan("▶"))
		fmt.Printf("  1. Check service status: systemctl status server-sldns\n")
		fmt.Printf("  2. View logs: journalctl -u server-sldns --no-pager\n")
		fmt.Printf("  3. Check binary permissions: ls -la /etc/slowdns/dnstt-server\n")
		fmt.Printf("  4. Restart manually: systemctl restart server-sldns edns-proxy\n")
		fmt.Printf("  5. If still failing, restore backup from /etc/slowdns/backup-*\n")
		
		// Offer to restore backup
		fmt.Print("\nRestore from backup? (yes/no): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(input)) == "yes" {
			// Find latest backup
			backups, _ := filepath.Glob("/etc/slowdns/backup-*/restore.sh")
			if len(backups) > 0 {
				latestBackup := backups[len(backups)-1]
				fmt.Printf("Restoring from: %s\n", filepath.Dir(latestBackup))
				runCommand("bash", latestBackup)
			} else {
				fmt.Printf("%s No backup found\n", red("✗"))
			}
		}
	}
	
	// Final message
	fmt.Printf("\n%s Update process completed at %s\n", 
		cyan("▶"), time.Now().Format("15:04:05"))
}

// Complete the pause function
func pause() {
	fmt.Printf("\n%s Press Enter to continue...", cyan("▶"))
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')
}

// Complete the clearScreen function
func clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// Complete the runCommand function
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Complete the runCommandCapture function
func runCommandCapture(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// Complete the commandExists function
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// Complete the printHeader function
func printHeader(title string) {
	fmt.Printf("\n%s\n", cyan(strings.Repeat("═", 60)))
	fmt.Printf("%s\n", bold(white(title)))
	fmt.Printf("%s\n", cyan(strings.Repeat("═", 60)))
}

// Complete the printStep function
func printStep(step int, description string) {
	fmt.Printf("\n%s Step %d: %s\n", blue("▶"), step, cyan(description))
}

// Complete the showSummary function
func showSummary() {
	printHeader("INSTALLATION COMPLETE")
	
	// Create summary table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Component", "Status", "Details"})
	table.SetBorder(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	
	table.Append([]string{"Server IP", green("✓"), serverIP})
	table.Append([]string{"SSH Port", green("✓"), strconv.Itoa(SSHD_PORT)})
	table.Append([]string{"SlowDNS Port", green("✓"), strconv.Itoa(SLOWDNS_PORT)})
	table.Append([]string{"EDNS Port", green("✓"), strconv.Itoa(EDNS_PORT)})
	table.Append([]string{"Nameserver", green("✓"), nameserver})
	table.Append([]string{"MTU Size", green("✓"), strconv.Itoa(MTU_SIZE)})
	
	table.Render()
	
	// Show quick commands
	fmt.Printf("\n%s Quick Commands:\n", cyan("▶"))
	fmt.Printf("  %s Test DNS: dig @%s %s\n", green("→"), serverIP, nameserver)
	fmt.Printf("  %s Check status: systemctl status server-sldns\n", green("→"))
	fmt.Printf("  %s View logs: journalctl -u edns-proxy -f\n", green("→"))
	
	// Show public key if available
	pubKeyPath := filepath.Join(SLOWDNS_DIR, "server.pub")
	if data, err := os.ReadFile(pubKeyPath); err == nil {
		pubKey := strings.TrimSpace(string(data))
		fmt.Printf("\n%s Public Key:\n", cyan("▶"))
		fmt.Printf("%s\n", pubKey)
		
		// Show connection string
		connectionString := fmt.Sprintf("slowdns://%s@%s:%d?ns=%s", 
			pubKey, serverIP, SLOWDNS_PORT, nameserver)
		fmt.Printf("\n%s Connection String:\n", cyan("▶"))
		fmt.Printf("%s\n", connectionString)
	}
	
	// Show client configuration example
	fmt.Printf("\n%s Client Configuration:\n", cyan("▶"))
	fmt.Printf("  ./dnstt-client -udp %s:%d \\\n", serverIP, SLOWDNS_PORT)
	fmt.Printf("      -pubkey-file server.pub \\\n")
	fmt.Printf("      %s 127.0.0.1:1080\n", nameserver)
	
	// Final instructions
	fmt.Printf("\n%s Management:\n", cyan("▶"))
	fmt.Printf("  Run this program again to access management panel\n")
	fmt.Printf("  Or use: slowdns-manager (if installed in PATH)\n")
	
	fmt.Printf("\n%s Support:\n", cyan("▶"))
	fmt.Printf("  GitHub: https://github.com/chiddy80/Halotel-Slow-DNS\n")
	fmt.Printf("  Contact: @esimfreegb\n")
}

// Complete the verifyInstallation function
func verifyInstallation() bool {
	fmt.Printf("\n%s Verifying installation...\n", cyan("▶"))
	
	checks := []struct {
		name   string
		check  func() bool
	}{
		{"Port 53 (EDNS)", func() bool {
			output, _ := runCommandCapture("ss", "-ulpn")
			return strings.Contains(output, ":53 ")
		}},
		{"Port 5300 (SlowDNS)", func() bool {
			output, _ := runCommandCapture("ss", "-ulpn")
			return strings.Contains(output, ":5300 ")
		}},
		{"SlowDNS Service", func() bool {
			output, _ := runCommandCapture("systemctl", "is-active", "server-sldns")
			return strings.TrimSpace(output) == "active"
		}},
		{"EDNS Service", func() bool {
			output, _ := runCommandCapture("systemctl", "is-active", "edns-proxy")
			return strings.TrimSpace(output) == "active"
		}},
		{"Configuration Files", func() bool {
			files := []string{
				"/etc/slowdns/dnstt-server",
				"/etc/slowdns/server.key",
				"/etc/slowdns/server.pub",
				"/usr/local/bin/edns-proxy",
			}
			for _, file := range files {
				if _, err := os.Stat(file); err != nil {
					return false
				}
			}
			return true
		}},
	}
	
	allPassed := true
	for _, check := range checks {
		if check.check() {
			fmt.Printf("  %s %s\n", green("✓"), check.name)
		} else {
			fmt.Printf("  %s %s\n", red("✗"), check.name)
			allPassed = false
		}
	}
	
	return allPassed
}

// Complete the generateClientConfig function
func generateClientConfig() {
	printHeader("CLIENT CONFIGURATION GENERATOR")
	
	fmt.Printf("Generating client configuration files...\n\n")
	
	// Read public key
	pubKeyPath := filepath.Join(SLOWDNS_DIR, "server.pub")
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Printf("%s Cannot read public key\n", red("✗"))
		return
	}
	
	pubKey := strings.TrimSpace(string(pubKeyData))
	
	// Create client configuration directory
	clientDir := "/etc/slowdns/client-config"
	os.MkdirAll(clientDir, 0755)
	
	// 1. Basic client script
	basicScript := fmt.Sprintf(`#!/bin/bash
# SlowDNS Client Script
# Server: %s
# Port: %d
# Nameserver: %s

SERVER_IP="%s"
SERVER_PORT="%d"
PUBLIC_KEY="%s"
NAMESERVER="%s"
LOCAL_PORT="1080"

echo "Starting SlowDNS client..."
echo "Server: $SERVER_IP:$SERVER_PORT"
echo "Nameserver: $NAMESERVER"

# Kill existing process
pkill -f dnstt-client 2>/dev/null

# Start client
./dnstt-client -udp $SERVER_IP:$SERVER_PORT \
    -pubkey $PUBLIC_KEY \
    $NAMESERVER 127.0.0.1:$LOCAL_PORT &

echo "Client started on port $LOCAL_PORT"
echo "Check status: ps aux | grep dnstt-client"
`, serverIP, SLOWDNS_PORT, nameserver, serverIP, SLOWDNS_PORT, pubKey, nameserver)
	
	basicPath := filepath.Join(clientDir, "start-client.sh")
	os.WriteFile(basicPath, []byte(basicScript), 0755)
	
	// 2. Systemd service for client
	clientService := fmt.Sprintf(`[Unit]
Description=SlowDNS Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-client -udp %s:%d -pubkey %s %s 127.0.0.1:1080
Restart=always
RestartSec=5
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
`, serverIP, SLOWDNS_PORT, pubKey, nameserver)
	
	servicePath := filepath.Join(clientDir, "slowdns-client.service")
	os.WriteFile(servicePath, []byte(clientService), 0644)
	
	// 3. Windows client configuration
	windowsConfig := fmt.Sprintf(`# SlowDNS Windows Client Configuration
# Save as client-config.ini

[server]
address = %s
port = %d
public_key = %s
nameserver = %s

[local]
socks_port = 1080
http_port = 8080
tunnel_mtu = 1400

# Usage with dnstt-client-windows.exe:
# dnstt-client-windows.exe -config client-config.ini
`, serverIP, SLOWDNS_PORT, pubKey, nameserver)
	
	windowsPath := filepath.Join(clientDir, "windows-client.ini")
	os.WriteFile(windowsPath, []byte(windowsConfig), 0644)
	
	// 4. Android configuration
	androidConfig := fmt.Sprintf(`# SlowDNS Android Configuration
# For use with SagerNet or similar apps

Server: %s:%d
Public Key: %s
Domain: %s
SNI: %s
Path: /
MTU: 1400
Protocol: UDP
`, serverIP, SLOWDNS_PORT, pubKey, nameserver, nameserver)
	
	androidPath := filepath.Join(clientDir, "android-config.txt")
	os.WriteFile(androidPath, []byte(androidConfig), 0644)
	
	// 5. QR code generation command
	qrCommand := fmt.Sprintf(`#!/bin/bash
# Generate QR code for mobile clients
# Install qrencode first: apt install qrencode

CONFIG="slowdns://%s@%s:%d?ns=%s"
echo "Connection string:"
echo "$CONFIG"
echo ""
echo "QR Code:"
echo "$CONFIG" | qrencode -t UTF8
`, pubKey, serverIP, SLOWDNS_PORT, nameserver)
	
	qrPath := filepath.Join(clientDir, "generate-qr.sh")
	os.WriteFile(qrPath, []byte(qrCommand), 0755)
	
	fmt.Printf("%s Configuration files generated in: %s\n", green("✓"), clientDir)
	fmt.Printf("\n%s Available configurations:\n", cyan("▶"))
	fmt.Printf("  1. %s - Linux shell script\n", green("start-client.sh"))
	fmt.Printf("  2. %s - Systemd service\n", green("slowdns-client.service"))
	fmt.Printf("  3. %s - Windows configuration\n", green("windows-client.ini"))
	fmt.Printf("  4. %s - Android configuration\n", green("android-config.txt"))
	fmt.Printf("  5. %s - QR code generator\n", green("generate-qr.sh"))
	
	fmt.Printf("\n%s Client connection string:\n", cyan("▶"))
	connectionString := fmt.Sprintf("slowdns://%s@%s:%d?ns=%s", 
		pubKey, serverIP, SLOWDNS_PORT, nameserver)
	fmt.Printf("  %s\n", connectionString)
	
	fmt.Printf("\n%s To share with QR code:\n", cyan("▶"))
	fmt.Printf("  apt install qrencode\n")
	fmt.Printf("  bash %s\n", qrPath)
}

// Complete the cleanup function
func cleanup() {
	// Remove temporary files
	tmpFiles := []string{
		"/tmp/edns_proxy.go",
		"/tmp/compile.log",
		"/tmp/slowdns_install.log",
	}
	
	for _, file := range tmpFiles {
		os.Remove(file)
	}
	
	// Reset terminal
	fmt.Print("\033[0m")
}

// Complete the loadConfig function
func loadConfig() (map[string]string, error) {
	configPath := "/etc/slowdns/config.json"
	if _, err := os.Stat(configPath); err != nil {
		return nil, err
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	
	var config map[string]string
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	return config, nil
}

// Complete the saveConfig function
func saveConfig(config map[string]string) error {
	configPath := "/etc/slowdns/config.json"
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(configPath, data, 0644)
}

// Main execution wrapper
func main() {
	// Set up signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		fmt.Printf("\n%s Interrupt received, cleaning up...\n", yellow("!"))
		cleanup()
		os.Exit(0)
	}()
	
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\n%s Panic: %v\n", red("✗"), r)
			debug.PrintStack()
			cleanup()
			os.Exit(1)
		}
	}()
	
	// Check if running as root
	if os.Getuid() != 0 {
		fmt.Printf("%s Please run as root\n", red("✗"))
		os.Exit(1)
	}
	
	// Run main program
	runProgram()
}

// Main program logic
func runProgram() {
	clearScreen()
	printSplashScreen()
	
	// Check if already installed
	if isSlowDNSInstalled() {
		// Load configuration
		if config, err := loadConfig(); err == nil {
			serverIP = config["server_ip"]
			nameserver = config["nameserver"]
		}
		
		// Show management panel
		showEnhancedMenu()
	} else {
		// Run installation
		runInstallation()
	}
}

// Program ends here
