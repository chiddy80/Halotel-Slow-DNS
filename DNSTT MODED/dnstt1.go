package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// ---------------- CONFIG ----------------
const (
	SLOWDNS_DIR      = "/etc/slowdns"
	DEFAULT_NS       = "dns.example.com"
	DNSTT_SERVER_URL = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/dnstt-server"
	SERVER_KEY_URL   = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
	SERVER_PUB_URL   = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
	EDNS_PROXY_GO    = "/etc/slowdns/edns_proxy.go"
	SLOWDNS_SERVICE  = "/etc/systemd/system/server-sldns.service"
	EDNS_SERVICE     = "/etc/systemd/system/edns-proxy.service"
)

// ---------------- UTILS ----------------
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func ensureGoInstalled() {
	if _, err := exec.LookPath("go"); err != nil {
		fmt.Println("[!] Go not found, installing...")
		runCommand("apt", "update")
		runCommand("apt", "install", "-y", "golang")
		fmt.Println("[✓] Go installed")
	}
}

// ---------------- MAIN ----------------
func main() {
	if os.Geteuid() != 0 {
		log.Fatal("[✗] Please run as root")
	}

	// Ensure Go is installed
	ensureGoInstalled()

	// Ask for nameserver
	var ns string
	fmt.Printf("Enter nameserver (default %s): ", DEFAULT_NS)
	fmt.Scanln(&ns)
	if ns == "" {
		ns = DEFAULT_NS
	}

	// Create SlowDNS directory
	fmt.Println("[*] Creating SlowDNS directory...")
	os.MkdirAll(SLOWDNS_DIR, 0755)

	// Download SlowDNS files
	fmt.Println("[*] Downloading dnstt-server...")
	if err := downloadFile(DNSTT_SERVER_URL, filepath.Join(SLOWDNS_DIR, "dnstt-server")); err != nil {
		log.Fatal("[✗] Failed to download dnstt-server:", err)
	}
	runCommand("chmod", "+x", filepath.Join(SLOWDNS_DIR, "dnstt-server"))

	fmt.Println("[*] Downloading server.key...")
	if err := downloadFile(SERVER_KEY_URL, filepath.Join(SLOWDNS_DIR, "server.key")); err != nil {
		log.Fatal("[✗] Failed to download server.key:", err)
	}
	runCommand("chmod", "600", filepath.Join(SLOWDNS_DIR, "server.key"))

	fmt.Println("[*] Downloading server.pub...")
	if err := downloadFile(SERVER_PUB_URL, filepath.Join(SLOWDNS_DIR, "server.pub")); err != nil {
		log.Fatal("[✗] Failed to download server.pub:", err)
	}

	// Create systemd service for SlowDNS
	fmt.Println("[*] Creating SlowDNS systemd service...")
	serviceContent := fmt.Sprintf(`[Unit]
Description=SlowDNS Server
After=network.target sshd.service

[Service]
Type=simple
ExecStart=%s/dnstt-server -udp :5300 -mtu 1800 -privkey-file %s/server.key %s 127.0.0.1:22
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
`, SLOWDNS_DIR, SLOWDNS_DIR, ns)

	os.WriteFile(SLOWDNS_SERVICE, []byte(serviceContent), 0644)
	runCommand("systemctl", "daemon-reload")
	runCommand("systemctl", "enable", "server-sldns")
	runCommand("systemctl", "restart", "server-sldns")

	// Create systemd service for EDNS Proxy
	if fileExists(EDNS_PROXY_GO) {
		fmt.Println("[*] Creating EDNS Proxy systemd service...")
		ednsService := fmt.Sprintf(`[Unit]
Description=EDNS Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/go run %s
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
`, EDNS_PROXY_GO)
		os.WriteFile(EDNS_SERVICE, []byte(ednsService), 0644)
		runCommand("systemctl", "daemon-reload")
		runCommand("systemctl", "enable", "edns-proxy")
		runCommand("systemctl", "restart", "edns-proxy")
	}

	fmt.Println("[✓] Installation complete. SlowDNS and EDNS proxy running.")
}
