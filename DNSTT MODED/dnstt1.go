package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ---------------- CONFIG ----------------
const (
	DEFAULT_NAMESERVER   = "dns.example.com"
	SLOWDNS_DIR          = "/etc/slowdns"
	LISTEN_PORT          = 5300
	SSH_PORT             = 22
	EDNS_EXTERNAL_SIZE   = 512
	EDNS_INTERNAL_SIZE   = 1800
	MAX_PACKET_SIZE      = 4096
	WORKERS              = 128
	UPSTREAM_TIMEOUT     = 3 * time.Second
	SERVER_KEY_URL       = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.key"
	SERVER_PUB_URL       = "https://raw.githubusercontent.com/chiddy80/Halotel-Slow-DNS/main/DNSTT%20MODED/server.pub"
)

// ---------------- TYPES ----------------
type packet struct {
	data []byte
	addr *net.UDPAddr
}

// ---------------- EDNS PATCH ----------------
func patchEDNS(data []byte, size uint16) []byte {
	if len(data) < 12 {
		return data
	}
	arcount := binary.BigEndian.Uint16(data[10:12])
	if arcount == 0 {
		return data
	}
	offset := 12
	skipName := func(buf []byte, off int) int {
		for off < len(buf) {
			l := buf[off]
			off++
			if l == 0 {
				break
			}
			if l&0xC0 == 0xC0 {
				off++
				break
			}
			off += int(l)
		}
		return off
	}
	qdcount := binary.BigEndian.Uint16(data[4:6])
	for i := 0; i < int(qdcount); i++ {
		offset = skipName(data, offset) + 4
		if offset >= len(data) {
			return data
		}
	}
	out := make([]byte, len(data))
	copy(out, data)
	for i := 0; i < int(arcount); i++ {
		offset = skipName(data, offset)
		if offset+10 > len(data) {
			return data
		}
		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		if rtype == 41 {
			binary.BigEndian.PutUint16(out[offset+2:offset+4], size)
			return out
		}
		rdlen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10 + int(rdlen)
	}
	return data
}

// ---------------- WORKER ----------------
func worker(wg *sync.WaitGroup, in <-chan packet, listener *net.UDPConn, nameserver string) {
	defer wg.Done()
	buf := make([]byte, MAX_PACKET_SIZE)
	for pkt := range in {
		upConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(nameserver), Port: LISTEN_PORT})
		if err != nil {
			continue
		}
		upConn.SetDeadline(time.Now().Add(UPSTREAM_TIMEOUT))
		_, err = upConn.Write(patchEDNS(pkt.data, EDNS_INTERNAL_SIZE))
		if err != nil {
			upConn.Close()
			continue
		}
		n, _, err := upConn.ReadFromUDP(buf)
		if err != nil {
			upConn.Close()
			continue
		}
		upConn.Close()
		resp := patchEDNS(buf[:n], EDNS_EXTERNAL_SIZE)
		listener.WriteToUDP(resp, pkt.addr)
	}
}

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

// ---------------- SSH & FIREWALL ----------------
func setupSSH(port int) error {
	fmt.Printf("[*] Configuring OpenSSH on port %d...\n", port)
	if !fileExists("/etc/ssh/sshd_config.bak") {
		if err := runCommand("cp", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.bak"); err != nil {
			return err
		}
	}
	conf := fmt.Sprintf(`
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
UseDNS no
`, port)
	if err := os.WriteFile("/etc/ssh/sshd_config", []byte(conf), 0600); err != nil {
		return err
	}
	return runCommand("systemctl", "restart", "sshd")
}

func setupFirewall(sshPort, dnsPort int) error {
	fmt.Println("[*] Setting up iptables rules...")
	commands := [][]string{
		{"iptables", "-F"},
		{"iptables", "-X"},
		{"iptables", "-t", "nat", "-F"},
		{"iptables", "-t", "nat", "-X"},
		{"iptables", "-P", "INPUT", "ACCEPT"},
		{"iptables", "-P", "FORWARD", "ACCEPT"},
		{"iptables", "-P", "OUTPUT", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", sshPort), "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", dnsPort), "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", dnsPort), "-j", "ACCEPT"},
		{"iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"},
	}
	for _, cmd := range commands {
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func disableIPv6() error {
	fmt.Println("[*] Disabling IPv6...")
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("1"), 0644); err != nil {
		return err
	}
	return runCommand("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1")
}

// ---------------- MAIN ----------------
func main() {
	if os.Geteuid() != 0 {
		fmt.Println("[✗] Please run as root")
		return
	}

	nameserver := ""
	fmt.Printf("Enter nameserver (default: %s): ", DEFAULT_NAMESERVER)
	fmt.Scanln(&nameserver)
	if nameserver == "" {
		nameserver = DEFAULT_NAMESERVER
	}

	fmt.Println("[✓] Starting SlowDNS Installer + Proxy...")

	// SSH setup
	if err := setupSSH(SSH_PORT); err != nil {
		log.Fatalf("[✗] SSH setup failed: %v", err)
	}
	fmt.Println("[✓] SSH configured")

	// Firewall
	if err := setupFirewall(SSH_PORT, LISTEN_PORT); err != nil {
		log.Fatalf("[✗] Firewall setup failed: %v", err)
	}
	fmt.Println("[✓] Firewall configured")

	// Disable IPv6
	if err := disableIPv6(); err != nil {
		log.Fatalf("[✗] IPv6 disable failed: %v", err)
	}
	fmt.Println("[✓] IPv6 disabled")

	// Create SlowDNS directory
	if !fileExists(SLOWDNS_DIR) {
		if err := os.MkdirAll(SLOWDNS_DIR, 0755); err != nil {
			log.Fatalf("[✗] Failed to create directory: %v", err)
		}
	}

	// Download keys
	fmt.Println("[*] Downloading server.key and server.pub...")
	if err := downloadFile(SERVER_KEY_URL, filepath.Join(SLOWDNS_DIR, "server.key")); err != nil {
		log.Fatalf("[✗] Failed to download server.key: %v", err)
	}
	if err := downloadFile(SERVER_PUB_URL, filepath.Join(SLOWDNS_DIR, "server.pub")); err != nil {
		log.Fatalf("[✗] Failed to download server.pub: %v", err)
	}
	fmt.Println("[✓] Keys downloaded")

	// Start SlowDNS/EDNS Proxy
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: LISTEN_PORT}
	listener, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("[✗] Failed to bind UDP port %d: %v", LISTEN_PORT, err)
	}
	defer listener.Close()
	fmt.Printf("[✓] SlowDNS Proxy listening on UDP port %d\n", LISTEN_PORT)

	jobs := make(chan packet, 1024)
	var wg sync.WaitGroup
	for i := 0; i < WORKERS; i++ {
		wg.Add(1)
		go worker(&wg, jobs, listener, nameserver)
	}

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("[!] Shutting down...")
		close(jobs)
		listener.Close()
	}()

	buf := make([]byte, MAX_PACKET_SIZE)
	for {
		n, addr, err := listener.ReadFromUDP(buf)
		if err != nil {
			break
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case jobs <- packet{data: data, addr: addr}:
		default:
		}
	}

	wg.Wait()
	fmt.Println("[✓] SlowDNS Proxy stopped gracefully")
}
