package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	LISTEN_ADDR   = ":53"
	UPSTREAM_ADDR = "127.0.0.1:5300"

	EXTERNAL_EDNS = 512
	INTERNAL_EDNS = 1800

	MAX_PACKET_SIZE = 4096
	WORKERS         = 128
	UPSTREAM_TIMEOUT = 3 * time.Second
)

type packet struct {
	data []byte
	addr *net.UDPAddr
}

/* ---------------- EDNS PATCH ---------------- */

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

/* ---------------- WORKER ---------------- */

func worker(
	wg *sync.WaitGroup,
	in <-chan packet,
	listener *net.UDPConn,
	upstream *net.UDPConn,
) {
	defer wg.Done()

	buf := make([]byte, MAX_PACKET_SIZE)

	for pkt := range in {
		upstream.SetDeadline(time.Now().Add(UPSTREAM_TIMEOUT))

		_, err := upstream.Write(patchEDNS(pkt.data, INTERNAL_EDNS))
		if err != nil {
			continue
		}

		n, _, err := upstream.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		resp := patchEDNS(buf[:n], EXTERNAL_EDNS)
		listener.WriteToUDP(resp, pkt.addr)
	}
}

/* ---------------- MAIN ---------------- */

func main() {
	log.Println("[EDNS] Starting hardened Go EDNS proxy")

	laddr, err := net.ResolveUDPAddr("udp", LISTEN_ADDR)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	uaddr, err := net.ResolveUDPAddr("udp", UPSTREAM_ADDR)
	if err != nil {
		log.Fatal(err)
	}

	upstream, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		log.Fatal(err)
	}
	defer upstream.Close()

	jobs := make(chan packet, 1024)

	var wg sync.WaitGroup
	for i := 0; i < WORKERS; i++ {
		wg.Add(1)
		go worker(&wg, jobs, listener, upstream)
	}

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("[EDNS] Shutting down...")
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
			// queue full → drop packet safely
		}
	}

	wg.Wait()
	log.Println("[EDNS] Clean shutdown")
}
