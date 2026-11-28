package main

// Lightweight identity probes for devices found by the local sweep:
//
//   - Ping TTL: operating systems start replies at different TTLs (Linux,
//     macOS, iOS and Android 64; Windows 128; most network equipment 255),
//     and on the local network no router lowers it, so the TTL suggests the
//     OS family.
//   - NetBIOS node status (UDP 137): Windows PCs and Samba hosts answer with
//     their computer name and workgroup.
//
// Both are read-only, unauthenticated and limited to the addresses the sweep
// already found on private ranges.

import (
	"context"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ttlPattern     = regexp.MustCompile(`(?i)\bttl[=:]\s*(\d{1,3})\b`)
	netbiosPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.$-]{0,14}$`)
)

// probeDevices adds the ping TTL and NetBIOS name to each device.
func probeDevices(ctx context.Context, devices map[string]*Neighbor) {
	ips := make([]string, 0, len(devices))
	for ip := range devices {
		ips = append(ips, ip)
	}
	var mutex sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		names := queryNetBIOS(ctx, ips)
		mutex.Lock()
		defer mutex.Unlock()
		for ip, n := range names {
			d := devices[ip]
			d.NetBIOSName, d.NetBIOSGroup = n[0], n[1]
			if d.Hostname == "" {
				d.Hostname = n[0]
			}
			d.Evidence = appendUnique(d.Evidence, "Answers NetBIOS name queries as "+n[0])
		}
	}()
	limit := make(chan struct{}, 48)
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			if ttl := pingTTL(ctx, ip); ttl > 0 {
				mutex.Lock()
				devices[ip].TTL = ttl
				mutex.Unlock()
			}
		}(ip)
	}
	wg.Wait()
}

func pingTTL(ctx context.Context, ip string) int {
	if ctx.Err() != nil || net.ParseIP(ip) == nil {
		return 0
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out string
	if runtime.GOOS == "windows" {
		out, _ = command(c, "ping", "-n", "1", "-w", "800", ip)
	} else {
		out, _ = command(c, "ping", "-c", "1", "-W", "1", ip)
	}
	return parseTTL(out)
}

// parseTTL reads the TTL from ping output; "unreachable" replies carry none.
func parseTTL(out string) int {
	m := ttlPattern.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	v, err := strconv.Atoi(m[1])
	if err != nil || v < 1 || v > 255 {
		return 0
	}
	return v
}

// nbstatQuery builds a NetBIOS node status request for the wildcard name "*".
func nbstatQuery() []byte {
	q := []byte{0x4e, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}
	name := append([]byte{'*'}, make([]byte, 15)...)
	for _, b := range name {
		q = append(q, 'A'+b>>4, 'A'+b&0x0f)
	}
	return append(q, 0x00, 0x00, 0x21, 0x00, 0x01)
}

// parseNBStat returns the computer name and workgroup from a node status response.
func parseNBStat(b []byte) (name, group string) {
	if len(b) < 57 || b[2]&0x80 == 0 {
		return "", ""
	}
	i := 12
	for i < len(b) {
		l := int(b[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 == 0xc0 {
			i += 2
			break
		}
		i += l + 1
	}
	i += 10 // type, class, TTL, data length
	if i >= len(b) {
		return "", ""
	}
	count := int(b[i])
	i++
	for k := 0; k < count && i+18 <= len(b); k++ {
		label := clean(strings.TrimRight(string(b[i:i+15]), " \x00"), 15)
		suffix, isGroup := b[i+15], b[i+16]&0x80 != 0
		i += 18
		if suffix != 0x00 || label == "" {
			continue
		}
		if !isGroup && name == "" {
			name = label
		} else if isGroup && group == "" {
			group = label
		}
	}
	if !netbiosPattern.MatchString(name) {
		return "", ""
	}
	return name, group
}

// queryNetBIOS sends one node status request to each address from a single socket.
func queryNetBIOS(ctx context.Context, ips []string) map[string][2]string {
	found := map[string][2]string{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return found
	}
	defer conn.Close()
	query := nbstatQuery()
	go func() {
		for _, ip := range ips {
			if ctx.Err() != nil {
				return
			}
			conn.WriteToUDP(query, &net.UDPAddr{IP: net.ParseIP(ip), Port: 137})
			time.Sleep(3 * time.Millisecond)
		}
	}()
	deadline := time.Now().Add(time.Duration(len(ips))*3*time.Millisecond + 2500*time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if name, group := parseNBStat(buf[:n]); name != "" {
			found[from.IP.String()] = [2]string{name, group}
		}
	}
	return found
}
