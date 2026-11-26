package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HostFacts struct {
	DeviceType   string `json:"deviceType,omitempty"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"osVersion,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
}
type InterfaceFacts struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
}
type Neighbor struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}
type DiscoveredDevice struct {
	OS               string   `json:"os,omitempty"`
	DeviceType       string   `json:"deviceType,omitempty"`
	Product          string   `json:"product,omitempty"`
	SSHBanner        string   `json:"sshBanner,omitempty"`
	WebTitle         string   `json:"webTitle,omitempty"`
	IdentityEvidence []string `json:"identityEvidence,omitempty"`
	IP               string   `json:"ip"`
	Hostname         string   `json:"hostname,omitempty"`
	OpenPorts        []int    `json:"openPorts"`
}
type ScanResult struct {
	Devices     []DiscoveredDevice `json:"devices"`
	Targets     int                `json:"targets"`
	StartedAt   string             `json:"startedAt"`
	CompletedAt string             `json:"completedAt"`
	Error       string             `json:"error,omitempty"`
}
type DiscoverySnapshot struct {
	InventoryWarnings []string         `json:"inventoryWarnings"`
	Services          []ManagedService `json:"services"`
	ServiceSource     string           `json:"serviceSource,omitempty"`
	Software          []Software       `json:"software"`
	SoftwareSource    string           `json:"softwareSource,omitempty"`
	Host              HostFacts        `json:"host"`
	Interfaces        []InterfaceFacts `json:"interfaces"`
	Neighbors         []Neighbor       `json:"neighbors"`
	NetworkScan       *ScanResult      `json:"networkScan,omitempty"`
	RequestedAt       string           `json:"requestedAt,omitempty"`
}
type DiscoveryProfile struct {
	Config struct {
		Enabled    bool     `json:"enabled"`
		ActiveScan bool     `json:"activeScan"`
		CIDRs      []string `json:"cidrs"`
		Ports      []int    `json:"ports"`
		Interval   int      `json:"intervalSeconds"`
	} `json:"config"`
	RequestedAt string `json:"requestedAt"`
	LastScanAt  string `json:"lastScanAt"`
}

func localDiscovery(ctx context.Context) (DiscoverySnapshot, error) {
	hostname, _ := os.Hostname()
	snapshot := DiscoverySnapshot{Host: HostFacts{Hostname: hostname, OS: runtime.GOOS}, Interfaces: []InterfaceFacts{}, Neighbors: []Neighbor{}, InventoryWarnings: []string{}}
	interfaces, e := net.Interfaces()
	if e != nil {
		return snapshot, e
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, e := iface.Addrs()
		if e != nil {
			continue
		}
		item := InterfaceFacts{Name: iface.Name, Index: iface.Index, MAC: iface.HardwareAddr.String(), Addresses: []string{}}
		for _, address := range addresses {
			p, e := netip.ParsePrefix(address.String())
			if e == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsUnspecified() {
				item.Addresses = append(item.Addresses, p.String())
			}
		}
		if len(item.Addresses) > 0 {
			snapshot.Interfaces = append(snapshot.Interfaces, item)
		}
	}
	if runtime.GOOS == "windows" {
		script := `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; $trinetraComputer=Get-CimInstance Win32_ComputerSystem; $trinetraBIOS=Get-CimInstance Win32_BIOS; $trinetraOS=Get-CimInstance Win32_OperatingSystem; @{Manufacturer=$trinetraComputer.Manufacturer;Model=$trinetraComputer.Model;Serial=$trinetraBIOS.SerialNumber;OS=$trinetraOS.Caption;OSVersion=$trinetraOS.Version;DeviceType=$(if($trinetraOS.ProductType -in @(2,3)){"Server"}elseif($trinetraComputer.PCSystemType -eq 2){"Laptop"}elseif($trinetraComputer.PCSystemType -eq 1){"Desktop"}else{""});Adapters=@(Get-NetIPConfiguration | ForEach-Object {@{Index=$_.InterfaceIndex;Gateway=$_.IPv4DefaultGateway.NextHop;DNS=@($_.DNSServer.ServerAddresses)}})} | ConvertTo-Json -Depth 5 -Compress`
		if raw, e := command(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script); e == nil {
			var facts struct {
				Manufacturer, Model, Serial, OS, OSVersion, DeviceType string
				Adapters                                               []struct {
					Index   int
					Gateway string
					DNS     []string
				}
			}
			if json.Unmarshal([]byte(strings.TrimPrefix(raw, "\ufeff")), &facts) == nil {
				snapshot.Host.Manufacturer = facts.Manufacturer
				snapshot.Host.Model = facts.Model
				snapshot.Host.Serial = facts.Serial
				if facts.OS != "" {
					snapshot.Host.OS = facts.OS
				}
				snapshot.Host.OSVersion = facts.OSVersion
				snapshot.Host.DeviceType = facts.DeviceType
				for i := range snapshot.Interfaces {
					for _, adapter := range facts.Adapters {
						if adapter.Index == snapshot.Interfaces[i].Index {
							snapshot.Interfaces[i].Gateway = adapter.Gateway
							snapshot.Interfaces[i].DNS = adapter.DNS
						}
					}
				}
			}
		}
		if snapshot.Host.OSVersion == "" {
			snapshot.InventoryWarnings = append(snapshot.InventoryWarnings, "Windows hardware details unavailable. Check access to CIM on the collector host; device type remains unclassified.")
		}
		if raw, e := command(ctx, "arp", "-a"); e == nil {
			snapshot.Neighbors = parseNeighbors(raw)
		}
	} else if runtime.GOOS == "linux" {
		for file, target := range map[string]*string{"/sys/class/dmi/id/sys_vendor": &snapshot.Host.Manufacturer, "/sys/class/dmi/id/product_name": &snapshot.Host.Model, "/sys/class/dmi/id/product_serial": &snapshot.Host.Serial} {
			if b, e := os.ReadFile(file); e == nil {
				*target = strings.TrimSpace(string(b))
			}
		}
		if chassis, e := os.ReadFile("/sys/class/dmi/id/chassis_type"); e == nil {
			switch strings.TrimSpace(string(chassis)) {
			case "8", "9", "10", "14", "30", "31", "32":
				snapshot.Host.DeviceType = "Laptop"
			case "3", "4", "5", "6", "7", "13", "15", "16":
				snapshot.Host.DeviceType = "Desktop"
			case "17", "23", "28", "29":
				snapshot.Host.DeviceType = "Server"
			}
		}
		if b, e := os.ReadFile("/etc/os-release"); e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					snapshot.Host.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				}
			}
		}
		if raw, e := command(ctx, "ip", "-4", "neigh", "show"); e == nil {
			snapshot.Neighbors = parseNeighbors(raw)
		}
		if b, e := os.ReadFile("/proc/net/route"); e == nil {
			for _, line := range strings.Split(string(b), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 2 && fields[1] == "00000000" {
					if bytes, e := hex.DecodeString(fields[2]); e == nil && len(bytes) == 4 {
						gateway := make(net.IP, 4)
						binary.BigEndian.PutUint32(gateway, binary.LittleEndian.Uint32(bytes))
						for i := range snapshot.Interfaces {
							if snapshot.Interfaces[i].Name == fields[0] {
								snapshot.Interfaces[i].Gateway = gateway.String()
							}
						}
					}
				}
			}
		}
	}
	softwareDue := time.Since(lastSoftware) >= 15*time.Minute
	snapshot.Software, snapshot.SoftwareSource = installedSoftware(ctx)
	if softwareDue && snapshot.Software == nil {
		snapshot.InventoryWarnings = append(snapshot.InventoryWarnings, "Installed software inventory unavailable on this collector. Check package manager or registry access.")
	}
	servicesDue := time.Since(lastServices) >= time.Minute
	snapshot.Services, snapshot.ServiceSource = managedServices(ctx)
	if servicesDue && snapshot.Services == nil {
		snapshot.InventoryWarnings = append(snapshot.InventoryWarnings, "Managed service inventory unavailable. Check local service-manager permissions and support; network process observations are separate.")
	}
	return snapshot, nil
}
func parseNeighbors(raw string) []Neighbor {
	out := []Neighbor{}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, e := netip.ParseAddr(fields[0])
		if e != nil || !ip.Is4() || !ip.IsPrivate() || ip.IsMulticast() || seen[ip.String()] {
			continue
		}
		mac := ""
		for _, field := range fields[1:] {
			if hw, e := net.ParseMAC(field); e == nil && len(hw) == 6 && field != "ff-ff-ff-ff-ff-ff" && field != "ff:ff:ff:ff:ff:ff" {
				mac = hw.String()
				break
			}
		}
		if mac == "" {
			continue
		}
		seen[ip.String()] = true
		out = append(out, Neighbor{IP: ip.String(), MAC: mac})
		if len(out) >= 512 {
			break
		}
	}
	return out
}
func discoveryTargets(cidrs []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	total := 0
	for _, raw := range cidrs {
		p, e := netip.ParsePrefix(strings.TrimSpace(raw))
		if e != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 discovery range")
		}
		p = p.Masked()
		count := uint64(1) << uint(32-p.Bits())
		if count > 1024 {
			return nil, fmt.Errorf("discovery range exceeds 1,024 addresses")
		}
		total += int(count)
		if total > 1024 {
			return nil, fmt.Errorf("discovery ranges exceed 1,024 addresses")
		}
		ip := p.Addr()
		for n := uint64(0); n < count; n++ {
			if !ip.IsPrivate() {
				return nil, fmt.Errorf("discovery supports private IPv4 ranges only")
			}
			skip := p.Bits() <= 30 && (n == 0 || n == count-1)
			if !skip && !seen[ip.String()] {
				out = append(out, ip.String())
				seen[ip.String()] = true
			}
			ip = ip.Next()
		}
	}
	return out, nil
}

type dialProbe func(context.Context, string, string) (net.Conn, error)

func scanNetwork(ctx context.Context, cidrs []string, ports []int, dial dialProbe) ScanResult {
	result := ScanResult{Devices: []DiscoveredDevice{}, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	targets, e := discoveryTargets(cidrs)
	if e != nil {
		result.Error = e.Error()
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return result
	}
	result.Targets = len(targets)
	if len(ports) == 0 || len(ports) > 32 {
		result.Error = "Select 1–32 TCP ports"
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return result
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			result.Error = "Invalid TCP port"
			return result
		}
	}
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	found := map[string][]int{}
	var mutex sync.Mutex
	var workers sync.WaitGroup
	for n := 0; n < 64; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					continue
				}
				probeCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
				connection, e := dial(probeCtx, "tcp", net.JoinHostPort(job.ip, strconv.Itoa(job.port)))
				cancel()
				if e == nil {
					connection.Close()
					mutex.Lock()
					found[job.ip] = append(found[job.ip], job.port)
					mutex.Unlock()
				}
			}
		}()
	}
send:
	for _, ip := range targets {
		for _, port := range ports {
			select {
			case jobs <- job{ip, port}:
			case <-ctx.Done():
				break send
			}
		}
	}
	close(jobs)
	workers.Wait()
	for ip, open := range found {
		sort.Ints(open)
		result.Devices = append(result.Devices, DiscoveredDevice{IP: ip, OpenPorts: open})
	}
	sort.Slice(result.Devices, func(i, j int) bool { return result.Devices[i].IP < result.Devices[j].IP })
	if ctx.Err() != nil {
		result.Error = "Scan time budget reached; results are partial"
	}
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return result
}
func shouldScan(profile DiscoveryProfile) bool {
	if !profile.Config.Enabled || !profile.Config.ActiveScan {
		return false
	}
	last, _ := time.Parse(time.RFC3339Nano, profile.LastScanAt)
	requested, _ := time.Parse(time.RFC3339Nano, profile.RequestedAt)
	if requested.After(last) {
		return true
	}
	interval := profile.Config.Interval
	if interval < 300 {
		interval = 900
	}
	return last.IsZero() || time.Since(last) >= time.Duration(interval)*time.Second
}
