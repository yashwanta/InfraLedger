package main

// Local network sweep: find every live device on the configured subnets,
// including printers, TVs, IoT devices, phones and NAS that do not answer TCP
// probes, and collect what they say about themselves.
//
//  1. Neighbor priming: one empty UDP datagram is sent to the discard port of
//     each address in the configured private ranges. To deliver it the OS must
//     resolve the address with ARP, and every powered-on device answers ARP even
//     when its firewall drops everything else, so the neighbor table read
//     afterwards lists every live device with its MAC address.
//  2. mDNS / DNS-SD (Bonjour) and SSDP (UPnP) queries: printers, smart TVs,
//     streaming sticks, speakers, smart-home hubs and NAS announce their name,
//     service types, manufacturer and model.
//  3. Reverse DNS names for addresses that are still unnamed.
//
// Everything is read-only and limited to private addresses; device description
// pages are fetched without credentials and never followed to another host.

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxNeighbors = 512

// mdnsServiceTypes are queried directly; others found via _services._dns-sd are queried in a second round.
var mdnsServiceTypes = []string{
	"_services._dns-sd._udp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp",
	"_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_amzn-wplay._tcp", "_androidtvremote2._tcp",
	"_hap._tcp", "_homekit._tcp", "_matter._tcp", "_hue._tcp", "_esphomelib._tcp", "_shelly._tcp", "_miio._udp", "_meshcop._udp", "_elg._tcp",
	"_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_nfs._tcp", "_device-info._tcp", "_workstation._tcp", "_companion-link._tcp",
	"_apple-mobdev2._tcp", "_rtsp._tcp", "_http._tcp", "_ssh._tcp",
}

var serviceTypePattern = regexp.MustCompile(`(_[a-z0-9-]+\._(?:tcp|udp))\.local\.?$`)

// txtModelKeys are TXT record keys that carry a model, manufacturer or friendly name.
var txtModelKeys = map[string]string{"md": "model", "model": "model", "ty": "model", "usb_mdl": "model", "product": "model", "mdl": "model",
	"usb_mfg": "manufacturer", "manufacturer": "manufacturer", "mfg": "manufacturer", "vendor": "manufacturer", "fn": "name"}

// sweepLocal returns neighbors enriched with every device found on the configured ranges.
func sweepLocal(ctx context.Context, cidrs []string, known []Neighbor) []Neighbor {
	devices := map[string]*Neighbor{}
	add := func(n Neighbor) *Neighbor {
		addr, err := netip.ParseAddr(n.IP)
		if err != nil || !addr.Is4() || !addr.IsPrivate() || addr.IsMulticast() {
			return nil
		}
		d := devices[n.IP]
		if d == nil {
			if len(devices) >= maxNeighbors {
				return nil
			}
			copy := n
			devices[n.IP] = &copy
			return &copy
		}
		if d.MAC == "" {
			d.MAC = n.MAC
		}
		if d.Hostname == "" {
			d.Hostname = n.Hostname
		}
		return d
	}
	for _, n := range known {
		add(n)
	}
	if targets, err := discoveryTargets(cidrs); err == nil && len(targets) > 0 {
		primeNeighbors(ctx, targets)
		for _, n := range readNeighborTable(ctx) {
			if d := add(n); d != nil {
				d.Evidence = appendUnique(d.Evidence, "Answered ARP during the local network sweep")
			}
		}
	}
	for ip, info := range queryMDNS(ctx) {
		if d := add(Neighbor{IP: ip}); d != nil {
			mergeInfo(d, info)
		}
	}
	for ip, info := range querySSDP(ctx) {
		if d := add(Neighbor{IP: ip}); d != nil {
			mergeInfo(d, info)
		}
	}
	reverseNames(ctx, devices)
	probeDevices(ctx, devices)
	out := make([]Neighbor, 0, len(devices))
	for _, d := range devices {
		d.Source = "Local network sweep"
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Less(b)
	})
	return out
}

func appendUnique(list []string, values ...string) []string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || len(list) >= 12 {
			continue
		}
		found := false
		for _, x := range list {
			if x == v {
				found = true
			}
		}
		if !found {
			list = append(list, v)
		}
	}
	return list
}

func mergeInfo(d *Neighbor, info *Neighbor) {
	d.Services = appendUnique(d.Services, info.Services...)
	d.Evidence = appendUnique(d.Evidence, info.Evidence...)
	for _, pair := range [][2]*string{{&d.FriendlyName, &info.FriendlyName}, {&d.Manufacturer, &info.Manufacturer}, {&d.Model, &info.Model}, {&d.UPnPType, &info.UPnPType}, {&d.Hostname, &info.Hostname}} {
		if *pair[0] == "" {
			*pair[0] = clean(*pair[1], 120)
		}
	}
}

func clean(s string, n int) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// primeNeighbors makes the OS resolve every target address with ARP.
func primeNeighbors(ctx context.Context, targets []string) {
	for _, ip := range targets {
		if ctx.Err() != nil {
			return
		}
		if conn, err := net.Dial("udp4", net.JoinHostPort(ip, "9")); err == nil {
			conn.Write([]byte{0})
			conn.Close()
		}
		time.Sleep(2 * time.Millisecond) // about 2 seconds for a /24; avoids an ARP burst
	}
	select {
	case <-ctx.Done():
	case <-time.After(2500 * time.Millisecond):
	}
}

// readNeighborTable returns the OS neighbor (ARP) table.
func readNeighborTable(ctx context.Context) []Neighbor {
	var raw string
	var err error
	if runtime.GOOS == "windows" {
		raw, err = command(ctx, "arp", "-a")
	} else {
		raw, err = command(ctx, "ip", "-4", "neigh", "show")
	}
	if err != nil {
		return nil
	}
	return parseNeighbors(raw)
}

// --- mDNS / DNS-SD -----------------------------------------------------------

func queryMDNS(ctx context.Context) map[string]*Neighbor {
	found := map[string]*Neighbor{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return found
	}
	defer conn.Close()
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	discovered := map[string]bool{}
	round := func(types []string) {
		for start := 0; start < len(types); start += 8 {
			end := min(start+8, len(types))
			msg := dnsmessage.Message{}
			for _, t := range types[start:end] {
				if name, err := dnsmessage.NewName(t + ".local."); err == nil {
					msg.Questions = append(msg.Questions, dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
				}
			}
			if packet, err := msg.Pack(); err == nil {
				conn.WriteToUDP(packet, group)
			}
		}
		// Windows Firewall admits unicast replies to a multicast query for 3 seconds.
		deadline := time.Now().Add(2800 * time.Millisecond)
		buf := make([]byte, 9000)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			conn.SetReadDeadline(deadline)
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			ip := from.IP.To4()
			if ip == nil {
				continue
			}
			info := found[ip.String()]
			if info == nil {
				if len(found) >= maxNeighbors {
					continue
				}
				info = &Neighbor{}
				found[ip.String()] = info
			}
			for _, t := range parseMDNS(buf[:n], info) {
				discovered[t] = true
			}
		}
	}
	round(mdnsServiceTypes)
	extra := []string{}
	for t := range discovered {
		known := false
		for _, k := range mdnsServiceTypes {
			if k == t {
				known = true
			}
		}
		if !known && len(extra) < 24 {
			extra = append(extra, t)
		}
	}
	if len(extra) > 0 && ctx.Err() == nil {
		sort.Strings(extra)
		round(extra)
	}
	for ip, info := range found {
		if len(info.Services) == 0 && info.Hostname == "" && info.FriendlyName == "" {
			delete(found, ip)
		}
	}
	return found
}

// parseMDNS records what one mDNS response says about its sender and returns
// the service types it mentions (from _services._dns-sd._udp enumeration).
func parseMDNS(packet []byte, info *Neighbor) []string {
	var p dnsmessage.Parser
	if _, err := p.Start(packet); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	types := []string{}
	record := func(h dnsmessage.ResourceHeader) error {
		owner := strings.ToLower(h.Name.String())
		switch h.Type {
		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				return err
			}
			target := r.PTR.String()
			if owner == "_services._dns-sd._udp.local." {
				if m := serviceTypePattern.FindStringSubmatch(strings.ToLower(target)); m != nil {
					types = append(types, m[1])
				}
				return nil
			}
			if m := serviceTypePattern.FindStringSubmatch(owner); m != nil {
				info.Services = appendUnique(info.Services, m[1])
				if label := instanceLabel(target, m[1]); label != "" && info.FriendlyName == "" {
					info.FriendlyName = clean(label, 120)
				}
			}
		case dnsmessage.TypeSRV:
			r, err := p.SRVResource()
			if err != nil {
				return err
			}
			if m := serviceTypePattern.FindStringSubmatch(owner); m != nil {
				info.Services = appendUnique(info.Services, m[1])
			}
			if host := strings.TrimSuffix(strings.TrimSuffix(r.Target.String(), "."), ".local"); host != "" && info.Hostname == "" {
				info.Hostname = clean(host, 120)
			}
		case dnsmessage.TypeTXT:
			r, err := p.TXTResource()
			if err != nil {
				return err
			}
			for _, entry := range r.TXT {
				key, value, ok := strings.Cut(entry, "=")
				field := txtModelKeys[strings.ToLower(key)]
				if !ok || field == "" || strings.TrimSpace(value) == "" {
					continue
				}
				value = clean(strings.Trim(value, "()"), 120)
				switch {
				case field == "model" && info.Model == "":
					info.Model = value
				case field == "manufacturer" && info.Manufacturer == "":
					info.Manufacturer = value
				case field == "name" && info.FriendlyName == "":
					info.FriendlyName = value
				}
			}
		case dnsmessage.TypeA:
			if _, err := p.AResource(); err != nil {
				return err
			}
			if host := strings.TrimSuffix(strings.TrimSuffix(h.Name.String(), "."), ".local"); host != "" && info.Hostname == "" {
				info.Hostname = clean(host, 120)
			}
		default:
			return skip(&p, h)
		}
		return nil
	}
	for _, section := range []func() (dnsmessage.ResourceHeader, error){p.AnswerHeader, p.AuthorityHeader, p.AdditionalHeader} {
		for {
			h, err := section()
			if err != nil {
				break
			}
			if record(h) != nil {
				return types
			}
		}
	}
	if len(info.Services) > 0 {
		info.Evidence = appendUnique(info.Evidence, "Announces mDNS services: "+strings.Join(info.Services, ", "))
	}
	return types
}

// skip discards the body of a resource the parser is positioned on.
func skip(p *dnsmessage.Parser, _ dnsmessage.ResourceHeader) error {
	if err := p.SkipAnswer(); err == nil {
		return nil
	}
	if err := p.SkipAuthority(); err == nil {
		return nil
	}
	return p.SkipAdditional()
}

func instanceLabel(instance, serviceType string) string {
	label := strings.TrimSuffix(strings.ToLower(instance), "."+serviceType+".local.")
	if label == strings.ToLower(instance) {
		return ""
	}
	original := instance[:len(label)]
	return strings.ReplaceAll(original, `\ `, " ")
}

// --- SSDP / UPnP ------------------------------------------------------------

type upnpDescription struct {
	Device struct {
		DeviceType       string `xml:"deviceType"`
		FriendlyName     string `xml:"friendlyName"`
		Manufacturer     string `xml:"manufacturer"`
		ModelName        string `xml:"modelName"`
		ModelDescription string `xml:"modelDescription"`
	} `xml:"device"`
}

func querySSDP(ctx context.Context) map[string]*Neighbor {
	found := map[string]*Neighbor{}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return found
	}
	defer conn.Close()
	group := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, target := range []string{"ssdp:all", "upnp:rootdevice"} {
		conn.WriteToUDP([]byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: "+target+"\r\n\r\n"), group)
	}
	locations := map[string]string{}
	deadline := time.Now().Add(2800 * time.Millisecond)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		ip := from.IP.To4()
		if ip == nil {
			continue
		}
		info := found[ip.String()]
		if info == nil {
			if len(found) >= maxNeighbors {
				continue
			}
			info = &Neighbor{}
			found[ip.String()] = info
		}
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "server":
				info.Evidence = appendUnique(info.Evidence, "UPnP server: "+clean(value, 150))
			case "st":
				if strings.HasPrefix(value, "urn:") || strings.Contains(value, "roku") || strings.Contains(value, "dial") {
					info.Services = appendUnique(info.Services, "upnp:"+clean(value, 100))
				}
			case "location":
				if u, err := http.NewRequest("GET", value, nil); err == nil && u.URL.Hostname() == ip.String() && (u.URL.Scheme == "http" || u.URL.Scheme == "https") {
					locations[ip.String()] = value
				}
			}
		}
	}
	var wg sync.WaitGroup
	var mutex sync.Mutex
	client := http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil}}
	limit := make(chan struct{}, 8)
	for ip, location := range locations {
		wg.Add(1)
		go func(ip, location string) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			request, err := http.NewRequestWithContext(ctx, "GET", location, nil)
			if err != nil {
				return
			}
			response, err := client.Do(request)
			if err != nil {
				return
			}
			defer response.Body.Close()
			var d upnpDescription
			if xml.NewDecoder(io.LimitReader(response.Body, 131072)).Decode(&d) != nil {
				return
			}
			mutex.Lock()
			defer mutex.Unlock()
			info := found[ip]
			info.FriendlyName, info.Manufacturer, info.Model, info.UPnPType = clean(d.Device.FriendlyName, 120), clean(d.Device.Manufacturer, 120), clean(strings.TrimSpace(d.Device.ModelName+" "+d.Device.ModelDescription), 120), clean(d.Device.DeviceType, 150)
			info.Evidence = appendUnique(info.Evidence, fmt.Sprintf("UPnP device: %s (%s)", info.FriendlyName, info.UPnPType))
		}(ip, location)
	}
	wg.Wait()
	return found
}

// --- reverse DNS --------------------------------------------------------------

func reverseNames(ctx context.Context, devices map[string]*Neighbor) {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	limit := make(chan struct{}, 16)
	for ip, d := range devices {
		if d.Hostname != "" {
			continue
		}
		wg.Add(1)
		go func(ip string, d *Neighbor) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			lookup, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(lookup, ip)
			if err != nil || len(names) == 0 {
				return
			}
			name := strings.TrimSuffix(names[0], ".")
			if hostnamePattern.MatchString(name) {
				mutex.Lock()
				d.Hostname = clean(name, 120)
				mutex.Unlock()
			}
		}(ip, d)
	}
	wg.Wait()
}
