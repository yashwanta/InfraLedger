package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Connection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"localAddress"`
	LocalPort     int    `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    int    `json:"remotePort"`
	State         string `json:"state"`
	PID           string `json:"pid"`
	Process       string `json:"process"`
}

func endpoint(value string) (string, int) {
	host, port, e := net.SplitHostPort(value)
	if e != nil {
		at := strings.LastIndex(value, ":")
		if at < 0 {
			return value, 0
		}
		host, port = value[:at], value[at+1:]
	}
	host = strings.Trim(host, "[]")
	number, _ := strconv.Atoi(port)
	return host, number
}
func command(ctx context.Context, name string, args ...string) (string, error) {
	output, e := exec.CommandContext(ctx, name, args...).Output()
	return string(output), e
}
func collect(ctx context.Context) ([]Connection, error) {
	out := []Connection{}
	if runtime.GOOS == "windows" {
		processes := map[string]string{}
		names, e := command(ctx, "tasklist", "/FO", "CSV", "/NH")
		if e == nil {
			reader := csv.NewReader(strings.NewReader(names))
			reader.FieldsPerRecord = -1
			for {
				row, e := reader.Read()
				if e != nil {
					break
				}
				if len(row) >= 2 {
					processes[row[1]] = row[0]
				}
			}
		}
		for _, protocol := range []string{"tcp", "udp"} {
			raw, e := command(ctx, "netstat", "-ano", "-p", protocol)
			if e != nil {
				return nil, e
			}
			for _, line := range strings.Split(raw, "\n") {
				f := strings.Fields(line)
				if len(f) < 4 || !strings.EqualFold(f[0], protocol) {
					continue
				}
				c := Connection{Protocol: strings.ToUpper(protocol)}
				c.LocalAddress, c.LocalPort = endpoint(f[1])
				c.RemoteAddress, c.RemotePort = endpoint(f[2])
				if protocol == "tcp" && len(f) >= 5 {
					c.State, c.PID = f[3], f[4]
				} else if protocol == "udp" {
					c.State, c.PID = "LISTENING", f[3]
				} else {
					continue
				}
				c.Process = processes[c.PID]
				if c.LocalPort > 0 {
					out = append(out, c)
				}
			}
		}
		return out, nil
	}
	if runtime.GOOS == "linux" {
		raw, e := command(ctx, "ss", "-H", "-antup")
		if e != nil {
			return nil, fmt.Errorf("Linux collector requires ss (iproute2): %w", e)
		}
		pidPattern := regexp.MustCompile(`pid=(\d+)`)
		namePattern := regexp.MustCompile(`"([^"]+)"`)
		for _, line := range strings.Split(raw, "\n") {
			f := strings.Fields(line)
			if len(f) < 6 {
				continue
			}
			c := Connection{Protocol: strings.ToUpper(f[0]), State: f[1]}
			c.LocalAddress, c.LocalPort = endpoint(f[4])
			c.RemoteAddress, c.RemotePort = endpoint(f[5])
			if match := pidPattern.FindStringSubmatch(line); len(match) > 1 {
				c.PID = match[1]
			}
			if match := namePattern.FindStringSubmatch(line); len(match) > 1 {
				c.Process = match[1]
			}
			if c.LocalPort > 0 {
				out = append(out, c)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("collector supports Windows and Linux; this platform is %s", runtime.GOOS)
}
func main() {
	server := flag.String("server", "http://127.0.0.1:5173", "InfraLedger server origin")
	interval := flag.Duration("interval", 30*time.Second, "Observation interval, minimum 5s")
	discover := flag.Bool("discover", true, "Automatically discover host facts, interfaces and configured networks")
	once := flag.Bool("once", false, "Send one snapshot and exit")
	flag.Parse()
	rawToken := os.Getenv("TRINETRA_TOKEN")
	if rawToken == "" {
		log.Fatal("Set TRINETRA_TOKEN to the device-scoped collector token")
	}
	origin, e := url.Parse(*server)
	if e != nil || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Hostname() == "" {
		log.Fatal("Use an origin such as https://docs.example.com")
	}
	local := origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1"
	if origin.Scheme != "https" && !(local && origin.Scheme == "http") {
		log.Fatal("Remote collectors require HTTPS")
	}
	if *interval < 5*time.Second {
		log.Fatal("Minimum interval is 5 seconds")
	}
	origin.Path = "/api/telemetry"
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("collector redirects are disabled") }}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	send := func() error {
		snapshotCtx, done := context.WithTimeout(ctx, 150*time.Second)
		defer done()
		connections, e := collect(snapshotCtx)
		if e != nil {
			return e
		}
		if len(connections) > 2000 {
			connections = connections[:2000]
		}
		payloadData := map[string]any{"connections": connections}
		if *discover {
			configURL := *origin
			configURL.Path = "/api/discovery/config"
			configRequest, requestErr := http.NewRequestWithContext(snapshotCtx, "GET", configURL.String(), nil)
			if requestErr != nil {
				return requestErr
			}
			configRequest.Header.Set("Authorization", "Bearer "+rawToken)
			configResponse, configErr := client.Do(configRequest)
			if configErr != nil {
				return configErr
			}
			var profile DiscoveryProfile
			decodeErr := json.NewDecoder(io.LimitReader(configResponse.Body, 1<<20)).Decode(&profile)
			configResponse.Body.Close()
			if configResponse.StatusCode != 200 {
				return fmt.Errorf("discovery configuration returned %d", configResponse.StatusCode)
			}
			if decodeErr != nil {
				return decodeErr
			}
			if profile.Config.Enabled {
				snapshot, discoveryErr := localDiscovery(snapshotCtx)
				if discoveryErr != nil {
					return discoveryErr
				}
				requested, _ := time.Parse(time.RFC3339Nano, profile.RequestedAt)
				lastScan, _ := time.Parse(time.RFC3339Nano, profile.LastScanAt)
				if requested.After(lastScan) {
					snapshot.RequestedAt = profile.RequestedAt
				}
				if shouldScan(profile) {
					scanCtx, stopScan := context.WithTimeout(snapshotCtx, 90*time.Second)
					dialer := net.Dialer{Timeout: 350 * time.Millisecond}
					result := scanNetwork(scanCtx, profile.Config.CIDRs, profile.Config.Ports, dialer.DialContext)
					enrichNetworkScan(scanCtx, &result)
					stopScan()
					snapshot.NetworkScan = &result
				}
				payloadData["discovery"] = snapshot
			}
		}
		payload, e := json.Marshal(payloadData)
		if e != nil {
			return e
		}
		request, e := http.NewRequestWithContext(ctx, "POST", origin.String(), bytes.NewReader(payload))
		if e != nil {
			return e
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+rawToken)
		response, e := client.Do(request)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			return fmt.Errorf("server returned %d: %s", response.StatusCode, body)
		}
		log.Printf("Reported %d socket observations", len(connections))
		return nil
	}
	for {
		if e := send(); e != nil {
			log.Print(e)
			if *once {
				os.Exit(1)
			}
		}
		if *once {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}
