package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

func identifyDevice(device *DiscoveredDevice, sshBanner, webTitle, serverHeader string) {
	device.SSHBanner = sshBanner
	// The server matches the page title and Server header against known
	// network-device signatures; the collector only reports what it saw.
	if webTitle != "" || serverHeader != "" {
		device.WebTitle = webTitle
		device.ServerHeader = serverHeader
		if webTitle != "" {
			device.IdentityEvidence = append(device.IdentityEvidence, "Web page title: "+webTitle)
		}
	}
	lower := strings.ToLower(sshBanner)
	if strings.Contains(lower, "debian") || strings.Contains(lower, "ubuntu") || strings.Contains(lower, "redhat") || strings.Contains(lower, "fedora") {
		device.OS = "Linux"
		device.IdentityEvidence = append(device.IdentityEvidence, "SSH banner: "+sshBanner)
	}
	// An SSH listener alone does not establish the device's hardware role.
	if strings.Contains(strings.ToLower(webTitle), "proxmox virtual environment") && strings.HasPrefix(strings.ToLower(serverHeader), "pve-api-daemon/") {
		device.Product = "Proxmox Virtual Environment"
		device.DeviceType = "Server"
		device.OS = "Linux"
		device.WebTitle = webTitle
		device.IdentityEvidence = append(device.IdentityEvidence, "HTTPS title: "+webTitle, "HTTPS Server header: "+serverHeader, "Unauthenticated service identification; certificate and hardware identity are unverified.")
		candidate := strings.TrimSpace(strings.Split(webTitle, " - ")[0])
		if hostnamePattern.MatchString(candidate) && !strings.Contains(strings.ToLower(candidate), "proxmox") {
			device.Hostname = candidate
		}
	}
}

func enrichNetworkScan(ctx context.Context, result *ScanResult) {
	jobs := make(chan int)
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				device := &result.Devices[index]
				sshBanner, webTitle, serverHeader := "", "", ""
				for _, port := range device.OpenPorts {
					if ctx.Err() != nil {
						break
					}
					probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
					if port == 22 {
						dialer := net.Dialer{}
						if connection, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(device.IP, "22")); err == nil {
							deadline, _ := probeCtx.Deadline()
							connection.SetDeadline(deadline)
							line, err := bufio.NewReader(io.LimitReader(connection, 512)).ReadString('\n')
							connection.Close()
							if err == nil && strings.HasPrefix(line, "SSH-") {
								sshBanner = strings.TrimSpace(line)
							}
						}
					}
					if scheme := webPorts[port]; scheme != "" && (webTitle == "" || port == 8006) {
						// Dedicated public identification request. Never sends credentials/cookies,
						// follows redirects, or reuses this transport for authenticated operations.
						if title, server := fetchWebIdentity(probeCtx, scheme, device.IP, port); title != "" || server != "" {
							webTitle, serverHeader = title, server
						}
					}
					cancel()
				}
				identifyDevice(device, sshBanner, webTitle, serverHeader)
			}
		}()
	}
	for i := range result.Devices {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return
		}
	}
	close(jobs)
	workers.Wait()
}

// webPorts are the management-interface ports whose landing page is read for identification.
var webPorts = map[int]string{80: "http", 8080: "http", 443: "https", 8443: "https", 8006: "https"}

// fetchWebIdentity reads the page title and Server header of an unauthenticated landing page.
func fetchWebIdentity(ctx context.Context, scheme, ip string, port int) (title, server string) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: nil}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, fmt.Sprint(port))), nil)
	if err != nil {
		return "", ""
	}
	response, err := client.Do(request)
	if err != nil {
		return "", ""
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
	response.Body.Close()
	server = response.Header.Get("Server")
	if len(server) > 200 {
		server = server[:200]
	}
	if match := titlePattern.FindSubmatch(body); len(match) > 1 {
		title = strings.Join(strings.Fields(html.UnescapeString(string(match[1]))), " ")
		if len(title) > 300 {
			title = ""
		}
	}
	return title, server
}
