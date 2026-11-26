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
					if port == 8006 {
						// Dedicated public identification request. Never sends credentials/cookies,
						// follows redirects, or reuses this transport for authenticated operations.
						transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: nil}
						client := http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
						request, err := http.NewRequestWithContext(probeCtx, "GET", fmt.Sprintf("https://%s:8006/", device.IP), nil)
						if err == nil {
							if response, err := client.Do(request); err == nil {
								body, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
								response.Body.Close()
								if response.StatusCode == http.StatusOK {
									match := titlePattern.FindSubmatch(body)
									if len(match) > 1 {
										webTitle = strings.TrimSpace(html.UnescapeString(string(match[1])))
										if len(webTitle) > 300 {
											webTitle = ""
										}
									}
									serverHeader = response.Header.Get("Server")
								}
							}
						}
						transport.CloseIdleConnections()
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
