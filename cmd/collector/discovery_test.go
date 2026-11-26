package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestDiscoveryTargets(t *testing.T) {
	targets, err := discoveryTargets([]string{"10.20.30.0/24"})
	if err != nil || len(targets) != 254 || targets[0] != "10.20.30.1" || targets[253] != "10.20.30.254" {
		t.Fatal(targets, err)
	}
	for _, cidr := range []string{"8.8.8.0/24", "127.0.0.0/24", "192.168.0.0/16", "bad"} {
		if _, err := discoveryTargets([]string{cidr}); err == nil {
			t.Fatal("accepted", cidr)
		}
	}
}
func TestNeighborParsing(t *testing.T) {
	items := parseNeighbors("10.20.30.2 00-11-22-33-44-55 dynamic\n10.20.30.2 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n224.0.0.1 01-00-5e-00-00-01 static\n10.20.30.3 dev eth0 INCOMPLETE")
	if len(items) != 1 || items[0].IP != "10.20.30.2" {
		t.Fatal(items)
	}
}
func TestConfiguredPortScanUsesOnlyAllowedTargets(t *testing.T) {
	result := scanNetwork(context.Background(), []string{"10.20.30.0/30"}, []int{80, 443}, func(_ context.Context, network, target string) (net.Conn, error) {
		if network != "tcp" || !strings.HasPrefix(target, "10.20.30.") {
			t.Errorf("unexpected target %s", target)
		}
		if strings.HasSuffix(target, ":80") {
			a, b := net.Pipe()
			b.Close()
			return a, nil
		}
		return nil, fmt.Errorf("closed")
	})
	if result.Targets != 2 || len(result.Devices) != 2 || len(result.Devices[0].OpenPorts) != 1 || result.Devices[0].OpenPorts[0] != 80 {
		t.Fatal(result)
	}
}
