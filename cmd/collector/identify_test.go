package main

import "testing"

func TestProxmoxRequiresProductEvidence(t *testing.T) {
	device := DiscoveredDevice{IP: "10.20.30.120", OpenPorts: []int{22, 8006}}
	identifyDevice(&device, "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4", "pve01 - Proxmox Virtual Environment", "pve-api-daemon/3.0")
	if device.DeviceType != "Server" || device.OS != "Linux" || device.Hostname != "pve01" || len(device.IdentityEvidence) < 3 {
		t.Fatal(device)
	}
	device = DiscoveredDevice{IP: "10.20.30.133", OpenPorts: []int{22}}
	identifyDevice(&device, "SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13", "", " ")
	if device.OS != "Linux" || device.DeviceType != "" {
		t.Fatal("SSH does not establish a hardware role", device)
	}
	device = DiscoveredDevice{IP: "10.20.30.134", OpenPorts: []int{8006}}
	identifyDevice(&device, "", "pve01 - Proxmox Virtual Environment", "nginx")
	if device.DeviceType != "" {
		t.Fatal("title alone must not establish Proxmox identity", device)
	}
}
