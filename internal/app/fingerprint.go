package app

// Unauthenticated identification of discovered devices.
//
// Discovery sees a device's MAC address (neighbor cache), open TCP ports and,
// for web interfaces, the login page title. None of these prove what a device
// is, so the results are recorded as evidence with a confidence label and only
// change the device type of records that discovery created and nobody has
// classified by hand.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var ouiData []byte

var (
	ouiOnce  sync.Once
	ouiTable map[string]string
)

// macVendor returns the IEEE-registered manufacturer for a MAC address, or "".
// Locally administered (randomized) addresses have no manufacturer.
func macVendor(mac string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) < 3 || hw[0]&0x02 != 0 {
		return ""
	}
	ouiOnce.Do(func() {
		ouiTable = map[string]string{}
		reader, err := gzip.NewReader(bytes.NewReader(ouiData))
		if err != nil {
			return
		}
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			prefix, vendor, ok := strings.Cut(scanner.Text(), "\t")
			if ok {
				ouiTable[prefix] = vendor
			}
		}
	})
	return ouiTable[strings.ToUpper(strings.ReplaceAll(hw[:3].String(), ":", ""))]
}

// vendorShortNames maps registry spellings to the names people use.
var vendorShortNames = []struct{ match, name string }{
	{"routerboard", "MikroTik"}, {"mikrotik", "MikroTik"}, {"ubiquiti", "Ubiquiti"}, {"cisco", "Cisco"},
	{"juniper", "Juniper Networks"}, {"aruba", "Aruba"}, {"hewlett packard enterprise", "HPE"},
	{"hewlett packard", "HP"}, {"tp-link", "TP-Link"}, {"netgear", "NETGEAR"}, {"fortinet", "Fortinet"},
	{"palo alto", "Palo Alto Networks"}, {"sonicwall", "SonicWall"}, {"ruckus", "Ruckus"}, {"arista", "Arista"},
	{"extreme networks", "Extreme Networks"}, {"d-link", "D-Link"}, {"zyxel", "Zyxel"}, {"synology", "Synology"},
	{"qnap", "QNAP"}, {"brother", "Brother"}, {"seiko epson", "Epson"}, {"canon", "Canon"}, {"xerox", "Xerox"},
	{"lexmark", "Lexmark"}, {"kyocera", "Kyocera"}, {"ricoh", "Ricoh"}, {"dell", "Dell"}, {"lenovo", "Lenovo"},
	{"apple", "Apple"}, {"intel", "Intel"}, {"microsoft", "Microsoft"}, {"vmware", "VMware"}, {"proxmox", "Proxmox"},
	{"huawei", "Huawei"}, {"meraki", "Cisco Meraki"}, {"grandstream", "Grandstream"}, {"hikvision", "Hikvision"},
	{"dahua", "Dahua"}, {"axis communications", "Axis"}, {"raspberry pi", "Raspberry Pi"}, {"supermicro", "Supermicro"},
}

func shortVendor(vendor string) string {
	lower := strings.ToLower(vendor)
	for _, v := range vendorShortNames {
		if strings.Contains(lower, v.match) {
			return v.name
		}
	}
	return vendor
}

// networkOnlyVendors make (almost) nothing but network infrastructure, so their
// MAC prefix alone is reasonable evidence of a network device.
var networkOnlyVendors = []string{"MikroTik", "Ubiquiti", "Juniper Networks", "Aruba", "Fortinet", "Palo Alto Networks", "SonicWall", "Ruckus", "Arista", "Extreme Networks", "Cisco Meraki"}

// networkCategories are the device types discovery may assign to network gear.
var networkCategories = []string{"Router", "Switch", "Access point", "Firewall", "Network device", "Printer", "Storage"}

// webSignatures recognise network device management pages by their title or
// Server header. Order matters: the first match wins.
var webSignatures = []struct{ match, category, product string }{
	{"routeros", "Router", "MikroTik RouterOS"}, {"mikrotik", "Router", "MikroTik RouterOS"},
	{"edgeos", "Router", "Ubiquiti EdgeOS"}, {"edgerouter", "Router", "Ubiquiti EdgeRouter"},
	{"unifi os", "Network device", "UniFi OS"}, {"unifi network", "Network device", "UniFi Network"}, {"unifi", "Network device", "UniFi"},
	{"pfsense", "Firewall", "pfSense"}, {"opnsense", "Firewall", "OPNsense"}, {"fortigate", "Firewall", "Fortinet FortiGate"},
	{"sonicwall", "Firewall", "SonicWall"}, {"sophos", "Firewall", "Sophos Firewall"}, {"watchguard", "Firewall", "WatchGuard Firebox"},
	{"palo alto", "Firewall", "Palo Alto Networks"}, {"openwrt", "Router", "OpenWrt"}, {"luci", "Router", "OpenWrt LuCI"},
	{"dd-wrt", "Router", "DD-WRT"}, {"asuswrt", "Router", "ASUSWRT"}, {"omada", "Network device", "TP-Link Omada"},
	{"instant on", "Network device", "Aruba Instant On"}, {"aruba", "Network device", "Aruba"}, {"meraki", "Network device", "Cisco Meraki"},
	{"cisco", "Network device", "Cisco"}, {"procurve", "Switch", "HPE ProCurve"}, {"netgear", "Network device", "NETGEAR"},
	{"synology", "Storage", "Synology DiskStation"}, {"diskstation", "Storage", "Synology DiskStation"}, {"qnap", "Storage", "QNAP"}, {"truenas", "Storage", "TrueNAS"},
	{"laserjet", "Printer", "HP LaserJet"}, {"officejet", "Printer", "HP OfficeJet"}, {"hp color", "Printer", "HP printer"},
	{"epson", "Printer", "Epson"}, {"brother", "Printer", "Brother"}, {"canon", "Printer", "Canon"}, {"xerox", "Printer", "Xerox"},
	{"lexmark", "Printer", "Lexmark"}, {"kyocera", "Printer", "Kyocera"}, {"ricoh", "Printer", "Ricoh"}, {"jetdirect", "Printer", "HP JetDirect"},
}

func matchWebSignature(title, server string) (category, product string) {
	text := strings.ToLower(title + " " + server)
	for _, s := range webSignatures {
		if strings.Contains(text, s.match) {
			return s.category, s.product
		}
	}
	return "", ""
}

// autoClassifiable reports whether discovery may set the device type of d:
// only records it created, still unclassified or classified by discovery itself.
func autoClassifiable(d M) bool {
	return d["categoryAutoDetected"] == true || contains([]string{"Network endpoint", "Endpoint", "Computer", "Unknown", "Unclassified", ""}, S(d, "category"))
}

// classify sets the device type with the evidence that justified it.
func classify(d M, category, evidence string) {
	if category == "" || !autoClassifiable(d) {
		return
	}
	// A specific type is never replaced by the generic "Network device".
	if category == "Network device" && contains(networkCategories, S(d, "category")) && S(d, "category") != "Network device" {
		return
	}
	d["category"] = category
	d["categoryAutoDetected"] = true
	addEvidence(d, evidence)
}

func addEvidence(d M, evidence string) {
	if evidence == "" {
		return
	}
	list := strArray(d["identificationEvidence"])
	if contains(list, evidence) {
		return
	}
	list = append(list, evidence)
	if len(list) > 10 {
		list = list[len(list)-10:]
	}
	d["identificationEvidence"] = list
}

// applyMACVendor records the manufacturer behind a MAC address on d.
func applyMACVendor(d M) {
	vendor := macVendor(S(d, "mac"))
	if vendor == "" {
		return
	}
	d["macVendor"] = vendor
	short := shortVendor(vendor)
	if S(d, "manufacturer") == "" || d["manufacturerFromMAC"] == true {
		d["manufacturer"] = short
		d["manufacturerFromMAC"] = true
	}
	if contains(networkOnlyVendors, short) {
		classify(d, "Network device", "MAC address registered to "+vendor)
	}
}
