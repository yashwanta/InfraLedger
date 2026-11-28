package app

import (
	"log"
	"net"
	"strings"
)

// Device identity for discovered network devices: manufacturer, type and an
// estimated operating system, built from what can be seen without signing in
// (MAC registry, mDNS/UPnP announcements, NetBIOS names and the ping TTL).
// Estimates are marked osInferred so a documented or collector-reported OS
// always wins and a later, stronger signal can replace them.

// identityVersion is bumped whenever the rules change so existing records are re-evaluated once at startup.
const identityVersion = "3"

// identifyLocalDevice applies every identification step to d from one observation.
func identifyLocalDevice(d, obs M) {
	noteProbeFacts(d, obs)
	applyMACVendor(d)
	describeLocalDevice(d, obs)
	classifyPrivateAddress(d)
	inferOS(d)
}

// isRandomizedMAC reports a locally administered address: phones, tablets and
// some laptops use one per Wi-Fi network for privacy, so it names no manufacturer.
func isRandomizedMAC(mac string) bool {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0 && hw[0]&0x01 == 0
}

func noteProbeFacts(d, obs M) {
	if ttl := int(N(obs, "ttl")); ttl > 0 && ttl <= 255 {
		d["pingTTL"] = ttl
	}
	if v := clip(S(obs, "hostname"), 180); v != "" {
		d["observedHostname"] = v
	}
	if v := clip(S(obs, "netbiosName"), 40); v != "" {
		d["netbiosName"] = v
		if S(d, "observedHostname") == "" {
			d["observedHostname"] = v
		}
	}
	if v := clip(S(obs, "netbiosGroup"), 40); v != "" {
		d["netbiosGroup"] = v
	}
	if isRandomizedMAC(S(d, "mac")) {
		d["macRandomized"] = true
		d["macVendor"] = "Private (randomized) address"
	} else {
		delete(d, "macRandomized")
	}
}

// ttlFamily maps a LAN ping TTL to the OS family whose default it matches.
func ttlFamily(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl <= 64:
		return "unix"
	case ttl <= 128:
		return "windows"
	default:
		return "network"
	}
}

// classifyPrivateAddress labels unclassified devices that use a private Wi-Fi address.
func classifyPrivateAddress(d M) {
	if d["macRandomized"] != true || !contains([]string{"Network endpoint", "Endpoint", ""}, S(d, "category")) {
		return
	}
	if ttlFamily(int(N(d, "pingTTL"))) == "windows" {
		classify(d, "Laptop", "Private Wi-Fi address and Windows ping TTL (laptop with random hardware addresses on)")
		return
	}
	classify(d, categoryPhone, "Private (randomized) Wi-Fi address: phones and tablets use one by default")
}

type osRule struct {
	match func(c osContext) bool
	os    func(c osContext) string
	why   string
}

type osContext struct {
	text, vendor, category, family string
	services                       []string
	netbios, randomized            bool
	mac                            string
}

func (c osContext) mentions(words ...string) bool {
	for _, w := range words {
		if strings.Contains(c.text, w) {
			return true
		}
	}
	return false
}
func (c osContext) announces(names ...string) bool {
	for _, s := range c.services {
		for _, n := range names {
			if strings.Contains(s, n) {
				return true
			}
		}
	}
	return false
}
func (c osContext) vendorIs(names ...string) bool {
	for _, n := range names {
		if strings.Contains(c.vendor, n) {
			return true
		}
	}
	return false
}
func fixed(s string) func(osContext) string { return func(osContext) string { return s } }

var osRules = []osRule{
	{func(c osContext) bool { return c.mentions("iphone") }, fixed("iOS"), "Device name or announcement identifies an iPhone"},
	{func(c osContext) bool { return c.mentions("ipad") }, fixed("iPadOS"), "Device name or announcement identifies an iPad"},
	{func(c osContext) bool { return c.mentions("appletv", "apple tv") }, fixed("tvOS"), "Announces itself as an Apple TV"},
	{func(c osContext) bool { return c.mentions("homepod") }, fixed("HomePod software"), "Announces itself as a HomePod"},
	{func(c osContext) bool {
		return c.mentions("macbook", "imac", "macmini", "mac mini", "macpro", "mac studio") || c.announces("_afpovertcp._tcp")
	}, fixed("macOS"), "Announces a Mac model or Apple file sharing"},
	{func(c osContext) bool { return c.announces("_apple-mobdev2._tcp") }, fixed("iOS / iPadOS"), "Announces Apple mobile device sync"},
	{func(c osContext) bool {
		return c.announces("_androidtvremote2._tcp") || c.mentions("android tv", "bravia")
	}, fixed("Android TV"), "Announces Android TV remote control"},
	{func(c osContext) bool { return c.mentions("android", "galaxy-", "pixel-", "oneplus") }, fixed("Android"), "Device name identifies an Android phone or tablet"},
	{func(c osContext) bool {
		return c.mentions("webos") || c.vendorIs("lg electronics") && c.category == categoryMedia
	}, fixed("LG webOS"), "LG media device"},
	{func(c osContext) bool { return c.mentions("tizen") || c.mentions("[tv] samsung") }, fixed("Samsung Tizen"), "Samsung smart TV"},
	{func(c osContext) bool { return c.mentions("roku") || c.vendorIs("roku") }, fixed("Roku OS"), "Roku device"},
	{func(c osContext) bool { return c.announces("_googlecast._tcp") || c.mentions("chromecast") }, fixed("Google Cast (Chromecast / Google TV)"), "Announces Google Cast"},
	{func(c osContext) bool { return c.netbios && c.family == "windows" }, fixed("Windows"), "Answers NetBIOS name queries and replies to ping with the Windows TTL (128)"},
	{func(c osContext) bool { return c.netbios && c.family == "unix" }, fixed("Linux (Samba file sharing)"), "Answers NetBIOS name queries with a Linux/Unix TTL (64)"},
	{func(c osContext) bool { return c.vendorIs("proxmox") }, func(c osContext) string {
		return map[string]string{"unix": "Linux (Proxmox VM)", "windows": "Windows (Proxmox VM)"}[c.family]
	}, "Proxmox virtual network card; guest OS family from the ping TTL"},
	{func(c osContext) bool { return strings.HasPrefix(c.mac, "00:15:5d") }, func(c osContext) string {
		return map[string]string{"unix": "Linux (Hyper-V VM)", "windows": "Windows (Hyper-V VM)", "": "Hyper-V virtual machine"}[c.family]
	}, "Microsoft Hyper-V virtual network card"},
	{func(c osContext) bool { return c.vendorIs("apple") }, func(c osContext) string {
		if c.category == "Laptop" || c.category == "Desktop" || c.category == "Computer" {
			return "macOS"
		}
		return "Apple iOS / macOS"
	}, "MAC address registered to Apple"},
	{func(c osContext) bool { return c.vendorIs("amazon") }, fixed("Fire OS (Amazon device)"), "MAC address registered to Amazon (Echo, Fire TV, Kindle)"},
	{func(c osContext) bool { return c.vendorIs("nintendo") }, fixed("Nintendo system software"), "MAC address registered to Nintendo"},
	{func(c osContext) bool { return c.category == "Printer" }, fixed("Printer firmware"), "Identified as a printer"},
	{func(c osContext) bool { return c.category == categoryCamera }, fixed("Camera firmware (embedded Linux)"), "Identified as a network camera"},
	{func(c osContext) bool { return c.category == categoryIoT }, fixed("Embedded firmware"), "Identified as a smart-home / IoT device"},
	{func(c osContext) bool { return c.category == categoryMedia }, fixed("Smart TV / media firmware"), "Identified as a TV or media device"},
	{func(c osContext) bool { return c.category == "Storage" }, fixed("NAS operating system"), "Identified as network storage"},
	{func(c osContext) bool { return contains(networkCategories, c.category) || c.family == "network" }, func(c osContext) string {
		if c.vendorIs("cisco") {
			return "Cisco IOS / network OS"
		}
		return "Network device firmware"
	}, "Network equipment (by type, manufacturer or a ping TTL of 255)"},
	{func(c osContext) bool { return c.randomized && c.family == "unix" }, fixed("iOS or Android (private Wi-Fi address)"), "Private Wi-Fi address with a Unix-family ping TTL: almost always a phone or tablet"},
	{func(c osContext) bool { return c.randomized && c.family == "" }, fixed("iOS or Android (private Wi-Fi address)"), "Private (randomized) Wi-Fi address: phones and tablets use one by default"},
	{func(c osContext) bool { return c.family == "windows" }, fixed("Windows"), "Ping TTL 128 is the Windows default"},
	{func(c osContext) bool { return c.family == "unix" }, fixed("Linux / Unix-like"), "Ping TTL 64: Linux, macOS, iOS, Android or embedded firmware"},
}

// inferOS estimates the operating system of a device nobody has documented.
func inferOS(d M) {
	if S(d, "os") != "" && d["osInferred"] != true {
		return
	}
	services := strArray(d["advertisedServices"])
	c := osContext{
		text:       strings.ToLower(strings.Join([]string{S(d, "advertisedName"), S(d, "model"), S(d, "observedHostname"), S(d, "name"), S(d, "upnpDeviceType"), S(d, "platform"), S(d, "netbiosName")}, " ")),
		vendor:     strings.ToLower(S(d, "macVendor") + " " + S(d, "manufacturer")),
		category:   S(d, "category"),
		family:     ttlFamily(int(N(d, "pingTTL"))),
		services:   services,
		netbios:    S(d, "netbiosName") != "",
		randomized: d["macRandomized"] == true,
		mac:        strings.ToLower(S(d, "mac")),
	}
	for _, rule := range osRules {
		if !rule.match(c) {
			continue
		}
		if os := rule.os(c); os != "" {
			d["os"], d["osInferred"], d["osEvidence"] = os, true, rule.why
			return
		}
	}
	if d["osInferred"] == true { // the earlier estimate no longer has support
		delete(d, "os")
		delete(d, "osInferred")
		delete(d, "osEvidence")
	}
}

// refreshDeviceIdentity re-applies the identification rules to discovered
// devices already in the database, once per identityVersion.
func (a *App) refreshDeviceIdentity() {
	if v := a.get("SELECT value FROM meta WHERE key='device_identity_version'"); v != nil && S(v, "value") == identityVersion {
		return
	}
	actor := a.get("SELECT * FROM users WHERE role='admin' AND active=1 ORDER BY created LIMIT 1")
	if actor == nil {
		return
	}
	actor = clone(actor)
	actor["name"] = "InfraLedger maintenance"
	changed, failed := 0, 0
	for _, r := range a.q("SELECT * FROM records WHERE type='assets' AND deleted IS NULL") {
		d := decode(S(r, "data"))
		if d["autoDiscovered"] != true || S(d, "mac") == "" && S(d, "ip") == "" {
			continue
		}
		before := J(d)
		identifyLocalDevice(d, M{})
		if J(d) == before {
			continue
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					failed++
				}
			}()
			a.observedUpdate(actor, r, d)
			changed++
		}()
	}
	a.run("INSERT OR REPLACE INTO meta(key,value) VALUES('device_identity_version',?)", identityVersion)
	if changed > 0 || failed > 0 {
		log.Printf("Device identification refreshed: %d discovered device(s) updated, %d skipped", changed, failed)
	}
}
