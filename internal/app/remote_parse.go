package app

// Parsing of read-only remote inventory output into the same snapshot shape the
// endpoint collector sends, so ingestDiscovery handles both identically.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// linuxInventoryScript only reads system information. Every command tolerates
// missing tools and permissions; nothing is written on the target.
const linuxInventoryScript = `LC_ALL=C; export LC_ALL
echo '##HOSTNAME'; hostname 2>/dev/null
echo '##OSRELEASE'; cat /etc/os-release 2>/dev/null
echo '##KERNEL'; uname -r 2>/dev/null
echo '##DMI'; for f in sys_vendor product_name product_serial chassis_type; do printf '%s=' "$f"; cat "/sys/class/dmi/id/$f" 2>/dev/null || echo; done
echo '##ADDR'; ip -o -4 addr show 2>/dev/null
echo '##LINK'; ip -o link show 2>/dev/null
echo '##ROUTE'; ip -4 route show default 2>/dev/null
echo '##DNS'; grep '^nameserver' /etc/resolv.conf 2>/dev/null
echo '##CPU'; nproc 2>/dev/null
echo '##MEM'; grep MemTotal /proc/meminfo 2>/dev/null
echo '##PKG'; if command -v dpkg-query >/dev/null 2>&1; then echo 'source=dpkg'; dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\n' 2>/dev/null | head -n 4900; elif command -v rpm >/dev/null 2>&1; then echo 'source=rpm'; rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null | head -n 4900; elif command -v apk >/dev/null 2>&1; then echo 'source=apk'; apk info -v 2>/dev/null | head -n 4900; fi
echo '##SERVICES'; systemctl list-units --type=service --state=running --no-legend --plain --no-pager 2>/dev/null | head -n 1900
echo '##END'
`

// windowsInventoryScript runs read-only CIM and registry queries and prints JSON.
const windowsInventoryScript = `$ErrorActionPreference='SilentlyContinue'
$cs=Get-CimInstance Win32_ComputerSystem; $os=Get-CimInstance Win32_OperatingSystem; $bios=Get-CimInstance Win32_BIOS; $enc=Get-CimInstance Win32_SystemEnclosure
$ifs=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $c=$_; $a=@(); for($i=0;$i -lt @($c.IPAddress).Count;$i++){ if($c.IPAddress[$i] -match '^\d+\.\d+\.\d+\.\d+$'){ $m=$c.IPSubnet[$i]; $bits=0; foreach($o in $m.Split('.')){ $bits+=[Convert]::ToString([int]$o,2).Replace('0','').Length }; $a+="$($c.IPAddress[$i])/$bits" } }; [pscustomobject]@{name=$c.Description;index=$c.InterfaceIndex;mac=$c.MACAddress;addresses=$a;gateway=@($c.DefaultIPGateway)[0];dns=@($c.DNSServerSearchOrder)} })
$sw=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | ForEach-Object { Get-ItemProperty $_ } | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } | Select-Object -First 4900 | ForEach-Object { [pscustomobject]@{key=$_.PSChildName;name=$_.DisplayName;version=$_.DisplayVersion;publisher=$_.Publisher;installLocation=$_.InstallLocation} })
$svc=@(Get-CimInstance Win32_Service -Filter "State='Running'" | Select-Object -First 1900 | ForEach-Object { [pscustomobject]@{key=$_.Name;name=$_.DisplayName;description=$_.Description;state=$_.State;startMode=$_.StartMode;account=$_.StartName;executablePath=$_.PathName;pid=[string]$_.ProcessId} })
[pscustomobject]@{hostname=$env:COMPUTERNAME;domain=$cs.Domain;manufacturer=$cs.Manufacturer;model=$cs.Model;serial=$bios.SerialNumber;chassis=@($enc.ChassisTypes);productType=$os.ProductType;os=$os.Caption;osVersion=$os.Version;build=$os.BuildNumber;cpus=$cs.NumberOfLogicalProcessors;memoryBytes=$cs.TotalPhysicalMemory;interfaces=$ifs;software=$sw;services=$svc} | ConvertTo-Json -Depth 4 -Compress
`

func splitSections(output string) map[string][]string {
	sections := map[string][]string{}
	current := ""
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "##") && len(line) < 20 {
			current = strings.TrimPrefix(line, "##")
			sections[current] = []string{}
			continue
		}
		if current != "" && strings.TrimSpace(line) != "" {
			sections[current] = append(sections[current], line)
		}
	}
	return sections
}

var linuxAddrLine = regexp.MustCompile(`^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)`)
var linuxLinkLine = regexp.MustCompile(`^(\d+):\s+([^:@\s]+)[^\n]*link/ether\s+([0-9a-fA-F:]{17})`)
var linuxRouteLine = regexp.MustCompile(`^default via (\d+\.\d+\.\d+\.\d+) dev (\S+)`)

func clip(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// parseLinuxInventory converts linuxInventoryScript output to a discovery snapshot.
func parseLinuxInventory(output string) (M, error) {
	sections := splitSections(output)
	if _, ok := sections["END"]; !ok {
		return nil, fmt.Errorf("Remote inventory output was incomplete")
	}
	first := func(name string) string {
		if lines := sections[name]; len(lines) > 0 {
			return strings.TrimSpace(lines[0])
		}
		return ""
	}
	osRelease := map[string]string{}
	for _, line := range sections["OSRELEASE"] {
		if k, v, ok := strings.Cut(line, "="); ok {
			osRelease[k] = strings.Trim(v, `"'`)
		}
	}
	dmi := map[string]string{}
	for _, line := range sections["DMI"] {
		if k, v, ok := strings.Cut(line, "="); ok {
			dmi[k] = strings.TrimSpace(v)
		}
	}
	host := M{"hostname": clip(first("HOSTNAME"), 120), "os": "Linux", "osVersion": clip(firstNonEmpty(osRelease["PRETTY_NAME"], osRelease["NAME"]), 120), "kernel": clip(first("KERNEL"), 80), "manufacturer": clip(dmi["sys_vendor"], 120), "model": clip(dmi["product_name"], 120), "serial": clip(dmi["product_serial"], 120)}
	if n, err := strconv.Atoi(first("CPU")); err == nil {
		host["cpus"] = n
	}
	if fields := strings.Fields(first("MEM")); len(fields) >= 2 {
		if kb, err := strconv.ParseFloat(fields[1], 64); err == nil {
			host["memoryBytes"] = kb * 1024
		}
	}
	// SMBIOS chassis types: 8,9,10,14,31,32 portable; 17,23,28,29 server.
	switch strings.TrimSpace(dmi["chassis_type"]) {
	case "8", "9", "10", "14", "31", "32":
		host["deviceType"] = "Laptop"
	case "17", "23", "28", "29":
		host["deviceType"] = "Server"
	}
	macs := map[string]string{}
	for _, line := range sections["LINK"] {
		if m := linuxLinkLine.FindStringSubmatch(line); m != nil {
			macs[m[2]] = strings.ToLower(m[3])
		}
	}
	gateway := map[string]string{}
	for _, line := range sections["ROUTE"] {
		if m := linuxRouteLine.FindStringSubmatch(line); m != nil {
			gateway[m[2]] = m[1]
		}
	}
	dns := []string{}
	for _, line := range sections["DNS"] {
		if fields := strings.Fields(line); len(fields) == 2 {
			if addr, err := netip.ParseAddr(fields[1]); err == nil && addr.Is4() {
				dns = append(dns, addr.String())
			}
		}
	}
	byName := map[string]M{}
	order := []string{}
	for _, line := range sections["ADDR"] {
		m := linuxAddrLine.FindStringSubmatch(line)
		if m == nil || m[1] == "lo" {
			continue
		}
		iface := byName[m[1]]
		if iface == nil {
			iface = M{"name": clip(m[1], 80), "mac": macs[m[1]], "addresses": []string{}, "gateway": gateway[m[1]], "dns": dns}
			byName[m[1]] = iface
			order = append(order, m[1])
		}
		iface["addresses"] = append(iface["addresses"].([]string), m[2])
	}
	interfaces := []any{}
	for _, name := range order {
		interfaces = append(interfaces, jsonRoundTrip(byName[name]))
	}
	snapshot := M{"host": host, "interfaces": interfaces, "neighbors": []any{}}
	if lines, ok := sections["PKG"]; ok && len(lines) > 0 {
		source := strings.TrimPrefix(lines[0], "source=")
		software := []any{}
		for _, line := range lines[1:] {
			parts := strings.Split(line, "\t")
			name, version, publisher := parts[0], "", ""
			if source == "apk" {
				// apk prints name-version-release in a single field
				if i := strings.LastIndex(name, "-"); i > 0 {
					if j := strings.LastIndex(name[:i], "-"); j > 0 {
						name, version = name[:j], name[j+1:]
					}
				}
			}
			if len(parts) > 1 {
				version = parts[1]
			}
			if len(parts) > 2 {
				publisher = parts[2]
			}
			if name = clip(name, 180); name == "" {
				continue
			}
			software = append(software, M{"key": source + ":" + name, "name": name, "version": clip(version, 120), "publisher": clip(publisher, 180)})
		}
		snapshot["software"] = software
		snapshot["softwareSource"] = source + " package database (remote SSH)"
	}
	if lines, ok := sections["SERVICES"]; ok {
		services := []any{}
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
				continue
			}
			unit := clip(fields[0], 180)
			description := clip(strings.Join(fields[4:], " "), 500)
			services = append(services, M{"key": unit, "name": firstNonEmpty(description, unit), "description": description, "state": "Running"})
		}
		snapshot["services"] = services
		snapshot["serviceSource"] = "systemd (remote SSH)"
	}
	return snapshot, nil
}

// parseWindowsInventory converts windowsInventoryScript JSON to a discovery snapshot.
func parseWindowsInventory(output string) (M, error) {
	start := strings.Index(output, "{")
	if start < 0 {
		return nil, fmt.Errorf("Remote inventory output was incomplete")
	}
	var raw M
	if err := json.Unmarshal([]byte(output[start:]), &raw); err != nil {
		return nil, fmt.Errorf("Remote inventory returned invalid data")
	}
	host := M{"hostname": clip(S(raw, "hostname"), 120), "os": "Windows", "osVersion": clip(strings.TrimSpace(S(raw, "os")+" "+S(raw, "osVersion")), 160), "manufacturer": clip(S(raw, "manufacturer"), 120), "model": clip(S(raw, "model"), 120), "serial": clip(S(raw, "serial"), 120), "domain": clip(S(raw, "domain"), 120)}
	if n := N(raw, "cpus"); n > 0 {
		host["cpus"] = n
	}
	if n := N(raw, "memoryBytes"); n > 0 {
		host["memoryBytes"] = n
	}
	if N(raw, "productType") == 2 || N(raw, "productType") == 3 {
		host["deviceType"] = "Server"
	} else {
		portable := false
		for _, value := range listOf(raw["chassis"]) {
			switch int(toFloat(value)) {
			case 8, 9, 10, 14, 30, 31, 32:
				portable = true
			}
		}
		if portable {
			host["deviceType"] = "Laptop"
		} else if N(raw, "productType") == 1 {
			host["deviceType"] = "Desktop"
		}
	}
	interfaces := []any{}
	for _, value := range listOf(raw["interfaces"]) {
		iface := obj(value)
		addresses := []string{}
		for _, a := range listOf(iface["addresses"]) {
			if s, ok := a.(string); ok {
				addresses = append(addresses, s)
			}
		}
		dns := []string{}
		for _, a := range listOf(iface["dns"]) {
			if s, ok := a.(string); ok {
				dns = append(dns, s)
			}
		}
		interfaces = append(interfaces, jsonRoundTrip(M{"name": clip(S(iface, "name"), 150), "index": iface["index"], "mac": strings.ToLower(strings.ReplaceAll(S(iface, "mac"), "-", ":")), "addresses": addresses, "gateway": S(iface, "gateway"), "dns": dns}))
	}
	software := []any{}
	for _, value := range listOf(raw["software"]) {
		item := obj(value)
		if S(item, "name") == "" {
			continue
		}
		software = append(software, M{"key": "registry:" + clip(S(item, "key"), 400), "name": clip(S(item, "name"), 180), "version": clip(S(item, "version"), 120), "publisher": clip(S(item, "publisher"), 180), "installLocation": clip(S(item, "installLocation"), 400)})
	}
	services := []any{}
	for _, value := range listOf(raw["services"]) {
		item := obj(value)
		if S(item, "key") == "" {
			continue
		}
		services = append(services, M{"key": clip(S(item, "key"), 180), "name": clip(firstNonEmpty(S(item, "name"), S(item, "key")), 180), "description": clip(S(item, "description"), 2000), "state": clip(S(item, "state"), 40), "startMode": clip(S(item, "startMode"), 40), "account": clip(S(item, "account"), 180), "executablePath": clip(S(item, "executablePath"), 600), "pid": clip(S(item, "pid"), 20)})
	}
	return M{"host": host, "interfaces": interfaces, "neighbors": []any{}, "software": software, "softwareSource": "Windows registry (remote WinRM)", "services": services, "serviceSource": "Windows services (remote WinRM)"}, nil
}

// listOf accepts a JSON array or a single object (PowerShell collapses
// one-element arrays) and always returns a slice.
func listOf(value any) []any {
	switch v := value.(type) {
	case []any:
		return v
	case nil:
		return nil
	default:
		return []any{v}
	}
}

func toFloat(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

// jsonRoundTrip normalises typed slices (e.g. []string) to []any so the shared
// ingestion helpers see the same types as decoded collector JSON.
func jsonRoundTrip(value M) M {
	var out M
	_ = json.Unmarshal([]byte(J(value)), &out)
	return out
}
