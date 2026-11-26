package main

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"time"
)

type Software struct {
	Key             string `json:"key"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Publisher       string `json:"publisher,omitempty"`
	InstallLocation string `json:"installLocation,omitempty"`
}

var lastSoftware time.Time

// Registry reads avoid Win32_Product, which can trigger MSI repair operations.
func installedSoftware(ctx context.Context) ([]Software, string) {
	if time.Since(lastSoftware) < 15*time.Minute {
		return nil, ""
	}
	if runtime.GOOS == "windows" {
		script := `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; $roots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'); $items=@(foreach($root in $roots){Get-ItemProperty $root -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -and !$_.SystemComponent} | ForEach-Object {@{key=$_.PSPath;name=$_.DisplayName;version=$_.DisplayVersion;publisher=$_.Publisher;installLocation=$_.InstallLocation}}}); ConvertTo-Json -InputObject $items -Compress -Depth 3`
		raw, err := command(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		if err != nil {
			return nil, ""
		}
		var items []Software
		if json.Unmarshal([]byte(strings.TrimPrefix(raw, "\ufeff")), &items) != nil {
			return nil, ""
		}
		lastSoftware = time.Now()
		if items == nil {
			items = []Software{}
		}
		return items, "Windows machine-wide uninstall registry (portable and per-user applications may be absent)"
	}
	if runtime.GOOS == "linux" {
		for _, manager := range []struct {
			name string
			args []string
		}{
			{"dpkg-query", []string{"-W", "-f=${db:Status-Status}\t${Package}:${Architecture}\t${Version}\n"}},
			{"rpm", []string{"-qa", "--qf", "installed\t%{NAME}.%{ARCH}\t%{VERSION}-%{RELEASE}\n"}},
			{"apk", []string{"list", "--installed"}},
		} {
			raw, err := command(ctx, manager.name, manager.args...)
			if err != nil {
				continue
			}
			items := []Software{}
			for _, line := range strings.Split(raw, "\n") {
				fields := strings.Split(strings.TrimSpace(line), "\t")
				if manager.name == "apk" {
					parts := strings.Fields(line)
					if len(parts) > 0 {
						items = append(items, Software{Key: "apk:" + parts[0], Name: parts[0]})
					}
					continue
				}
				if len(fields) == 3 && fields[0] == "installed" {
					items = append(items, Software{Key: manager.name + ":" + fields[1], Name: fields[1], Version: fields[2]})
				}
			}
			if len(items) > 5000 {
				items = items[:5000]
			}
			lastSoftware = time.Now()
			return items, "Linux package manager: " + manager.name + " (up to 5000 packages; unmanaged applications may be absent)"
		}
	}
	return nil, ""
}
