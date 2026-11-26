package main

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"time"
)

type ManagedService struct {
	Key            string `json:"key"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	PID            string `json:"pid"`
	State          string `json:"state"`
	ExecutablePath string `json:"executablePath"`
	StartMode      string `json:"startMode"`
	Account        string `json:"account"`
}

var lastServices time.Time

func managedServices(ctx context.Context) ([]ManagedService, string) {
	if time.Since(lastServices) < time.Minute {
		return nil, ""
	}
	if runtime.GOOS == "windows" {
		script := `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; $items=@(Get-CimInstance Win32_Service | ForEach-Object {@{key=$_.Name;name=$_.DisplayName;description=$_.Description;pid=[string]$_.ProcessId;state=$_.State;executablePath=$_.PathName;startMode=$_.StartMode;account=$_.StartName}}); ConvertTo-Json -InputObject $items -Depth 3 -Compress`
		raw, err := command(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		if err != nil {
			return nil, ""
		}
		var items []ManagedService
		if json.Unmarshal([]byte(strings.TrimPrefix(raw, "\ufeff")), &items) != nil {
			return nil, ""
		}
		lastServices = time.Now()
		if items == nil {
			items = []ManagedService{}
		}
		return items, "Windows service manager"
	}
	if runtime.GOOS == "linux" {
		raw, err := command(ctx, "systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager")
		if err != nil {
			return nil, ""
		}
		items := []ManagedService{}
		for _, line := range strings.Split(raw, "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 {
				items = append(items, ManagedService{Key: f[0], Name: f[0], Description: strings.Join(f[4:], " "), State: f[2] + " / " + f[3]})
			}
		}
		lastServices = time.Now()
		return items, "Linux systemd loaded units (inactive installed units may be absent)"
	}
	return nil, ""
}
