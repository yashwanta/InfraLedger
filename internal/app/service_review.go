package app

import "strings"

// Review is an explanation of observable properties, never a malware verdict.
func serviceReview(process string, port float64, address string) M {
	p := strings.ToLower(process)
	description := "Network-active process observed on this endpoint. Confirm its owner, executable path, and publisher before trusting its identity."
	known := map[string]string{
		"lsass.exe":    "Windows Local Security Authority process. Handles authentication and local security policy. The process name alone does not verify its identity.",
		"svchost.exe":  "Windows service host. Multiple instances can host different Windows services; inspect service membership to identify the workload.",
		"system":       "Windows kernel networking activity. A socket attributed to System does not identify a single installed application.",
		"services.exe": "Windows Service Control Manager process. Starts and manages Windows services.",
		"sshd":         "Secure Shell server providing remote administration and file transfer.",
		"nginx":        "Web server and reverse proxy. Review exposed listeners and upstream application configuration.",
		"postgres":     "PostgreSQL database process. Review client access rules and network exposure.",
	}
	if s := known[p]; s != "" {
		description = s
	}
	reasons := []string{}
	if strings.HasPrefix(p, "process ") || p == "unknown" || p == "" {
		reasons = append(reasons, "Executable name could not be resolved by the collector.")
	}
	if address == "0.0.0.0" || address == "::" || address == "*" {
		reasons = append(reasons, "Listens on all interfaces. Check firewall policy and whether remote access is intended; this does not prove Internet exposure.")
	}
	if port == 23 || port == 21 {
		reasons = append(reasons, "Port commonly associated with an unencrypted protocol. Verify the actual service and whether a secure alternative is available.")
	}
	status := "Identity unverified"
	if len(reasons) > 0 {
		status = "Needs review"
	}
	return M{"description": description, "reviewStatus": status, "reviewReasons": reasons, "reviewScope": "Rule-based configuration review; executable signatures, vulnerabilities, and malware are not assessed."}
}
