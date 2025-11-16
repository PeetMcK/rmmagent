/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the "License").
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	trmm "github.com/wh1te909/trmm-shared"
)

// TransformSystemInfo converts OSQuery system_info to AgentInfoNats
func (a *Agent) TransformSystemInfo(results []map[string]string) (*trmm.AgentInfoNats, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("no system_info results")
	}

	row := results[0]

	// Get OS version
	osResults, err := a.osqueryClient.Query(QueryOSVersion)
	if err != nil {
		return nil, fmt.Errorf("os_version query failed: %w", err)
	}
	if len(osResults) == 0 {
		return nil, fmt.Errorf("no os_version results")
	}
	osRow := osResults[0]

	// Get uptime for boot_time calculation
	uptimeResults, _ := a.osqueryClient.Query(QueryUptime)
	var bootTime int64
	if len(uptimeResults) > 0 {
		totalSeconds, _ := strconv.ParseInt(uptimeResults[0]["total_seconds"], 10, 64)
		bootTime = time.Now().Unix() - totalSeconds
	}

	// Get logged-in user
	userResults, _ := a.osqueryClient.Query(QueryLoggedInUsers)
	var username string = "None"
	if len(userResults) > 0 {
		username = userResults[0]["user"]
	}

	// Convert RAM from bytes to GB
	ramBytes, _ := strconv.ParseFloat(row["physical_memory"], 64)
	ramGB := ramBytes / 1024 / 1024 / 1024

	// Build OS string with build number and code name for macOS
	var osString string
	if runtime.GOOS == "darwin" {
		// macOS: Include build number and code name
		build := osRow["build"]
		codeName := getMacOSCodeName(osRow["version"])
		if codeName != "" {
			osString = fmt.Sprintf("%s %s (%s) - %s", osRow["name"], osRow["version"], build, codeName)
		} else if build != "" {
			osString = fmt.Sprintf("%s %s (%s)", osRow["name"], osRow["version"], build)
		} else {
			osString = fmt.Sprintf("%s %s", osRow["name"], osRow["version"])
		}
	} else {
		osString = fmt.Sprintf("%s %s %s", osRow["name"], osRow["version"], osRow["arch"])
	}

	// Check if reboot needed (platform-specific)
	rebootNeeded, _ := a.SystemRebootRequired()

	return &trmm.AgentInfoNats{
		Agentid:      a.AgentID,
		Username:     username,
		Hostname:     row["hostname"],
		OS:           osString,
		Platform:     runtime.GOOS,
		TotalRAM:     ramGB,
		BootTime:     bootTime,
		RebootNeeded: rebootNeeded,
		GoArch:       runtime.GOARCH,
	}, nil
}

// TransformDisks converts OSQuery mounts to WinDisksNats
func (a *Agent) TransformDisks(results []map[string]string) (*trmm.WinDisksNats, error) {
	var disks []trmm.Disk

	for _, row := range results {
		blocks, _ := strconv.ParseUint(row["blocks"], 10, 64)
		blockSize, _ := strconv.ParseUint(row["blocks_size"], 10, 64)
		blocksFree, _ := strconv.ParseUint(row["blocks_free"], 10, 64)

		totalBytes := blocks * blockSize
		freeBytes := blocksFree * blockSize
		usedBytes := totalBytes - freeBytes

		var percent int
		if totalBytes > 0 {
			percent = int((float64(usedBytes) / float64(totalBytes)) * 100)
		}

		// Get friendly device name and type for macOS
		deviceName := row["device"]
		fsType := row["type"]
		if runtime.GOOS == "darwin" && row["path"] == "/" {
			volName, volType := a.getMacOSVolumeInfo(row["path"])
			if volName != "" {
				deviceName = volName
			}
			if volType != "" {
				fsType = volType
			}
		}

		// Convert bytes to GB for display
		totalGB := float64(totalBytes) / 1024 / 1024 / 1024
		usedGB := float64(usedBytes) / 1024 / 1024 / 1024
		freeGB := float64(freeBytes) / 1024 / 1024 / 1024

		disk := trmm.Disk{
			Device:  deviceName,
			Fstype:  fsType,
			Total:   fmt.Sprintf("%.2f GB", totalGB),
			Used:    fmt.Sprintf("%.2f GB", usedGB),
			Free:    fmt.Sprintf("%.2f GB", freeGB),
			Percent: percent,
		}

		disks = append(disks, disk)
	}

	return &trmm.WinDisksNats{
		Agentid: a.AgentID,
		Disks:   disks,
	}, nil
}

// getMacOSVolumeInfo gets the friendly volume name and type for a macOS mount point
func (a *Agent) getMacOSVolumeInfo(mountPath string) (string, string) {
	cmd := exec.Command("diskutil", "info", mountPath)
	output, err := cmd.Output()
	if err != nil {
		return "", ""
	}

	var volumeName, volumeType string

	// Parse output to find "Volume Name:" and "APFS Volume Group"
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Volume Name:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				volumeName = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "APFS Volume Group:") {
			volumeType = "APFS Volume Group"
		}
	}

	return volumeName, volumeType
}

// TransformServices converts OSQuery launchd/systemd to WinSvcNats format
func (a *Agent) TransformServices(results []map[string]string) (*trmm.WinSvcNats, error) {
	var services []trmm.WindowsService

	for _, row := range results {
		var svc trmm.WindowsService

		if runtime.GOOS == "darwin" {
			// launchd format
			svc = trmm.WindowsService{
				Name:        row["name"],
				DisplayName: row["display_name"],
				Status:      determineLaunchdStatus(row),
				BinPath:     row["program"],
				Username:    row["username"],
				Description: fmt.Sprintf("launchd: %s", row["path"]),
				StartType:   determineLaunchdStartType(row),
			}
		} else {
			// systemd format
			svc = trmm.WindowsService{
				Name:        row["name"],
				DisplayName: row["name"],
				Status:      mapSystemdState(row["active_state"]),
				BinPath:     row["fragment_path"],
				Username:    row["user"],
				Description: row["description"],
				StartType:   mapSystemdLoadState(row["load_state"]),
			}
		}

		services = append(services, svc)
	}

	return &trmm.WinSvcNats{
		Agentid: a.AgentID,
		WinSvcs: services,
	}, nil
}

// determineLaunchdStatus infers service status from launchd properties
// Note: OSQuery's launchd table doesn't provide runtime status, so we infer:
// - If disabled=1, service is stopped
// - Otherwise, we assume it's running/enabled (this is a best-effort approximation)
func determineLaunchdStatus(launchdRow map[string]string) string {
	if launchdRow["disabled"] == "1" || launchdRow["disabled"] == "true" {
		return "stopped"
	}
	// For services that are enabled, we assume they're running
	// This is not 100% accurate but launchd table doesn't provide runtime status
	return "running"
}

// determineLaunchdStartType determines the start type for launchd services
func determineLaunchdStartType(launchdRow map[string]string) string {
	if launchdRow["run_at_load"] == "1" || launchdRow["run_at_load"] == "true" {
		return "automatic"
	}
	if launchdRow["disabled"] == "1" || launchdRow["disabled"] == "true" {
		return "disabled"
	}
	if launchdRow["on_demand"] == "1" || launchdRow["on_demand"] == "true" {
		return "manual"
	}
	return "manual"
}

// mapSystemdState maps systemd active_state to Windows service status
func mapSystemdState(state string) string {
	switch state {
	case "active":
		return "running"
	case "inactive":
		return "stopped"
	case "failed":
		return "stopped"
	default:
		return state
	}
}

// mapSystemdLoadState maps systemd load_state to Windows service start type
func mapSystemdLoadState(state string) string {
	switch state {
	case "enabled":
		return "automatic"
	case "disabled":
		return "disabled"
	default:
		return "manual"
	}
}

// TransformSoftware converts OSQuery apps/packages to software list
func (a *Agent) TransformSoftware(results []map[string]string) ([]trmm.WinSoftwareList, error) {
	var software []trmm.WinSoftwareList

	for _, row := range results {
		var sw trmm.WinSoftwareList

		if runtime.GOOS == "darwin" {
			// macOS apps format
			sw = trmm.WinSoftwareList{
				Name:        row["name"],
				Version:     row["version"],
				Publisher:   row["path"],
				InstallDate: row["copyright"],
				Location:    row["path"],
				Source:      "osquery-apps",
			}
		} else {
			// Linux packages format
			sw = trmm.WinSoftwareList{
				Name:     row["name"],
				Version:  row["version"],
				Location: row["source"],
			}

			if size, ok := row["size"]; ok {
				sw.Size = size
			}
			if vendor, ok := row["vendor"]; ok && vendor != "" {
				sw.Publisher = vendor
			} else if maintainer, ok := row["maintainer"]; ok && maintainer != "" {
				sw.Publisher = maintainer
			}

			// Determine source (RPM vs DEB)
			if _, ok := row["release"]; ok {
				sw.Source = "osquery-rpm"
			} else {
				sw.Source = "osquery-deb"
			}
		}

		software = append(software, sw)
	}

	return software, nil
}

// NetworkInterface represents a network interface with its addresses and configuration
type NetworkInterface struct {
	Name      string         `json:"name"`
	MAC       string         `json:"mac"`
	Status    string         `json:"status"` // "UP" or "DOWN"
	Type      string         `json:"type"`   // "Ethernet", "WiFi", etc.
	IPv4      []string       `json:"ipv4,omitempty"`
	IPv6      []string       `json:"ipv6,omitempty"`
	Gateway   string         `json:"gateway,omitempty"`
	DNS       []string       `json:"dns,omitempty"`
	SSID      string         `json:"ssid,omitempty"`
	MTU       int            `json:"mtu"`
}

// TransformNetworkInterfaces converts OSQuery network data to NetworkInterface format
func (a *Agent) TransformNetworkInterfaces(
	interfacesResults []map[string]string,
	addressesResults []map[string]string,
	gatewayResults []map[string]string,
	dnsResults []map[string]string,
	wifiResults []map[string]string,
) (string, []string, error) {
	// Build map of interfaces
	interfaceMap := make(map[string]*NetworkInterface)

	// Build WiFi interface map first
	wifiInterfaces := make(map[string]string) // interface name -> SSID
	for _, row := range wifiResults {
		wifiInterfaces[row["interface"]] = row["ssid"]
	}

	// Process interface details
	for _, row := range interfacesResults {
		iface := &NetworkInterface{
			Name: row["interface"],
			MAC:  row["mac"],
			IPv4: []string{},
			IPv6: []string{},
			DNS:  []string{},
		}

		// Determine status from flags (bit 0 = UP/DOWN)
		flags, _ := strconv.Atoi(row["flags"])
		if (flags & 1) == 1 {
			iface.Status = "UP"
		} else {
			iface.Status = "DOWN"
		}

		// Check if this is a WiFi interface
		if ssid, isWiFi := wifiInterfaces[row["interface"]]; isWiFi {
			iface.Type = "Wi-Fi"
			iface.SSID = ssid
		} else {
			// Classify interface type
			iface.Type = classifyInterface(row["interface"])
		}

		// MTU
		iface.MTU, _ = strconv.Atoi(row["mtu"])

		interfaceMap[row["interface"]] = iface
	}

	// Process addresses
	for _, row := range addressesResults {
		ifaceName := row["interface"]
		address := row["address"]
		mask := row["mask"]

		iface, ok := interfaceMap[ifaceName]
		if !ok {
			continue
		}

		// Check if IPv4 or IPv6
		if strings.Contains(address, ".") {
			// IPv4
			cidr := maskToCIDR(mask, false)
			if cidr > 0 {
				iface.IPv4 = append(iface.IPv4, fmt.Sprintf("%s/%d", address, cidr))
			} else {
				iface.IPv4 = append(iface.IPv4, address)
			}
		} else if strings.Contains(address, ":") {
			// IPv6 - filter out link-local and loopback
			if isRoutableIPv6(address) {
				// Remove zone ID (e.g., %en0)
				address = strings.Split(address, "%")[0]
				cidr := maskToCIDR(mask, true)
				if cidr > 0 {
					iface.IPv6 = append(iface.IPv6, fmt.Sprintf("%s/%d", address, cidr))
				} else {
					iface.IPv6 = append(iface.IPv6, address)
				}
			}
		}
	}

	// Process default gateway
	for _, row := range gatewayResults {
		ifaceName := row["interface"]
		gateway := row["gateway"]

		if iface, ok := interfaceMap[ifaceName]; ok {
			iface.Gateway = gateway
		}
	}

	// Process DNS servers (apply to all interfaces or primary)
	dnsServers := []string{}
	for _, row := range dnsResults {
		dnsServers = append(dnsServers, row["address"])
	}

	// Apply DNS to primary interface (one with gateway)
	for _, iface := range interfaceMap {
		if iface.Gateway != "" {
			iface.DNS = dnsServers
			break
		}
	}

	// Format output for display
	var primaryIP string
	var outputLines []string

	// Find primary interface (has gateway and is UP)
	var primaryIface *NetworkInterface
	for _, iface := range interfaceMap {
		if iface.Gateway != "" && iface.Status == "UP" {
			primaryIface = iface
			break
		}
	}

	// If no primary found, use first UP interface
	if primaryIface == nil {
		for _, iface := range interfaceMap {
			if iface.Status == "UP" && len(iface.IPv4) > 0 {
				primaryIface = iface
				break
			}
		}
	}

	// Build formatted IP information
	if primaryIface != nil {
		// Primary IP for backward compatibility
		if len(primaryIface.IPv4) > 0 {
			primaryIP = strings.Split(primaryIface.IPv4[0], "/")[0] // Just IP without CIDR for primary
		}

		// Format primary interface with all details
		interfaceLabel := primaryIface.Type
		if primaryIface.SSID != "" {
			interfaceLabel = fmt.Sprintf("%s (%s)", primaryIface.Type, primaryIface.SSID)
		}

		outputLines = append(outputLines, fmt.Sprintf("Interface: %s", interfaceLabel))

		// Add IPv4 addresses
		for _, ip := range primaryIface.IPv4 {
			outputLines = append(outputLines, fmt.Sprintf("IP: %s", ip))
		}

		// Add Gateway if available
		if primaryIface.Gateway != "" {
			outputLines = append(outputLines, fmt.Sprintf("GW: %s", primaryIface.Gateway))
		}

		// Add DNS servers if available
		if len(primaryIface.DNS) > 0 {
			dnsStr := strings.Join(primaryIface.DNS, " | ")
			outputLines = append(outputLines, fmt.Sprintf("DNS: %s", dnsStr))
		}

		// Add IPv6 if available
		for _, ip := range primaryIface.IPv6 {
			outputLines = append(outputLines, fmt.Sprintf("IPv6: %s", ip))
		}

		// Add MAC address
		if primaryIface.MAC != "" && primaryIface.MAC != "00:00:00:00:00:00" {
			outputLines = append(outputLines, fmt.Sprintf("MAC: %s", primaryIface.MAC))
		}

		// Add other active interfaces if any
		for name, iface := range interfaceMap {
			if name != primaryIface.Name && iface.Status == "UP" && (len(iface.IPv4) > 0 || len(iface.IPv6) > 0) {
				outputLines = append(outputLines, "")
				interfaceLabel := iface.Type
				if iface.SSID != "" {
					interfaceLabel = fmt.Sprintf("%s (%s)", iface.Type, iface.SSID)
				}
				outputLines = append(outputLines, fmt.Sprintf("Interface: %s", interfaceLabel))
				for _, ip := range iface.IPv4 {
					outputLines = append(outputLines, fmt.Sprintf("IP: %s", ip))
				}
				for _, ip := range iface.IPv6 {
					outputLines = append(outputLines, fmt.Sprintf("IPv6: %s", ip))
				}
				if iface.MAC != "" && iface.MAC != "00:00:00:00:00:00" {
					outputLines = append(outputLines, fmt.Sprintf("MAC: %s", iface.MAC))
				}
			}
		}

		// Add offline interfaces with MAC addresses
		for name, iface := range interfaceMap {
			if iface.Status == "DOWN" && iface.MAC != "" && iface.MAC != "00:00:00:00:00:00" {
				outputLines = append(outputLines, "")
				outputLines = append(outputLines, fmt.Sprintf("Interface: %s (Offline)", name))
				outputLines = append(outputLines, fmt.Sprintf("MAC: %s", iface.MAC))
			}
		}
	}

	return primaryIP, outputLines, nil
}

// maskToCIDR converts netmask to prefix length
func maskToCIDR(maskStr string, isIPv6 bool) int {
	// Parse mask as IP
	mask := net.ParseIP(maskStr)
	if mask == nil {
		return 0
	}

	// Convert to net.IPMask
	var ipMask net.IPMask
	if isIPv6 {
		ipMask = net.IPMask(mask.To16())
	} else {
		ipMask = net.IPMask(mask.To4())
	}

	if ipMask == nil {
		return 0
	}

	// Count bits
	ones, bits := ipMask.Size()
	if bits == 0 {
		return 0
	}

	return ones
}

// classifyInterface determines interface type from name
func classifyInterface(name string) string {
	switch {
	case name == "lo0":
		return "Loopback"
	case strings.HasPrefix(name, "en"):
		return "Ethernet"
	case strings.HasPrefix(name, "utun"):
		return "VPN"
	case strings.HasPrefix(name, "awdl"):
		return "AWDL"
	case strings.HasPrefix(name, "llw"):
		return "LocalLinkWiFi"
	case strings.HasPrefix(name, "bridge"):
		return "Bridge"
	default:
		return "Other"
	}
}

// isRoutableIPv6 checks if an IPv6 address is routable (not link-local)
func isRoutableIPv6(addr string) bool {
	// Remove zone ID if present
	addr = strings.Split(addr, "%")[0]

	// Exclude link-local (fe80::)
	if strings.HasPrefix(addr, "fe80:") {
		return false
	}

	// Exclude loopback (::1)
	if strings.HasPrefix(addr, "::1") {
		return false
	}

	// Exclude multicast (ff00::)
	if strings.HasPrefix(addr, "ff") {
		return false
	}

	return true
}

// parseMacOSNameFromRTF parses the OS name from the software license RTF file
func parseMacOSNameFromRTF() string {
	rtfPath := "/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/en.lproj/OSXSoftwareLicense.rtf"

	data, err := os.ReadFile(rtfPath)
	if err != nil {
		return ""
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		// Look for the line containing "SOFTWARE LICENSE AGREEMENT FOR macOS"
		if strings.Contains(line, "SOFTWARE LICENSE AGREEMENT FOR macOS") {
			// Extract everything after "macOS "
			idx := strings.Index(line, "macOS ")
			if idx == -1 {
				continue
			}

			// Get text after "macOS "
			afterMacOS := line[idx+6:] // 6 = len("macOS ")

			// Remove RTF formatting (anything with backslashes or braces)
			// Split by backslash first to remove RTF commands
			if strings.Contains(afterMacOS, "\\") {
				afterMacOS = strings.Split(afterMacOS, "\\")[0]
			}

			// Clean up any remaining non-alphanumeric characters except spaces and dots
			var cleaned strings.Builder
			for _, r := range afterMacOS {
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '.' {
					cleaned.WriteRune(r)
				}
			}
			cleanedStr := strings.TrimSpace(cleaned.String())

			// Split by whitespace
			parts := strings.Fields(cleanedStr)
			if len(parts) < 2 {
				continue
			}

			// Last part is the version number, everything before is the OS name
			osName := strings.Join(parts[:len(parts)-1], " ")
			return osName
		}
	}

	return ""
}

// getMacOSCodeName returns the code name for a macOS version
func getMacOSCodeName(version string) string {
	// Map macOS versions to code names
	codeNames := map[string]string{
		// macOS 10.x (Mac OS X / OS X)
		"10.0":  "Cheetah",
		"10.1":  "Puma",
		"10.2":  "Jaguar",
		"10.3":  "Panther",
		"10.4":  "Tiger",
		"10.5":  "Leopard",
		"10.6":  "Snow Leopard",
		"10.7":  "Lion",
		"10.8":  "Mountain Lion",
		"10.9":  "Mavericks",
		"10.10": "Yosemite",
		"10.11": "El Capitan",
		"10.12": "Sierra",
		"10.13": "High Sierra",
		"10.14": "Mojave",
		"10.15": "Catalina",

		// macOS 11+ (by major version)
		"11": "Big Sur",
		"12": "Monterey",
		"13": "Ventura",
		"14": "Sonoma",
		"15": "Sequoia",
		"26": "Tahoe",
	}

	// For versions starting with "10.", check the full version (e.g., "10.15")
	if strings.HasPrefix(version, "10.") {
		// Extract major.minor (e.g., "10.15.7" -> "10.15")
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			majorMinor := parts[0] + "." + parts[1]
			if name, ok := codeNames[majorMinor]; ok {
				return name
			}
		}
	} else {
		// For versions 11+, use just the major version (e.g., "26.1" -> "26")
		parts := strings.Split(version, ".")
		if len(parts) >= 1 {
			major := parts[0]
			if name, ok := codeNames[major]; ok {
				return name
			}
		}
	}

	// Fallback: Try to parse from RTF file for unknown versions
	if name := parseMacOSNameFromRTF(); name != "" {
		return name
	}

	return ""
}
