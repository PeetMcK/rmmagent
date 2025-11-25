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
	"regexp"
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

	var volumeName, volumeType, fileVaultStatus string

	// Parse output to find Volume Name, File System type, and FileVault status
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Volume Name:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				volumeName = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "File System Personality:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				fsType := strings.TrimSpace(parts[1])
				// For APFS, indicate it's a volume group
				if fsType == "APFS" {
					volumeType = "APFS Volume Group"
				} else {
					volumeType = fsType
				}
			}
		}
		if strings.Contains(line, "FileVault:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				fileVaultStatus = strings.TrimSpace(parts[1])
			}
		}
	}

	// Append encryption status to volume type if FileVault is enabled
	if fileVaultStatus != "" && strings.Contains(strings.ToLower(fileVaultStatus), "yes") {
		volumeType = volumeType + " (Encrypted)"
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

// NetworkServiceInfo represents a network service from networksetup
type NetworkServiceInfo struct {
	Name   string
	Device string
	Order  int
}

// getNetworkServices returns ordered list of network services from networksetup
func (a *Agent) getNetworkServices() []NetworkServiceInfo {
	services := []NetworkServiceInfo{}

	opts := a.NewCMDOpts()
	opts.Command = "networksetup -listnetworkserviceorder"
	out := a.CmdV2(opts)

	if out.Status.Error != nil {
		a.Logger.Errorf("DEBUG: networksetup command failed: %v", out.Status.Error)
		return services
	}

	a.Logger.Errorf("DEBUG: networksetup output: %s", out.Stdout)

	lines := strings.Split(out.Stdout, "\n")
	var currentService string
	var currentOrder int

	// Regular expression to parse: (Hardware Port: X, Device: Y)
	deviceRe := regexp.MustCompile(`\(Hardware Port: .+?, Device: (.+?)\)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip header and empty lines
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}

		// Check if this is a service name line (starts with number in parentheses)
		// Must start with "(" followed by a digit
		if strings.HasPrefix(line, "(") && len(line) > 1 && line[1] >= '0' && line[1] <= '9' && strings.Contains(line, ")") {
			// Extract service name after the order number
			parts := strings.SplitN(line, ")", 2)
			if len(parts) == 2 {
				currentService = strings.TrimSpace(parts[1])
				// Extract order number
				orderStr := strings.Trim(parts[0], "()")
				currentOrder, _ = strconv.Atoi(orderStr)
				a.Logger.Errorf("DEBUG: Found service: %s (order %d)", currentService, currentOrder)
			}
		} else if currentService != "" && strings.HasPrefix(line, "(Hardware Port:") {
			// Extract device name from the line
			matches := deviceRe.FindStringSubmatch(line)
			if len(matches) > 1 {
				device := matches[1]
				services = append(services, NetworkServiceInfo{
					Name:   currentService,
					Device: device,
					Order:  currentOrder,
				})
				a.Logger.Errorf("DEBUG: Added service: %s -> %s", currentService, device)
				currentService = ""
			}
		}
	}

	a.Logger.Errorf("DEBUG: Total services found: %d", len(services))
	return services
}

// TransformNetworkInterfaces converts OSQuery network data to NetworkInterface format
func (a *Agent) TransformNetworkInterfaces(
	interfacesResults []map[string]string,
	addressesResults []map[string]string,
	gatewayResults []map[string]string,
	dnsResults []map[string]string,
	wifiResults []map[string]string,
) (string, []string, error) {
	// Get network services from networksetup in order
	networkServices := a.getNetworkServices()

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

	// Build formatted IP information by iterating through network services in order
	for idx, service := range networkServices {
		iface, exists := interfaceMap[service.Device]
		if !exists {
			// Service exists but no interface data from OSQuery - show as offline with no MAC
			if idx > 0 {
				outputLines = append(outputLines, "")
			}
			outputLines = append(outputLines, fmt.Sprintf("Interface: %s (%s) (Offline)", service.Name, service.Device))
			continue
		}

		// Set primary IP from first active interface
		if primaryIP == "" && len(iface.IPv4) > 0 {
			primaryIP = strings.Split(iface.IPv4[0], "/")[0]
		}

		// Add blank line before each interface except the first
		if idx > 0 {
			outputLines = append(outputLines, "")
		}

		// Check if interface is active (has IP addresses)
		isActive := len(iface.IPv4) > 0 || len(iface.IPv6) > 0

		if isActive {
			// Active interface - show all details
			outputLines = append(outputLines, fmt.Sprintf("Interface: %s (%s)", service.Name, service.Device))

			// Add IPv4 addresses
			for _, ip := range iface.IPv4 {
				outputLines = append(outputLines, fmt.Sprintf("IP: %s", ip))
			}

			// Add Gateway if available
			if iface.Gateway != "" {
				outputLines = append(outputLines, fmt.Sprintf("GW: %s", iface.Gateway))
			}

			// Add DNS servers if available
			if len(iface.DNS) > 0 {
				dnsStr := strings.Join(iface.DNS, " | ")
				outputLines = append(outputLines, fmt.Sprintf("DNS: %s", dnsStr))
			}

			// Add IPv6 if available
			for _, ip := range iface.IPv6 {
				outputLines = append(outputLines, fmt.Sprintf("IPv6: %s", ip))
			}

			// Add MAC address
			if iface.MAC != "" && iface.MAC != "00:00:00:00:00:00" {
				outputLines = append(outputLines, fmt.Sprintf("MAC: %s", iface.MAC))
			}
		} else {
			// Offline interface - show with MAC if available
			outputLines = append(outputLines, fmt.Sprintf("Interface: %s (%s) (Offline)", service.Name, service.Device))
			if iface.MAC != "" && iface.MAC != "00:00:00:00:00:00" {
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

// TransformAssetsCPU transforms OSQuery cpu_info results to Win32_Processor format
func (a *Agent) TransformAssetsCPU(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var cpuData []map[string]interface{}

	// macOS cpu_info returns one row per physical CPU package
	for _, result := range results {
		cpu := make(map[string]interface{})

		cpu["DeviceID"] = result["device_id"]
		cpu["Name"] = result["model"]
		cpu["Manufacturer"] = result["manufacturer"]
		cpu["ProcessorType"] = result["processor_type"]
		cpu["NumberOfCores"] = result["number_of_cores"]
		cpu["NumberOfLogicalProcessors"] = result["logical_processors"]
		cpu["CurrentClockSpeed"] = result["current_clock_speed"]
		cpu["MaxClockSpeed"] = result["max_clock_speed"]
		cpu["SocketDesignation"] = result["socket_designation"]

		// Apple Silicon specific
		if result["number_of_efficiency_cores"] != "" && result["number_of_efficiency_cores"] != "0" {
			cpu["NumberOfEfficiencyCores"] = result["number_of_efficiency_cores"]
		}
		if result["number_of_performance_cores"] != "" && result["number_of_performance_cores"] != "0" {
			cpu["NumberOfPerformanceCores"] = result["number_of_performance_cores"]
		}

		cpuData = append(cpuData, cpu)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{cpuData}
}

// extractCPUManufacturer extracts manufacturer from CPU brand
func extractCPUManufacturer(brand string) string {
	brand = strings.ToLower(brand)
	if strings.Contains(brand, "intel") {
		return "Intel"
	} else if strings.Contains(brand, "amd") {
		return "AMD"
	} else if strings.Contains(brand, "apple") {
		return "Apple"
	}
	return ""
}

// TransformAssetsMemory transforms OSQuery memory_devices results to Win32_PhysicalMemory format
func (a *Agent) TransformAssetsMemory(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var memData []map[string]interface{}

	for _, result := range results {
		// Skip entries with no size
		if result["size"] == "" || result["size"] == "0" {
			continue
		}

		mem := make(map[string]interface{})
		mem["Handle"] = result["handle"]
		mem["Capacity"] = result["size"]
		mem["MemoryType"] = result["type"]
		mem["TypeDetail"] = result["type_detail"]
		mem["FormFactor"] = result["form_factor"]
		mem["DeviceLocator"] = result["device_locator"]
		mem["BankLabel"] = result["bank_locator"]
		mem["Manufacturer"] = result["manufacturer"]
		mem["SerialNumber"] = result["serial_number"]
		mem["AssetTag"] = result["asset_tag"]
		mem["PartNumber"] = result["part_number"]
		mem["Speed"] = result["configured_clock_speed"]
		mem["ConfiguredVoltage"] = result["configured_voltage"]
		mem["TotalWidth"] = result["total_width"]
		mem["DataWidth"] = result["data_width"]

		memData = append(memData, mem)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{memData}
}

// TransformAssetsBIOS transforms OSQuery platform_info results to Win32_BIOS format
func (a *Agent) TransformAssetsBIOS(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var biosData []map[string]interface{}
	bios := make(map[string]interface{})

	if len(results) > 0 {
		result := results[0]
		bios["Manufacturer"] = result["vendor"]
		bios["Name"] = result["vendor"]
		bios["Version"] = result["version"]
		bios["ReleaseDate"] = result["date"]
		bios["SMBIOSBIOSVersion"] = result["version"]
		bios["BIOSVersion"] = []string{result["version"]}
	}

	biosData = append(biosData, bios)

	// Return in Windows WMI format: array of arrays
	return []interface{}{biosData}
}

// TransformAssetsMotherboard transforms OSQuery ioreg results to Win32_BaseBoard format
func (a *Agent) TransformAssetsMotherboard(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var boardData []map[string]interface{}
	board := make(map[string]interface{})

	// Parse IORegistry key-value pairs
	for _, result := range results {
		key := result["key"]
		value := result["value"]

		switch {
		case strings.Contains(key, "manufacturer"):
			board["Manufacturer"] = value
		case strings.Contains(key, "board-id"):
			board["Product"] = value
		case strings.Contains(key, "serial"):
			board["SerialNumber"] = value
		case strings.Contains(key, "version"):
			board["Version"] = value
		case key == "model":
			board["Model"] = value
		}
	}

	boardData = append(boardData, board)

	// Return in Windows WMI format: array of arrays
	return []interface{}{boardData}
}

// TransformAssetsMotherboardFromSystemInfo creates motherboard data from system_info (fallback for macOS without ioreg)
func (a *Agent) TransformAssetsMotherboardFromSystemInfo(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var boardData []map[string]interface{}
	board := make(map[string]interface{})

	result := results[0]
	board["Manufacturer"] = result["hardware_vendor"]
	board["Product"] = result["hardware_model"]
	board["Version"] = result["hardware_version"]
	board["SerialNumber"] = result["hardware_serial"]

	boardData = append(boardData, board)

	// Return in Windows WMI format: array of arrays
	return []interface{}{boardData}
}

// TransformAssetsDisk transforms OSQuery block_devices results to Win32_DiskDrive format
func (a *Agent) TransformAssetsDisk(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	// Also get SMART info if available
	smartResults, _ := a.osqueryClient.Query(QuerySMARTDriveInfo)
	smartMap := make(map[string]map[string]string)
	for _, smart := range smartResults {
		deviceName := smart["device_name"]
		smartMap[deviceName] = smart
	}

	var diskData []map[string]interface{}

	for _, result := range results {
		disk := make(map[string]interface{})
		disk["Name"] = result["name"]
		disk["Model"] = result["model"]
		disk["Size"] = result["size"]
		disk["InterfaceType"] = result["type"]
		disk["BytesPerSector"] = result["block_size"]

		// Add SMART data if available
		if smart, ok := smartMap["/dev/"+result["name"]]; ok {
			disk["SerialNumber"] = smart["serial_number"]
			disk["FirmwareRevision"] = smart["firmware_version"]
		}

		diskData = append(diskData, disk)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{diskData}
}

// TransformAssetsGPU transforms OSQuery pci_devices results to Win32_VideoController format
func (a *Agent) TransformAssetsGPU(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var gpuData []map[string]interface{}

	for _, result := range results {
		gpu := make(map[string]interface{})
		gpu["Name"] = result["model"]
		gpu["VideoProcessor"] = result["model"]
		gpu["AdapterCompatibility"] = result["vendor"]
		gpu["DriverVersion"] = result["driver"]
		gpu["PNPDeviceID"] = result["pci_slot"]

		gpuData = append(gpuData, gpu)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{gpuData}
}

// TransformAssetsGPUFromStrings transforms GPU strings (from system_profiler) to Win32_VideoController format
func (a *Agent) TransformAssetsGPUFromStrings(gpus []string) []interface{} {
	if len(gpus) == 0 {
		return []interface{}{}
	}

	var gpuData []map[string]interface{}

	for _, gpuStr := range gpus {
		gpu := make(map[string]interface{})
		gpu["Name"] = gpuStr
		gpu["VideoProcessor"] = gpuStr
		gpu["AdapterCompatibility"] = "Apple"

		gpuData = append(gpuData, gpu)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{gpuData}
}

// TransformAssetsUSB transforms OSQuery usb_devices results to Win32_USBController format
func (a *Agent) TransformAssetsUSB(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var usbData []map[string]interface{}

	// Include all USB devices (not just hubs/controllers)
	deviceMap := make(map[string]map[string]interface{})

	for _, result := range results {
		// Create unique key to avoid duplicates
		key := result["vendor_id"] + ":" + result["model_id"] + ":" + result["usb_address"]
		if _, exists := deviceMap[key]; !exists {
			usb := make(map[string]interface{})
			usb["Name"] = result["model"]
			usb["Manufacturer"] = result["vendor"]
			usb["DeviceID"] = result["usb_address"]
			usb["Description"] = result["model"]
			usb["PNPDeviceID"] = fmt.Sprintf("USB\\VID_%s&PID_%s", result["vendor_id"], result["model_id"])
			deviceMap[key] = usb
		}
	}

	for _, usb := range deviceMap {
		usbData = append(usbData, usb)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{usbData}
}

// TransformAssetsOS transforms OSQuery os_version results to Win32_OperatingSystem format
func (a *Agent) TransformAssetsOS(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var osData []map[string]interface{}
	os := make(map[string]interface{})

	if len(results) > 0 {
		result := results[0]
		osName := result["name"]
		osVersion := result["version"]

		// Add code name for macOS
		if result["platform"] == "darwin" {
			codeName := getMacOSCodeName(osVersion)
			if codeName != "" {
				osName = osName + " " + codeName
			}
		}

		os["Caption"] = osName
		os["Version"] = osVersion
		os["BuildNumber"] = result["build"]
		os["OSArchitecture"] = result["arch"]
		os["Name"] = osName
		os["Manufacturer"] = "Apple Inc."
	}

	osData = append(osData, os)

	// Return in Windows WMI format: array of arrays
	return []interface{}{osData}
}

// TransformAssetsComputerSystem transforms OSQuery system_info results to Win32_ComputerSystem format
func (a *Agent) TransformAssetsComputerSystem(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var sysData []map[string]interface{}
	sys := make(map[string]interface{})

	if len(results) > 0 {
		result := results[0]
		sys["Manufacturer"] = result["hardware_vendor"]
		sys["Model"] = result["hardware_model"]
		sys["Name"] = result["hostname"]
		sys["TotalPhysicalMemory"] = result["physical_memory"]
		sys["NumberOfProcessors"] = "1" // Most Macs have 1 physical CPU package
		sys["NumberOfLogicalProcessors"] = result["cpu_logical_cores"]
	}

	sysData = append(sysData, sys)

	// Return in Windows WMI format: array of arrays
	return []interface{}{sysData}
}

// TransformAssetsComputerSystemProduct transforms OSQuery system_info results to Win32_ComputerSystemProduct format
func (a *Agent) TransformAssetsComputerSystemProduct(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var prodData []map[string]interface{}
	prod := make(map[string]interface{})

	if len(results) > 0 {
		result := results[0]
		prod["Name"] = result["hardware_model"]
		prod["Vendor"] = result["hardware_vendor"]
		prod["Version"] = result["hardware_version"]
		prod["UUID"] = result["uuid"]
		prod["IdentifyingNumber"] = result["hardware_serial"]
	}

	prodData = append(prodData, prod)

	// Return in Windows WMI format: array of arrays
	return []interface{}{prodData}
}

// TransformAssetsNetworkAdapter transforms OSQuery interface_details results to Win32_NetworkAdapter format
func (a *Agent) TransformAssetsNetworkAdapter(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	// Get network services for friendly names
	networkServices := a.getNetworkServices()
	serviceMap := make(map[string]string) // device -> friendly name
	for _, svc := range networkServices {
		serviceMap[svc.Device] = svc.Name
	}

	var adapterData []map[string]interface{}

	for _, result := range results {
		adapter := make(map[string]interface{})

		// Use friendly name if available, otherwise use interface name
		friendlyName := serviceMap[result["interface"]]
		if friendlyName == "" {
			friendlyName = result["interface"]
		}

		adapter["Name"] = friendlyName
		adapter["Description"] = friendlyName
		adapter["MACAddress"] = result["mac"]
		adapter["AdapterType"] = result["type"]
		adapter["Speed"] = "" // Not available in interface_details

		// Determine if enabled based on flags
		flags := result["flags"]
		adapter["NetEnabled"] = strings.Contains(flags, "UP")

		adapterData = append(adapterData, adapter)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{adapterData}
}

// TransformAssetsNetworkConfig transforms OSQuery network data to Win32_NetworkAdapterConfiguration format
func (a *Agent) TransformAssetsNetworkConfig(
	interfacesResults []map[string]string,
	addressesResults []map[string]string,
	gatewayResults []map[string]string,
	dnsResults []map[string]string,
) []interface{} {
	if len(interfacesResults) == 0 {
		return []interface{}{}
	}

	// Get network services for friendly names
	networkServices := a.getNetworkServices()
	serviceMap := make(map[string]string) // device -> friendly name
	for _, svc := range networkServices {
		serviceMap[svc.Device] = svc.Name
	}

	// Build map of interfaces with their configuration
	configMap := make(map[string]map[string]interface{})

	// Process interfaces
	for _, iface := range interfacesResults {
		ifaceName := iface["interface"]
		friendlyName := serviceMap[ifaceName]
		if friendlyName == "" {
			friendlyName = ifaceName
		}

		config := make(map[string]interface{})
		config["Description"] = friendlyName
		config["Caption"] = friendlyName
		config["MACAddress"] = iface["mac"]
		config["Index"] = ifaceName
		config["IPAddress"] = []string{}
		config["IPSubnet"] = []string{}
		config["DefaultIPGateway"] = []string{}
		config["DNSServerSearchOrder"] = []string{}
		config["IPEnabled"] = strings.Contains(iface["flags"], "UP")

		configMap[ifaceName] = config
	}

	// Add IP addresses and subnets
	for _, addr := range addressesResults {
		if config, ok := configMap[addr["interface"]]; ok {
			ipAddresses := config["IPAddress"].([]string)
			ipSubnets := config["IPSubnet"].([]string)
			config["IPAddress"] = append(ipAddresses, addr["address"])
			config["IPSubnet"] = append(ipSubnets, addr["mask"])
		}
	}

	// Add default gateways
	for _, gw := range gatewayResults {
		if config, ok := configMap[gw["interface"]]; ok {
			gateways := config["DefaultIPGateway"].([]string)
			config["DefaultIPGateway"] = append(gateways, gw["gateway"])
		}
	}

	// Add DNS servers (apply to all interfaces)
	dnsServers := []string{}
	for _, dns := range dnsResults {
		dnsServers = append(dnsServers, dns["address"])
	}
	for _, config := range configMap {
		config["DNSServerSearchOrder"] = dnsServers
	}

	// Convert to array format
	var configData []map[string]interface{}
	for _, config := range configMap {
		configData = append(configData, config)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{configData}
}

// TransformAssetsMonitors transforms OSQuery connected_displays results to Win32_DesktopMonitor format
func (a *Agent) TransformAssetsMonitors(results []map[string]string) []interface{} {
	if len(results) == 0 {
		return []interface{}{}
	}

	var monitorData []map[string]interface{}

	for _, result := range results {
		monitor := make(map[string]interface{})

		monitor["Name"] = result["name"]
		monitor["MonitorType"] = result["display_type"]
		monitor["SerialNumber"] = result["serial_number"]
		monitor["ProductID"] = result["product_id"]
		monitor["VendorID"] = result["vendor_id"]

		// Parse resolution (e.g., "1710 x 1107 @ 60.00Hz")
		resolution := result["resolution"]
		monitor["Description"] = resolution

		// Parse pixels (e.g., "3420 x 2214")
		pixels := result["pixels"]
		if strings.Contains(pixels, " x ") {
			parts := strings.Split(pixels, " x ")
			if len(parts) == 2 {
				monitor["ScreenWidth"] = parts[0]
				monitor["ScreenHeight"] = parts[1]
			}
		}

		monitor["ConnectionType"] = result["connection_type"]
		monitor["Main"] = result["main"] == "1"
		monitor["Mirror"] = result["mirror"] == "1"

		// Manufacturing date
		if result["manufactured_year"] != "0" && result["manufactured_year"] != "" {
			monitor["ManufacturedYear"] = result["manufactured_year"]
			monitor["ManufacturedWeek"] = result["manufactured_week"]
		}

		monitorData = append(monitorData, monitor)
	}

	// Return in Windows WMI format: array of arrays
	return []interface{}{monitorData}
}
