//go:build !windows
// +build !windows

/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the “License”).
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	rmm "github.com/amidaware/rmmagent/shared"
	ps "github.com/elastic/go-sysinfo"
	"github.com/go-resty/resty/v2"
	"github.com/jaypipes/ghw"
	"github.com/kardianos/service"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	psHost "github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	trmm "github.com/wh1te909/trmm-shared"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// getMacMarketingName returns the marketing name for a Mac model identifier
func getMacMarketingName(modelID string) string {
	// Map of model identifiers to marketing names
	// Updated as of 2023 - add new models as needed
	marketingNames := map[string]string{
		// MacBook Air M2 (2022-2023)
		"Mac14,2":  "MacBook Air - 13-inch, M2, 2022",
		"Mac14,15": "MacBook Air - 15-inch, M2, 2023",

		// MacBook Air M3 (2024)
		"Mac15,12": "MacBook Air - 13-inch, M3, 2024",
		"Mac15,13": "MacBook Air - 15-inch, M3, 2024",

		// MacBook Pro 13-inch M2 (2022)
		"Mac14,7": "MacBook Pro - 13-inch, M2, 2022",

		// MacBook Pro 14-inch M2 (2023)
		"Mac14,9":  "MacBook Pro - 14-inch, M2 Pro, 2023",
		"Mac14,5":  "MacBook Pro - 14-inch, M2 Max, 2023",

		// MacBook Pro 16-inch M2 (2023)
		"Mac14,10": "MacBook Pro - 16-inch, M2 Pro, 2023",
		"Mac14,6":  "MacBook Pro - 16-inch, M2 Max, 2023",

		// MacBook Pro 14-inch M3 (2023)
		"Mac15,3":  "MacBook Pro - 14-inch, M3, 2023",
		"Mac15,6":  "MacBook Pro - 14-inch, M3 Pro, 2023",
		"Mac15,10": "MacBook Pro - 14-inch, M3 Max, 2023",

		// MacBook Pro 16-inch M3 (2023)
		"Mac15,7":  "MacBook Pro - 16-inch, M3 Pro, 2023",
		"Mac15,11": "MacBook Pro - 16-inch, M3 Max, 2023",

		// Mac mini M2 (2023)
		"Mac14,3":  "Mac mini - M2, 2023",
		"Mac14,12": "Mac mini - M2 Pro, 2023",

		// Mac Studio M2 (2023)
		"Mac14,13": "Mac Studio - M2 Max, 2023",
		"Mac14,14": "Mac Studio - M2 Ultra, 2023",

		// iMac 24-inch M3 (2023)
		"Mac15,4": "iMac - 24-inch, M3, 2023",
		"Mac15,5": "iMac - 24-inch, M3, 2023",

		// Mac Pro M2 (2023)
		"Mac14,8": "Mac Pro - M2 Ultra, 2023",
	}

	if name, ok := marketingNames[modelID]; ok {
		return name
	}
	return ""
}

func ShowStatus(version string) {
	fmt.Println(version)
}

func (a *Agent) GetDisks() []trmm.Disk {
	ret := make([]trmm.Disk, 0)
	partitions, err := disk.Partitions(false)
	if err != nil {
		a.Logger.Debugln(err)
		return ret
	}

	for _, p := range partitions {
		if strings.Contains(p.Device, "dev/loop") || strings.Contains(p.Device, "devfs") {
			continue
		}
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			a.Logger.Debugln(err)
			continue
		}

		d := trmm.Disk{
			Device:  p.Device,
			Fstype:  p.Fstype,
			Total:   ByteCountSI(usage.Total),
			Used:    ByteCountSI(usage.Used),
			Free:    ByteCountSI(usage.Free),
			Percent: int(usage.UsedPercent),
		}
		ret = append(ret, d)

	}
	return ret
}

func (a *Agent) SystemRebootRequired() (bool, error) {
	// deb
	paths := [2]string{"/var/run/reboot-required", "/run/reboot-required"}
	for _, p := range paths {
		if trmm.FileExists(p) {
			return true, nil
		}
	}
	// rhel
	bins := [2]string{"/usr/bin/needs-restarting", "/bin/needs-restarting"}
	for _, bin := range bins {
		if trmm.FileExists(bin) {
			opts := a.NewCMDOpts()
			// https://man7.org/linux/man-pages/man1/needs-restarting.1.html
			// -r Only report whether a full reboot is required (exit code 1) or not (exit code 0).
			opts.Command = fmt.Sprintf("%s -r", bin)
			out := a.CmdV2(opts)

			if out.Status.Error != nil {
				a.Logger.Debugln("SystemRebootRequired(): ", out.Status.Error.Error())
				continue
			}

			if out.Status.Exit == 1 {
				return true, nil
			}

			return false, nil
		}
	}
	return false, nil
}

func (a *Agent) LoggedOnUser() string {
	var ret string
	users, err := psHost.Users()
	if err != nil {
		return ret
	}

	// return the first logged in user
	for _, user := range users {
		if user.User != "" {
			ret = user.User
			break
		}
	}
	return ret
}

func (a *Agent) osString() string {
	h, err := psHost.Info()
	if err != nil {
		return "error getting host info"
	}
	plat := cases.Title(language.AmericanEnglish).String(h.Platform)
	return fmt.Sprintf("%s %s %s %s", plat, h.PlatformVersion, h.KernelArch, h.KernelVersion)
}

func NewAgentConfig() *rmm.AgentConfig {
	viper.SetConfigName("tacticalagent")
	viper.SetConfigType("json")
	viper.AddConfigPath("/etc/")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()

	if err != nil {
		return &rmm.AgentConfig{}
	}

	agentpk := viper.GetString("agentpk")
	pk, _ := strconv.Atoi(agentpk)

	ret := &rmm.AgentConfig{
		BaseURL:          viper.GetString("baseurl"),
		AgentID:          viper.GetString("agentid"),
		APIURL:           viper.GetString("apiurl"),
		Token:            viper.GetString("token"),
		AgentPK:          agentpk,
		PK:               pk,
		Cert:             viper.GetString("cert"),
		Proxy:            viper.GetString("proxy"),
		CustomMeshDir:    viper.GetString("meshdir"),
		NatsProxyPath:    viper.GetString("natsproxypath"),
		NatsProxyPort:    viper.GetString("natsproxyport"),
		NatsStandardPort: viper.GetString("natsstandardport"),
		NatsPingInterval: viper.GetInt("natspinginterval"),
		Insecure:         viper.GetString("insecure"),
	}
	return ret
}

func (a *Agent) RunScript(code string, shell string, args []string, timeout int, runasuser bool, envVars []string, nushellEnableConfig bool, denoDefaultPermissions string) (stdout, stderr string, exitcode int, e error) {
	code = removeWinNewLines(code)
	content := []byte(code)

	f, err := createNixTmpFile(shell)
	if err != nil {
		a.Logger.Errorln("RunScript createNixTmpFile()", err)
		return "", err.Error(), 85, err
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(content); err != nil {
		a.Logger.Errorln(err)
		return "", err.Error(), 85, err
	}

	if err := f.Close(); err != nil {
		a.Logger.Errorln(err)
		return "", err.Error(), 85, err
	}

	if err := os.Chmod(f.Name(), 0770); err != nil {
		a.Logger.Errorln(err)
		return "", err.Error(), 85, err
	}

	opts := a.NewCMDOpts()
	opts.IsScript = true
	switch shell {
	case "nushell":
		var nushellArgs []string
		if nushellEnableConfig {
			nushellArgs = []string{
				"--config",
				filepath.Join(nixAgentEtcDir, "nushell", "config.nu"),
				"--env-config",
				filepath.Join(nixAgentEtcDir, "nushell", "env.nu"),
			}
		} else {
			nushellArgs = []string{"--no-config-file"}
		}
		opts.Shell = a.NuBin
		opts.Args = nushellArgs
		opts.Args = append(opts.Args, f.Name())
		opts.Args = append(opts.Args, args...)
		if !trmm.FileExists(a.NuBin) {
			a.Logger.Errorln("RunScript(): Executable does not exist. Install Nu and try again:", a.NuBin)
			err := errors.New("File Not Found: " + a.NuBin)
			return "", err.Error(), 85, err
		}

	case "deno":
		opts.Shell = a.DenoBin
		opts.Args = []string{
			"run",
			"--no-prompt",
		}
		if !trmm.FileExists(a.DenoBin) {
			a.Logger.Errorln("RunScript(): Executable does not exist. Install deno and try again:", a.DenoBin)
			err := errors.New("File Not Found: " + a.DenoBin)
			return "", err.Error(), 85, err
		}

		// Search the environment variables for DENO_PERMISSIONS and use that to set permissions for the script.
		// https://docs.deno.com/runtime/manual/basics/permissions#permissions-list
		// DENO_PERMISSIONS is not an official environment variable.
		// https://docs.deno.com/runtime/manual/basics/env_variables
		// DENO_DEFAULT_PERMISSIONS is used if not found in the environment variables.
		found := false
		for i, v := range envVars {
			if strings.HasPrefix(v, "DENO_PERMISSIONS=") {
				permissions := strings.Split(v, "=")[1]
				opts.Args = append(opts.Args, strings.Split(permissions, " ")...)
				// Remove the DENO_PERMISSIONS variable from the environment variables slice.
				// It's possible more variables may exist with the same prefix.
				envVars = append(envVars[:i], envVars[i+1:]...)
				found = true
				break
			}
		}
		if !found && denoDefaultPermissions != "" {
			opts.Args = append(opts.Args, strings.Split(denoDefaultPermissions, " ")...)
		}

		// Can't append a variadic slice after a string arg.
		// https://pkg.go.dev/builtin#append
		opts.Args = append(opts.Args, f.Name())
		opts.Args = append(opts.Args, args...)

	default:
		opts.Shell = f.Name()
		opts.Args = args
	}

	opts.EnvVars = envVars
	opts.Timeout = time.Duration(timeout)
	a.Logger.Debugln("RunScript():", opts.Shell, opts.Args)
	out := a.CmdV2(opts)
	retError := ""
	if out.Status.Error != nil {
		retError += CleanString(out.Status.Error.Error())
		retError += "\n"
	}
	if len(out.Stderr) > 0 {
		retError += out.Stderr
	}
	return out.Stdout, retError, out.Status.Exit, nil
}

func SetDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func (a *Agent) seEnforcing() bool {
	opts := a.NewCMDOpts()
	opts.Command = "getenforce"
	out := a.CmdV2(opts)
	return out.Status.Exit == 0 && strings.Contains(out.Stdout, "Enforcing")
}

func (a *Agent) AgentUpdate(url, inno, version string) error {

	self, err := os.Executable()
	if err != nil {
		a.Logger.Errorln("AgentUpdate() os.Executable():", err)
		return err
	}

	// more reliable method to get current working directory than os.Getwd()
	cwd := filepath.Dir(self)
	// create a tmpfile in same location as current binary
	// avoids issues with /tmp dir and other fs mount issues
	f, err := os.CreateTemp(cwd, "trmm")
	if err != nil {
		a.Logger.Errorln("AgentUpdate() os.CreateTemp:", err)
		return err
	}
	defer os.Remove(f.Name())

	a.Logger.Infof("Agent updating from %s to %s", a.Version, version)
	a.Logger.Debugln("Downloading agent update from", url)

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(15 * time.Minute)
	rClient.SetDebug(a.Debug)
	if len(a.Proxy) > 0 {
		rClient.SetProxy(a.Proxy)
	}
	if a.Insecure {
		insecureConf := &tls.Config{
			InsecureSkipVerify: true,
		}
		rClient.SetTLSClientConfig(insecureConf)
	}

	r, err := rClient.R().SetOutput(f.Name()).Get(url)
	if err != nil {
		a.Logger.Errorln("AgentUpdate() download:", err)
		f.Close()
		return err
	}
	if r.IsError() {
		a.Logger.Errorln("AgentUpdate() status code:", r.StatusCode())
		f.Close()
		return errors.New("err")
	}

	f.Close()
	os.Chmod(f.Name(), 0755)
	err = os.Rename(f.Name(), self)
	if err != nil {
		a.Logger.Errorln("AgentUpdate() os.Rename():", err)
		return err
	}

	if runtime.GOOS == "linux" && a.seEnforcing() {
		se := a.NewCMDOpts()
		se.Command = fmt.Sprintf("restorecon -rv %s", self)
		out := a.CmdV2(se)
		a.Logger.Debugf("%+v\n", out)
	}

	opts := a.NewCMDOpts()
	opts.Detached = true
	switch runtime.GOOS {
	case "linux":
		opts.Command = "systemctl restart tacticalagent.service"
	case "darwin":
		opts.Command = "launchctl kickstart -k system/tacticalagent"
	default:
		return nil
	}

	a.CmdV2(opts)
	return nil
}

func (a *Agent) AgentUninstall(code string) {
	f, err := createNixTmpFile()
	if err != nil {
		a.Logger.Errorln("AgentUninstall createNixTmpFile():", err)
		return
	}

	f.Write([]byte(code))
	f.Close()
	os.Chmod(f.Name(), 0770)

	opts := a.NewCMDOpts()
	opts.IsScript = true
	opts.Shell = f.Name()
	if runtime.GOOS == "linux" {
		opts.Args = []string{"uninstall"}
	}
	opts.Detached = true
	a.CmdV2(opts)
}

func (a *Agent) NixMeshNodeID() string {
	var meshNodeID string
	meshSuccess := false
	a.Logger.Debugln("Getting mesh node id")

	if !trmm.FileExists(a.MeshSystemEXE) {
		a.Logger.Debugln(a.MeshSystemEXE, "does not exist. Skipping.")
		return ""
	}

	opts := a.NewCMDOpts()
	opts.IsExecutable = true
	opts.Shell = a.MeshSystemEXE
	opts.Command = "-nodeid"

	for !meshSuccess {
		out := a.CmdV2(opts)
		meshNodeID = out.Stdout
		a.Logger.Debugln("Stdout:", out.Stdout)
		a.Logger.Debugln("Stderr:", out.Stderr)
		if meshNodeID == "" {
			time.Sleep(1 * time.Second)
			continue
		} else if strings.Contains(strings.ToLower(meshNodeID), "graphical version") || strings.Contains(strings.ToLower(meshNodeID), "zenity") {
			time.Sleep(1 * time.Second)
			continue
		}
		meshSuccess = true
	}
	return meshNodeID
}

func (a *Agent) getMeshNodeID() (string, error) {
	return a.NixMeshNodeID(), nil
}

func (a *Agent) RecoverMesh() {
	a.Logger.Infoln("Attempting mesh recovery")
	opts := a.NewCMDOpts()
	def := "systemctl restart meshagent.service"
	switch runtime.GOOS {
	case "linux":
		opts.Command = def
	case "darwin":
		opts.Command = "launchctl kickstart -k system/meshagent"
	default:
		opts.Command = def
	}
	a.CmdV2(opts)
	a.SyncMeshNodeID()
}

func (a *Agent) GetWMIInfo() map[string]interface{} {
	wmiInfo := make(map[string]interface{})
	ips := make([]string, 0)
	disks := make([]string, 0)
	cpus := make([]string, 0)
	gpus := make([]string, 0)

	// local ips - use OSQuery if available, fallback to ps.Host()
	if a.osqueryClient != nil {
		// Query network interfaces via OSQuery
		a.Logger.Errorln("DEBUG: Starting network interface queries via OSQuery")
		interfacesResults, err1 := a.osqueryClient.Query(QueryNetworkInterfaces)
		a.Logger.Errorln("DEBUG: QueryNetworkInterfaces completed, err:", err1)
		addressesResults, err2 := a.osqueryClient.Query(QueryInterfaceAddresses)
		a.Logger.Errorln("DEBUG: QueryInterfaceAddresses completed, err:", err2)
		gatewayResults, err3 := a.osqueryClient.Query(QueryDefaultGateway)
		a.Logger.Errorln("DEBUG: QueryDefaultGateway completed, err:", err3)
		dnsResults, err4 := a.osqueryClient.Query(QueryDNS)
		a.Logger.Errorln("DEBUG: QueryDNS completed, err:", err4)
		wifiResults, _ := a.osqueryClient.Query(QueryWiFi) // WiFi may not be available

		if err1 != nil {
			a.Logger.Errorf("OSQuery QueryNetworkInterfaces failed: %v", err1)
		}
		if err2 != nil {
			a.Logger.Errorf("OSQuery QueryInterfaceAddresses failed: %v", err2)
		}
		if err3 != nil {
			a.Logger.Errorf("OSQuery QueryDefaultGateway failed: %v", err3)
		}
		if err4 != nil {
			a.Logger.Errorf("OSQuery QueryDNS failed: %v", err4)
		}

		if err1 == nil && err2 == nil && err3 == nil && err4 == nil {
			a.Logger.Errorln("DEBUG: All queries succeeded, calling TransformNetworkInterfaces")
			_, allIPsArray, err := a.TransformNetworkInterfaces(
				interfacesResults,
				addressesResults,
				gatewayResults,
				dnsResults,
				wifiResults,
			)
			if err == nil && len(allIPsArray) > 0 {
				ips = allIPsArray
				a.Logger.Errorf("DEBUG: Successfully transformed network interfaces, got %d lines", len(allIPsArray))
			} else if err != nil {
				a.Logger.Errorf("TransformNetworkInterfaces failed: %v", err)
			} else {
				a.Logger.Errorln("DEBUG: TransformNetworkInterfaces returned empty array")
			}
		} else {
			a.Logger.Errorln("DEBUG: One or more queries failed, using gopsutil fallback")
		}
	}

	// Fallback to ps.Host() if OSQuery failed or not available
	if len(ips) == 0 {
		host, err := ps.Host()
		if err != nil {
			a.Logger.Errorln("GetWMIInfo() ps.Host()", err)
		} else {
			for _, ip := range host.Info().IPs {
				if strings.Contains(ip, "127.0.") || strings.Contains(ip, "::1/128") {
					continue
				}
				ips = append(ips, ip)
			}
		}
	}
	wmiInfo["local_ips"] = ips

	// disks
	if runtime.GOOS == "darwin" {
		// macOS: Use diskutil to get physical disks only
		opts := a.NewCMDOpts()
		opts.Command = "diskutil list physical | grep -E '^\\/dev\\/disk[0-9]+ \\(internal, physical\\):'"
		diskListOut := a.CmdV2(opts)

		lines := strings.Split(diskListOut.Stdout, "\n")
		for _, line := range lines {
			if strings.Contains(line, "/dev/disk") && strings.Contains(line, "internal, physical") {
				// Extract disk name (e.g., "disk0")
				parts := strings.Fields(line)
				if len(parts) > 0 {
					diskName := strings.TrimPrefix(parts[0], "/dev/")

					// Get disk info from diskutil
					opts3 := a.NewCMDOpts()
					opts3.Command = fmt.Sprintf("diskutil info %s", diskName)
					diskInfo := a.CmdV2(opts3)

					var deviceName, diskSize string
					infoLines := strings.Split(diskInfo.Stdout, "\n")
					for _, infoLine := range infoLines {
						if strings.Contains(infoLine, "Device / Media Name:") {
							parts := strings.Split(infoLine, ":")
							if len(parts) >= 2 {
								deviceName = strings.TrimSpace(parts[1])
							}
						}
						if strings.Contains(infoLine, "Disk Size:") {
							parts := strings.Split(infoLine, ":")
							if len(parts) >= 2 {
								// Extract size from format like "1.0 TB (1000204886016 Bytes)"
								sizePart := strings.TrimSpace(parts[1])
								if strings.Contains(sizePart, "(") {
									diskSize = strings.Split(sizePart, "(")[0]
									diskSize = strings.TrimSpace(diskSize)
								}
							}
						}
					}

					if deviceName != "" && diskSize != "" {
						disks = append(disks, fmt.Sprintf("%s %s", deviceName, diskSize))
					} else if diskSize != "" {
						disks = append(disks, fmt.Sprintf("Internal SSD %s", diskSize))
					}
				}
			}
		}
	} else {
		// Linux: Use ghw library
		block, err := ghw.Block(ghw.WithDisableWarnings())
		ignore := []string{"ram", "loop"}
		if err != nil {
			a.Logger.Errorln("ghw.Block()", err)
		} else {
			for _, disk := range block.Disks {
				if disk.IsRemovable || contains(disk.Name, ignore) {
					continue
				}
				ret := fmt.Sprintf("%s %s %s %s %s %s", disk.Vendor, disk.Model, disk.StorageController, disk.DriveType, disk.Name, ByteCountSI(disk.SizeBytes))
				ret = strings.TrimSpace(strings.ReplaceAll(ret, "unknown", ""))
				disks = append(disks, ret)
			}
		}
	}
	wmiInfo["disks"] = disks

	// Query OSQuery for system_info if available (CPU, model, serial, cores)
	var systemInfoResult map[string]string
	var osVersionResult map[string]string
	osqueryAvailable := false

	if a.osqueryClient != nil {
		systemInfoResults, err1 := a.osqueryClient.Query(QuerySystemInfo)
		osVersionResults, err2 := a.osqueryClient.Query(QueryOSVersion)

		if err1 == nil && len(systemInfoResults) > 0 {
			systemInfoResult = systemInfoResults[0]
			osqueryAvailable = true
		}
		if err2 == nil && len(osVersionResults) > 0 {
			osVersionResult = osVersionResults[0]
		}
	}

	// cpus - use OSQuery if available, fallback to gopsutil
	if osqueryAvailable && systemInfoResult["cpu_brand"] != "" {
		cpuBrand := systemInfoResult["cpu_brand"]
		// Add core count if available
		if systemInfoResult["cpu_physical_cores"] != "" {
			cpuBrand = fmt.Sprintf("%s (%s core CPU)", cpuBrand, systemInfoResult["cpu_physical_cores"])
		}
		cpus = append(cpus, cpuBrand)
	} else {
		// Fallback to gopsutil
		cpuInfo, err := cpu.Info()
		if err != nil {
			a.Logger.Errorln("cpu.Info()", err)
		} else {
			if len(cpuInfo) > 0 {
				if cpuInfo[0].ModelName != "" {
					cpus = append(cpus, cpuInfo[0].ModelName)
				}
			}
		}
	}
	wmiInfo["cpus"] = cpus

	// cpu_cores - add physical and logical core counts (OSQuery only)
	if osqueryAvailable {
		wmiInfo["cpu_physical_cores"] = systemInfoResult["cpu_physical_cores"]
		wmiInfo["cpu_logical_cores"] = systemInfoResult["cpu_logical_cores"]
	}

	// os_build - add OS build number (OSQuery only)
	if osVersionResult != nil && osVersionResult["build"] != "" {
		wmiInfo["os_build"] = osVersionResult["build"]
	}

	// make/model
	wmiInfo["make_model"] = ""
	chassis, err := ghw.Chassis(ghw.WithDisableWarnings())
	if err != nil {
		a.Logger.Debugln("ghw.Chassis()", err)
	} else {
		if chassis.Vendor != "" || chassis.Version != "" {
			wmiInfo["make_model"] = fmt.Sprintf("%s %s", chassis.Vendor, chassis.Version)
		}
	}

	if runtime.GOOS == "darwin" {
		// Use OSQuery if available, fallback to system_profiler
		if osqueryAvailable && systemInfoResult["hardware_model"] != "" {
			modelIdentifier := systemInfoResult["hardware_model"]

			// Try to get marketing name from model identifier
			marketingName := getMacMarketingName(modelIdentifier)

			if marketingName != "" {
				wmiInfo["make_model"] = marketingName
			} else {
				// Fallback: use vendor + model
				vendor := systemInfoResult["hardware_vendor"]
				if vendor != "" {
					wmiInfo["make_model"] = fmt.Sprintf("%s %s", vendor, modelIdentifier)
				} else {
					wmiInfo["make_model"] = modelIdentifier
				}
			}
		} else {
			// Fallback to system_profiler if OSQuery unavailable
			opts := a.NewCMDOpts()
			opts.Command = "system_profiler SPHardwareDataType"
			out := a.CmdV2(opts)

			var modelName, modelIdentifier, chip, coreInfo string
			lines := strings.Split(out.Stdout, "\n")
			for _, line := range lines {
				if strings.Contains(line, "Model Name:") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						modelName = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "Model Identifier:") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						modelIdentifier = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "Chip:") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						chip = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "Total Number of Cores:") {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						fullCoreInfo := strings.TrimSpace(parts[1])
						// Extract just the number before any parentheses
						// e.g. "8 (4 performance and 4 efficiency)" -> "8"
						if idx := strings.Index(fullCoreInfo, "("); idx > 0 {
							coreInfo = strings.TrimSpace(fullCoreInfo[:idx])
						} else {
							coreInfo = fullCoreInfo
						}
					}
				}
			}

			// Append core info to chip name if available
			if chip != "" && coreInfo != "" {
				chip = fmt.Sprintf("%s (%s core CPU)", chip, coreInfo)
			}

			// Try to get marketing name from model identifier
			marketingName := getMacMarketingName(modelIdentifier)

			if marketingName != "" {
				wmiInfo["make_model"] = marketingName
			} else if modelName != "" && chip != "" {
				wmiInfo["make_model"] = fmt.Sprintf("%s - %s", modelName, chip)
			} else if modelName != "" {
				wmiInfo["make_model"] = modelName
			} else {
				// Fallback to model identifier
				wmiInfo["make_model"] = modelIdentifier
			}
		}
	}

	// gfx cards

	gpu, err := ghw.GPU(ghw.WithDisableWarnings())
	if err != nil {
		a.Logger.Debugln("ghw.GPU()", err)
	} else {
		for _, i := range gpu.GraphicsCards {
			if i.DeviceInfo != nil {
				ret := fmt.Sprintf("%s %s", i.DeviceInfo.Vendor.Name, i.DeviceInfo.Product.Name)
				gpus = append(gpus, ret)
			}

		}
	}

	// macOS: Get GPU core count from system_profiler
	if runtime.GOOS == "darwin" && len(gpus) == 0 {
		opts := a.NewCMDOpts()
		opts.Command = "system_profiler SPDisplaysDataType"
		out := a.CmdV2(opts)

		var gpuName, gpuCores string
		lines := strings.Split(out.Stdout, "\n")
		for i, line := range lines {
			if strings.Contains(line, "Chipset Model:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					gpuName = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "Total Number of Cores:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					gpuCores = strings.TrimSpace(parts[1])
				}
				// Break after finding cores (assuming cores come after chipset)
				if gpuName != "" && gpuCores != "" {
					break
				}
			}
			// Also check if this is a section header like "Apple M2:"
			if strings.Contains(line, ":") && i > 0 {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "Apple M") && strings.HasSuffix(trimmed, ":") {
					gpuName = strings.TrimSuffix(trimmed, ":")
				}
			}
		}

		if gpuName != "" && gpuCores != "" {
			gpus = append(gpus, fmt.Sprintf("%s (%s Core GPU)", gpuName, gpuCores))
		} else if gpuCores != "" {
			gpus = append(gpus, fmt.Sprintf("%s Core GPU", gpuCores))
		}
	}

	wmiInfo["gpus"] = gpus

	// temp hack for ARM cpu/make/model if rasp pi
	var makeModel string
	if strings.Contains(runtime.GOARCH, "arm") {
		file, _ := os.Open("/proc/cpuinfo")
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if strings.Contains(strings.ToLower(scanner.Text()), "raspberry") {
				model := strings.Split(scanner.Text(), ":")
				if len(model) == 2 {
					makeModel = strings.TrimSpace(model[1])
					break
				}
			}
		}
	}

	switch runtime.GOOS {
	case "linux":
		baseboard, err := ghw.Baseboard()
		if err != nil {
			a.Logger.Debugln("ghw.Baseboard()", err)
			wmiInfo["serialnumber"] = "n/a"
		} else {
			wmiInfo["serialnumber"] = baseboard.SerialNumber
		}
	case "darwin":
		// Use OSQuery if available, fallback to ioreg
		if osqueryAvailable && systemInfoResult["hardware_serial"] != "" {
			wmiInfo["serialnumber"] = systemInfoResult["hardware_serial"]
		} else {
			// Fallback to ioreg
			opts := a.NewCMDOpts()
			serialCmd := `ioreg -l | grep IOPlatformSerialNumber | grep -o '"IOPlatformSerialNumber" = "[^"]*"' | awk -F'"' '{print $4}'`
			opts.Command = serialCmd
			out := a.CmdV2(opts)
			if out.Status.Error != nil {
				a.Logger.Debugln("ioreg get serial number: ", out.Status.Error.Error())
				wmiInfo["serialnumber"] = "n/a"
			} else {
				wmiInfo["serialnumber"] = removeNewlines(out.Stdout)
			}
		}
	default:
		wmiInfo["serialnumber"] = "n/a"
	}

	if len(cpus) == 0 {
		wmiInfo["cpus"] = []string{makeModel}
	}
	if makeModel != "" && (wmiInfo["make_model"] == "" || wmiInfo["make_model"] == "unknown unknown") {
		wmiInfo["make_model"] = makeModel
	}
	if len(gpus) == 1 && gpus[0] == "unknown unknown" {
		wmiInfo["gpus"] = ""
	}

	// Battery info (macOS laptops only)
	if runtime.GOOS == "darwin" && a.osqueryClient != nil {
		batteryResults, err := a.osqueryClient.Query(QueryBattery)
		if err == nil && len(batteryResults) > 0 {
			// Only include battery if data exists (laptops only)
			wmiInfo["battery"] = batteryResults[0]
		}
	}

	// Firewall status (macOS only)
	if runtime.GOOS == "darwin" && a.osqueryClient != nil {
		firewallResults, err := a.osqueryClient.Query(QueryFirewall)
		if err == nil && len(firewallResults) > 0 {
			row := firewallResults[0]
			globalState, _ := strconv.Atoi(row["global_state"])
			stealthEnabled, _ := strconv.Atoi(row["stealth_enabled"])

			wmiInfo["firewall_global_state"] = globalState
			wmiInfo["firewall_stealth"] = stealthEnabled == 1
		}
	}

	// Disk encryption (macOS only)
	if runtime.GOOS == "darwin" && a.osqueryClient != nil {
		encryptionResults, err := a.osqueryClient.Query(QueryDiskEncryption)
		if err == nil && len(encryptionResults) > 0 {
			// Get FileVault status for the boot volume
			for _, row := range encryptionResults {
				if row["name"] != "" {
					wmiInfo["encryption_status"] = row["filevault_status"]
					encrypted := row["encrypted"] == "1"
					wmiInfo["disk_encrypted"] = encrypted
					break // Just use first/primary volume
				}
			}
		}
	}

	// Assets collection for macOS (matching Windows WMI format)
	if runtime.GOOS == "darwin" && a.osqueryClient != nil {
		a.Logger.Infoln("Collecting Assets data via OSQuery for macOS")

		// 1. Operating System (Win32_OperatingSystem)
		if osResults, err := a.osqueryClient.Query(QueryOSVersion); err == nil && len(osResults) > 0 {
			wmiInfo["os"] = a.TransformAssetsOS(osResults)
		}

		// 2. CPU (Win32_Processor)
		if cpuResults, err := a.osqueryClient.Query(QueryCPUInfo); err == nil {
			wmiInfo["cpu"] = a.TransformAssetsCPU(cpuResults)
		}

		// 3. Memory (Win32_PhysicalMemory)
		if memResults, err := a.osqueryClient.Query(QueryMemoryDevices); err == nil && len(memResults) > 0 {
			wmiInfo["mem"] = a.TransformAssetsMemory(memResults)
		}

		// 4. BIOS (Win32_BIOS)
		if biosResults, err := a.osqueryClient.Query(QueryPlatformInfo); err == nil && len(biosResults) > 0 {
			wmiInfo["bios"] = a.TransformAssetsBIOS(biosResults)
		}

		// 5. Disks (Win32_DiskDrive)
		if diskResults, err := a.osqueryClient.Query(QueryBlockDevices); err == nil && len(diskResults) > 0 {
			wmiInfo["disk"] = a.TransformAssetsDisk(diskResults)
		}

		// 6. Computer System (Win32_ComputerSystem)
		if sysResults, err := a.osqueryClient.Query(QuerySystemInfo); err == nil && len(sysResults) > 0 {
			wmiInfo["comp_sys"] = a.TransformAssetsComputerSystem(sysResults)
		}

		// 7. Motherboard (Win32_BaseBoard) - Use system_info since ioreg table doesn't exist
		if sysResults, err := a.osqueryClient.Query(QuerySystemInfo); err == nil && len(sysResults) > 0 {
			wmiInfo["base_board"] = a.TransformAssetsMotherboardFromSystemInfo(sysResults)
		}

		// 8. Computer System Product (Win32_ComputerSystemProduct)
		if sysResults, err := a.osqueryClient.Query(QuerySystemInfo); err == nil && len(sysResults) > 0 {
			wmiInfo["comp_sys_prod"] = a.TransformAssetsComputerSystemProduct(sysResults)
		}

		// 9. Network Config (Win32_NetworkAdapterConfiguration)
		interfaceResults, err1 := a.osqueryClient.Query(QueryNetworkInterfaces)
		addressResults, err2 := a.osqueryClient.Query(QueryInterfaceAddresses)
		gatewayResults, err3 := a.osqueryClient.Query(QueryDefaultGateway)
		dnsResults, err4 := a.osqueryClient.Query(QueryDNS)

		if err1 == nil && err2 == nil && err3 == nil && err4 == nil && len(interfaceResults) > 0 {
			wmiInfo["network_config"] = a.TransformAssetsNetworkConfig(
				interfaceResults,
				addressResults,
				gatewayResults,
				dnsResults,
			)
		}

		// 10. Graphics (Win32_VideoController) - Use existing GPU data from system_profiler
		// pci_devices table doesn't work on Apple Silicon, use the gpus data we already collected
		if gpusArray, ok := wmiInfo["gpus"].([]string); ok && len(gpusArray) > 0 {
			wmiInfo["graphics"] = a.TransformAssetsGPUFromStrings(gpusArray)
		}

		// 11. USB (Win32_USBController)
		if usbResults, err := a.osqueryClient.Query(QueryUSBDevices); err == nil && len(usbResults) > 0 {
			wmiInfo["usb"] = a.TransformAssetsUSB(usbResults)
		} else {
			wmiInfo["usb"] = []interface{}{}
		}

		// 12. Network Adapters (Win32_NetworkAdapter)
		if adapterResults, err := a.osqueryClient.Query(QueryNetworkInterfaces); err == nil && len(adapterResults) > 0 {
			wmiInfo["network_adapter"] = a.TransformAssetsNetworkAdapter(adapterResults)
		}

		// 13. Desktop Monitors (Win32_DesktopMonitor)
		if displayResults, err := a.osqueryClient.Query(QueryConnectedDisplays); err == nil && len(displayResults) > 0 {
			wmiInfo["desktop_monitor"] = a.TransformAssetsMonitors(displayResults)
		} else {
			wmiInfo["desktop_monitor"] = []interface{}{}
		}

		a.Logger.Infoln("Assets data collection complete")
	}

	return wmiInfo
}

// InstallNushell will download nushell from GitHub and install (copy) it to nixAgentBinDir
func (a *Agent) InstallNushell(force bool) {
	sleepDelay := randRange(1, 10)
	a.Logger.Debugf("InstallNushell() sleeping for %v seconds", sleepDelay)
	time.Sleep(time.Duration(sleepDelay) * time.Second)

	conf := a.GetAgentCheckInConfig(a.GetCheckInConfFromAPI())
	if !conf.InstallNushell {
		return
	}

	if trmm.FileExists(a.NuBin) {
		if force {
			a.Logger.Debugln(a.NuBin, "InstallNushell(): Forced install. Removing nu binary.")
			err := os.Remove(a.NuBin)
			if err != nil {
				a.Logger.Errorln("InstallNushell(): Error removing nu binary:", err)
				return
			}
		} else {
			return
		}
	}

	if !trmm.FileExists(nixAgentBinDir) {
		err := os.MkdirAll(nixAgentBinDir, 0755)
		if err != nil {
			a.Logger.Errorln("InstallNushell(): Error creating nixAgentBinDir:", err)
			return
		}
	}

	if conf.NushellEnableConfig {
		// Create 0-byte config files for Nushell
		nushellPath := filepath.Join(nixAgentEtcDir, "nushell")
		nushellConfig := filepath.Join(nushellPath, "config.nu")
		nushellEnv := filepath.Join(nushellPath, "env.nu")
		if !trmm.FileExists(nushellPath) {
			err := os.MkdirAll(nushellPath, 0755)
			if err != nil {
				a.Logger.Errorln("InstallNushell(): Error creating nixAgentEtcDir/nushell:", err)
				return
			}
		}

		if !trmm.FileExists(nushellConfig) {
			_, err := os.Create(nushellConfig)
			if err != nil {
				a.Logger.Errorln("InstallNushell(): Error creating nushell config.nu:", err)
				return
			}
			err = os.Chmod(nushellConfig, 0744)
			if err != nil {
				a.Logger.Errorln("InstallNushell(): Error changing permissions for nushell config.nu:", err)
				return
			}
		}
		if !trmm.FileExists(nushellEnv) {
			_, err := os.Create(nushellEnv)
			if err != nil {
				a.Logger.Errorln("InstallNushell(): Error creating nushell env.nu:", err)
				return
			}
			err = os.Chmod(nushellEnv, 0744)
			if err != nil {
				a.Logger.Errorln("InstallNushell(): Error changing permissions for nushell env.nu:", err)
				return
			}
		}
	}

	var (
		assetName    string
		url          string
		targzDirName string
	)

	if conf.InstallNushellUrl != "" {
		url = conf.InstallNushellUrl
		url = strings.ReplaceAll(url, "{OS}", runtime.GOOS)
		url = strings.ReplaceAll(url, "{ARCH}", runtime.GOARCH)
		url = strings.ReplaceAll(url, "{VERSION}", conf.InstallNushellVersion)
	} else {
		switch runtime.GOOS {
		case "darwin":
			switch runtime.GOARCH {
			case "arm64":
				// https://github.com/nushell/nushell/releases/download/0.106.1/nu-0.106.1-aarch64-apple-darwin.tar.gz
				assetName = fmt.Sprintf("nu-%s-aarch64-apple-darwin.tar.gz", conf.InstallNushellVersion)
			default:
				a.Logger.Debugln("InstallNushell(): Unsupported architecture and OS:", runtime.GOARCH, runtime.GOOS)
				return
			}
		case "linux":
			switch runtime.GOARCH {
			case "amd64":
				// https://github.com/nushell/nushell/releases/download/0.106.1/nu-0.106.1-x86_64-unknown-linux-musl.tar.gz
				assetName = fmt.Sprintf("nu-%s-x86_64-unknown-linux-musl.tar.gz", conf.InstallNushellVersion)
			case "arm64":
				// https://github.com/nushell/nushell/releases/download/0.106.1/nu-0.106.1-aarch64-unknown-linux-musl.tar.gz
				assetName = fmt.Sprintf("nu-%s-aarch64-unknown-linux-musl.tar.gz", conf.InstallNushellVersion)
			default:
				a.Logger.Debugln("InstallNushell(): Unsupported architecture and OS:", runtime.GOARCH, runtime.GOOS)
				return
			}
		default:
			a.Logger.Debugln("InstallNushell(): Unsupported OS:", runtime.GOOS)
			return
		}
		url = fmt.Sprintf("https://github.com/nushell/nushell/releases/download/%s/%s", conf.InstallNushellVersion, assetName)
	}
	a.Logger.Debugln("InstallNushell(): Nu download url:", url)

	tmpDir, err := os.MkdirTemp("", "nutemp")
	if err != nil {
		a.Logger.Errorln("InstallNushell(): Error creating nushell temp directory:", err)
		return
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			a.Logger.Errorln("InstallNushell(): Error removing nushell temp directory:", err)
		}
	}(tmpDir)

	tmpAssetName := filepath.Join(tmpDir, assetName)
	a.Logger.Debugln("InstallNushell(): tmpAssetName:", tmpAssetName)

	rClient := resty.New()
	rClient.SetTimeout(20 * time.Minute)
	rClient.SetRetryCount(10)
	rClient.SetRetryWaitTime(1 * time.Minute)
	rClient.SetRetryMaxWaitTime(15 * time.Minute)
	if len(a.Proxy) > 0 {
		rClient.SetProxy(a.Proxy)
	}

	r, err := rClient.R().SetOutput(tmpAssetName).Get(url)
	if err != nil {
		a.Logger.Errorln("InstallNushell(): Unable to download nu:", err)
		return
	}
	if r.IsError() {
		a.Logger.Errorln("InstallNushell(): Unable to download nu. Status code:", r.StatusCode())
		return
	}

	if conf.InstallNushellUrl != "" {
		// InstallNushellUrl is not compressed.
		err = copyFile(filepath.Join(tmpDir, tmpAssetName), a.NuBin)
		if err != nil {
			a.Logger.Errorln("InstallNushell(): Failed to copy nu file to install dir:", err)
			return
		}
	} else {
		// GitHub asset is tar.gz compressed.
		targzDirName, err = a.ExtractTarGz(tmpAssetName, tmpDir)
		if err != nil {
			a.Logger.Errorln("InstallNushell(): Failed to extract downloaded tar.gz file:", err)
			return
		}

		err = copyFile(filepath.Join(tmpDir, targzDirName, "nu"), a.NuBin)
		if err != nil {
			a.Logger.Errorln("InstallNushell(): Failed to copy nu file to install dir:", err)
			return
		}
	}

	err = os.Chmod(a.NuBin, 0755)
	if err != nil {
		a.Logger.Errorln("InstallNushell(): Failed to chmod nu binary:", err)
		return
	}

}

// InstallDeno will download deno from GitHub and install (copy) it to nixAgentBinDir
func (a *Agent) InstallDeno(force bool) {
	sleepDelay := randRange(1, 10)
	a.Logger.Debugf("InstallDeno() sleeping for %v seconds", sleepDelay)
	time.Sleep(time.Duration(sleepDelay) * time.Second)

	conf := a.GetAgentCheckInConfig(a.GetCheckInConfFromAPI())
	if !conf.InstallDeno {
		return
	}

	if trmm.FileExists(a.DenoBin) {
		if force {
			a.Logger.Debugln(a.NuBin, "InstallDeno(): Forced install. Removing deno binary.")
			err := os.Remove(a.DenoBin)
			if err != nil {
				a.Logger.Errorln("InstallDeno(): Error removing deno binary:", err)
				return
			}
		} else {
			return
		}
	}

	if !trmm.FileExists(nixAgentBinDir) {
		err := os.MkdirAll(nixAgentBinDir, 0755)
		if err != nil {
			a.Logger.Errorln("InstallDeno(): Error creating nixAgentBinDir:", err)
			return
		}
	}

	var (
		assetName string
		url       string
	)

	if conf.InstallDenoUrl != "" {
		url = conf.InstallDenoUrl
		url = strings.ReplaceAll(url, "{OS}", runtime.GOOS)
		url = strings.ReplaceAll(url, "{ARCH}", runtime.GOARCH)
		url = strings.ReplaceAll(url, "{VERSION}", conf.InstallDenoVersion)
	} else {
		switch runtime.GOOS {
		case "darwin":
			switch runtime.GOARCH {
			case "arm64":
				// https://github.com/denoland/deno/releases/download/v1.38.2/deno-aarch64-apple-darwin.zip
				assetName = "deno-aarch64-apple-darwin.zip"
			case "amd64":
				// https://github.com/denoland/deno/releases/download/v1.38.2/deno-x86_64-apple-darwin.zip
				assetName = "deno-x86_64-apple-darwin.zip"
			default:
				a.Logger.Debugln("InstallDeno(): Unsupported architecture and OS:", runtime.GOARCH, runtime.GOOS)
				return
			}
		case "linux":
			switch runtime.GOARCH {
			case "amd64":
				// https://github.com/denoland/deno/releases/download/v1.38.2/deno-x86_64-unknown-linux-gnu.zip
				assetName = "deno-x86_64-unknown-linux-gnu.zip"
			default:
				a.Logger.Debugln("InstallDeno(): Unsupported architecture and OS:", runtime.GOARCH, runtime.GOOS)
				return
			}
		default:
			a.Logger.Debugln("InstallDeno(): Unsupported OS:", runtime.GOOS)
			return
		}
		url = fmt.Sprintf("https://github.com/denoland/deno/releases/download/%s/%s", conf.InstallDenoVersion, assetName)
	}
	a.Logger.Debugln("InstallDeno(): Deno download url:", url)

	tmpDir, err := os.MkdirTemp("", "denotemp")
	if err != nil {
		a.Logger.Errorln("InstallDeno(): Error creating deno temp directory:", err)
		return
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			a.Logger.Errorln("InstallDeno(): Error removing deno temp directory:", err)
		}
	}(tmpDir)

	tmpAssetName := filepath.Join(tmpDir, assetName)
	a.Logger.Debugln("InstallDeno(): tmpAssetName:", tmpAssetName)

	rClient := resty.New()
	rClient.SetTimeout(20 * time.Minute)
	rClient.SetRetryCount(10)
	rClient.SetRetryWaitTime(1 * time.Minute)
	rClient.SetRetryMaxWaitTime(15 * time.Minute)
	if len(a.Proxy) > 0 {
		rClient.SetProxy(a.Proxy)
	}

	r, err := rClient.R().SetOutput(tmpAssetName).Get(url)
	if err != nil {
		a.Logger.Errorln("InstallDeno(): Unable to download deno:", err)
		return
	}
	if r.IsError() {
		a.Logger.Errorln("InstallDeno(): Unable to download deno. Status code:", r.StatusCode())
		return
	}

	if conf.InstallDenoUrl != "" {
		// InstallDenoUrl is not compressed.
		err = copyFile(filepath.Join(tmpDir, tmpAssetName), a.DenoBin)
		if err != nil {
			a.Logger.Errorln("InstallDeno(): Failed to copy deno file to install dir:", err)
			return
		}
	} else {
		// GitHub asset is zip compressed.
		err = Unzip(tmpAssetName, tmpDir)
		if err != nil {
			a.Logger.Errorln("InstallDeno(): Failed to unzip downloaded zip file:", err)
			return
		}

		err = copyFile(filepath.Join(tmpDir, "deno"), a.DenoBin)
		if err != nil {
			a.Logger.Errorln("InstallDeno(): Failed to copy deno file to install dir:", err)
			return
		}
	}

	err = os.Chmod(a.DenoBin, 0755)
	if err != nil {
		a.Logger.Errorln("InstallDeno(): Failed to chmod deno binary:", err)
		return
	}

}

// GetAgentCheckInConfig will get the agent configuration from the server.
// The Windows agent stores the configuration in the registry. The UNIX agent does not store the config.
// @return AgentCheckInConfig
func (a *Agent) GetAgentCheckInConfig(ret AgentCheckInConfig) AgentCheckInConfig {
	// TODO: Persist the config to disk.
	return ret
}

// InitOSQuery initializes the OSQuery client for Unix systems
func (a *Agent) InitOSQuery() error {
	a.Logger.Info("Initializing OSQuery integration...")

	// Create OSQuery client pointing to tactical socket
	socketPath := "/var/tacticalosquery/osquery.em"
	a.osqueryClient = NewOSQueryClient(socketPath, a)

	// Test connection
	if err := a.osqueryClient.Connect(); err != nil {
		a.Logger.Warnf("OSQuery connection failed: %v - using legacy methods", err)
		a.useOSQuery = false
		return nil // Don't fail agent startup
	}

	// Test ping
	if err := a.osqueryClient.Ping(); err != nil {
		a.Logger.Warnf("OSQuery ping failed: %v - using legacy methods", err)
		a.useOSQuery = false
		return nil
	}

	a.useOSQuery = true
	a.Logger.Info("OSQuery integration enabled")

	return nil
}

// windows only below TODO add into stub file
func (a *Agent) PlatVer() (string, error) { return "", nil }

func (a *Agent) SendSoftware() {
	if !a.useOSQuery {
		a.Logger.Info("OSQuery not available, skipping software sync")
		return
	}

	a.Logger.Info("Starting software sync via OSQuery...")

	// Get software via OSQuery
	sw, err := a.GetInstalledSoftwareOSQuery()
	if err != nil {
		a.Logger.Warnf("Failed to get software via OSQuery: %v", err)
		return
	}

	a.Logger.Infof("Collected %d software items, sending to server", len(sw))

	// Send to server via REST API
	payload := map[string]interface{}{
		"agent_id": a.AgentID,
		"software": sw,
	}

	_, err = a.rClient.R().SetBody(payload).Post("/api/v3/software/")
	if err != nil {
		a.Logger.Warnf("Software sync error: %v", err)
	} else {
		a.Logger.Info("Software sync successful")
	}
}

// GetAgentInfoOSQuery retrieves system info via OSQuery
func (a *Agent) GetAgentInfoOSQuery() (*trmm.AgentInfoNats, error) {
	results, err := a.osqueryClient.Query(QuerySystemInfo)
	if err != nil {
		return nil, err
	}
	return a.TransformSystemInfo(results)
}

// GetDisksOSQuery retrieves disk info via OSQuery
func (a *Agent) GetDisksOSQuery() (*trmm.WinDisksNats, error) {
	results, err := a.osqueryClient.Query(QueryDisks)
	if err != nil {
		return nil, err
	}
	return a.TransformDisks(results)
}

// GetServicesOSQuery retrieves services via OSQuery
func (a *Agent) GetServicesOSQuery() (*trmm.WinSvcNats, error) {
	var query string
	if runtime.GOOS == "darwin" {
		query = QueryServicesMacOS
	} else {
		query = QueryServicesLinux
	}

	results, err := a.osqueryClient.Query(query)
	if err != nil {
		return nil, err
	}
	return a.TransformServices(results)
}

// GetInstalledSoftwareOSQuery retrieves software inventory via OSQuery
func (a *Agent) GetInstalledSoftwareOSQuery() ([]trmm.WinSoftwareList, error) {
	var query string

	// Platform-specific query selection
	if runtime.GOOS == "darwin" {
		query = QuerySoftwareMacOS
	} else {
		// Try Debian packages first
		query = QuerySoftwareDebianLinux
		results, err := a.osqueryClient.Query(query)
		if err != nil || len(results) == 0 {
			// Fall back to RPM if deb fails
			query = QuerySoftwareRPMLinux
		}
	}

	// Execute query
	results, err := a.osqueryClient.Query(query)
	if err != nil {
		return nil, fmt.Errorf("software query failed: %w", err)
	}

	// Transform results
	return a.TransformSoftware(results)
}

func (a *Agent) UninstallCleanup() {}

func (a *Agent) RunMigrations() {}

func GetServiceStatus(name string) (string, error) { return "", nil }

func (a *Agent) GetPython(force bool) {}

type SchedTask struct{ Name string }

func (a *Agent) PatchMgmnt(enable bool) error { return nil }

func (a *Agent) CreateSchedTask(st SchedTask) (bool, error) { return false, nil }

func DeleteSchedTask(name string) error { return nil }

func ListSchedTasks() []string { return []string{} }

func (a *Agent) GetEventLog(logName string, searchLastDays int) []rmm.EventLogMsg {
	return []rmm.EventLogMsg{}
}

func (a *Agent) GetServiceDetail(name string) trmm.WindowsService { return trmm.WindowsService{} }

func (a *Agent) ControlService(name, action string) rmm.WinSvcResp {
	return rmm.WinSvcResp{Success: false, ErrorMsg: "/na"}
}

func (a *Agent) EditService(name, startupType string) rmm.WinSvcResp {
	return rmm.WinSvcResp{Success: false, ErrorMsg: "/na"}
}

func (a *Agent) GetInstalledSoftware() []trmm.WinSoftwareList { return []trmm.WinSoftwareList{} }

func (a *Agent) ChecksRunning() bool { return false }

func (a *Agent) InstallChoco() {}

func (a *Agent) InstallWithChoco(name string) (string, error) { return "", nil }

func (a *Agent) GetWinUpdates() {}

func (a *Agent) InstallUpdates(guids []string) {}

func (a *Agent) installMesh(meshbin, exe, proxy string) (string, error) {
	return "not implemented", nil
}

func CMDShell(shell string, cmdArgs []string, command string, timeout int, detached bool, runasuser bool) (output [2]string, e error) {
	return [2]string{"", ""}, nil
}

func CMD(exe string, args []string, timeout int, detached bool) (output [2]string, e error) {
	return [2]string{"", ""}, nil
}

func (a *Agent) GetServices() []trmm.WindowsService { return []trmm.WindowsService{} }

func (a *Agent) Start(_ service.Service) error { return nil }

func (a *Agent) Stop(_ service.Service) error { return nil }

func (a *Agent) InstallService() error { return nil }
