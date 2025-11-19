//go:build darwin
// +build darwin

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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	rmm "github.com/amidaware/rmmagent/shared"
	"github.com/go-resty/resty/v2"
)

const installomatorPath = "/opt/tacticalagent/bin/Installomator.sh"

// InstallInstallomator downloads and installs Installomator.sh
func (a *Agent) InstallInstallomator() {
	var result rmm.InstallomatorInstalled
	result.AgentID = a.AgentID
	result.Installed = false

	rClient := resty.New()
	rClient.SetTimeout(30 * time.Second)
	if len(a.Proxy) > 0 {
		rClient.SetProxy(a.Proxy)
	}

	url := "/api/v3/installomator/"

	// Download Installomator.sh from GitHub
	a.Logger.Debugln("Downloading Installomator.sh from GitHub...")
	scriptURL := "https://raw.githubusercontent.com/Installomator/Installomator/main/Installomator.sh"
	r, err := rClient.R().Get(scriptURL)
	if err != nil {
		a.Logger.Debugln(err)
		a.rClient.R().SetBody(result).Post(url)
		return
	}
	if r.IsError() {
		a.Logger.Debugln("Failed to download Installomator.sh:", r.Status())
		a.rClient.R().SetBody(result).Post(url)
		return
	}

	// Ensure directory exists
	binDir := filepath.Dir(installomatorPath)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		a.Logger.Debugln("Failed to create bin directory:", err)
		a.rClient.R().SetBody(result).Post(url)
		return
	}

	// Write script to disk
	if err := os.WriteFile(installomatorPath, r.Body(), 0755); err != nil {
		a.Logger.Debugln("Failed to write Installomator.sh:", err)
		a.rClient.R().SetBody(result).Post(url)
		return
	}

	// Verify installation
	if _, err := os.Stat(installomatorPath); err != nil {
		a.Logger.Debugln("Installomator.sh not found after installation")
		a.rClient.R().SetBody(result).Post(url)
		return
	}

	// Get version
	version := a.GetInstalledInstallomatorVersion()
	result.Installed = true
	result.Version = version

	a.Logger.Debugln("Installomator installed successfully, version:", version)
	a.rClient.R().SetBody(result).Post(url)
}

// InstallWithInstallomator installs an application using Installomator
func (a *Agent) InstallWithInstallomator(label string) (string, error) {
	// Verify Installomator is installed
	if _, err := os.Stat(installomatorPath); err != nil {
		return "", fmt.Errorf("Installomator.sh not found at %s", installomatorPath)
	}

	// Run Installomator with label
	// BLOCKING_PROCESS_ACTION=ignore prevents interactive prompts
	// NOTIFY=silent prevents user notifications
	// LOGO=appstore uses App Store icon (built-in to macOS)
	cmd := exec.Command("/bin/zsh", installomatorPath, label)
	cmd.Env = append(os.Environ(),
		"BLOCKING_PROCESS_ACTION=ignore",
		"NOTIFY=silent",
		"LOGO=appstore",
		"DEBUG=0",
	)

	a.Logger.Debugln("Running Installomator with label:", label)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		a.Logger.Errorln("Installomator failed:", err)
		a.Logger.Errorln("Output:", outputStr)
		return outputStr, err
	}

	a.Logger.Debugln("Installomator completed successfully")
	return outputStr, nil
}

// GetInstalledInstallomatorVersion returns the version of installed Installomator
func (a *Agent) GetInstalledInstallomatorVersion() string {
	if _, err := os.Stat(installomatorPath); err != nil {
		return ""
	}

	// Read first few lines of script to find version
	// Installomator version is in a comment like: # VERSION=11.0
	cmd := exec.Command("head", "-n", "50", installomatorPath)
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# VERSION=") {
			version := strings.TrimPrefix(line, "# VERSION=")
			return strings.TrimSpace(version)
		}
		// Also check for VERSION= without # prefix (older format)
		if strings.HasPrefix(line, "VERSION=") && !strings.HasPrefix(line, "#") {
			version := strings.TrimPrefix(line, "VERSION=")
			// Remove quotes if present
			version = strings.Trim(version, "\"'")
			return strings.TrimSpace(version)
		}
	}

	return "unknown"
}

// CheckInstallomatorInstalled checks if Installomator is installed and returns status
func (a *Agent) CheckInstallomatorInstalled() (bool, string) {
	if _, err := os.Stat(installomatorPath); err != nil {
		return false, ""
	}
	version := a.GetInstalledInstallomatorVersion()
	return true, version
}
