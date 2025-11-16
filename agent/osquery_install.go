/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the "License").
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

//go:build !windows
// +build !windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	osqueryVersion      = "5.20.0"
	osqueryDownloadURL  = "https://github.com/osquery/osquery/releases/download/5.20.0/osquery-5.20.0.pkg"
	osqueryInstallDir   = "/opt/tacticalosquery"
	osqueryBinDir       = "/opt/tacticalosquery/bin"
	osqueryLibDir       = "/opt/tacticalosquery/lib"
	osqueryDataDir      = "/private/var/tacticalosquery"
	osqueryLogDir       = "/private/var/log/osquery"
	osqueryBin          = "/opt/tacticalosquery/lib/osquery.app/Contents/MacOS/osqueryd"
	osqueryiSymlink     = "/opt/tacticalosquery/bin/osqueryi"
	osqueryctlSymlink   = "/opt/tacticalosquery/bin/osqueryctl"
	osqueryConf         = "/private/var/tacticalosquery/osquery.conf"
	osqueryFlags        = "/private/var/tacticalosquery/osquery.flags"
	osqueryPlist        = "/Library/LaunchDaemons/io.osquery.agent.tacticalagent.plist"
	osqueryPlistLabel   = "io.osquery.agent.tacticalagent"
)

// getInstalledOSQueryVersion returns the installed OSQuery version or empty string if not installed
func (a *Agent) getInstalledOSQueryVersion() (string, error) {
	// Check if osqueryi symlink exists
	if _, err := os.Stat(osqueryiSymlink); os.IsNotExist(err) {
		return "", nil // Not installed
	}

	// Run osqueryi --version
	opts := a.NewCMDOpts()
	opts.Command = fmt.Sprintf("%s --version", osqueryiSymlink)
	out := a.CmdV2(opts)

	if out.Status.Error != nil {
		a.Logger.Debugln("Failed to get OSQuery version:", out.Status.Error)
		return "", out.Status.Error
	}

	// Parse version from output like "osqueryi version 5.20.0"
	re := regexp.MustCompile(`version\s+(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(out.Stdout)
	if len(matches) >= 2 {
		return matches[1], nil
	}

	return "", fmt.Errorf("could not parse version from output: %s", out.Stdout)
}

// versionGreaterOrEqual compares two semantic versions (X.Y.Z)
// Returns true if v1 >= v2
func versionGreaterOrEqual(v1, v2 string) bool {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// Pad to same length
	for len(parts1) < 3 {
		parts1 = append(parts1, "0")
	}
	for len(parts2) < 3 {
		parts2 = append(parts2, "0")
	}

	// Compare each part
	for i := 0; i < 3; i++ {
		var n1, n2 int
		fmt.Sscanf(parts1[i], "%d", &n1)
		fmt.Sscanf(parts2[i], "%d", &n2)

		if n1 > n2 {
			return true
		} else if n1 < n2 {
			return false
		}
	}

	return true // Equal
}

// InstallOSQuery downloads and installs OSQuery 5.20.0 for macOS
// Skips if version >= 5.20.0 already installed, unless force is true
func (a *Agent) InstallOSQuery(force bool) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("OSQuery installation only supported on macOS")
	}

	// Check existing version
	installedVer, err := a.getInstalledOSQueryVersion()
	if err == nil && installedVer != "" && !force {
		if versionGreaterOrEqual(installedVer, osqueryVersion) {
			a.Logger.Infof("OSQuery %s already installed (>= %s), skipping installation", installedVer, osqueryVersion)
			return nil
		}
		a.Logger.Infof("OSQuery %s installed, upgrading to %s", installedVer, osqueryVersion)
	}

	a.Logger.Infoln("Installing OSQuery", osqueryVersion)

	// Create temp directory for extraction
	tmpDir, err := os.MkdirTemp("", "osquery_*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download package
	pkgPath := filepath.Join(tmpDir, "osquery.pkg")
	a.Logger.Debugln("Downloading OSQuery from", osqueryDownloadURL)

	opts := a.NewCMDOpts()
	opts.Command = fmt.Sprintf("curl -L -o %s %s", pkgPath, osqueryDownloadURL)
	opts.Timeout = 300 // 5 minutes
	out := a.CmdV2(opts)
	if out.Status.Error != nil {
		return fmt.Errorf("failed to download OSQuery: %w", out.Status.Error)
	}

	// Verify download
	if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
		return fmt.Errorf("download succeeded but package file not found")
	}

	// Extract package
	extractDir := filepath.Join(tmpDir, "extracted")
	a.Logger.Debugln("Extracting package to", extractDir)

	opts = a.NewCMDOpts()
	opts.Command = fmt.Sprintf("pkgutil --expand-full %s %s", pkgPath, extractDir)
	out = a.CmdV2(opts)
	if out.Status.Error != nil {
		return fmt.Errorf("failed to extract package: %w", out.Status.Error)
	}

	// Create target directories
	a.Logger.Debugln("Creating OSQuery directories")
	dirs := []string{osqueryBinDir, osqueryLibDir, osqueryDataDir, osqueryLogDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Copy binaries
	a.Logger.Debugln("Copying OSQuery binaries")
	srcBinaries := filepath.Join(extractDir, "Payload", "opt", "osquery", "lib", "osquery.app")
	dstBinaries := filepath.Join(osqueryLibDir, "osquery.app")

	opts = a.NewCMDOpts()
	opts.Command = fmt.Sprintf("cp -R %s %s", srcBinaries, dstBinaries)
	out = a.CmdV2(opts)
	if out.Status.Error != nil {
		return fmt.Errorf("failed to copy binaries: %w", out.Status.Error)
	}

	// Create symlinks
	a.Logger.Debugln("Creating OSQuery symlinks")
	if err := a.createOSQuerySymlinks(); err != nil {
		return fmt.Errorf("failed to create symlinks: %w", err)
	}

	// Copy config files (lenses, certs, packs)
	a.Logger.Debugln("Copying OSQuery config files")
	configItems := []string{"lenses", "certs", "packs"}
	for _, item := range configItems {
		srcPath := filepath.Join(extractDir, "Payload", "private", "var", "osquery", item)
		dstPath := filepath.Join(osqueryDataDir, item)

		if _, err := os.Stat(srcPath); err == nil {
			opts = a.NewCMDOpts()
			opts.Command = fmt.Sprintf("cp -R %s %s", srcPath, dstPath)
			out = a.CmdV2(opts)
			if out.Status.Error != nil {
				a.Logger.Warnf("Failed to copy %s: %v", item, out.Status.Error)
			}
		}
	}

	// Create osquery.conf
	a.Logger.Debugln("Creating osquery.conf")
	if err := a.createOSQueryConfig(); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	// Create osquery.flags
	a.Logger.Debugln("Creating osquery.flags")
	if err := a.createOSQueryFlags(); err != nil {
		return fmt.Errorf("failed to create flags: %w", err)
	}

	// Create and load LaunchDaemon
	a.Logger.Debugln("Creating LaunchDaemon")
	if err := a.createOSQueryLaunchDaemon(); err != nil {
		return fmt.Errorf("failed to create LaunchDaemon: %w", err)
	}

	// Wait for socket to be created
	a.Logger.Debugln("Waiting for OSQuery socket")
	socketPath := "/var/tacticalosquery/osquery.em"
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			a.Logger.Infoln("OSQuery installed successfully")
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	a.Logger.Warnln("OSQuery installed but socket not found (may take longer to start)")
	return nil
}

// createOSQuerySymlinks creates symlinks in /opt/tacticalosquery/bin/
func (a *Agent) createOSQuerySymlinks() error {
	symlinks := map[string]string{
		osqueryiSymlink:   "../lib/osquery.app/Contents/MacOS/osqueryd",
		osqueryctlSymlink: "../lib/osquery.app/Contents/Resources/osqueryctl",
	}

	for linkPath, targetPath := range symlinks {
		// Remove existing symlink if present
		os.Remove(linkPath)

		// Create symlink
		if err := os.Symlink(targetPath, linkPath); err != nil {
			return fmt.Errorf("failed to create symlink %s: %w", linkPath, err)
		}
	}

	return nil
}

// createOSQueryConfig creates the osquery.conf file
func (a *Agent) createOSQueryConfig() error {
	config := `{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10,
    "pidfile": "/private/var/tacticalosquery/osqueryd.pid",
    "database_path": "/private/var/tacticalosquery/osquery.db",
    "extensions_socket": "/var/tacticalosquery/osquery.em",
    "extensions_autoload": "/private/var/tacticalosquery/extensions.load",
    "disable_logging": false,
    "logger_path": "/private/var/log/osquery"
  },
  "schedule": {},
  "packs": {}
}
`

	return os.WriteFile(osqueryConf, []byte(config), 0644)
}

// createOSQueryFlags creates the osquery.flags file
func (a *Agent) createOSQueryFlags() error {
	flags := `--pidfile=/private/var/tacticalosquery/osqueryd.pid
--database_path=/private/var/tacticalosquery/osquery.db
--extensions_socket=/var/tacticalosquery/osquery.em
--disable_logging=false
--logger_path=/private/var/log/osquery
`

	return os.WriteFile(osqueryFlags, []byte(flags), 0644)
}

// createOSQueryLaunchDaemon creates and loads the LaunchDaemon plist
func (a *Agent) createOSQueryLaunchDaemon() error {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.osquery.agent.tacticalagent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/opt/tacticalosquery/lib/osquery.app/Contents/MacOS/osqueryd</string>
        <string>--flagfile=/private/var/tacticalosquery/osquery.flags</string>
        <string>--config_path=/private/var/tacticalosquery/osquery.conf</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>60</integer>

    <key>StandardOutPath</key>
    <string>/private/var/log/osquery/osqueryd.stdout.log</string>

    <key>StandardErrorPath</key>
    <string>/private/var/log/osquery/osqueryd.stderr.log</string>
</dict>
</plist>
`

	// Write plist file
	if err := os.WriteFile(osqueryPlist, []byte(plist), 0644); err != nil {
		return fmt.Errorf("failed to write plist: %w", err)
	}

	// Load LaunchDaemon
	opts := a.NewCMDOpts()
	opts.Command = fmt.Sprintf("launchctl bootstrap system %s", osqueryPlist)
	out := a.CmdV2(opts)
	if out.Status.Error != nil {
		// Check if already loaded
		if strings.Contains(out.Stderr, "Already loaded") || strings.Contains(out.Stderr, "service already loaded") {
			a.Logger.Debugln("OSQuery LaunchDaemon already loaded")
			return nil
		}
		return fmt.Errorf("failed to load LaunchDaemon: %w", out.Status.Error)
	}

	return nil
}

// UninstallOSQuery removes all OSQuery components
func (a *Agent) UninstallOSQuery() error {
	if runtime.GOOS != "darwin" {
		return nil // Not an error, just not applicable
	}

	a.Logger.Infoln("Uninstalling OSQuery")

	// Unload LaunchDaemon
	a.Logger.Debugln("Unloading OSQuery LaunchDaemon")
	opts := a.NewCMDOpts()
	opts.Command = fmt.Sprintf("launchctl bootout system %s", osqueryPlist)
	out := a.CmdV2(opts)
	if out.Status.Error != nil {
		a.Logger.Debugln("Failed to unload LaunchDaemon:", out.Status.Error)
		// Continue anyway
	}

	// Remove plist
	if err := os.Remove(osqueryPlist); err != nil && !os.IsNotExist(err) {
		a.Logger.Debugln("Failed to remove plist:", err)
	}

	// Remove binaries
	if err := os.RemoveAll(osqueryInstallDir); err != nil && !os.IsNotExist(err) {
		a.Logger.Debugln("Failed to remove binaries:", err)
	}

	// Remove data directory
	if err := os.RemoveAll(osqueryDataDir); err != nil && !os.IsNotExist(err) {
		a.Logger.Debugln("Failed to remove data directory:", err)
	}

	// Optionally remove logs (keep for debugging)
	// os.RemoveAll(osqueryLogDir)

	a.Logger.Infoln("OSQuery uninstalled successfully")
	return nil
}

// CheckOSQueryStartup verifies OSQuery is installed and running during agent startup
// Automatically repairs/reinstalls if needed
func (a *Agent) CheckOSQueryStartup() {
	if runtime.GOOS != "darwin" {
		return // Only for macOS
	}

	a.Logger.Debugln("Checking OSQuery health on startup")

	// Check if osqueryd binary exists
	if _, err := os.Stat(osqueryBin); os.IsNotExist(err) {
		a.Logger.Warnln("OSQuery binary not found, installing")
		if err := a.InstallOSQuery(false); err != nil {
			a.Logger.Errorln("Failed to install OSQuery:", err)
		}
		return
	}

	// Check if LaunchDaemon plist exists
	if _, err := os.Stat(osqueryPlist); os.IsNotExist(err) {
		a.Logger.Warnln("OSQuery LaunchDaemon plist not found, recreating")
		if err := a.createOSQueryLaunchDaemon(); err != nil {
			a.Logger.Errorln("Failed to create LaunchDaemon:", err)
		}
		return
	}

	// Check if osqueryd process is running
	opts := a.NewCMDOpts()
	opts.Command = "pgrep -x osqueryd"
	out := a.CmdV2(opts)

	if out.Status.Error != nil || out.Stdout == "" {
		a.Logger.Warnln("OSQuery daemon not running, attempting to start")

		// Try to load LaunchDaemon
		opts = a.NewCMDOpts()
		opts.Command = fmt.Sprintf("launchctl bootstrap system %s", osqueryPlist)
		out = a.CmdV2(opts)

		if out.Status.Error != nil {
			// If bootstrap fails, try kickstart (may already be loaded)
			opts = a.NewCMDOpts()
			opts.Command = fmt.Sprintf("launchctl kickstart -k system/%s", osqueryPlistLabel)
			out = a.CmdV2(opts)

			if out.Status.Error != nil {
				a.Logger.Errorln("Failed to start OSQuery daemon:", out.Status.Error)
				return
			}
		}

		a.Logger.Infoln("OSQuery daemon started successfully")
	}

	// Check if socket exists (wait briefly for it to be created)
	socketPath := "/var/tacticalosquery/osquery.em"
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			a.Logger.Debugln("OSQuery health check passed")
			return
		}
		time.Sleep(1 * time.Second)
	}

	a.Logger.Warnln("OSQuery socket not found after starting daemon")
}

// RecoverOSQuery attempts to recover a non-functioning OSQuery installation
// Similar to RecoverMesh() - stops, cleans, and restarts OSQuery
func (a *Agent) RecoverOSQuery() {
	if runtime.GOOS != "darwin" {
		return // Only for macOS
	}

	a.Logger.Infoln("Attempting OSQuery recovery")

	// Stop the LaunchDaemon
	opts := a.NewCMDOpts()
	opts.Command = fmt.Sprintf("launchctl bootout system %s", osqueryPlist)
	a.CmdV2(opts)

	// Force kill any osqueryd processes
	opts = a.NewCMDOpts()
	opts.Command = "pkill -9 osqueryd"
	a.CmdV2(opts)

	// Wait briefly for processes to terminate
	time.Sleep(2 * time.Second)

	// Remove socket and pid file if they exist
	os.Remove("/var/tacticalosquery/osquery.em")
	os.Remove("/private/var/tacticalosquery/osqueryd.pid")

	// Reload LaunchDaemon
	opts = a.NewCMDOpts()
	opts.Command = fmt.Sprintf("launchctl bootstrap system %s", osqueryPlist)
	out := a.CmdV2(opts)

	if out.Status.Error != nil {
		a.Logger.Errorln("Failed to reload OSQuery LaunchDaemon:", out.Status.Error)

		// If reload fails, try full reinstall
		a.Logger.Infoln("Attempting full OSQuery reinstall")
		if err := a.InstallOSQuery(true); err != nil {
			a.Logger.Errorln("OSQuery reinstall failed:", err)
			return
		}
	}

	// Wait for socket to be created
	socketPath := "/var/tacticalosquery/osquery.em"
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			a.Logger.Infoln("OSQuery recovery successful")
			return
		}
		time.Sleep(1 * time.Second)
	}

	a.Logger.Warnln("OSQuery recovery completed but socket not found")
}
