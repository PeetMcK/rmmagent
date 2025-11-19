//go:build !darwin
// +build !darwin

/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the "License").
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

// InstallInstallomator is a stub for non-Darwin platforms
func (a *Agent) InstallInstallomator() {}

// InstallWithInstallomator is a stub for non-Darwin platforms
func (a *Agent) InstallWithInstallomator(label string) (string, error) {
	return "", nil
}

// GetInstalledInstallomatorVersion is a stub for non-Darwin platforms
func (a *Agent) GetInstalledInstallomatorVersion() string {
	return ""
}

// CheckInstallomatorInstalled is a stub for non-Darwin platforms
func (a *Agent) CheckInstallomatorInstalled() (bool, string) {
	return false, ""
}
