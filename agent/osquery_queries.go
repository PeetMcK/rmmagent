/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the "License").
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

const (
	// QuerySystemInfo retrieves basic system information
	QuerySystemInfo = `
SELECT
    hostname,
    uuid,
    cpu_brand,
    cpu_physical_cores,
    cpu_logical_cores,
    physical_memory,
    hardware_vendor,
    hardware_model,
    hardware_version,
    hardware_serial
FROM system_info
`

	// QueryOSVersion retrieves operating system version information
	QueryOSVersion = `
SELECT
    name,
    version,
    major,
    minor,
    patch,
    build,
    platform,
    arch
FROM os_version
`

	// QueryDisks retrieves disk mount information
	QueryDisks = `
SELECT
    device,
    path,
    type,
    blocks,
    blocks_size,
    blocks_free,
    blocks_available
FROM mounts
WHERE device LIKE '/dev/%'
  AND type NOT IN ('devfs', 'autofs', 'tmpfs')
  AND path = '/'
ORDER BY path
`

	// QueryServicesMacOS retrieves launchd services on macOS
	QueryServicesMacOS = `
SELECT
    label as name,
    name as display_name,
    path,
    program,
    username,
    groupname,
    run_at_load,
    keep_alive,
    on_demand,
    disabled
FROM launchd
WHERE path LIKE '/Library/Launch%'
   OR path LIKE '/System/Library/Launch%'
ORDER BY label
`

	// QueryServicesLinux retrieves systemd services on Linux
	QueryServicesLinux = `
SELECT
    name,
    description,
    load_state,
    active_state,
    sub_state,
    fragment_path,
    user,
    id
FROM systemd_units
WHERE type = 'service'
ORDER BY name
`

	// QuerySoftwareMacOS retrieves installed applications on macOS
	QuerySoftwareMacOS = `
SELECT
    name,
    bundle_identifier,
    bundle_short_version as version,
    path,
    bundle_name,
    category,
    copyright,
    minimum_system_version,
    display_name,
    last_opened_time
FROM apps
WHERE path LIKE '/Applications/%'
   OR path LIKE '/System/Applications/%'
ORDER BY name
`

	// QuerySoftwareDebianLinux retrieves deb packages on Debian/Ubuntu
	QuerySoftwareDebianLinux = `
SELECT
    name,
    version,
    source,
    size,
    arch,
    revision,
    status,
    maintainer,
    section,
    priority
FROM deb_packages
WHERE status = 'install ok installed'
ORDER BY name
`

	// QuerySoftwareRPMLinux retrieves RPM packages on RedHat/CentOS
	QuerySoftwareRPMLinux = `
SELECT
    name,
    version,
    release,
    source,
    size,
    arch,
    install_time,
    vendor
FROM rpm_packages
ORDER BY name
`

	// QueryLoggedInUsers retrieves currently logged in users
	QueryLoggedInUsers = `
SELECT
    user,
    tty,
    host,
    time,
    type
FROM logged_in_users
WHERE type = 'user'
`

	// QueryUptime retrieves system uptime information
	QueryUptime = `
SELECT
    total_seconds,
    hours,
    minutes,
    days
FROM uptime
`

	// QueryNetworkInterfaces retrieves network interface details
	QueryNetworkInterfaces = `
SELECT
  id.interface,
  id.mac,
  id.type,
  id.flags,
  id.mtu,
  id.ipackets,
  id.opackets,
  id.ibytes,
  id.obytes
FROM interface_details id
WHERE id.interface NOT LIKE 'utun%'
  AND id.interface NOT LIKE 'gif%'
  AND id.interface NOT LIKE 'stf%'
  AND id.interface NOT LIKE 'bridge%'
  AND id.interface NOT LIKE 'awdl%'
  AND id.interface NOT LIKE 'llw%'
  AND id.interface != 'lo0'
ORDER BY id.interface
`

	// QueryInterfaceAddresses retrieves IP addresses per interface
	QueryInterfaceAddresses = `
SELECT
  interface,
  address,
  mask
FROM interface_addresses
WHERE address NOT LIKE '127.%'
  AND address NOT LIKE '::1%'
ORDER BY interface, address
`

	// QueryDefaultGateway retrieves default gateway
	QueryDefaultGateway = `
SELECT DISTINCT gateway, interface
FROM routes
WHERE destination = '0.0.0.0' AND netmask = 0
`

	// QueryDNS retrieves DNS servers
	QueryDNS = `
SELECT address FROM dns_resolvers WHERE type = 'nameserver'
`

	// QueryWiFi retrieves WiFi connection info
	QueryWiFi = `
SELECT interface, ssid, bssid, rssi, transmit_rate, channel, channel_band
FROM wifi_status
WHERE interface LIKE 'en%'
`

	// QueryBattery retrieves battery information (macOS laptops only)
	QueryBattery = `
SELECT
    health,
    condition,
    cycle_count,
    percent_remaining,
    max_capacity,
    designed_capacity,
    state,
    charging,
    manufacturer,
    model
FROM battery
`

	// QueryFirewall retrieves Application Layer Firewall status (macOS)
	QueryFirewall = `
SELECT
    global_state,
    stealth_enabled,
    logging_enabled
FROM alf
`

	// QueryDiskEncryption retrieves FileVault encryption status (macOS)
	QueryDiskEncryption = `
SELECT
    name,
    uuid,
    filevault_status,
    encrypted,
    encryption_status
FROM disk_encryption
WHERE name != ''
`
)

// QueryDefinitions maps query names to SQL for easy lookup
var QueryDefinitions = map[string]string{
	"system_info":          QuerySystemInfo,
	"os_version":           QueryOSVersion,
	"disks":                QueryDisks,
	"services_macos":       QueryServicesMacOS,
	"services_linux":       QueryServicesLinux,
	"software_macos":       QuerySoftwareMacOS,
	"software_deb":         QuerySoftwareDebianLinux,
	"software_rpm":         QuerySoftwareRPMLinux,
	"logged_users":         QueryLoggedInUsers,
	"uptime":               QueryUptime,
	"network_interfaces":   QueryNetworkInterfaces,
	"interface_addresses":  QueryInterfaceAddresses,
	"default_gateway":      QueryDefaultGateway,
	"dns":                  QueryDNS,
	"wifi":                 QueryWiFi,
	"battery":              QueryBattery,
	"firewall":             QueryFirewall,
	"disk_encryption":      QueryDiskEncryption,
}
