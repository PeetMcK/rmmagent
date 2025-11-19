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

	// QueryCPUInfo retrieves detailed CPU information
	QueryCPUInfo = `
SELECT
    device_id,
    model,
    manufacturer,
    processor_type,
    number_of_cores,
    logical_processors,
    current_clock_speed,
    max_clock_speed,
    socket_designation,
    number_of_efficiency_cores,
    number_of_performance_cores
FROM cpu_info
`

	// QueryMemoryInfo retrieves system memory information
	QueryMemoryInfo = `
SELECT
    memory_total,
    memory_free,
    buffers,
    cached,
    swap_total,
    swap_free
FROM memory_info
`

	// QueryMemoryDevices retrieves physical memory device information
	QueryMemoryDevices = `
SELECT
    handle,
    size,
    type,
    type_detail,
    form_factor,
    set,
    device_locator,
    bank_locator,
    manufacturer,
    serial_number,
    asset_tag,
    part_number,
    configured_clock_speed,
    configured_voltage,
    total_width,
    data_width
FROM memory_devices
WHERE size != '0'
`

	// QueryPlatformInfo retrieves BIOS/platform information
	QueryPlatformInfo = `
SELECT
    vendor,
    version,
    date,
    revision,
    address,
    size,
    volume_size,
    extra
FROM platform_info
`

	// QueryBlockDevices retrieves block device (disk) information
	QueryBlockDevices = `
SELECT
    name,
    parent,
    vendor,
    model,
    size,
    block_size,
    uuid,
    type,
    label
FROM block_devices
WHERE name LIKE '/dev/disk%'
  AND parent = ''
ORDER BY name
`

	// QuerySMARTDriveInfo retrieves SMART disk information
	QuerySMARTDriveInfo = `
SELECT
    device_name,
    disk_id,
    driver_type,
    model_family,
    device_model,
    serial_number,
    firmware_version,
    user_capacity,
    smart_supported,
    smart_enabled
FROM smart_drive_info
`

	// QueryPCIDevices retrieves PCI device information (for GPUs)
	QueryPCIDevices = `
SELECT
    pci_slot,
    driver,
    vendor,
    vendor_id,
    model,
    model_id,
    class,
    subclass,
    pci_class,
    pci_subclass
FROM pci_devices
WHERE class = '030000'
   OR pci_class LIKE '03%'
ORDER BY pci_slot
`

	// QueryUSBDevices retrieves USB device information
	QueryUSBDevices = `
SELECT
    usb_address,
    usb_port,
    vendor,
    vendor_id,
    model,
    model_id,
    serial,
    class,
    subclass,
    protocol,
    removable
FROM usb_devices
ORDER BY usb_address
`

	// QueryIORegPlatform retrieves macOS platform information from IORegistry
	QueryIORegPlatform = `
SELECT
    key,
    value
FROM ioreg
WHERE class = 'IOPlatformExpertDevice'
  AND (key LIKE 'board-%'
   OR key LIKE 'manufacturer'
   OR key LIKE 'product-%'
   OR key LIKE 'version'
   OR key LIKE 'serial%'
   OR key = 'model'
   OR key = 'IOPlatformUUID')
`

	// QueryIORegBIOS retrieves macOS BIOS/firmware information from IORegistry
	QueryIORegBIOS = `
SELECT
    key,
    value
FROM ioreg
WHERE (path LIKE 'IODeviceTree:/efi/platform%'
    OR key LIKE 'Boot%'
    OR key LIKE 'firmware%'
    OR key LIKE 'ROM%')
  AND key NOT LIKE '%Function%'
  AND key NOT LIKE '%Spec%'
`

	// QueryIORegGPU retrieves macOS GPU information from IORegistry
	QueryIORegGPU = `
SELECT
    key,
    value,
    class,
    parent
FROM ioreg
WHERE (class LIKE '%GPU%'
    OR class LIKE '%Display%'
    OR class = 'IOPCIDevice')
  AND (key LIKE 'model'
   OR key LIKE 'VRAM%'
   OR key LIKE 'device-%'
   OR key LIKE 'vendor-%'
   OR key LIKE 'IOName')
`

	// QueryConnectedDisplays retrieves connected display/monitor information (macOS)
	QueryConnectedDisplays = `
SELECT
    name,
    product_id,
    serial_number,
    vendor_id,
    manufactured_week,
    manufactured_year,
    display_id,
    pixels,
    resolution,
    connection_type,
    display_type,
    main,
    mirror,
    online
FROM connected_displays
WHERE online = 1
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
	"cpu_info":             QueryCPUInfo,
	"memory_info":          QueryMemoryInfo,
	"memory_devices":       QueryMemoryDevices,
	"platform_info":        QueryPlatformInfo,
	"block_devices":        QueryBlockDevices,
	"smart_drive_info":     QuerySMARTDriveInfo,
	"pci_devices":          QueryPCIDevices,
	"usb_devices":          QueryUSBDevices,
	"ioreg_platform":       QueryIORegPlatform,
	"ioreg_bios":           QueryIORegBIOS,
	"ioreg_gpu":            QueryIORegGPU,
	"connected_displays":   QueryConnectedDisplays,
}
