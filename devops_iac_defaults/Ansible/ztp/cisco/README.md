# Cisco ZTP Dispatch Scripts

## Overview

This directory contains Zero-Touch Provisioning (ZTP) dispatch scripts for various Cisco device families. Each script enables automatic provisioning of network devices using DHCP and TFTP.

## Editable Scripts

All scripts in this directory are editable through the Peregrine Ansible & OpenTofu workspace console:

### cisco-dispatch
- **Devices**: Catalyst 9000, 9200, 9300, 9500 series switches
- **Protocol**: Cisco IOS CLI
- **Usage**: Default provisioning for Catalyst switches
- **Features**: SSH configuration, hostname setup, VLAN management

### csr-dispatch
- **Devices**: CSR1000v, C8000v virtual routers  
- **Protocol**: Cisco IOS CLI
- **Usage**: Cloud and virtual deployment provisioning
- **Features**: Virtual interface configuration, GigabitEthernet setup

### ios-xr-dispatch
- **Devices**: NCS 500, 5500, 8000 series (IOS-XR)
- **Protocol**: IOS-XR CLI (double-exclamation syntax)
- **Usage**: Service provider and enterprise routing
- **Features**: Management interface configuration, IOS-XR specific commands

### isr-dispatch
- **Devices**: ISR 1000, ISR 4000, ASR 1000 series routers
- **Protocol**: Cisco IOS CLI
- **Usage**: Branch and wide-area network (WAN) provisioning
- **Features**: Multiple interface configuration, default route setup

### nexus-poap
- **Devices**: Nexus 3000, 9000 series data center switches
- **Protocol**: POAP (PowerOn Auto Provisioning - Python/Tcl)
- **Usage**: Data center and campus network provisioning
- **Features**: Device discovery, hierarchical staging

### catalyst-legacy
- **Devices**: Catalyst 2960, 3560, 3750 (legacy switches)
- **Protocol**: AutoInstall CLI
- **Usage**: Legacy network deployments
- **Features**: VLAN interface configuration, FastEthernet port setup

## Editing in Console

All files are editable through the Peregrine console at: `/OpenTofu/ztp/cisco/`

To edit:
1. Navigate to the ZTP workspace → Cisco directory
2. Select a dispatch script
3. Click "Edit" to modify the provisioning commands
4. Changes are immediately available for new device boots

## DHCP/TFTP Routing

Device families are automatically routed to their respective scripts via dnsmasq configuration:
- Each device family is identified via DHCP vendor class or model identifier
- The appropriate dispatch script is delivered as the bootfile
- Devices execute the script at boot time for zero-touch configuration

## Default Credentials

All scripts provision devices with:
- **Username**: admin
- **Password**: admin123
- **SSH**: Enabled on port 22
- **Access Level**: Privilege 15 (full administrative)

> ⚠️ Change credentials in production deployments

## Script Format

- **IOS/IOS-XR/AutoInstall**: Plain Cisco CLI commands, one per line
- **POAP**: Python/Tcl executable that outputs Cisco commands
- **No TCL/Expect required**: Modern ZTP uses direct CLI command injection

## Integration

These scripts are:
1. **Discoverable**: Registered in manifest.json and __init__.py
2. **Executable**: chmod +x for TFTP delivery
3. **Editable**: Full modification capability in workspace console
4. **Tracked**: Each file version-controlled through IaC system
5. **Testable**: Deploy to test network segment before production

## Adding New Device Families

To add support for new device families:
1. Create new dispatch script: `{family}-dispatch`
2. Add routing rule to dnsmasq config: `dhcp-match=set:cisco-{family},124,MODEL`
3. Add bootstrap directive: `dhcp-boot=tag:cisco-{family},cisco/{family}-dispatch`
4. Register in manifest.json for console discoverability
5. Make executable: `chmod +x {family}-dispatch`

## Support

For issues or questions about ZTP provisioning:
- Check dnsmasq logs: `/var/lib/peregrine/ztp/dnsmasq.log`
- View active leases: `/var/lib/peregrine/ztp/dnsmasq.leases`
- Verify TFTP transfers: grep "sent" in dnsmasq.log
