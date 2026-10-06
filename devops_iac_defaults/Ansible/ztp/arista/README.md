# Arista ZTP Dispatch Scripts

## Overview

This directory contains Zero-Touch Provisioning (ZTP) dispatch scripts for Arista EOS switches. Each script enables automatic provisioning of network devices using DHCP and TFTP.

## Editable Scripts

All scripts in this directory are editable through the Peregrine Ansible & OpenTofu workspace console:

### 7xxx-fixed-dispatch
- **Devices**: Arista 7050, 7280 series fixed-config switches
- **Protocol**: EOS CLI
- **Usage**: Campus and branch network provisioning
- **Features**: IP routing, Management interface, SSH configuration

### 7500-7800-dispatch
- **Devices**: Arista 7500, 7800 series modular chassis
- **Protocol**: EOS CLI
- **Usage**: Data center and core network provisioning
- **Features**: Supervisor module support, extended vty lines, modular interface configuration

### 710p-7200s-dispatch
- **Devices**: Arista 710P, 7200S series access switches
- **Protocol**: EOS CLI
- **Usage**: Access layer and aggregation provisioning
- **Features**: IP routing, event monitor management, simplified interface configuration

### veos-dispatch
- **Devices**: Arista vEOS virtual switch instances
- **Protocol**: EOS CLI
- **Usage**: Cloud labs, CI/CD pipelines, virtual testing
- **Features**: Multiple virtual interface configuration, default routing, data plane interfaces

## Editing in Console

All files are editable through the Peregrine console at: `/OpenTofu/ztp/arista/`

To edit:
1. Navigate to the ZTP workspace → Arista directory
2. Select a dispatch script
3. Click "Edit" to modify the provisioning commands
4. Changes are immediately available for new device boots

## DHCP/TFTP Routing

Device families are automatically routed to their respective scripts via dnsmasq configuration:
- Arista 7050/7280 (7xxx Fixed) → 7xxx-fixed-dispatch
- Arista 7500/7800 (Modular) → 7500-7800-dispatch
- Arista 710P/7200S → 710p-7200s-dispatch
- Arista vEOS → veos-dispatch

Each device family is identified via DHCP model identifier and routed appropriately.

## Default Credentials

All scripts provision devices with:
- **Username**: admin
- **Password**: admin123
- **SSH**: Enabled on port 22
- **Access Level**: Privilege 15 (full administrative)

> ⚠️ Change credentials in production deployments

## Script Format

All scripts use plain Arista EOS CLI commands:
- One command per line
- Use exclamation mark (!) for comments
- Support standard `configure terminal` / `end` structure
- Compatible with both physical and virtual EOS instances

## Integration

These scripts are:
1. **Discoverable**: Registered in manifest.json and __init__.py
2. **Executable**: chmod +x for TFTP delivery
3. **Editable**: Full modification capability in workspace console
4. **Tracked**: Each file version-controlled through IaC system
5. **Testable**: Deploy to test network segment before production

## Adding New Device Families

To add support for new Arista device families:
1. Create new dispatch script: `{family}-dispatch`
2. Add classification to dnsmasq config: `dhcp-vendorclass=set:arista-{family},Arista`
3. Add model matching: `dhcp-match=set:arista-{family},124,MODEL`
4. Add bootstrap directive: `dhcp-boot=tag:arista-{family},arista/{family}-dispatch`
5. Register in manifest.json for console discoverability
6. Make executable: `chmod +x {family}-dispatch`

## Support

For issues or questions about ZTP provisioning:
- Check dnsmasq logs: `/var/lib/peregrine/ztp/dnsmasq.log`
- View active leases: `/var/lib/peregrine/ztp/dnsmasq.leases`
- Verify TFTP transfers: grep "sent" in dnsmasq.log
- Arista device logs available via SSH once provisioned

## Arista EOS References

- [Arista Zero Touch Provisioning Documentation](https://www.arista.com)
- [EOS CLI Configuration Guide](https://www.arista.com)
- Supported boot methods: DHCP Option 67 (TFTP bootfile)
