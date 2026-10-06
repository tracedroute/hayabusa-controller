# Aruba HPE ZTP Dispatch Scripts

Complete Zero Touch Provisioning support for Aruba AOS-CX and AOS-S devices.

## Device Families

### AOS-CX (Campus Switching)
- **Models**: 6000, 6100, 6200, 6300, 6400, 8000, 83xx
- **Script**: `aos-cx-dispatch`
- **Protocol**: TFTP (DHCP Option 67)
- **File Format**: CLI Configuration
- **Default Management IP**: 192.168.2.50/24
- **Default Credentials**: admin / admin123

### AOS-S (Access Layer)  
- **Models**: 2530, 2540, 2930, 3810, 5400R
- **Script**: `aos-s-dispatch`
- **Protocol**: TFTP (DHCP Option 67)
- **File Format**: CLI Configuration
- **Default Management IP**: 192.168.2.80/24
- **Default Credentials**: admin / admin123

## Editing Scripts

All dispatch scripts are fully editable in the Ansible & OpenTofu workspace console:

1. Navigate to: `OpenTofu` → `ztp` → `aruba`
2. Click any dispatch script to open in editor
3. Modify configuration as needed
4. Save changes (effective on next device boot)

## Boot Process

1. Device powers on with ZTP enabled
2. Sends DHCPDISCOVER on management interface
3. Receives DHCPOFFER with bootfile (Option 67): `aruba/aos-cx-dispatch` or `aruba/aos-s-dispatch`
4. Sends DHCPREQUEST
5. Receives DHCPACK + TFTP server address (192.168.2.1)
6. Downloads dispatch script via TFTP
7. Applies configuration automatically

## Default Configuration

All scripts configure:
- Hostname (vendor-specific)
- Management interface with IP address
- SSH/administrative access
- Spanning tree
- Basic interface configuration

## Customization

Edit the respective dispatch script to customize:
- Interface configurations
- VLAN assignments
- Spanning tree settings
- Additional protocols
- User credentials
