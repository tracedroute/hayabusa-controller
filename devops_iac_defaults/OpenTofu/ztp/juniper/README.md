# Juniper Networks ZTP Dispatch Scripts

Complete Zero Touch Provisioning support for Juniper EX, QFX, MX, and SRX series devices.

## Device Families

### EX Series (Access/Aggregation)
- **Models**: EX2200, EX2300, EX3400, EX4200, EX4300, EX4400, EX4600
- **Script**: `ex-series-dispatch`
- **Protocol**: TFTP (DHCP Option 43)
- **File Format**: Juniper JunOS Configuration
- **Default Management IP**: 192.168.2.60/24
- **Default Credentials**: admin / admin123

### QFX Series (Data Center)
- **Models**: QFX3100, QFX3500, QFX5100, QFX5120, QFX10000
- **Script**: `qfx-series-dispatch`
- **Protocol**: TFTP (DHCP Option 43)
- **File Format**: Juniper JunOS Configuration
- **Default Management IP**: 192.168.2.70/24
- **Default Credentials**: admin / admin123

### MX Series (Edge/Core)
- **Models**: MX80, MX104, MX240, MX480, MX960
- **Script**: `mx-series-dispatch`
- **Protocol**: TFTP (DHCP Option 43)
- **File Format**: Juniper JunOS Configuration
- **Default Management IP**: 192.168.2.90/24
- **Default Credentials**: admin / admin123

### SRX Series (Security)
- **Models**: SRX100, SRX200, SRX300, SRX320, SRX345, SRX550, SRX1500, SRX4100, SRX5000
- **Script**: `srx-series-dispatch`
- **Protocol**: TFTP (DHCP Option 43)
- **File Format**: Juniper JunOS Configuration
- **Default Management IP**: 192.168.2.110/24
- **Default Credentials**: admin / admin123

## Editing Scripts

All dispatch scripts are fully editable in the Ansible & OpenTofu workspace console:

1. Navigate to: `my-tofu-project` → `ztp` → `juniper`
2. Click any dispatch script to open in editor
3. Modify JunOS configuration as needed
4. Save changes (effective on next device boot)

## Boot Process

1. Device powers on with ZTP enabled
2. Sends DHCPDISCOVER on management interface
3. Receives DHCPOFFER with TFTP server info (Option 43)
4. Sends DHCPREQUEST
5. Receives DHCPACK
6. Downloads dispatch script via TFTP
7. Applies JunOS configuration automatically

## Default Configuration

All scripts configure:
- Hostname (device family specific)
- Management interface with IP address
- SSH version 2 and NETCONF access
- Root and admin users with credentials
- Basic interface configuration
- Static default route
- Router ID (MX/SRX only)

## Customization

Edit the respective dispatch script to customize:
- System hostname and domain
- User accounts and authentication
- Interface IP addresses and routing
- Security policies (SRX only)
- VLAN configuration (EX only)
- Any other JunOS configuration statements
