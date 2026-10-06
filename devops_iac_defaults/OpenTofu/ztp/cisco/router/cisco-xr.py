#!/usr/bin/env python3
import subprocess
import sys

def configure_ios_xr():
    config_commands = [
        'hostname cisco-router-ztp',
        'domain-name local',
        'ntp server 1.1.1.1',
        'ntp server 8.8.8.8',
        'username admin privilege 15 secret Cisco123!',
        'ssh server v2',
        'interface MgmtEth0/RP0/CPU0/0',
        'ip address dhcp',
        'no shutdown',
        'interface GigabitEthernet0/0/0/0',
        'description WAN-ZTP-Primary',
        'ip address dhcp',
        'no shutdown',
        'interface GigabitEthernet0/0/0/1',
        'description LAN',
        'ip address 192.168.3.1/24',
        'no shutdown',
        'router static',
        'address-family ipv4 unicast',
        '0.0.0.0/0 192.168.2.1',
        'commit'
    ]
    
    for cmd in config_commands:
        try:
            result = subprocess.run(['cli', 'configure', cmd], capture_output=True, text=True)
            if result.returncode != 0:
                print(f'Error executing {cmd}: {result.stderr}')
                return False
        except Exception as e:
            print(f'Exception executing {cmd}: {e}')
            return False
    
    print('Cisco IOS XR configuration completed successfully')
    return True

if __name__ == '__main__':
    configure_ios_xr()
