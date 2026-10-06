#!/usr/bin/env python3
import cli

config = """
hostname cisco-switch-ztp
ip domain-name local
ntp server 1.1.1.1
ntp server 8.8.8.8
username admin privilege 15 secret Cisco123!
ip ssh version 2
line vty 0 4
 login local
 transport input ssh
interface Vlan1
 ip address dhcp
 no shutdown
interface GigabitEthernet0/0
 switchport mode access
 switchport access vlan 1
 no shutdown
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 1
 no shutdown
ip default-gateway 192.168.2.1
"""

for line in config.strip().splitlines():
    line = line.strip()
    if line:
        cli.configurep([line])

cli.cli("write memory")
