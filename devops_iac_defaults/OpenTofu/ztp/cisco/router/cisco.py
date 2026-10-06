#!/usr/bin/env python3
import cli

config = """
hostname cisco-router-ztp
ip domain-name local
ntp server 1.1.1.1
ntp server 8.8.8.8
username admin privilege 15 secret Cisco123!
ip ssh version 2
line vty 0 4
 login local
 transport input ssh
interface GigabitEthernet0
 ip address dhcp
 no shutdown
ip route 0.0.0.0 0.0.0.0 dhcp
"""

for line in config.strip().splitlines():
    line = line.strip()
    if line:
        cli.configurep([line])

cli.cli("write memory")
