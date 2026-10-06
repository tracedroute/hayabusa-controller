#!/bin/sh

cli -c "configure
set system host-name juniper-router-ztp
set system domain-name local
set system time-zone UTC
set system root-authentication encrypted-password "\$6\$lYg9W0YL\$TsWGzgYmQ.2h2pGRNXV7YYaaUKm515plUCma/18U5Sr43pSky5Ag.JAef31pu3TxJkwust07Kk2OoUzDX9Z0w/"
set system services ssh root-login allow
set system services ssh protocol-version v2
set system ntp server 1.1.1.1
set system ntp server 8.8.8.8
set interfaces fxp0 unit 0 family inet dhcp
set interfaces ge-0/0/0 unit 0 description WAN-ZTP-Primary
set interfaces ge-0/0/0 unit 0 family inet dhcp
set interfaces ge-0/0/1 unit 0 description LAN
set interfaces ge-0/0/1 unit 0 family inet address 192.168.2.1/24
set routing-options static route 0.0.0.0/0 next-hop 192.168.2.254
commit and-quit"
