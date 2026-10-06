"""
Juniper Local ZTP Provisioning Module
Supports EX, QFX, MX, and SRX device families
"""

__version__ = "1.0.0"
__vendor__ = "Juniper"

DEVICE_FAMILIES = {
    "EX-Series": {
        "name": "Juniper EX Series Switches",
        "dispatch_script": "ex-series-dispatch",
        "protocol": "TFTP",
        "boot_trigger": "DHCP Option 43",
        "management_port": "ge-0/0/0",
        "default_ip": "192.168.2.110",
    },
    "QFX-Series": {
        "name": "Juniper QFX Data Center Switches",
        "dispatch_script": "qfx-series-dispatch",
        "protocol": "TFTP",
        "boot_trigger": "DHCP Option 43",
        "management_port": "xe-0/0/0",
        "default_ip": "192.168.2.111",
    },
    "MX-Series": {
        "name": "Juniper MX Series Routers",
        "dispatch_script": "mx-series-dispatch",
        "protocol": "TFTP",
        "boot_trigger": "DHCP Option 43",
        "management_port": "ge-0/0/0",
        "default_ip": "192.168.2.112",
    },
    "SRX-Series": {
        "name": "Juniper SRX Series Security Gateways",
        "dispatch_script": "srx-series-dispatch",
        "protocol": "TFTP",
        "boot_trigger": "DHCP Option 43",
        "management_port": "ge-0/0/0",
        "default_ip": "192.168.2.113",
    },
}

DEFAULT_CREDENTIALS = {
    "username": "root",
    "password": "admin123",
}

SSH_CONFIG = {
    "version": 2,
    "enabled": True,
    "port": 22,
}

NETCONF_CONFIG = {
    "enabled": True,
    "port": 830,
}
