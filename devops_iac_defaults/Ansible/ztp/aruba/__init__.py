"""
Aruba/HPE Local ZTP Provisioning Module
Supports AOS-CX and AOS-S device families
"""

__version__ = "1.0.0"
__vendor__ = "Aruba"

DEVICE_FAMILIES = {
    "AOS-CX-6300": {
        "name": "Aruba AOS-CX 6300 Series",
        "dispatch_script": "aos-cx-6300-dispatch",
        "protocol": "TFTP",
        "boot_trigger": "DHCP Option 67",
        "management_port": "Management 1/1/1",
        "default_ip": "192.168.2.90",
    },
    "AOS-CX-8300": {
        "name": "Aruba AOS-CX 8300 Series",
        "dispatch_script": "aos-cx-8300-dispatch",
        "protocol": "TFTP",
        "boot_trigger": "DHCP Option 67",
        "management_port": "Management 1/1/1",
        "default_ip": "192.168.2.91",
    },
    "AOS-S": {
        "name": "Aruba AOS-S Switches (2530/2540/2930/3810/5400)",
        "dispatch_script": "aos-s-dispatch",
        "protocol": "TFTP",
        "boot_trigger": "DHCP Option 43/67",
        "management_port": "Management",
        "default_ip": "192.168.2.92",
    },
}

DEFAULT_CREDENTIALS = {
    "username": "admin",
    "password": "admin123",
}

SSH_CONFIG = {
    "version": 2,
    "enabled": True,
    "port": 22,
}
