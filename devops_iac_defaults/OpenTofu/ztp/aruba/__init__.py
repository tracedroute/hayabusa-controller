"""
Aruba HPE ZTP Dispatch Scripts Module
Provides device-family-specific provisioning for Aruba AOS-CX and AOS-S devices
"""

DISPATCH_SCRIPTS = {
    "aos-cx": {
        "name": "Aruba AOS-CX Dispatch",
        "description": "Zero Touch Provisioning for Aruba AOS-CX 6000/6100/6200/6300/6400/8000/83xx",
        "device_families": ["AOS-CX 6000", "AOS-CX 6100", "AOS-CX 6200", "AOS-CX 6300", "AOS-CX 6400", "AOS-CX 8000", "AOS-CX 83xx"],
        "protocol": "TFTP",
        "format": "CLI",
        "file": "aos-cx-dispatch",
        "default_user": "admin",
        "default_password": "admin123",
        "default_mgmt_ip": "192.168.2.50/24",
    },
    "aos-s": {
        "name": "Aruba AOS-S Dispatch",
        "description": "Zero Touch Provisioning for Aruba AOS-S 2530/2540/2930/3810/5400R",
        "device_families": ["AOS-S 2530", "AOS-S 2540", "AOS-S 2930", "AOS-S 3810", "AOS-S 5400R"],
        "protocol": "TFTP",
        "format": "CLI",
        "file": "aos-s-dispatch",
        "default_user": "admin",
        "default_password": "admin123",
        "default_mgmt_ip": "192.168.2.80/24",
    },
}

__all__ = ["DISPATCH_SCRIPTS"]
