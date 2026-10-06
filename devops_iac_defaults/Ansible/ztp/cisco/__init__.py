"""
Cisco ZTP Dispatch Scripts Module
Enables discovery and editing of ZTP provisioning scripts in the Peregrine console.
"""

__all__ = [
    'cisco_dispatch',
    'csr_dispatch',
    'ios_xr_dispatch',
    'isr_dispatch',
    'nexus_poap',
    'catalyst_legacy',
]

ZTP_DISPATCH_SCRIPTS = {
    'cisco-dispatch': {
        'title': 'Catalyst 9000/9200/9300/9500',
        'description': 'Cisco Catalyst 9000 series switches ZTP provisioning script',
        'device_families': ['Catalyst 9000', 'Catalyst 9200', 'Catalyst 9300', 'Catalyst 9500'],
        'protocol': 'CLI',
        'editable': True,
    },
    'csr-dispatch': {
        'title': 'CSR1000v / C8000v',
        'description': 'Cisco CSR1000v and C8000v virtual router ZTP provisioning',
        'device_families': ['CSR1000v', 'C8000v'],
        'protocol': 'CLI',
        'editable': True,
    },
    'ios-xr-dispatch': {
        'title': 'IOS-XR (NCS 500/5500/8000)',
        'description': 'Cisco IOS-XR NCS series router ZTP provisioning with IOS-XR CLI syntax',
        'device_families': ['NCS 500', 'NCS 5500', 'NCS 8000'],
        'protocol': 'IOS-XR CLI',
        'editable': True,
    },
    'isr-dispatch': {
        'title': 'ISR / ASR (1000/4000)',
        'description': 'Cisco ISR 1000/4000 and ASR 1000 router ZTP provisioning',
        'device_families': ['ISR 1000', 'ISR 4000', 'ASR 1000'],
        'protocol': 'CLI',
        'editable': True,
    },
    'nexus-poap': {
        'title': 'Nexus 3000/9000 (POAP)',
        'description': 'Cisco Nexus 3000/9000 series POAP (PowerOn Auto Provisioning) script',
        'device_families': ['Nexus 3000', 'Nexus 9000'],
        'protocol': 'POAP (Python)',
        'editable': True,
    },
    'catalyst-legacy': {
        'title': 'Catalyst Legacy (2960/3560/3750)',
        'description': 'Pre-9000 Catalyst switches with AutoInstall support',
        'device_families': ['Catalyst 2960', 'Catalyst 3560', 'Catalyst 3750'],
        'protocol': 'AutoInstall CLI',
        'editable': True,
    },
}
