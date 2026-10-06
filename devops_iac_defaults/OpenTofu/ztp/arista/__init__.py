"""
Arista ZTP Dispatch Scripts Module
Enables discovery and editing of ZTP provisioning scripts in the Peregrine console.
"""

__all__ = [
    '7xxx_fixed_dispatch',
    '7500_7800_dispatch',
    '710p_7200s_dispatch',
    'veos_dispatch',
]

ZTP_DISPATCH_SCRIPTS = {
    '7xxx-fixed-dispatch': {
        'title': 'Arista 7xxx Fixed Configuration',
        'description': 'Arista 7050/7280 series fixed-config switches ZTP provisioning',
        'device_families': ['Arista 7050', 'Arista 7280'],
        'protocol': 'EOS CLI',
        'editable': True,
    },
    '7500-7800-dispatch': {
        'title': 'Arista 7500/7800 Modular Chassis',
        'description': 'Arista 7500/7800 modular chassis switches ZTP provisioning',
        'device_families': ['Arista 7500', 'Arista 7800'],
        'protocol': 'EOS CLI',
        'editable': True,
    },
    '710p-7200s-dispatch': {
        'title': 'Arista 710P / 7200S Series',
        'description': 'Arista 710P and 7200S series switches ZTP provisioning',
        'device_families': ['Arista 710P', 'Arista 7200S'],
        'protocol': 'EOS CLI',
        'editable': True,
    },
    'veos-dispatch': {
        'title': 'Arista vEOS (Virtual)',
        'description': 'Arista vEOS virtual switch instances ZTP provisioning',
        'device_families': ['Arista vEOS'],
        'protocol': 'EOS CLI',
        'editable': True,
    },
}
