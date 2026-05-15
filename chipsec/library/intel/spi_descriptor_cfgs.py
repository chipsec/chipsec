


FLMAP0_CFG = {
    'name': 'FLMAP0',
    'desc': 'Flash Map 0',
    'size': 4,            # bytes; FLMAP0 is a 32-bit DWORD
    'value': 0,           # initial value (or omit to default to 0)
    'FIELDS': {
        'FCBA': {'bit': 0,  'size': 8, 'desc': 'Flash Component Base Address'},
        'NC':   {'bit': 8,  'size': 2, 'desc': 'Number of Components'},
        'FRBA': {'bit': 16, 'size': 8, 'desc': 'Flash Region Base Address'},
    },
}

FLMAP1_CFG = {
    'name': 'FLMAP1',
    'instance': None,
    'desc': 'Flash Map 1 Register',
    'size': 4,
    'FIELDS': {
        'FMBA':  {'bit': 0,  'size': 8, 'desc': 'Flash Master Base Address'},
        'NM':    {'bit': 8,  'size': 2, 'desc': 'Number of Masters'},
        'FPSBA': {'bit': 16, 'size': 8, 'desc': 'Flash PCH Strap Base Address'},
        'PSL':   {'bit': 24, 'size': 8, 'desc': 'PCH Strap Length'},
    },
}

FLMAP2_CFG = {
    'name': 'FLMAP2',
    'instance': None,
    'desc': 'Flash Map 2 Register',
    'size': 4,
    'FIELDS': {
        'FCPUSBA': {'bit': 0,  'size': 8, 'desc': 'Flash CPU Strap Base Address'},
        'CPUSL':   {'bit': 8,  'size': 8, 'desc': 'Processor Strap Length'},
        'ICCRIBA': {'bit': 16, 'size': 8, 'desc': 'ICC Register Init Base Address'},
    },
}

FLREG_CFG = {
    'name': 'FLREG',
    'instance': None,
    'desc': 'Flash Region (Platform Data) Register',
    'size': 4,
    'FIELDS': {
        'RB': {'bit': 0,  'size': 13, 'desc': 'Region Base'},
        'RL': {'bit': 16, 'size': 13, 'desc': 'Region Limit'},
    },
}

FLMSTR_CFG = {
    'name': 'FLMSTR',
    'instance': None,
    'desc': 'Flash Master',
    'size': 4,
    'FIELDS': {
        'MRRA': {'bit': 16, 'size': 8, 'desc': 'Master Region Read Access'},
        'MRWA': {'bit': 24, 'size': 8, 'desc': 'Master Region Write Access'},
    },
}