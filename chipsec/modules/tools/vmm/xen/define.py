# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2016, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#


"""
Xen specific defines
"""

hypercall_names = {
    0: 'set_trap_table',
    1: 'mmu_update',
    2: 'set_gdt',
    3: 'stack_switch',
    4: 'set_callbacks',
    5: 'fpu_taskswitch',
    6: 'sched_op_compat',
    7: 'platform_op',
    8: 'set_debugreg',
    9: 'get_debugreg',
    10: 'update_descriptor',
    12: 'memory_op',
    13: 'multicall',
    14: 'update_va_mapping',
    15: 'set_timer_op',
    16: 'event_channel_op_compat',
    17: 'xen_version',
    18: 'console_io',
    19: 'physdev_op_compat',
    20: 'grant_table_op',
    21: 'vm_assist',
    22: 'update_va_mapping_otherdomain',
    23: 'iret',
    24: 'vcpu_op',
    25: 'set_segment_base',
    26: 'mmuext_op',
    27: 'xsm_op',
    28: 'nmi_op',
    29: 'sched_op',
    30: 'callback_op',
    31: 'xenoprof_op',
    32: 'event_channel_op',
    33: 'physdev_op',
    34: 'hvm_op',
    35: 'sysctl',
    36: 'domctl',
    37: 'kexec_op',
    38: 'tmem_op',
    39: 'xc_reserved_op',
    40: 'xenpmu_op',
    48: 'arch_0',
    49: 'arch_1',
    50: 'arch_2',
    51: 'arch_3',
    52: 'arch_4',
    53: 'arch_5',
    54: 'arch_6',
    55: 'arch_7'
}


def get_hypercall_name(vector, defvalue=''):
    return hypercall_names[vector].upper() if vector in hypercall_names else defvalue


hypercall_status_codes = {
    0: ['XEN_STATUS_SUCCESS', 'Status success'],
    1: ['XEN_ERRNO_EPERM', 'Operation not permitted'],
    2: ['XEN_ERRNO_ENOENT', 'No such file or directory'],
    3: ['XEN_ERRNO_ESRCH', 'No such process'],
    4: ['XEN_ERRNO_EINTR', 'Interrupted system call'],
    5: ['XEN_ERRNO_EIO', 'I/O error'],
    6: ['XEN_ERRNO_ENXIO', 'No such device or address'],
    7: ['XEN_ERRNO_E2BIG', 'Arg list too long'],
    8: ['XEN_ERRNO_ENOEXEC', 'Exec format error'],
    9: ['XEN_ERRNO_EBADF', 'Bad file number'],
    10: ['XEN_ERRNO_ECHILD', 'No child processes'],
    11: ['XEN_ERRNO_EAGAIN', 'Try again'],
    12: ['XEN_ERRNO_ENOMEM', 'Out of memory'],
    13: ['XEN_ERRNO_EACCES', 'Permission denied'],
    14: ['XEN_ERRNO_EFAULT', 'Bad address'],
    16: ['XEN_ERRNO_EBUSY', 'Device or resource busy'],
    17: ['XEN_ERRNO_EEXIST', 'File exists'],
    18: ['XEN_ERRNO_EXDEV', 'Cross-device link'],
    19: ['XEN_ERRNO_ENODEV', 'No such device'],
    22: ['XEN_ERRNO_EINVAL', 'Invalid argument'],
    23: ['XEN_ERRNO_ENFILE', 'File table overflow'],
    24: ['XEN_ERRNO_EMFILE', 'Too many open files'],
    28: ['XEN_ERRNO_ENOSPC', 'No space left on device'],
    31: ['XEN_ERRNO_EMLINK', 'Too many links'],
    33: ['XEN_ERRNO_EDOM', 'Math argument out of domain of func'],
    34: ['XEN_ERRNO_ERANGE', 'Math result not representable'],
    35: ['XEN_ERRNO_EDEADLK', 'Resource deadlock would occur'],
    36: ['XEN_ERRNO_ENAMETOOLONG', 'File name too long'],
    37: ['XEN_ERRNO_ENOLCK', 'No record locks available'],
    38: ['XEN_ERRNO_ENOSYS', 'Function not implemented'],
    61: ['XEN_ERRNO_ENODATA', 'No data available'],
    62: ['XEN_ERRNO_ETIME', 'Timer expired'],
    74: ['XEN_ERRNO_EBADMSG', 'Not a data message'],
    75: ['XEN_ERRNO_EOVERFLOW', 'Value too large for defined data type'],
    84: ['XEN_ERRNO_EILSEQ', 'Illegal byte sequence'],
    85: ['XEN_ERRNO_ERESTART', 'Interrupted system call should be restarted'],
    88: ['XEN_ERRNO_ENOTSOCK', 'Socket operation on non-socket'],
    95: ['XEN_ERRNO_EOPNOTSUPP', 'Operation not supported on transport endpoint'],
    98: ['XEN_ERRNO_EADDRINUSE', 'Address already in use'],
    99: ['XEN_ERRNO_EADDRNOTAVAIL', 'Cannot assign requested address'],
    105: ['XEN_ERRNO_ENOBUFS', 'No buffer space available'],
    106: ['XEN_ERRNO_EISCONN', 'Transport endpoint is already connected'],
    107: ['XEN_ERRNO_ENOTCONN', 'Transport endpoint is not connected'],
    110: ['XEN_ERRNO_ETIMEDOUT', 'Connection timed out']
}


def get_iverr(status, bits=64):
    mask = (1 << bits) - 1
    return (mask - status + 1) & mask


def get_hypercall_status(code, brief=False):
    defstatus = [f'0x{code:016X}', f'Status 0x{code:016X}']
    if (code >> 32) == 0xFFFFFFFF:
        code = get_iverr(code)
        defstatus = [f'XEN_ERRNO_{code:04X}', f'Unknown error 0x{code:04X}']
    desc = hypercall_status_codes.get(code, defstatus)
    return desc[0] if brief else desc[1]


def get_hypercall_status_extended(code):
    return f'{get_hypercall_status(code, False)} - {get_hypercall_status(code, True)}'


def get_invalid_hypercall_code():
    return XEN_ERRNO_ENOSYS


xenmem_commands = {
    0: 'XENMEM_INCREASE_RESERVATION',
    1: 'XENMEM_DECREASE_RESERVATION',
    2: 'XENMEM_MAXIMUM_RAM_PAGE',
    3: 'XENMEM_CURRENT_RESERVATION',
    4: 'XENMEM_MAXIMUM_RESERVATION',
    5: 'XENMEM_MACHPHYS_MFN_LIST',
    6: 'XENMEM_POPULATE_PHYSMAP',
    7: 'XENMEM_ADD_TO_PHYSMAP',
    8: 'XENMEM_TRANSLATE_GPFN_LIST',
    9: 'XENMEM_MEMORY_MAP',
    10: 'XENMEM_MACHINE_MEMORY_MAP',
    11: 'XENMEM_EXCHANGE',
    12: 'XENMEM_MACHPHYS_MAPPING',
    15: 'XENMEM_REMOVE_FROM_PHYSMAP',
    23: 'XENMEM_ADD_TO_PHYSMAP_RANGE'
}

xen_version_commands = {
    0: 'XENVER_VERSION',
    1: 'XENVER_EXTRAVERSION',
    2: 'XENVER_COMPILE_INFO',
    3: 'XENVER_CAPABILITIES',
    4: 'XENVER_CHANGESET',
    5: 'XENVER_PLATFORM_PARAMETERS',
    6: 'XENVER_GET_FEATURES',
    7: 'XENVER_PAGESIZE',
    8: 'XENVER_GUEST_HANDLE',
    9: 'XENVER_COMMANDLINE'
}

console_io_commands = {
    0: 'CONSOLEIO_WRITE',
    1: 'CONSOLEIO_READ'
}

schedop_commands = {
    0: 'SCHEDOP_YIELD',
    1: 'SCHEDOP_BLOCK',
    2: 'SCHEDOP_SHUTDOWN',
    3: 'SCHEDOP_POLL',
    4: 'SCHEDOP_REMOTE_SHUTDOWN',
    5: 'SCHEDOP_SHUTDOWN_CODE',
    6: 'SCHEDOP_WATCHDOG'
}

evtchop_commands = {
    0: 'EVTCHOP_BIND_INTERDOMAIN',
    1: 'EVTCHOP_BIND_VIRQ',
    2: 'EVTCHOP_BIND_PIRQ',
    3: 'EVTCHOP_CLOSE',
    4: 'EVTCHOP_SEND',
    5: 'EVTCHOP_STATUS',
    6: 'EVTCHOP_ALLOC_UNBOUND',
    7: 'EVTCHOP_BIND_IPI',
    8: 'EVTCHOP_BIND_VCPU',
    9: 'EVTCHOP_UNMASK',
    10: 'EVTCHOP_RESET',
    11: 'EVTCHOP_INIT_CONTROL',
    12: 'EVTCHOP_EXPAND_ARRAY',
    13: 'EVTCHOP_SET_PRIORITY'
}

hvmop_commands = {
    0: 'HVMOP_SET_PARAM',
    1: 'HVMOP_GET_PARAM',
    9: 'HVMOP_PAGETABLE_DYING',
    15: 'HVMOP_GET_MEMTYPE'
}

xenpmuop_commands = {
    0: 'XENPMU_MODE_GET',
    1: 'XENPMU_MODE_SET',
    2: 'XENPMU_FEATURE_GET',
    3: 'XENPMU_FEATURE_SET',
    4: 'XENPMU_INIT',
    5: 'XENPMU_FINISH',
    6: 'XENPMU_LVTPC_SET',
    7: 'XENPMU_FLUSH'
}


def set_variables(varlist):
    import re
    for i in varlist:
        var = re.sub(r'([a-z])([A-Z]+)', r'\1_\2', varlist[i])
        var = var.upper()
        exec(f'global {var}; {var}={i:d}')


set_variables(hypercall_names)
set_variables(xenmem_commands)
set_variables(xen_version_commands)
set_variables(console_io_commands)
set_variables(schedop_commands)
set_variables(evtchop_commands)
set_variables(hvmop_commands)
set_variables(xenpmuop_commands)
set_variables({get_iverr(i): hypercall_status_codes[i][0] for i in hypercall_status_codes.keys()})
