#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#



"""
Xen specific defines
"""

hypercall_names = {
          0:     'set_trap_table',
          1:     'mmu_update',
          2:     'set_gdt',
          3:     'stack_switch',
          4:     'set_callbacks',
          5:     'fpu_taskswitch',
          6:     'sched_op_compat',
          7:     'platform_op',
          8:     'set_debugreg',
          9:     'get_debugreg',
         10:     'update_descriptor',
         12:     'memory_op',
         13:     'multicall',
         14:     'update_va_mapping',
         15:     'set_timer_op',
         16:     'event_channel_op_compat',
         17:     'xen_version',
         18:     'console_io',
         19:     'physdev_op_compat',
         20:     'grant_table_op',
         21:     'vm_assist',
         22:     'update_va_mapping_otherdomain',
         23:     'iret',
         24:     'vcpu_op',
         25:     'set_segment_base',
         26:     'mmuext_op',
         27:     'xsm_op',
         28:     'nmi_op',
         29:     'sched_op',
         30:     'callback_op',
         31:     'xenoprof_op',
         32:     'event_channel_op',
         33:     'physdev_op',
         34:     'hvm_op',
         35:     'sysctl',
         36:     'domctl',
         37:     'kexec_op',
         38:     'tmem_op',
         39:     'xc_reserved_op',
         40:     'xenpmu_op',
         48:     'arch_0',
         49:     'arch_1',
         50:     'arch_2',
         51:     'arch_3',
         52:     'arch_4',
         53:     'arch_5',
         54:     'arch_6',
         55:     'arch_7'
}

def get_hypercall_name(vector, defvalue = ''):
    return hypercall_names[vector].upper() if vector in hypercall_names else defvalue

hypercall_status_codes = {
          1:     ['XEN_ERRNO_EPERM',         'Operation not permitted'                       ],
          2:     ['XEN_ERRNO_ENOENT',        'No such file or directory'                     ],
          3:     ['XEN_ERRNO_ESRCH',         'No such process'                               ],
          4:     ['XEN_ERRNO_EINTR',         'Interrupted system call'                       ],
          5:     ['XEN_ERRNO_EIO',           'I/O error'                                     ],
          6:     ['XEN_ERRNO_ENXIO',         'No such device or address'                     ],
          7:     ['XEN_ERRNO_E2BIG',         'Arg list too long'                             ],
          8:     ['XEN_ERRNO_ENOEXEC',       'Exec format error'                             ],
          9:     ['XEN_ERRNO_EBADF',         'Bad file number'                               ],
         10:     ['XEN_ERRNO_ECHILD',        'No child processes'                            ],
         11:     ['XEN_ERRNO_EAGAIN',        'Try again'                                     ],
         12:     ['XEN_ERRNO_ENOMEM',        'Out of memory'                                 ],
         13:     ['XEN_ERRNO_EACCES',        'Permission denied'                             ],
         14:     ['XEN_ERRNO_EFAULT',        'Bad address'                                   ],
         16:     ['XEN_ERRNO_EBUSY',         'Device or resource busy'                       ],
         17:     ['XEN_ERRNO_EEXIST',        'File exists'                                   ],
         18:     ['XEN_ERRNO_EXDEV',         'Cross-device link'                             ],
         19:     ['XEN_ERRNO_ENODEV',        'No such device'                                ],
         22:     ['XEN_ERRNO_EINVAL',        'Invalid argument'                              ],
         23:     ['XEN_ERRNO_ENFILE',        'File table overflow'                           ],
         24:     ['XEN_ERRNO_EMFILE',        'Too many open files'                           ],
         28:     ['XEN_ERRNO_ENOSPC',        'No space left on device'                       ],
         31:     ['XEN_ERRNO_EMLINK',        'Too many links'                                ],
         33:     ['XEN_ERRNO_EDOM',          'Math argument out of domain of func'           ],
         34:     ['XEN_ERRNO_ERANGE',        'Math result not representable'                 ],
         35:     ['XEN_ERRNO_EDEADLK',       'Resource deadlock would occur'                 ],
         36:     ['XEN_ERRNO_ENAMETOOLONG',  'File name too long'                            ],
         37:     ['XEN_ERRNO_ENOLCK',        'No record locks available'                     ],
         38:     ['XEN_ERRNO_ENOSYS',        'Function not implemented'                      ],
         61:     ['XEN_ERRNO_ENODATA',       'No data available'                             ],
         62:     ['XEN_ERRNO_ETIME',         'Timer expired'                                 ],
         74:     ['XEN_ERRNO_EBADMSG',       'Not a data message'                            ],
         75:     ['XEN_ERRNO_EOVERFLOW',     'Value too large for defined data type'         ],
         84:     ['XEN_ERRNO_EILSEQ',        'Illegal byte sequence'                         ],
         85:     ['XEN_ERRNO_ERESTART',      'Interrupted system call should be restarted'   ],
         88:     ['XEN_ERRNO_ENOTSOCK',      'Socket operation on non-socket'                ],
         95:     ['XEN_ERRNO_EOPNOTSUPP',    'Operation not supported on transport endpoint' ],
         98:     ['XEN_ERRNO_EADDRINUSE',    'Address already in use'                        ],
         99:     ['XEN_ERRNO_EADDRNOTAVAIL', 'Cannot assign requested address'               ],
        105:     ['XEN_ERRNO_ENOBUFS',       'No buffer space available'                     ],
        106:     ['XEN_ERRNO_EISCONN',       'Transport endpoint is already connected'       ],
        107:     ['XEN_ERRNO_ENOTCONN',      'Transport endpoint is not connected'           ],
        110:     ['XEN_ERRNO_ETIMEDOUT',     'Connection timed out'                          ]
}

def get_iverr(status):
    return 0x10000000000000000 - (status & 0xFFFFFFFFFFFFFFFF)

def get_hypercall_status(code, defvalue = ''):
    code = get_iverr(code)
    return "%s '%s'" % (hypercall_status_codes[code][0], hypercall_status_codes[code][1]) if code in hypercall_status_codes else defvalue

def get_invalid_hypercall_code():
    return XEN_ERRNO_ENOSYS

for i in hypercall_status_codes:
    exec("%s=%s" % (hypercall_status_codes[i][0], get_iverr(i)))
