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
Hyper-V specific defines
"""

import re

msrs = {
    0x40000000: 'HV_X64_MSR_GUEST_OS_ID',
    0x40000001: 'HV_X64_MSR_HYPERCALL',
    0x40000002: 'HV_X64_MSR_VP_INDEX',
    0x40000003: 'HV_X64_MSR_RESET',
    0x40000010: 'HV_X64_MSR_VP_RUNTIME',
    0x40000020: 'HV_X64_MSR_TIME_REF_COUNT',
    0x40000021: 'HV_X64_MSR_REFERENCE_TSC',
    0x40000022: 'HV_X64_MSR_TSC_FREQUENCY',
    0x40000023: 'HV_X64_MSR_APIC_FREQUENCY',
    0x40000070: 'HV_X64_MSR_EOI',
    0x40000071: 'HV_X64_MSR_ICR',
    0x40000072: 'HV_X64_MSR_TPR',
    0x40000073: 'HV_X64_MSR_APIC_ASSIST_PAGE',
    0x40000080: 'HV_X64_MSR_SCONTROL',
    0x40000081: 'HV_X64_MSR_SVERSION',
    0x40000082: 'HV_X64_MSR_SIEFP',
    0x40000083: 'HV_X64_MSR_SIMP',
    0x40000084: 'HV_X64_MSR_EOM',
    0x40000090: 'HV_X64_MSR_SINT0',
    0x40000091: 'HV_X64_MSR_SINT1',
    0x40000092: 'HV_X64_MSR_SINT2',
    0x40000093: 'HV_X64_MSR_SINT3',
    0x40000094: 'HV_X64_MSR_SINT4',
    0x40000095: 'HV_X64_MSR_SINT5',
    0x40000096: 'HV_X64_MSR_SINT6',
    0x40000097: 'HV_X64_MSR_SINT7',
    0x40000098: 'HV_X64_MSR_SINT8',
    0x40000099: 'HV_X64_MSR_SINT9',
    0x4000009A: 'HV_X64_MSR_SINT10',
    0x4000009B: 'HV_X64_MSR_SINT11',
    0x4000009C: 'HV_X64_MSR_SINT12',
    0x4000009D: 'HV_X64_MSR_SINT13',
    0x4000009E: 'HV_X64_MSR_SINT14',
    0x4000009F: 'HV_X64_MSR_SINT15',
    0x400000B0: 'HV_X64_MSR_STIMER0_CONFIG',
    0x400000B1: 'HV_X64_MSR_STIMER0_COUNT',
    0x400000B2: 'HV_X64_MSR_STIMER1_CONFIG',
    0x400000B3: 'HV_X64_MSR_STIMER1_COUNT',
    0x400000B4: 'HV_X64_MSR_STIMER2_CONFIG',
    0x400000B5: 'HV_X64_MSR_STIMER2_COUNT',
    0x400000B6: 'HV_X64_MSR_STIMER3_CONFIG',
    0x400000B7: 'HV_X64_MSR_STIMER3_COUNT',
    0x400000C1: 'HV_X64_MSR_POWER_STATE_TRIGGER_C1',
    0x400000C2: 'HV_X64_MSR_POWER_STATE_TRIGGER_C2',
    0x400000C3: 'HV_X64_MSR_POWER_STATE_TRIGGER_C3',
    0x400000D1: 'HV_X64_MSR_POWER_STATE_CONFIG_C1',
    0x400000D2: 'HV_X64_MSR_POWER_STATE_CONFIG_C2',
    0x400000D3: 'HV_X64_MSR_POWER_STATE_CONFIG_C3',
    0x400000E0: 'HV_X64_MSR_STATS_PARTITION_RETAIL_PAGE',
    0x400000E1: 'HV_X64_MSR_STATS_PARTITION_INTERNAL_PAGE',
    0x400000E2: 'HV_X64_MSR_STATS_VP_RETAIL_PAGE',
    0x400000E3: 'HV_X64_MSR_STATS_VP_INTERNAL_PAGE',
    0x400000F0: 'HV_X64_MSR_GUEST_IDLE',
    0x400000F1: 'HV_X64_MSR_SYNTH_DEBUG_CONTROL',
    0x400000F2: 'HV_X64_MSR_SYNTH_DEBUG_STATUS',
    0x400000F3: 'HV_X64_MSR_SYNTH_DEBUG_SEND_BUFFER',
    0x400000F4: 'HV_X64_MSR_SYNTH_DEBUG_RECEIVE_BUFFER',
    0x400000F5: 'HV_X64_MSR_SYNTH_DEBUG_PENDING_BUFFER',
    0x40000100: 'HV_X64_MSR_CRASH_P0',
    0x40000101: 'HV_X64_MSR_CRASH_P1',
    0x40000102: 'HV_X64_MSR_CRASH_P2',
    0x40000103: 'HV_X64_MSR_CRASH_P3',
    0x40000104: 'HV_X64_MSR_CRASH_P4',
    0x40000105: 'HV_X64_MSR_CRASH_CTL'
}


def get_msr_name(code, defvalue=''):
    return msrs[code] if code in msrs else defvalue


hypercall_status_codes = {
    0x0000: 'HV_STATUS_SUCCESS',
    0x0001: 'HV_RESERVED_01H',
    0x0002: 'HV_STATUS_INVALID_HYPERCALL_CODE',
    0x0003: 'HV_STATUS_INVALID_HYPERCALL_INPUT',
    0x0004: 'HV_STATUS_INVALID_ALIGNMENT',
    0x0005: 'HV_STATUS_INVALID_PARAMETER',
    0x0006: 'HV_STATUS_ACCESS_DENIED',
    0x0007: 'HV_STATUS_INVALID_PARTITION_STATE',
    0x0008: 'HV_STATUS_OPERATION_DENIED',
    0x0009: 'HV_STATUS_UNKNOWN_PROPERTY',
    0x000A: 'HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE',
    0x000B: 'HV_STATUS_INSUFFICIENT_MEMORY',
    0x000C: 'HV_STATUS_PARTITION_TOO_DEEP',
    0x000D: 'HV_STATUS_INVALID_PARTITION_ID',
    0x000E: 'HV_STATUS_INVALID_VP_INDEX',
    0x000F: 'HV_RESERVED_0FH',
    0x0010: 'HV_RESERVED_10H',
    0x0011: 'HV_STATUS_INVALID_PORT_ID',
    0x0012: 'HV_STATUS_INVALID_CONNECTION_ID',
    0x0013: 'HV_STATUS_INSUFFICIENT_BUFFERS',
    0x0014: 'HV_STATUS_NOT_ACKNOWLEDGED',
    0x0015: 'HV_RESERVED_15H',
    0x0016: 'HV_STATUS_ACKNOWLEDGED',
    0x0017: 'HV_STATUS_INVALID_SAVE_RESTORE_STATE',
    0x0018: 'HV_STATUS_INVALID_SYNIC_STATE',
    0x0019: 'HV_STATUS_OBJECT_IN_USE',
    0x001A: 'HV_STATUS_INVALID_PROXIMITY_DOMAIN_INFO',
    0x001B: 'HV_STATUS_NO_DATA',
    0x001C: 'HV_STATUS_INACTIVE',
    0x001D: 'HV_STATUS_NO_RESOURCES',
    0x001E: 'HV_STATUS_FEATURE_UNAVAILABLE',
    0x001F: 'HV_STATUS_PARTIAL_PACKET',
    0x0020: 'HV_STATUS_PROCESSOR_FEATURE_SSE3_NOT_SUPPORTED',
    0x0021: 'HV_STATUS_PROCESSOR_FEATURE_LAHFSAHF_NOT_SUPPORTED',
    0x0022: 'HV_STATUS_PROCESSOR_FEATURE_SSSE3_NOT_SUPPORTED',
    0x0023: 'HV_STATUS_PROCESSOR_FEATURE_SSE4_1_NOT_SUPPORTED',
    0x0024: 'HV_STATUS_PROCESSOR_FEATURE_SSE4_2_NOT_SUPPORTED',
    0x0025: 'HV_STATUS_PROCESSOR_FEATURE_SSE4A_NOT_SUPPORTED',
    0x0026: 'HV_STATUS_PROCESSOR_FEATURE_XOP_NOT_SUPPORTED',
    0x0027: 'HV_STATUS_PROCESSOR_FEATURE_POPCNT_NOT_SUPPORTED',
    0x0028: 'HV_STATUS_PROCESSOR_FEATURE_CMPXCHG16B_NOT_SUPPORTED',
    0x0029: 'HV_STATUS_PROCESSOR_FEATURE_ALTMOVCR8_NOT_SUPPORTED',
    0x002A: 'HV_STATUS_PROCESSOR_FEATURE_LZCNT_NOT_SUPPORTED',
    0x002B: 'HV_STATUS_PROCESSOR_FEATURE_MISALIGNED_SSE_NOT_SUPPORTED',
    0x002C: 'HV_STATUS_PROCESSOR_FEATURE_MMX_EXT_NOT_SUPPORTED',
    0x002D: 'HV_STATUS_PROCESSOR_FEATURE_3DNOW_NOT_SUPPORTED',
    0x002E: 'HV_STATUS_PROCESSOR_FEATURE_EXTENDED_3DNOW_NOT_SUPPORTED',
    0x002F: 'HV_STATUS_PROCESSOR_FEATURE_PAGE_1GB_NOT_SUPPORTED',
    0x0030: 'HV_STATUS_PROCESSOR_CACHE_LINE_FLUSH_SIZE_INCOMPATIBLE',
    0x0031: 'HV_STATUS_PROCESSOR_FEATURE_XSAVE_NOT_SUPPORTED',
    0x0032: 'HV_STATUS_PROCESSOR_FEATURE_XSAVEOPT_NOT_SUPPORTED',
    0x0033: 'HV_STATUS_INSUFFICIENT_BUFFER',
    0x0034: 'HV_STATUS_PROCESSOR_FEATURE_XSAVE_AVX_NOT_SUPPORTED',
    0x0035: 'HV_STATUS_PROCESSOR_FEATURE_XSAVE_FEATURE_NOT_SUPPORTED',
    0x0036: 'HV_STATUS_PROCESSOR_XSAVE_SAVE_AREA_INCOMPATIBLE',
    0x0037: 'HV_STATUS_INCOMPATIBLE_PROCESSOR',
    0x0038: 'HV_STATUS_INSUFFICIENT_DEVICE_DOMAINS',
    0x0039: 'HV_STATUS_PROCESSOR_FEATURE_AES_NOT_SUPPORTED',
    0x003A: 'HV_STATUS_PROCESSOR_FEATURE_PCLMULQDQ_NOT_SUPPORTED',
    0x003B: 'HV_STATUS_PROCESSOR_FEATURE_INCOMPATIBLE_XSAVE_FEATURES',
    0x003C: 'HV_STATUS_CPUID_FEATURE_VALIDATION_ERROR',
    0x003D: 'HV_STATUS_CPUID_XSAVE_FEATURE_VALIDATION_ERROR',
    0x003E: 'HV_STATUS_PROCESSOR_STARTUP_TIMEOUT',
    0x003F: 'HV_STATUS_SMX_ENABLED',
    0x0040: 'HV_STATUS_PROCESSOR_FEATURE_PCID_NOT_SUPPORTED',
    0x0041: 'HV_STATUS_INVALID_LP_INDEX',
    0x0042: 'HV_STATUS_FEATURE_FMA4_NOT_SUPPORTED',
    0x0043: 'HV_STATUS_FEATURE_F16C_NOT_SUPPORTED',
    0x0044: 'HV_STATUS_PROCESSOR_FEATURE_RDRAND_NOT_SUPPORTED',
    0x0045: 'HV_STATUS_PROCESSOR_FEATURE_RDWRFSGS_NOT_SUPPORTED',
    0x0046: 'HV_STATUS_PROCESSOR_FEATURE_SMEP_NOT_SUPPORTED',
    0x0047: 'HV_STATUS_PROCESSOR_FEATURE_ENHANCED_FAST_STRING_NOT_SUPPORTED',
    0x0048: 'HV_STATUS_PROCESSOR_FEATURE_MOVBE_NOT_SUPPORTED',
    0x0049: 'HV_STATUS_PROCESSOR_FEATURE_BMI1_NOT_SUPPORTED',
    0x004A: 'HV_STATUS_PROCESSOR_FEATURE_BMI2_NOT_SUPPORTED',
    0x004B: 'HV_STATUS_PROCESSOR_FEATURE_HLE_NOT_SUPPORTED',
    0x004C: 'HV_STATUS_PROCESSOR_FEATURE_RTM_NOT_SUPPORTED',
    0x004D: 'HV_STATUS_PROCESSOR_FEATURE_XSAVE_FMA_NOT_SUPPORTED',
    0x004E: 'HV_STATUS_PROCESSOR_FEATURE_XSAVE_AVX2_NOT_SUPPORTED',
    0x004F: 'HV_STATUS_PROCESSOR_FEATURE_NPIEP1_NOT_SUPPORTED'
}


def get_hypercall_status(code, defvalue=''):
    return hypercall_status_codes[code] if code in hypercall_status_codes else defvalue


hypercall_names = {
    0x0001: 'HvSwitchVirtualAddressSpace',
    0x0002: 'HvFlushVirtualAddressSpace',
    0x0003: 'HvFlushVirtualAddressList',
    0x0004: 'HvGetLogicalProcessorRunTime',
    0x0008: 'HvNotifyLongSpinWait',
    0x0009: 'HvParkedVirtualProcessors',
    0x0040: 'HvCreatePartition',
    0x0041: 'HvInitializePartition',
    0x0042: 'HvFinalizePartition',
    0x0043: 'HvDeletePartition',
    0x0044: 'HvGetPartitionProperty',
    0x0045: 'HvSetPartitionProperty',
    0x0046: 'HvGetPartitionId',
    0x0047: 'HvGetNextChildPartition',
    0x0048: 'HvDepositMemory',
    0x0049: 'HvWithdrawMemory',
    0x004A: 'HvGetMemoryBalance',
    0x004B: 'HvMapGpaPages',
    0x004C: 'HvUnmapGpaPages',
    0x004D: 'HvInstallIntercept',
    0x004E: 'HvCreateVp',
    0x004F: 'HvDeleteVp',
    0x0050: 'HvGetVpRegisters',
    0x0051: 'HvSetVpRegisters',
    0x0052: 'HvTranslateVirtualAddress',
    0x0053: 'HvReadGpa',
    0x0054: 'HvWriteGpa',
    0x0055: 'HvAssertVirtualInterrupt',
    0x0056: 'HvClearVirtualInterrupt',
    0x0057: 'HvCreatePort',
    0x0058: 'HvDeletePort',
    0x0059: 'HvConnectPort',
    0x005A: 'HvGetPortProperty',
    0x005B: 'HvDisconnectPort',
    0x005C: 'HvPostMessage',
    0x005D: 'HvSignalEvent',
    0x005E: 'HvSavePartitionState',
    0x005F: 'HvRestorePartitionState',
    0x0060: 'HvInitializeEventLogBufferGroup',
    0x0061: 'HvFinalizeEventLogBufferGroup',
    0x0062: 'HvCreateEventLogBuffer',
    0x0063: 'HvDeleteEventLogBuffer',
    0x0064: 'HvMapEventLogBuffer',
    0x0065: 'HvUnmapEventLogBuffer',
    0x0066: 'HvSetEventLogGroupSources',
    0x0067: 'HvReleaseEventLogBuffer',
    0x0068: 'HvFlushEventLogBuffer',
    0x0069: 'HvPostDebugData',
    0x006A: 'HvRetrieveDebugData',
    0x006B: 'HvResetDebugSession',
    0x006C: 'HvMapStatsPage',
    0x006D: 'HvUnmapStatsPage',
    0x006E: 'HvCallMapSparseGpaPages',
    0x006F: 'HvCallSetSystemProperty',
    0x0070: 'HvCallSetPortProperty',
    0x0076: 'HvCallAddLogicalProcessor',
    0x0077: 'HvCallRemoveLogicalProcessor',
    0x0078: 'HvCallQueryNumaDistance',
    0x0079: 'HvCallSetLogicalProcessorProperty',
    0x007A: 'HvCallGetLogicalProcessorProperty',
    0x007B: 'HvCallGetSystemProperty',
    0x007C: 'HvCallMapDeviceInterrupt',
    0x007D: 'HvCallUnmapDeviceInterrupt',
    0x007E: 'HvCallCreateDeviceDomain',
    0x007F: 'HvCallDeleteDeviceDomain',
    0x0080: 'HvCallMapDevicePages',
    0x0081: 'HvCallUnmapDevicePages',
    0x0082: 'HvCallAttachDevice',
    0x0083: 'HvCallDetachDevice',
    0x0084: 'HvCallEnterSleepState',
    0x0085: 'HvCallPrepareForSleep',
    0x0086: 'HvCallPrepareForHibernate',
    0x0087: 'HvCallNotifyPartitionEvent',
    0x0088: 'HvCallGetLogicalProcessorRegisters',
    0x0089: 'HvCallSetLogicalProcessorRegisters',
    0x008A: 'HvCallQueryAssociatedLpsforMca',
    0x008B: 'HvCallNotifyRingEmpty',
    0x008C: 'HvCallInjectSyntheticMachineCheck',
    0x008D: 'HvCallScrubPartition',
    0x008E: 'HvCallCollectLivedump',
    0x008F: 'HvCallDisableHypervisor',
    0x0090: 'HvCallModifySparseGpaPages',
    0x0091: 'HvCallRegisterInterceptResult',
    0x0092: 'HvCallUnregisterInterceptResult'
}


def get_hypercall_name(code, defvalue=''):
    return hypercall_names[code] if code in hypercall_names else defvalue


hv_porttype = {
    0x0001: 'HvPortTypeMessage',
    0x0002: 'HvPortTypeEvent',
    0x0003: 'HvPortTypeMonitor'
}

GOOD_PARAMS_STATUSES = ['HV_STATUS_SUCCESS', 'HV_STATUS_ACCESS_DENIED']

cpuid_desc = {0x40000003: {}}

cpuid_desc[0x40000003]['EAX'] = {
    0: 'VP Runtime (HV_X64_MSR_VP_RUNTIME) available',
    1: 'Partition Reference Counter (HV_X64_MSR_TIME_REF_COUNT) available',
    2: 'Basic SynIC MSRs (HV_X64_MSR_SCONTROL..HV_X64_MSR_EOM and HV_X64_MSR_SINTxx) available',
    3: 'Synthetic Timer MSRs (HV_X64_MSR_STIMER0_CONFIG..HV_X64_MSR_STIMER3_COUNT) available',
    4: 'APIC access MSRs (HV_X64_MSR_EOI, HV_X64_MSR_ICR and HV_X64_MSR_TPR) are available',
    5: 'Hypercall MSRs (HV_X64_MSR_GUEST_OS_ID and HV_X64_MSR_HYPERCALL) available',
    6: 'Access virtual processor index MSR (HV_X64_MSR_VP_INDEX) available',
    7: 'Virtual system reset MSR (HV_X64_MSR_RESET) is available',
    8: 'Access statistics pages MSRs available',
    9: 'Partition Reference TSC MSR (HV_X64_MSR_REFERENCE_TSC) available',
    10: 'Virtual Guest Idle State MSR (HV_X64_MSR_GUEST_IDLE) available',
    11: 'Timer frequency MSRs (HV_X64_MSR_TSC_FREQUENCY and HV_X64_MSR_APIC_FREQUENCY) available',
    12: 'Debug MSRs (HV_X64_MSR_SYNTH_DEBUG_*) available'
}

cpuid_desc[0x40000003]['EBX'] = {
    0: 'CreatePartitions',
    1: 'AccessPartitionId',
    2: 'AccessMemoryPool',
    3: 'AdjustMessageBuffers',
    4: 'PostMessages',
    5: 'SignalEvents',
    6: 'CreatePort',
    7: 'ConnectPort',
    8: 'AccessStats',
    9: 'RsvdZ',
    10: 'RsvdZ',
    11: 'Debugging',
    12: 'CpuManagement',
    13: 'ConfigureProfiler',
    14: 'EnableExpandedStackwalking'
}

cpuid_desc[0x40000003]['ECX'] = {
    0: 'Maximum Processor Power State (bit 0)',
    1: 'Maximum Processor Power State (bit 1)',
    2: 'Maximum Processor Power State (bit 2)',
    4: 'HPET is required to enter C3'
}

cpuid_desc[0x40000003]['EDX'] = {
    0: 'The MWAIT instruction is available',
    1: 'Guest debugging support is available',
    2: 'Performance Monitor support is available',
    3: 'Support for physical CPU dynamic partitioning events is available',
    4: 'Support for passing hypercall input parameter block via XMM registers is available',
    5: 'Support for a virtual guest idle state is available',
    6: 'Support for hypervisor sleep state is available',
    7: 'Support for querying NUMA distances is available',
    8: 'Support for determining timer frequencies is available',
    9: 'Support for injecting synthetic machine checks is available',
    10: 'Support for guest crash MSRs is available',
    11: 'Support for debug MSRs is available',
    12: 'Npiep1Available',
    13: 'DiableHypervisorAvailable'
}

### HYPERV DEFINES #############################################################

# VMBUS version is 32 bit entity broken up into two 16 bit quantities: major_number . minor_number
VERSION_WS2008 = ((0 << 16) | (13))  # 0 . 13 (Windows Server 2008)
VERSION_WIN7 = ((1 << 16) | (1))   # 1 . 1  (Windows 7)
VERSION_WIN8 = ((2 << 16) | (4))   # 2 . 4  (Windows 8)
VERSION_WIN8_1 = ((3 << 16) | (0))   # 3 . 0  (Windows 8 R2)

vmbus_versions = {
    VERSION_WS2008: 'Windows Server 2008',
    VERSION_WIN7: 'Windows 7',
    VERSION_WIN8: 'Windows 8',
    VERSION_WIN8_1: 'Windows 8 R2'
}

VMBUS_MESSAGE_CONNECTION_ID = 1
VMBUS_MESSAGE_PORT_ID = 1
VMBUS_EVENT_CONNECTION_ID = 2
VMBUS_EVENT_PORT_ID = 2
VMBUS_MONITOR_CONNECTION_ID = 3
VMBUS_MONITOR_PORT_ID = 3
VMBUS_MESSAGE_SINT = 2

### HV MESSAGE DEFINES #########################################################

# Define hypervisor message types
hv_message_type = {
    0x00000000: 'HVMSG_NONE',
    # Memory access messages
    0x80000000: 'HVMSG_UNMAPPED_GPA',
    0x80000001: 'HVMSG_GPA_INTERCEPT',
    # Timer notification messages
    0x80000010: 'HVMSG_TIMER_EXPIRED',
    # Error messages
    0x80000020: 'HVMSG_INVALID_VP_REGISTER_VALUE',
    0x80000021: 'HVMSG_UNRECOVERABLE_EXCEPTION',
    0x80000022: 'HVMSG_UNSUPPORTED_FEATURE',
    # Trace buffer complete messages
    0x80000040: 'HVMSG_EVENTLOG_BUFFERCOMPLETE',
    # Platform-specific processor intercept messages
    0x80010000: 'HVMSG_X64_IOPORT_INTERCEPT',
    0x80010001: 'HVMSG_X64_MSR_INTERCEPT',
    0x80010002: 'HVMSG_X64_CPUID_INTERCEPT',
    0x80010003: 'HVMSG_X64_EXCEPTION_INTERCEPT',
    0x80010004: 'HVMSG_X64_APIC_EOI',
    0x80010005: 'HVMSG_X64_LEGACY_FP_ERROR'
}

### MSG CHANNEL DEFINES ########################################################

CHANNELMSG_INVALID = 0
CHANNELMSG_OFFERCHANNEL = 1
CHANNELMSG_RESCIND_CHANNELOFFER = 2
CHANNELMSG_REQUESTOFFERS = 3
CHANNELMSG_ALLOFFERS_DELIVERED = 4
CHANNELMSG_OPENCHANNEL = 5
CHANNELMSG_OPENCHANNEL_RESULT = 6
CHANNELMSG_CLOSECHANNEL = 7
CHANNELMSG_GPADL_HEADER = 8
CHANNELMSG_GPADL_BODY = 9
CHANNELMSG_GPADL_CREATED = 10
CHANNELMSG_GPADL_TEARDOWN = 11
CHANNELMSG_GPADL_TORNDOWN = 12
CHANNELMSG_RELID_RELEASED = 13
CHANNELMSG_INITIATE_CONTACT = 14
CHANNELMSG_VERSION_RESPONSE = 15
CHANNELMSG_UNLOAD = 16

vmbus_channel_message_type = {
    0: 'ChannelMessageInvalid',
    1: 'ChannelMessageOfferChannel',
    2: 'ChannelMessageRescindChannelOffer',
    3: 'ChannelMessageRequestOffers',
    4: 'ChannelMessageAllOffersDelivered',
    5: 'ChannelMessageOpenChannel',
    6: 'ChannelMessageOpenChannelResult',
    7: 'ChannelMessageCloseChannel',
    8: 'ChannelMessageGpadlHeader',
    9: 'ChannelMessageGpadlBody',
    10: 'ChannelMessageGpadlCreated',
    11: 'ChannelMessageGpadlTeardown',
    12: 'ChannelMessageGpadlTorndown',
    13: 'ChannelMessageRelIdReleased',
    14: 'ChannelMessageInitiateContact',
    15: 'ChannelMessageVersionResponse',
    16: 'ChannelMessageUnload'
}

channel_flags = {
    0x00: 'VMBUS_CHANNEL_ENUMERATE_DEVICE_INTERFACE',
    0x01: 'VMBUS_CHANNEL_SERVER_SUPPORTS_TRANSFER_PAGES',
    0x02: 'VMBUS_CHANNEL_SERVER_SUPPORTS_GPADLS',
    0x04: 'VMBUS_CHANNEL_NAMED_PIPE_MODE',
    0x08: 'VMBUS_CHANNEL_LOOPBACK_OFFER',
    0x09: 'VMBUS_CHANNEL_PARENT_OFFER',
    0x0a: 'VMBUS_CHANNEL_REQUEST_MONITORED_NOTIFICATION'
}

# GUID definitions of various offer types - services offered to the guest
HV_NIC_GUID = '{f8615163-df3e-46c5-913f-f2d2f965ed0e}'
HV_IDE_GUID = '{32412632-86cb-44a2-9b5c-50d1417354f5}'
HV_SCSI_GUID = '{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}'
HV_SHUTDOWN_GUID = '{0e0b6031-5213-4934-818b-38d90ced39db}'
HV_TS_GUID = '{9527e630-d0ae-497b-adce-e80ab0175caf}'
HV_HEART_BEAT_GUID = '{57164f39-9115-4e78-ab55-382f3bd5422d}'
HV_KVP_GUID = '{a9a0f4e7-5a45-4d96-b827-8a841e8c03e6}'
HV_DM_GUID = '{525074dc-8985-46e2-8057-a307dc18a502}'
HV_MOUSE_GUID = '{cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a}'
HV_VSS_GUID = '{35fa2e29-ea23-4236-ae96-3a6ebacba440}'
HV_SYNTHVID_GUID = '{da0a7802-e377-4aac-8e77-0558eb1073f8}'
HV_SYNTHFC_GUID = '{2f9bcc4a-0069-4af3-b76b-6fd0be528cda}'
HV_FCOPY_GUID = '{34d14be3-dee4-41c8-9ae7-6b174977c192}'
HV_KBD_GUID = '{f912ad6d-2b17-48ea-bd65-f927a61c7684}'
REMOTE_DESKTOP_GUID = '{276aacf4-ac15-426c-98dd-7521ad3f01fe}'
VOLUME_SHADOW_COPY_GUID = '{35fa2e29-ea23-4236-96ae-3a6ebacba440}'
AVMA_GUID = '{3375baf4-9e15-4b30-b765-67acb10d607b}'
DESKTOP_CONTROL_GUID = '{f8e65716-3cb3-4a06-9a60-1889c5cccab5}'

hv_guid_desc = {
    HV_NIC_GUID: 'Microsoft Hyper-V Network',
    HV_IDE_GUID: 'Microsoft Hyper-V IDE',
    HV_SCSI_GUID: 'Microsoft Hyper-V SCSI Controller',
    HV_SHUTDOWN_GUID: 'Microsoft Hyper-V Shutdown',
    HV_TS_GUID: 'Microsoft Hyper-V Time Synch',
    HV_HEART_BEAT_GUID: 'Microsoft Hyper-V Heartbeat',
    HV_KVP_GUID: 'Microsoft Hyper-V KVP',
    HV_DM_GUID: 'Microsoft Hyper-V Dynamic memory',
    HV_MOUSE_GUID: 'Microsoft Hyper-V Mouse',
    HV_VSS_GUID: 'Microsoft Hyper-V VSS Backup/Restore',
    HV_SYNTHVID_GUID: 'Microsoft Hyper-V Synthetic Video',
    HV_SYNTHFC_GUID: 'Microsoft Hyper-V Synthetic FC',
    HV_FCOPY_GUID: 'Microsoft Hyper-V Guest File Copy Service',
    HV_KBD_GUID: 'Microsoft Hyper-V Virtual Keyboard',
    REMOTE_DESKTOP_GUID: 'Microsoft Hyper-V Remote Desktop Virtualization',
    VOLUME_SHADOW_COPY_GUID: 'Microsoft Hyper-V Volume Shadow Copy',
    AVMA_GUID: 'Microsoft Hyper-V Automatic Virtual Machine Activation (AVMA)',
    DESKTOP_CONTROL_GUID: 'Microsoft Hyper-V Remote Desktop Control Channel'
}

### VMBUS PACKET DEFINES #######################################################

vm_pkt = {
    0x0: 'VM_PKT_INVALID',
    0x1: 'VM_PKT_SYNCH',
    0x2: 'VM_PKT_ADD_XFER_PAGESET',
    0x3: 'VM_PKT_RM_XFER_PAGESET',
    0x4: 'VM_PKT_ESTABLISH_GPADL',
    0x5: 'VM_PKT_TEARDOWN_GPADL',
    0x6: 'VM_PKT_DATA_INBAND',
    0x7: 'VM_PKT_DATA_USING_XFER_PAGES',
    0x8: 'VM_PKT_DATA_USING_GPADL',
    0x9: 'VM_PKT_DATA_USING_GPA_DIRECT',
    0xa: 'VM_PKT_CANCEL_REQUEST',
    0xb: 'VM_PKT_COMP',
    0xc: 'VM_PKT_DATA_USING_ADDITIONAL_PKT',
    0xd: 'VM_PKT_ADDITIONAL_DATA'
}

VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED = 1

################################################################################


def set_variables(varlist):
    for i in varlist:
        var = re.sub(r"([a-z])([A-Z]+)", r"\1_\2", varlist[i])
        var = var.upper()
        exec(f'global {var}; {var}={i:d}')


set_variables(msrs)
set_variables(hypercall_status_codes)
set_variables(hypercall_names)
set_variables(hv_porttype)
set_variables(hv_message_type)
set_variables(channel_flags)
set_variables(vm_pkt)
