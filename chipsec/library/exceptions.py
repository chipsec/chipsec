# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation
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


# ================================================
# CHIPSEC common
# ================================================

# Register
class UninitializedRegisterError (RuntimeError):
    pass


class ScopeNotFoundError(RuntimeError):
    pass 


class NonRegisterInScopeError(RuntimeError):
    pass 


# Register/Device/Lock/Control Objs
class ObjectInstanceNotFoundError (RuntimeError):
    pass


# Chipset
class UnknownChipsetError(RuntimeError):
    pass


class DeviceNotFoundError(RuntimeError):
    pass


class RegisterNotFoundError(RuntimeError):
    pass


class RegisterTypeNotFoundError(RuntimeError):
    pass


class CSBusNotFoundError(RuntimeError):
    pass


class CSFirstNotFoundError(RuntimeError):
    pass


class CSConfigError(RuntimeError):
    pass


class CSReadError(RuntimeError):
    def __init__(self, msg: str) -> None:
        super(CSReadError, self).__init__(msg)


#Cfg
# Custom exception classes for better error handling
class PlatformDetectionError(CSConfigError):
    """Raised when platform detection fails."""
    pass


class ConfigurationValidationError(CSConfigError):
    """Raised when configuration validation fails."""
    pass


class ParserLoadError(CSConfigError):
    """Raised when parser loading fails."""
    pass


class ControlError(Exception):
    """Exception raised when control operations fail."""
    pass


class ParserError(Exception):
    """Base exception for parser-related errors."""
    pass


class XMLConversionError(ParserError):
    """Exception raised when XML data conversion fails."""
    pass


class ConfigurationError(ParserError):
    """Exception raised when configuration processing fails."""
    pass


class GenericConfigError(Exception):
    """Custom exception for generic configuration errors."""
    pass


#IP Config Errors
class IOConfigError(GenericConfigError):
    """Custom exception for I/O configuration errors."""
    pass


class IOBarConfigError(GenericConfigError):
    """Custom exception for I/O BAR configuration errors."""
    pass


class MemoryConfigError(GenericConfigError):
    """Custom exception for memory configuration errors."""
    pass


class MM_MSGBUSConfigError(GenericConfigError):
    """Exception raised for MM_MSGBUS configuration-specific errors."""
    pass


class MMIOBarConfigError(GenericConfigError):
    """Custom exception for MMIO BAR configuration errors."""
    pass


class MSGBUSConfigError(GenericConfigError):
    """Exception raised for MSGBUS configuration-specific errors."""
    pass


class MSRConfigError(GenericConfigError):
    """Exception raised for MSR configuration-specific errors."""
    pass


class PCIConfigError(GenericConfigError):
    """Custom exception for PCI configuration errors."""
    pass


class PlatformConfigError(GenericConfigError):
    """Exception raised for platform configuration-specific errors."""
    pass


# Register Config Errors
class ControlHelperError(CSConfigError):
    """Exception raised for control helper-specific errors."""
    pass


class IORegisterError(CSConfigError):
    """Exception raised for I/O register-specific errors."""
    pass


class IOBARRegisterError(CSConfigError):
    """Exception raised for I/O BAR register-specific errors."""
    pass


class LockHelperError(CSConfigError):
    """Exception raised for lock helper-specific errors."""
    pass


class MemoryRegisterError(CSConfigError):
    """Exception raised for memory register-specific errors."""
    pass


class MM_MSGBUSRegisterError(CSConfigError):
    """Exception raised for MM_MSGBUS register-specific errors."""
    pass


class MMCFGRegisterError(CSConfigError):
    """Exception raised for MMCFG register-specific errors."""
    pass


class MMIORegisterError(CSConfigError):
    """Exception raised for MMIO register-specific errors."""
    pass


class MSGBUSRegisterError(CSConfigError):
    """Exception raised for MSGBUS register-specific errors."""
    pass


class MSRRegisterError(CSConfigError):
    """Exception raised for MSR register-specific errors."""
    pass


class PCIRegisterError(CSConfigError):
    """Custom exception for PCI register configuration errors."""
    pass


# ================================================
# HAL
# ================================================
class HALNotFoundError (RuntimeError):
    pass


class HALInitializationError (RuntimeError):
    pass


class AcpiRuntimeError (RuntimeError):
    pass


class SizeRuntimeError (RuntimeError):
    pass


class CmosRuntimeError (RuntimeError):
    pass


class CmosAccessError (RuntimeError):
    pass


class CPURuntimeError (RuntimeError):
    pass


class CpuIDRuntimeError (RuntimeError):
    pass


class IGDRuntimeError (RuntimeError):
    pass


class PortIORuntimeError (RuntimeError):
    pass


class IOBARRuntimeError (RuntimeError):
    pass


class BARNotFoundError (RuntimeError):
    pass


class IOBARNotFoundError (BARNotFoundError):
    pass


class MMIOBARNotFoundError (BARNotFoundError):
    pass


class IOMMUError (RuntimeError):
    pass


class MsgBusRuntimeError (RuntimeError):
    pass


class MsrRuntimeError (RuntimeError):
    pass


class PciRuntimeError (RuntimeError):
    pass


class PciDeviceNotFoundError (RuntimeError):
    pass


class MemoryRuntimeError (RuntimeError):
    pass


class MemoryAccessError (RuntimeError):
    pass


class SpiRuntimeError (RuntimeError):
    pass


class SpiAccessError (RuntimeError):
    pass


class TpmRuntimeError (RuntimeError):
    pass


class VirtualMemoryRuntimeError (RuntimeError):
    pass


class VirtualMemoryAccessError (RuntimeError):
    pass


class VMMRuntimeError (RuntimeError):
    pass


class InvalidMemoryAddress (RuntimeError):
    pass


# ================================================
# OS Helper
# ================================================
class OsHelperError (RuntimeError):
    def __init__(self, msg: str, errorcode: int) -> None:
        super(OsHelperError, self).__init__(msg)
        self.errorcode = errorcode


class HWAccessViolationError (OsHelperError):
    pass


class UnimplementedAPIError (OsHelperError):
    def __init__(self, api_name: str) -> None:
        super(UnimplementedAPIError, self).__init__(f"'{api_name}' is not implemented", 0)


class DALHelperError (RuntimeError):
    pass


class EfiHelperError (RuntimeError):
    pass


# ================================================
# Logger
# ================================================
class LoggerError (RuntimeWarning):
    pass


# ================================================
# Tools
# ================================================
class BadSMIDetected (RuntimeError):
    pass
