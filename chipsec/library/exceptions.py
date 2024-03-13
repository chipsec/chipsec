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

# HAL


class AcpiRuntimeError (RuntimeError):
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


class IOBARNotFoundError (RuntimeError):
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

# OS Helper


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

# Logger


class LoggerError (RuntimeWarning):
    pass

# tools


class BadSMIDetected (RuntimeError):
    pass
