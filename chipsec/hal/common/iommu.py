# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Access to IOMMU engines - uses DMAR table for dynamic VT-d engine discovery
"""

from chipsec.hal import hal_base
from chipsec.library.exceptions import IOMMUError
from chipsec.cfg.parsers.iommu_parser import IOMMUCommands
from typing import List, Dict, Optional, Tuple
import os
import struct

class IOMMU(hal_base.HALBase):

    def __init__(self, cs):
        super(IOMMU, self).__init__(cs)
        self.iommu_config: Optional[IOMMUCommands] = None
        self.engines: Dict[str, int] = {}  # engine_name -> base_address
        self.engine_info: Dict[str, Dict[str, object]] = {}  # per-engine metadata (segment, scopes, flags)
        self.rmrrs: List[Dict[str, object]] = []
        self.atsrs: List[Dict[str, object]] = []
        self.initialized = False

    def initialize(self) -> None:
        """
        Initialize IOMMU by discovering VT-d engines from DMAR table and loading register configs.
        This replaces hardcoded IOMMU_ENGINES with runtime DMAR-based discovery.
        """
        if self.initialized:
            return
        
        # Discover VT-d engines from DMAR DRHD structures
        self._discover_vtd_engines()
        
        # Load register definitions from XML
        self._load_iommu_configs()
        
        # Bind discovered bases to config
        if self.iommu_config:
            self.iommu_config.set_engine_bases(self.engines)
        
        self.initialized = True
        self.logger.log_hal(f"[IOMMU] Initialized with {len(self.engines)} VT-d engines")

    def _discover_vtd_engines(self) -> None:
        """
        Discover VT-d engine MMIO base addresses from DMAR ACPI table.
        Direct binary parsing like ACPI AML parser - simple and reliable.
        
        DMAR Table Format:
        - Standard ACPI header (36 bytes)
        - Host Address Width (1 byte)
        - Flags (1 byte)
        - Reserved (10 bytes)
        - Remapping Structures (variable):
            DRHD (Type 0): Contains RegisterBaseAddress at offset 8
        """
        try:
            # Check if DMAR table exists
            if not self.cs.hals.acpi.is_ACPI_table_present('DMAR'):
                self.logger.log_warning("[IOMMU] DMAR table not present")
                return
            
            # Get raw DMAR table bytes
            dmar_tables = self.cs.hals.acpi.get_ACPI_table('DMAR')
            if not dmar_tables or len(dmar_tables) == 0:
                self.logger.log_warning("[IOMMU] Could not read DMAR table")
                return
            
            # Extract full table: header + body
            dmar_header, dmar_body = dmar_tables[0]
            dmar_data = dmar_header + dmar_body  # Concatenate for full table
            
            if len(dmar_data) < 48:  # Header + minimal DMAR header
                self.logger.log_warning(f"[IOMMU] DMAR table too short: {len(dmar_data)} bytes")
                return
            
            self.logger.log_hal(f"[IOMMU] Parsing DMAR table ({len(dmar_data)} bytes)")
            
            # Parse DMAR structures starting at offset 48
            # (36-byte ACPI header + 12-byte DMAR-specific header)
            pos = 48
            engine_idx = 0
            
            while pos + 4 <= len(dmar_data):  # Need at least type/len
                struct_type = struct.unpack('<H', dmar_data[pos:pos+2])[0]
                struct_len = struct.unpack('<H', dmar_data[pos+2:pos+4])[0]

                if struct_len < 4 or pos + struct_len > len(dmar_data):
                    self.logger.log_hal(f"[IOMMU] Invalid structure at offset {pos}: len={struct_len}")
                    break
                
                # DRHD structure (Type 0)
                if struct_type == 0 and struct_len >= 16:
                    flags = dmar_data[pos+4]
                    segment = struct.unpack('<H', dmar_data[pos+6:pos+8])[0]
                    include_all = bool(flags & 0x1)
                    # RegisterBaseAddress is at offset 8 from structure start
                    if pos + 16 <= len(dmar_data):
                        base = struct.unpack('<Q', dmar_data[pos+8:pos+16])[0]
                        if base > 0:
                            engine_name = f'VTD{engine_idx}'
                            self.engines[engine_name] = base
                            scopes = self._parse_device_scopes(dmar_data[pos:pos+struct_len], struct_len, header_size=16)
                            self.engine_info[engine_name] = {
                                'segment': segment,
                                'flags': flags,
                                'include_all': include_all,
                                'scopes': scopes
                            }
                            self.logger.log_hal(f"[IOMMU] Discovered {engine_name} at 0x{base:016X}")
                            engine_idx += 1

                # RMRR structure (Type 1)
                elif struct_type == 1 and struct_len >= 24:
                    segment = struct.unpack('<H', dmar_data[pos+6:pos+8])[0]
                    base = struct.unpack('<Q', dmar_data[pos+8:pos+16])[0]
                    limit = struct.unpack('<Q', dmar_data[pos+16:pos+24])[0]
                    scopes = self._parse_device_scopes(dmar_data[pos:pos+struct_len], struct_len, header_size=24)
                    self.rmrrs.append({
                        'segment': segment,
                        'base': base,
                        'limit': limit,
                        'scopes': scopes
                    })

                # ATSR structure (Type 2)
                elif struct_type == 2 and struct_len >= 8:
                    flags = dmar_data[pos+4]
                    segment = struct.unpack('<H', dmar_data[pos+6:pos+8])[0]
                    scopes = self._parse_device_scopes(dmar_data[pos:pos+struct_len], struct_len, header_size=8)
                    self.atsrs.append({
                        'segment': segment,
                        'flags': flags,
                        'scopes': scopes
                    })
                
                pos += struct_len
            
            if not self.engines:
                self.logger.log_warning("[IOMMU] No DRHD structures found in DMAR")
            else:
                self.logger.log_hal(f"[IOMMU] Total engines discovered: {len(self.engines)}")
                
        except Exception as e:
            self.logger.log_error(f"[IOMMU] DMAR discovery failed: {e}")
            import traceback
            self.logger.log_error(traceback.format_exc())

    def _parse_device_scopes(self, struct_blob: bytes, struct_len: int, header_size: int = 16) -> List[Dict[str, object]]:
        """Parse device scopes inside a DMAR structure."""
        scopes: List[Dict[str, object]] = []
        cursor = header_size
        end = min(len(struct_blob), struct_len)

        while cursor + 2 <= end:
            ds_type = struct_blob[cursor]
            ds_len = struct_blob[cursor + 1]

            # DeviceScope header is 6 bytes minimum; stop on malformed entries
            if ds_len < 6 or cursor + ds_len > end:
                break

            flags = struct_blob[cursor + 2]
            enum_id = struct_blob[cursor + 3]
            start_bus = struct_blob[cursor + 4]

            path_bytes = struct_blob[cursor + 6: cursor + ds_len]
            path: List[Tuple[int, int]] = []
            for idx in range(0, len(path_bytes), 2):
                if idx + 1 >= len(path_bytes):
                    break
                path.append((path_bytes[idx], path_bytes[idx + 1]))

            scopes.append({
                'type': ds_type,
                'flags': flags,
                'enum_id': enum_id,
                'start_bus': start_bus,
                'path': path
            })

            cursor += ds_len

        return scopes

    def _scope_primary_bdf(self, scope: Dict[str, object]) -> Optional[Tuple[int, int, int]]:
        """Return the primary B:D.F for a device scope, if present."""
        path: List[Tuple[int, int]] = scope.get('path', [])  # type: ignore[arg-type]
        if not path:
            return None
        dev, fun = path[0]
        bus = scope.get('start_bus', 0)  # type: ignore[assignment]
        return (bus, dev, fun)

    def get_engine_device_bdfs(self, engine_name: str) -> List[Tuple[int, int, int]]:
        """Return a list of B:D.F tuples associated with an engine's scopes."""
        info = self.engine_info.get(engine_name, {})
        scopes = info.get('scopes', [])
        bdfs: List[Tuple[int, int, int]] = []
        for scope in scopes:
            bdf = self._scope_primary_bdf(scope)
            if bdf:
                bdfs.append(bdf)
        return bdfs

    def _format_scopes_compact(self, scopes: List[Dict[str, object]]) -> str:
        """Format a list of scopes as short labels (B:D.F or type)."""
        labels: List[str] = []
        for scope in scopes:
            bdf = self._scope_primary_bdf(scope)
            if bdf:
                bus, dev, fun = bdf
                labels.append(f'{bus:02X}:{dev:02X}.{fun:d}')
            else:
                labels.append(f'type{scope.get("type", "?")}')
        return ' '.join(labels)

    def get_engine_descriptions(self) -> List[Tuple[str, int, str]]:
        """Return (engine_name, base, label) tuples with primary B:D.F and flags."""
        desc: List[Tuple[str, int, str]] = []
        for eng, base in self.engines.items():
            labels: List[str] = []
            bdfs = self.get_engine_device_bdfs(eng)
            if bdfs:
                bus, dev, fun = bdfs[0]
                labels.append(f'{bus:02X}:{dev:02X}.{fun:d}')

            info = self.engine_info.get(eng, {})
            if info.get('include_all', False):
                labels.append('include-all')

            desc.append((eng, base, ' '.join(labels)))
        return desc

    def describe_rmrr(self) -> List[str]:
        """Return human-readable summaries of RMRR entries."""
        lines: List[str] = []
        for idx, rmrr in enumerate(self.rmrrs):
            seg = rmrr.get('segment', 0)
            base = rmrr.get('base', 0)
            limit = rmrr.get('limit', 0)
            scopes = rmrr.get('scopes', [])
            scope_s = self._format_scopes_compact(scopes)
            lines.append(
                f'RMRR[{idx}] seg=0x{seg:04X} base=0x{base:016X} limit=0x{limit:016X} scopes=[{scope_s}]'
            )
        return lines

    def describe_atsr(self) -> List[str]:
        """Return human-readable summaries of ATSR entries."""
        lines: List[str] = []
        for idx, atsr in enumerate(self.atsrs):
            seg = atsr.get('segment', 0)
            flags = atsr.get('flags', 0)
            scopes = atsr.get('scopes', [])
            scope_s = self._format_scopes_compact(scopes)
            lines.append(
                f'ATSR[{idx}] seg=0x{seg:04X} flags=0x{flags:02X} scopes=[{scope_s}]'
            )
        return lines

    def _load_iommu_configs(self) -> None:
        """Load IOMMU register definitions from XML configs."""
        try:
            # Try standard extra-config loader
            self.cs.Cfg.add_extra_configs(os.path.join('8086', 'IOMMU'), None, True)
            
            self.iommu_config = IOMMUCommands(self.cs.Cfg)
            reg_count = len(self.iommu_config.regs) if self.iommu_config else 0
            self.logger.log_hal(f"[IOMMU] Loaded {reg_count} register definitions")
        except Exception as e:
            self.logger.log_error(f"[IOMMU] Config loading failed: {e}")

    def get_IOMMU_Base_Address(self, iommu_engine: str) -> int:
        """Get VT-d engine MMIO base address for discovered engines."""
        if not self.initialized:
            self.initialize()

        if iommu_engine in self.engines:
            return self.engines[iommu_engine]

        raise IOMMUError(f'IOMMUError: unknown IOMMU engine {iommu_engine}')

    def get_discovered_engines(self) -> List[str]:
        """Return list of discovered VT-d engine names."""
        if not self.initialized:
            self.initialize()
        return list(self.engines.keys())

    def read_IOMMU_reg(self, engine_name: str, reg_name: str) -> int:
        """
        Read VT-d register using dynamic address binding.
        
        Args:
            engine_name: Engine identifier (e.g., 'VTD0')
            reg_name: Register name (e.g., 'VER', 'CAP', 'GSTS')
        
        Returns:
            Register value
        """
        if not self.initialized:
            self.initialize()
        
        if not self.iommu_config:
            raise IOMMUError("[IOMMU] Config not loaded")
        
        reg = self.iommu_config.get_reg(reg_name)
        if not reg:
            raise IOMMUError(f"[IOMMU] Register {reg_name} not found")
        
        base = self.engines.get(engine_name)
        if base is None:
            raise IOMMUError(f"[IOMMU] Engine {engine_name} not found")
        
        addr = self.iommu_config.compute_reg_address(reg, base)
        return self.cs.hals.mmio.read_MMIO_reg(addr, 0, reg.size)
    
    def write_IOMMU_reg(self, engine_name: str, reg_name: str, value: int) -> None:
        """
        Write VT-d register using dynamic address binding.
        
        Args:
            engine_name: Engine identifier
            reg_name: Register name
            value: Value to write
        """
        if not self.initialized:
            self.initialize()
        
        if not self.iommu_config:
            raise IOMMUError("[IOMMU] Config not loaded")
        
        reg = self.iommu_config.get_reg(reg_name)
        if not reg:
            raise IOMMUError(f"[IOMMU] Register {reg_name} not found")
        
        base = self.engines.get(engine_name)
        if base is None:
            raise IOMMUError(f"[IOMMU] Engine {engine_name} not found")
        
        addr = self.iommu_config.compute_reg_address(reg, base)
        self.cs.hals.mmio.write_MMIO_reg(addr, 0, value, reg.size)
    
    def is_IOMMU_Engine_Enabled(self, iommu_engine: str) -> bool:
        """Check if VT-d engine is enabled (base address is non-zero)."""
        if not self.initialized:
            self.initialize()

        if iommu_engine in self.engines:
            return self.engines[iommu_engine] != 0

        raise IOMMUError(f'IOMMUError: unknown IOMMU engine {iommu_engine}')

    def is_IOMMU_Translation_Enabled(self, iommu_engine: str) -> bool:
        """Check if translation is enabled (GSTS.TES bit)."""
        if not self.initialized:
            self.initialize()

        if iommu_engine in self.engines and self.iommu_config:
            gsts = self.read_IOMMU_reg(iommu_engine, 'GSTS')
            return (gsts >> 31) & 1 == 1

        raise IOMMUError(f'IOMMUError: unknown IOMMU engine {iommu_engine}')

    def set_IOMMU_Translation(self, iommu_engine: str, te: int) -> bool:
        """Enable/disable translation by setting GCMD.TE bit."""
        if not self.initialized:
            self.initialize()

        if iommu_engine in self.engines and self.iommu_config:
            try:
                gcmd = self.read_IOMMU_reg(iommu_engine, 'GCMD')
                if te:
                    gcmd |= (1 << 31)  # Set TE bit
                else:
                    gcmd &= ~(1 << 31)  # Clear TE bit
                self.write_IOMMU_reg(iommu_engine, 'GCMD', gcmd)
                return True
            except Exception as e:
                self.logger.log_error(f"[IOMMU] Failed to set translation: {e}")
                return False

        raise IOMMUError(f'IOMMUError: unknown IOMMU engine {iommu_engine}')

    def dump_IOMMU_configuration(self, iommu_engine: str) -> None:
        """Dump VT-d engine configuration - works with both discovered and legacy engines."""
        if not self.initialized:
            self.initialize()
        
        self.logger.log("==================================================================")
        self.logger.log(f'[iommu] {iommu_engine} IOMMU Engine Configuration')
        self.logger.log("==================================================================")
        
        # Get base address
        try:
            base = self.get_IOMMU_Base_Address(iommu_engine)
            self.logger.log(f'MMIO base                 : 0x{base:016X}')
        except IOMMUError as e:
            self.logger.log(f'Error: {e}')
            return
        
        if base == 0:
            self.logger.log("IOMMU engine base address is zero")
            return
        
        self.logger.log("------------------------------------------------------------------")
        
        if iommu_engine in self.engines and self.iommu_config:
            ver = self.read_IOMMU_reg(iommu_engine, 'VER')
            ver_min = ver & 0xF
            ver_max = (ver >> 4) & 0xF
            self.logger.log(f'Version                   : {ver_max}.{ver_min}')

            enabled = self.is_IOMMU_Engine_Enabled(iommu_engine)
            self.logger.log(f'Engine enabled            : {enabled:d}')

            te = self.is_IOMMU_Translation_Enabled(iommu_engine)
            self.logger.log(f'Translation enabled       : {te:d}')

            rtaddr = self.read_IOMMU_reg(iommu_engine, 'RTADDR')
            rtaddr_rta = rtaddr & 0xFFFFFFFFFFFFF000
            self.logger.log(f'Root Table Address        : 0x{rtaddr_rta:016X}')

            irta = self.read_IOMMU_reg(iommu_engine, 'IRTA')
            irta_addr = irta & 0xFFFFFFFFFFFFF000
            self.logger.log(f'Interrupt Remapping Table : 0x{irta_addr:016X}')

            self.logger.log("------------------------------------------------------------------")
            self.logger.log("Protected Memory:")

            pmen = self.read_IOMMU_reg(iommu_engine, 'PMEN')
            pmen_epm = (pmen >> 31) & 1
            pmen_prs = (pmen >> 0) & 1
            self.logger.log(f'  Enabled                 : {pmen_epm}')
            self.logger.log(f'  Status                  : {pmen_prs}')

            plmbase = self.read_IOMMU_reg(iommu_engine, 'PLMBASE')
            plmbase_addr = plmbase & 0xFFFFFFFFF000
            plmlimit = self.read_IOMMU_reg(iommu_engine, 'PLMLIMIT')
            plmlimit_addr = plmlimit | 0xFFF

            phmbase = self.read_IOMMU_reg(iommu_engine, 'PHMBASE')
            phmbase_addr = phmbase & 0xFFFFFFFFFFFFFFFC
            phmlimit = self.read_IOMMU_reg(iommu_engine, 'PHMLIMIT')
            phmlimit_addr = phmlimit | 0x3

            self.logger.log(f'  Low Memory Base         : 0x{plmbase_addr:016X}')
            self.logger.log(f'  Low Memory Limit        : 0x{plmlimit_addr:016X}')
            self.logger.log(f'  High Memory Base        : 0x{phmbase_addr:016X}')
            self.logger.log(f'  High Memory Limit       : 0x{phmlimit_addr:016X}')

            self.logger.log("------------------------------------------------------------------")
            self.logger.log("Capabilities:\n")

            cap = self.read_IOMMU_reg(iommu_engine, 'CAP')
            self.logger.log(f'CAP  = 0x{cap:016X}')
            ecap = self.read_IOMMU_reg(iommu_engine, 'ECAP')
            self.logger.log(f'ECAP = 0x{ecap:016X}')
            self.logger.log('')
            return

        raise IOMMUError(f'IOMMUError: unknown IOMMU engine {iommu_engine}')

    def dump_IOMMU_page_tables(self, iommu_engine: str) -> None:
        """Dump VT-d page tables - simplified for compatibility."""
        if not self.initialized:
            self.initialize()
        
        self.logger.log(f"[iommu] Page table dumping not yet supported for {iommu_engine}")

    def dump_IOMMU_status(self, iommu_engine: str) -> None:
        """Dump VT-d engine status registers."""
        if not self.initialized:
            self.initialize()
        
        self.logger.log('==================================================================')
        self.logger.log(f'[iommu] {iommu_engine} IOMMU Engine Status:')
        self.logger.log('==================================================================')
        
        if iommu_engine in self.engines and self.iommu_config:
            gsts = self.read_IOMMU_reg(iommu_engine, 'GSTS')
            self.logger.log(f'GSTS = 0x{gsts:08X}')
            fsts = self.read_IOMMU_reg(iommu_engine, 'FSTS')
            self.logger.log(f'FSTS = 0x{fsts:08X}')
            return None

        raise IOMMUError(f'IOMMUError: unknown IOMMU engine {iommu_engine}')


haldata = {"arch":[hal_base.HALBase.MfgIds.Any], 'name': {'iommu': "IOMMU"}}
