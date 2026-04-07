# XML Configuration Register Extractor

A Python script that extracts all registers from CHIPSEC XML configuration files into a single flat list, following all `config` attribute references and identifying duplicates with their differences.

## Features

- **Recursive parsing**: Automatically follows `config` attributes to include all referenced XML files
- **Flat register list**: Consolidates all registers into a single, easy-to-browse file
- **Controls extraction**: Extracts control definitions alongside registers
- **Cross-reference validation**: Detects undefined register/field references (e.g., BAR `base_field` pointing to a non-existent field)
- **Duplicate detection**: Identifies when a register or control is defined in multiple files
- **Delta analysis**: Shows detailed differences between duplicate register/control definitions
- **File dependency tree**: Visualizes how configuration files reference each other
- **Type-based grouping**: Organizes registers by type (msr, pcicfg, mmio, memory, etc.) and controls by context
- **Offset-based sorting**: Within each type/context, items are sorted by offset for easy navigation
- **Glob pattern support**: Accept glob patterns (e.g., `adl*.xml`) as input arguments
- **Auto-discover mode**: When run with no arguments, scans `chipsec/cfg/` for all platform configurations and processes each independently

## Usage

### Basic Usage

```bash
python extract_registers.py [xml_file_or_glob ...] [-o output_file_or_dir] [--cfg-dir DIR]
```

### Examples

#### Extract from a single XML file:
```bash
python extract_registers.py chipsec/cfg/8086/adl.xml
```

#### Extract using a glob pattern:
```bash
python extract_registers.py "chipsec/cfg/8086/adl*.xml"
```

#### Extract from multiple XML files:
```bash
python extract_registers.py chipsec/cfg/8086/adl.xml chipsec/cfg/8086/adl_custom.xml
```

#### Save output to a file:
```bash
python extract_registers.py chipsec/cfg/8086/adl.xml -o adl_registers.txt
```

#### Auto-discover all platforms (no arguments):
```bash
python extract_registers.py
```

#### Auto-discover with output directory:
```bash
python extract_registers.py -o results/
```

## Output Format

The generated output file contains:

1. **Header Section**
   - Total number of unique registers
   - Total number of unique controls
   - Total files processed
   - Cross-reference error count
   - Parse/config error count
   - List of all processed files
   - File dependency tree showing config references

2. **Cross-Reference Validation Errors** (if any)
   - Undefined register references
   - Invalid field references with suggestions (e.g., "did you mean ...?")
   - Available fields listed for each invalid reference

3. **Registers Section** (grouped by type, then context, then offset)
   - Register name
   - Source file path
   - Included by (top-level XML file that referenced it)
   - Context path (how it was referenced)
   - Register type (msr, pcicfg, mmio, memory, etc.)
   - All register attributes (offset, size, desc, etc.)
   - Field definitions with their attributes
   - Full XML representation

4. **Controls Section** (grouped by context)
   - Control name
   - Source file path
   - Included by (top-level XML file that referenced it)
   - Context path
   - All control attributes (register, field, desc, etc.)
   - Full XML representation

5. **Duplicate Analysis** (when applicable for both registers and controls)
   - Number of files defining the same register/control
   - Detailed comparison of attribute differences
   - Field-by-field delta showing additions, removals, and modifications

## Example Output

```
================================================================================
CHIPSEC XML Configuration - Flat Register List
================================================================================

Total unique registers: 231
Total unique controls: 3
Total files processed: 13
Cross-reference errors: 0
Parse/config errors: 0

Processed files:
  1. C:\path\to\chipsec\cfg\8086\adl.xml
  2. C:\path\to\chipsec\cfg\8086\MSR\msr2.xml
  ...

File dependency tree:
└─ C:\path\to\chipsec\cfg\8086\adl.xml
  └─ C:\path\to\chipsec\cfg\8086\HOSTCTL\hostctl1.xml
  └─ C:\path\to\chipsec\cfg\8086\MSR\msr2.xml
  ...

================================================================================
REGISTERS
================================================================================

================================================================================
Type: MSR
================================================================================

--------------------------------------------------------------------------------
Context: MSR
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
Register: IA32_FEATURE_CONTROL
--------------------------------------------------------------------------------
Source: C:\path\to\chipsec\cfg\8086\MSR\msr2.xml
Included by: C:\path\to\chipsec\cfg\8086\adl.xml
Context: MSR
Type: msr
desc: Processor Feature Control
msr: 0x3A

Fields:
  - LOCK
      bit: 0
      desc: Lock
      size: 1
  - EN_VMX_INSIDE_SMX
      bit: 1
      desc: Enable VMX inside SMX operation
      size: 1
  ...

XML:
  <register name="IA32_FEATURE_CONTROL" type="msr" msr="0x3A" desc="...">
    <field name="LOCK" bit="0" size="1" desc="Lock" />
    ...
  </register>

================================================================================
CONTROLS
================================================================================

--------------------------------------------------------------------------------
Context: HOSTCTL
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
Control: TSEGBaseLock
--------------------------------------------------------------------------------
Source: C:\path\to\chipsec\cfg\8086\HOSTCTL\hostctl1.xml
Included by: C:\path\to\chipsec\cfg\8086\adl.xml
Context: HOSTCTL
desc: TSEG Base Lock
field: LOCK
register: TSEGMB

XML:
  <control name="TSEGBaseLock" register="TSEGMB" field="LOCK" desc="TSEG Base Lock" />
```

## Configuration File Format

The script understands CHIPSEC XML configuration files with:

- **Register definitions**: `<register>` elements with attributes (name, type, offset, size, etc.)
- **Control definitions**: `<control>` elements with attributes (name, register, field, desc, etc.)
- **Config references**: `config` attributes using dot notation (e.g., `HOSTCTL.hostctl1.xml`)
- **Field definitions**: `<field>` child elements defining register bit fields
- **Nested configurations**: Devices, subcomponents, MSR definitions, memory ranges, etc.

### Config Path Resolution

The script resolves `config` attributes using the following logic:

1. Converts dot notation to paths: `HOSTCTL.hostctl1.xml` → `HOSTCTL/hostctl1.xml`
2. Searches relative to the current file's directory
3. Walks up the directory tree to find the vendor directory (a 4-hex-digit directory name under `cfg/`, e.g., `8086`, `1022`)
4. Uses all provided input file paths as potential base directories

## Exit Codes

- **0**: Success, no errors found
- **1**: One or more errors occurred (parse errors, file-not-found, or cross-reference validation errors)

## Auto-Discover Mode

When run with no file arguments, the script scans the `--cfg-dir` directory (default: `chipsec/cfg`) for XML files containing `<configuration platform="...">` tags, groups them by platform, and processes each platform independently. The `template.xml` file is excluded from auto-discovery.

In this mode, `-o` specifies the output directory (default: current directory) and output files are named `<platform>_registers.txt`.

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Tips

### Find all registers of a specific type:
After generating the output, search for the type section:
```
Type: MSR
Type: PCICFG
Type: MMIO
```

### View all controls:
Scroll to the end of the output or search for:
```
CONTROLS
```

### Identify platform-specific differences:
Compare two platforms:
```bash
python extract_registers.py platform1.xml platform2.xml -o comparison.txt
```
Then search for "DEFINED IN" to see registers or controls that appear in both.

### Trace where a register or control is used:
The "Included by" field shows which top-level XML file caused it to be included.
The "Context" field shows the path through the XML hierarchy:
```
Included by: C:\path\to\chipsec\cfg\8086\adl.xml
Context: HOSTCTL/MCHBAR
```
This means the item was found via: top-level adl.xml → HOSTCTL device → MCHBAR subcomponent

## Troubleshooting

### Warning: Config file not found

If you see warnings about missing config files:
```
Warning: Config file not found: HOSTCTL.hostctl1.xml (referenced from ...)
```

This usually means:
- The referenced XML file doesn't exist in the expected location
- The file path is incorrect in the source XML
- The script couldn't find the correct base directory

The script will continue processing and extract registers from all files it can find.

### No registers or controls found

If the output shows 0 registers or 0 controls:
- Check that the input XML files are valid
- Verify the XML files contain `<register>` and/or `<control>` elements
- Check file permissions
- Some XML files may only contain registers or only contain controls

## License

This script is provided as-is for working with CHIPSEC configuration files.
