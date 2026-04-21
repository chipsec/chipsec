---
name: 'XML Standards'
description: 'Coding conventions for XML files'
applyTo: '**/**.xml'
---

# CHIPSEC XML Configuration File Standards

CHIPSEC uses XML files to describe platform hardware configuration. These files live under `chipsec/cfg/<vendor_id>/` and are validated against `chipsec/cfg/chipsec_cfg.xsd`.

Use `chipsec/cfg/template.xml` as the canonical reference for new files.

## File Structure

Every platform configuration file must follow this top-level structure, in order:

```xml
<?xml version="1.0"?>
<configuration platform="PLATFORM_CODE" req_pch="True|False">
<!--
  License header (see below)
-->

  <info ...>          <!-- platform identification -->
  <pci>               <!-- integrated PCI devices -->
  <msr>               <!-- MSR definition references -->
  <mmio>              <!-- MMIO BARs -->
  <io>                <!-- I/O BARs -->
  <memory>            <!-- memory ranges -->
  <ima>               <!-- indirect memory accesses -->
  <registers>         <!-- configuration registers -->
  <controls>          <!-- named controls over register fields -->
  <locks>             <!-- named locks over register fields -->

</configuration>
```

Omit sections that are not applicable. Do not include empty section elements.

## XML Declaration

Always include the XML declaration as the very first line:

```xml
<?xml version="1.0"?>
```

For files containing non-ASCII characters, add an encoding attribute:

```xml
<?xml version="1.0" encoding="utf-8"?>
```

## License Header

Include the standard CHIPSEC license comment block immediately after the `<configuration>` opening tag, before any content:

```xml
<!--
CHIPSEC: Platform Security Assessment Framework
Copyright (c) <YEAR>, Intel Corporation

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; Version 2.
...
Contact information:
chipsec@intel.com
-->
```

## Root Element

```xml
<configuration platform="ADL" req_pch="True">
```

- `platform`: Short uppercase platform code (e.g., `ADL`, `LNL`, `KBL`, `PCH_8XX`). PCH configuration files must use a `PCH_` prefix for the platform code (e.g., `PCH_8XX`).
- `req_pch`: `True` if the platform requires a PCH companion chip; `False` for SoC platforms where PCH is integrated (e.g., LNL).

## `<info>` — Platform Identification

```xml
<info family="core" detection_value="0x90670-0x90672, 0x906a0-0x906a4">
  <sku did="0x4621" name="AlderLake" code="ADL" longname="ADL-P/H 4+8"/>
</info>
```

- `family`: Processor family string (e.g. `core`).
- `detection_value`: CPUID stepping range(s) used to identify the platform. Use `0xXXXXX` hex format. Ranges use `-`; multiple values use `, `.
- Each `<sku>` child represents a specific device ID variant:
  - `did`: PCI Device ID in `0xXXXX` hex. Ranges are supported (e.g., `0x7F00-0x7F1F`). Multiple values use commas.
  - `name`: Human-readable short name.
  - `code`: Uppercase platform code matching `platform` in `<configuration>`.
  - `longname`: Descriptive full name.

## `<pci>` — Integrated Devices

```xml
<pci>
  <device name="HOSTCTL" bus="0x00" dev="0x00" fun="0" did="0x4621,0x4660" config="HOSTCTL.hostctl1.xml">
    <subcomponent type="mmiobar" name="MCHBAR" register="MCHBAR" base_field="MCHBAR" size="0x8000" enable_bit="0" desc="Host Memory Mapped Register Range" config="MMIO.mmio0.xml"/>
  </device>
  <device name="SPI" vid="0x8086" did="0x7F24" config="SPI.spi0.xml"/>
</pci>
```

### `<device>` Attributes

- `name`: Uppercase functional name (e.g., `HOSTCTL`, `SPI`, `MEI1`, `IGD`). Should be unique within the file.
- `bus`/`dev`/`fun`: PCI address in hex (e.g., `bus="0x00" dev="0x1F" fun="5"`). Use when the address is fixed or DID is unknown.
- `vid`: PCI Vendor ID in `0xXXXX` hex. Use when matching by VID+DID instead of fixed address. Preferred.
- `did`: PCI Device ID in `0xXXXX` hex. Comma-separated and/or range notation (e.g., `did="0x7F30-0x7F47"`).
- `config`: Reference to a sub-config XML file in `Namespace.filename.xml` format (e.g., `SPI.spi0.xml`).

### `<subcomponent>` Attributes

Used to declare memory-mapped or I/O BARs owned by a device:

- `type`: `mmiobar` or `iobar`.
- `name`: Uppercase bar name (e.g., `MCHBAR`, `SPIBAR`).
- `register`: The register name (from `<registers>`) that holds the bar base address.
- `base_field`: The field name within that register containing the base address.
- `size`: Size of the mapped region in hex.
- `enable_bit` or `enable_field`: Bit position or field name that enables the bar.
- `offset`: Optional additional offset from the base address.
- `fixed_address`: Known physical address override (e.g., `fixed_address="0xFE000000"`).
- `desc`: Short human-readable description.
- `config`: Optional sub-config XML reference for the bar's registers.

## `<msr>` — MSR Definitions

```xml
<msr>
  <definition name="MSR" config="MSR.msr2.xml"/>
</msr>
```

References a shared MSR register definition file. The `name` attribute is `MSR` by convention.

## `<mmio>` — MMIO BARs (standalone)

Used in sub-config files (not typically in top-level platform files). For top-level, prefer referencing the BAR via a `<subcomponent>` element in the `<pci>` section:

```xml
<mmio>
  <bar name="SPIBAR" register="SPIBAR0" base_field="MEMBAR" size="0x1000" enable_bit="0" desc="SPI mmio Range"/>
</mmio>
```


## `<io>` — I/O BARs

Used in sub-config files (not typically in top-level platform files). For top-level, prefer referencing the BAR via a `<subcomponent>` element in the `<pci>` section:

```xml
<io>
  <definition name="IO" port="0xCF9" config="IO.io0.xml"/>
  <bar name="ABASE" register="ABASE" base_field="BA" size="0x100" fixed_address="0x1800" desc="ACPI Base Address" config="IO.acpi0.xml"/>
</io>
```

## `<memory>` — Memory Ranges

```xml
<memory>
  <range name="TPM" access="mmio" address="0xFED40000" limit="0xFED4FFFF" config="TPM.tpm12.xml"/>
  <range name="TXT" access="mmio" address="0xFED30000" limit="0xFED4FFFF" config="TPM.txt.xml"/>
</memory>
```

- `access`: `mmio` or `dram`.
- `address`: Start physical address in hex.
- `limit`: End physical address in hex (inclusive). Use `limit` instead of `size` when the end address is known.
- `config`: Optional reference to a sub-config XML defining the range's registers.

## `<registers>` — Configuration Registers

Used in sub-config files (not typically in top-level platform files).

```xml
<registers>
  <!-- pcicfg register -->
  <register name="BC" type="pcicfg" offset="0xDC" size="4" desc="BIOS Control">
    <field name="BIOSWE"  bit="0" size="1" desc="BIOS Write Enable"/>
    <field name="BLE"     bit="1" size="1" desc="BIOS Lock Enable"/>
    <field name="SMM_BWP" bit="5" size="1" desc="SMM BIOS Write Protection"/>
  </register>

  <!-- msr register -->
  <register name="IA32_FEATURE_CONTROL" type="msr" msr="0x3A" desc="Processor Feature Control">
    <field name="LOCK"              bit="0"  size="1" desc="Lock"/>
    <field name="EN_VMX_OUTSIDE_SMX" bit="2" size="1" desc="Enable VMX outside SMX operation"/>
  </register>

  <!-- mmio register -->
  <register name="HSFS" type="mmio" bar="SPIBAR" offset="0x04" size="4" desc="Hardware Sequencing Flash Status Register">
    <field name="FLOCKDN" bit="15" size="1" desc="Flash Configuration Lock-Down"/>
  </register>

  <!-- register with lockedby -->
  <register name="ROMPROTECT0" type="pcicfg" device="LPC" offset="0x050" size="4" lockedby="SpiHostAccessRomEn" desc="ROM Protect 0">
    <field name="WriteProtect" bit="10" size="1" desc="Write Protect"/>
  </register>
</registers>
```

### Register Attributes

- `name`: Uppercase or SCREAMING_SNAKE_CASE unique register name within the file scope.
- `type`: One of `pcicfg`, `mmcfg`, `msr`, `mmio`, `io`, `iobar`, `msgbus`, `mm_msgbus`, `indirect`.
- `desc`: Short human-readable description.
- `size`: Register width in bytes (e.g., `1`, `2`, `4`, `8`).
- `offset`: Register offset in hex from the device's base address (for `pcicfg`, `mmio`).
- `msr`: MSR address in hex (for `type="msr"`).
- `bar`: Named BAR from `<mmio>` that this register is offset from (for `type="mmio"`).
- `device`: Device `name` from `<pci>` this register belongs to (for `pcicfg` when device context is ambiguous).
- `lockedby`: Name of a lock (from `<locks>`) that controls write access to this register.
- `access`: Optional access type — one of `RW`, `RO`, `RW1C`, `RW0C`, `RW1S`, `RWS`, `RW-O`, `W1S`, `RW-L`.

### `<field>` Attributes

- `name`: Uppercase field name, unique within the register.
- `bit`: LSB position of the field (0-indexed).
- `size`: Width of the field in bits.
- `desc`: Short human-readable description.
- `access`: Optional per-field access type (same values as register `access`).
- `lockedby`: Optional lock name controlling this specific field (e.g., `lockedby="MPC.SRL"`).

## `<controls>` — Named Controls

Controls provide a semantic name for a specific register field used as a platform feature toggle:

```xml
<controls>
  <control name="SmmBiosWriteProtection" register="BC"  field="SMM_BWP" desc="SMM BIOS Write Protection"/>
  <control name="BiosLockEnable"         register="BC"  field="BLE"     desc="BIOS Lock Enable"/>
  <control name="BiosWriteEnable"        register="BC"  field="BIOSWE"  desc="BIOS Write Enable"/>
</controls>
```

- `name`: PascalCase descriptive name for the control.
- `register`: Name of the register (from `<registers>`) containing this control.
- `field`: Name of the field within that register.
- `desc`: Short human-readable description.

## `<locks>` — Named Locks

Locks represent write-once or lock-bit protected fields that signal a hardware security configuration is enforced:

```xml
<locks>
  <lock name="BiosInterfaceLockDown" register="BC"     field="BILD"    value="0x1" desc="BIOS Interface Lock-Down"/>
  <lock                              register="SATAGC" field="REGLOCK" value="0x1" type="RW/O" desc="RW/O Register"/>
</locks>
```

- `name`: Optional PascalCase descriptive name. Omit if the lock is purely a write-once hardware constraint without a semantic name.
- `register`: Name of the register containing the lock field.
- `field`: Name of the lock bit field.
- `value`: Hex value that indicates the lock is set (typically `0x1`).
- `type`: Optional access type qualifier (e.g., `RW/O` for write-once registers).
- `desc`: Short human-readable description.

## Numeric Values

- Always use lowercase hex with `0x` prefix: `0x1F`, `0xFED40000`, `0x8086`.
- Use hex for all addresses, offsets, masks, sizes, and IDs.
- Do not use decimal for hardware numeric values.

## Naming Conventions

- Platform codes: `UPPER_SNAKE_CASE` (e.g., `ADL`, `PCH_8XX`, `LNL`).
- Device names: `UPPER_SNAKE_CASE` (e.g., `HOSTCTL`, `P2SBC`, `MEI1`).
- Register names: `UPPER_SNAKE_CASE` (e.g., `IA32_FEATURE_CONTROL`, `HSFS`, `BC`).
- Field names: `UPPER_SNAKE_CASE` or short uppercase abbreviations (e.g., `LOCK`, `SMM_BWP`, `FLOCKDN`).
- Control names: `PascalCase` (e.g., `SmmBiosWriteProtection`, `BiosLockEnable`).
- Lock names: `PascalCase` when named (e.g., `BiosInterfaceLockDown`).
- Sub-config file references: `NAMESPACE.filename.xml` (e.g., `SPI.spi0.xml`, `HOSTCTL.hostctl1.xml`).

## Sub-Config Files

Detailed register definitions for individual devices are placed in separate sub-config XML files rather than the top-level platform file. This keeps platform files concise and allows definitions to be shared across platforms.

- Sub-config files contain a `<configuration>` root with no `platform` attribute.
- They may contain `<registers>`, `<mmio>`, `<io>`, `<controls>`, and `<locks>` sections.
- They are referenced via the `config` attribute on `<device>`, `<subcomponent>`, `<range>`, or `<bar>` elements.

## Comments

- Use XML comments (`<!-- -->`) for in-line notes about unverified values, disabled alternatives, or review reminders.
- When possible, add a comment including the source of the value being defined (e.g. datasheet document ID, datasheet page/section, register specification, or other authoritative reference) so that future reviewers can trace the origin of the definition. 
- Mark unreviewed definitions clearly:

```xml
<!-- Using default configuration files for devices. Need to verify registers once documentation is available. -->
```

