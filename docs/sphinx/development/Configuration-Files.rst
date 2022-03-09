.. _Configuration-Files:

Configuration Files
===================

Provide a human readable abstraction for registers in the system

    ==================================== ================================================
    ``chipsec/cfg/8086``                   platform specific configuration xml files
    ``chipsec/cfg/8086/common.xml``        common configuration
    ``chipsec/cfg/8086/<platform>.xml``    configuration for a specific <platform>
    ==================================== ================================================

Broken into common and platform specific configuration files.

Used to define controls, registers and bit fields.

Common files always loaded first so the platform files can override values.

Correct platform configuration files loaded based off of platform detection.

Configuration File Example
--------------------------

.. code-block:: xml

   <mmio>
   <bar name="SPIBAR" bus="0" dev="0x1F" fun="5" reg="0x10" width="4" mask="0xFFFFF000" size="0x1000" desc="SPI Controller Register Range" offset="0x0"/>
   </mmio>
   <registers>
   <register name="BC" type="pcicfg" bus="0" dev="0x1F" fun="5" offset="0xDC" size="4" desc="BIOS Control">
   <field name="BIOSWE" bit="0" size="1" desc="BIOS Write Enable" />
   …
   <field name="BILD" bit="7" size="1" desc="BIOS Interface Lock Down"/>
   </register>
   </registers>
   <controls>
   <control name="BiosInterfaceLockDown" register="BC" field="BILD" desc="BIOS Interface Lock-Down"/>
   </controls>

List of Cfg components
----------------------

.. toctree::

   ../modules/chipsec.cfg.8086.rst
