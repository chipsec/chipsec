.. _Configuration-Files:

Configuration Files
===================

CHIPSEC configuration maps platform and device identities to register,
field, control and BAR definitions. Platform files are stored under
``chipsec/cfg/<vendor-id>/``; reusable definitions are grouped into XML
fragments under the same directory. Platform detection selects the platform
files, whose device entries refer to those fragments with ``config``.

For example, ``chipsec/cfg/8086/kbl.xml`` selects a configuration fragment
for the SPI device:

.. code-block:: xml

    <pci>
       <device name="SPI" bus="0x00" dev="0x1F" fun="5"
                   config="SPI.spi0.xml" />
    </pci>

The referenced ``chipsec/cfg/8086/SPI/spi0.xml`` contains the register and
control definitions:

.. code-block:: xml

    <configuration>
       <registers>
          <register name="BC" type="pcicfg" offset="0xDC" size="4"
                         desc="BIOS Control">
             <field name="BLE" bit="1" size="1" desc="BIOS Lock Enable" />
          </register>
       </registers>
       <controls>
          <control name="BiosLockEnable" register="BC" field="BLE"
                        desc="BIOS Lock Enable" />
       </controls>
    </configuration>

The platform XML is parsed for device and other platform configuration
sections; register, control and lock definitions belong in referenced
configuration fragments. Placing those sections directly in a platform XML
does not load them in the current configuration pipeline. Follow a nearby
platform and its referenced fragments when adding definitions.

List of Cfg components
----------------------

.. toctree::

   ../modules/chipsec.cfg.8086.rst
