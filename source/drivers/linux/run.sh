#!/bin/bash

a1="0x"`cat /proc/kallsyms | grep ' page_is_ram' | head -1 |cut -d ' ' -f 1`
if [ "$a1" == "0x" ]; then
	echo "Cannot find symbol 'page_is_ram'";
	exit;
fi

# note: these may not be found, due to lack of CONFIG_PCI...
a2="0x"`cat /proc/kallsyms | grep ' raw_pci_read' | head -1 |cut -d ' ' -f 1`
if [ "$a2" == "0x" ]; then
	a2="0"
fi
a3="0x"`cat /proc/kallsyms | grep ' raw_pci_write' | head -1 |cut -d ' ' -f 1`
if [ "$a3" == "0x" ]; then
	a3="0"
fi

cat WARNING.txt

echo -n "Module: insmod chipsec.ko a1=$a1 a2=$a2 a3=$a3 : ";
insmod chipsec.ko a1="$a1" a2="$a2" a3="$a3" || exit;
chown root:root /dev/chipsec
chmod 600 /dev/chipsec
##############echo -n "Module: insmod chipsec.ko a1=$a1 : ";
##############insmod chipsec.ko a1="$a1" || exit;
echo "OK";
echo -n "Device: "; sleep 1;ls /dev/chipsec
