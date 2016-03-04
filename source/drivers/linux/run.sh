#!/bin/bash

a1="0x"`cat /proc/kallsyms | grep ' page_is_ram' | head -1 |cut -d ' ' -f 1`
if [ "$a1" == "0x" ]; then
	echo "Cannot find symbol 'page_is_ram'";
	exit;
fi

cat WARNING.txt

echo -n "Module: insmod chipsec.ko a1=$a1 : ";
insmod chipsec.ko a1="$a1" || exit;
chown root:root /dev/chipsec
chmod 600 /dev/chipsec
##############echo -n "Module: insmod chipsec.ko a1=$a1 : ";
##############insmod chipsec.ko a1="$a1" || exit;
echo "OK";
echo -n "Device: "; sleep 1;ls /dev/chipsec
