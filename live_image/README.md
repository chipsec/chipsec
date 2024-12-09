Requirements:

- mkosi (tested with v22 and v24.3): https://github.com/systemd/mkosi
- a Linux distribution with the requirements for mkosi, ie. Python and a package manager (tested with Fedora 41)

How to build:

```
cd live_image/
mkosi genkey
mkosi build
# test boot in a VM
mkosi qemu
# burn to usb key - check first the device name with `lsblk`
sudo mkosi burn /dev/sdX
```

How to use:

- disable Secure Boot on the machine under test (or put it in Setup Mode, or import /ESP/loader/keys/auto/db.auth)
- boot on the USB key
- you can boot to a UEFI Shell and use the UEFI version of chipsec (not recommended)
- or you can boot to Linux and run `chipsec_main` or `chipsec_util`
- you can change keyboard layout with `loadkeys`

TODO:

- write proper documentation
- make partition grow on first boot to use the full disk space (with custom repartd configuration in mkosi.extra)
- add useful packages
- rebuild Python UEFI instead of using the version bundled with chipsec?
