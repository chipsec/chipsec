#!/usr/bin/env python3
# CHIPSEC: Platform Security Assessment Framework
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
"""Launch a QEMU virtual machine with a UEFI Shell and chipsec

This scripts uses the UEFI Shell provided by OVMF firmware. Therefore it
requires both QEMU (for x86_64 system emulation) and OVMF to be installed.
It also requires qemu-img, to create a temporary boot disk.

On Debian and Ubuntu, installing these requirements can be done with:

    sudo apt install ovmf qemu-system-x86 qemu-utils

Usage examples:

    # Run chipsec_main.py in the default QEMU virtual machine
    qemu_efi.py -m

    # Enumerate PCI devices of the virtual machine (like command "pci" of UEFI shell)
    qemu_efi.py -u pci enumerate

    # Launch a Python interpreter where it is possible to import chipsec and edk2
    qemu_efi.py -p

    # Launch an interactive UEFI shell (no auto-run command)
    qemu_efi.py

    # Reuse an existing disk image (skip rebuild)
    qemu_efi.py --reuse-disk /tmp/efidisk_xyz/disk.qcow2 -m

    # Force rebuild the disk even if one already exists
    qemu_efi.py --rebuild -m

    # Use the Q35 machine type (default is i440fx / 'pc')
    qemu_efi.py -M q35 -m

    # Use Q35 with SMM enabled
    qemu_efi.py -M q35,smm=on -m

Keys (in -nographic mode):
    Ctrl-A X    quit QEMU
    Ctrl-A H    QEMU monitor help
"""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile


CHIPSEC_BASE = Path(__file__).parent / ".."
PYTHON_INSTALL_ZIP = CHIPSEC_BASE / "__install__" / "UEFI" / "chipsec_py368_uefi_x64.zip"
PYTHON_EFI_COMMAND = "python.efi"

OVMF_CODE_LOCATIONS = (
    # Arch Linux https://archlinux.org/packages/extra/any/edk2-ovmf/
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    # Debian https://packages.debian.org/fr/sid/all/ovmf/filelist
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    # Fedora https://fedora.pkgs.org/35/fedora-updates-x86_64/edk2-ovmf-20211126gitbb1bba3d7767-1.fc35.noarch.rpm.html
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    # Fallback
    "/usr/share/qemu/OVMF.fd",
)

OVMF_VARS_LOCATIONS = (
    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
    "/usr/share/edk2/ovmf/OVMF_VARS.fd",
)

INTERACTIVE_NSH = """\
@echo -off
echo ========================================
echo  CHIPSEC interactive UEFI shell
echo ========================================
echo.
echo Chipsec is mounted at fs0:\\chipsec
echo Python is at python.efi
echo.
echo Example commands:
echo   python.efi chipsec_main.py
echo   python.efi chipsec_util.py
echo.
echo Type 'reset' to exit QEMU
echo To quit QEMU press Ctrl-A then X
echo ========================================
fs0:
cd chipsec
"""


def create_efi_disk(filename, startup_nsh=None):
    """Create a disk bootable through UEFI with chipsec

    This function copies all needed files to a temporary directory and uses
    qemu-img to convert this directory into a FAT partition.
    """
    with tempfile.TemporaryDirectory(prefix="efidisk_") as tmpdir:
        # Unzip Python into the temporary directory
        print("Extracting {} to {} ...".format(PYTHON_INSTALL_ZIP.name, tmpdir))
        with zipfile.ZipFile(PYTHON_INSTALL_ZIP) as python_zip:
            python_zip.extractall(tmpdir)

        # Copy Chipsec
        print("Copying chipsec to {} ...".format(tmpdir))
        for extension in (".py", ".xml", ".xsd", ".ini", ".json"):
            for filepath in CHIPSEC_BASE.glob("**/*" + extension):
                rel = filepath.relative_to(CHIPSEC_BASE)
                if rel.parts[0] in ("tests", "docs", "drivers", "scripts", "logs"):
                    continue
                destination = Path(tmpdir) / "chipsec" / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(filepath, destination)

        # Create startup.nsh
        if startup_nsh:
            with (Path(tmpdir) / "startup.nsh").open("w") as f:
                f.write(startup_nsh)

        # Convert to QCow image
        print("Converting to QCow2 format in {} ...".format(filename))
        subprocess.run(
            ("qemu-img", "convert", "-c", "-f", "vvfat", "-O", "qcow2", "fat:" + tmpdir, filename),
            check=True
        )


def unescape_arguments(args):
    """Replace " -" with "-" in the arguments"""
    return [arg[1:] if arg.startswith(" -") else arg for arg in args]


def _find_ovmf_vars(ovmf_code_path=None):
    """Locate the writable OVMF variable store (VARS) template."""
    ovmf_env = os.environ.get('OVMF_VARS')
    if ovmf_env and Path(ovmf_env).exists():
        return ovmf_env
    if ovmf_code_path:
        candidate = ovmf_code_path.replace('OVMF_CODE', 'OVMF_VARS')
        if candidate != ovmf_code_path and Path(candidate).exists():
            return candidate
    for path in OVMF_VARS_LOCATIONS:
        if Path(path).exists():
            return path
    return None


def main():
    parser = argparse.ArgumentParser(description="Launch a QEMU virtual machine with a UEFI Shell and chipsec")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-m", "--main", nargs="*", type=str,
                       help="start chipsec_main.py, optionally with some arguments")
    group.add_argument("-p", "--python", nargs="*", type=str,
                       help="start a Python-UEFI shell, optionally with some arguments")
    group.add_argument("-u", "--util", nargs="+", type=str,
                       help="start chipsec_util.py, with some arguments (use ' -' to escape the dash prefix)")
    parser.add_argument("--ovmf", type=str,
                        help="path to the OVMF firmware code")
    parser.add_argument("--memory", type=str, default="512M",
                        help="set the RAM size of the virtual machine (QEMU option -m)")
    parser.add_argument("-g", "--gui", action="store_true",
                        help="use QEMU graphics window")
    parser.add_argument("-H", "--host-cpu", action="store_true",
                        help="use host CPU")
    parser.add_argument("-M", "--machine", type=str,
                        help="specify QEMU machine ('pc', 'q35,smm=on'...)")
    parser.add_argument("-Q", "--qemu-arg", nargs="+", type=str,
                        help="specify additional QEMU arguments (use ' -' to escape the dash prefix)")
    parser.add_argument("--reuse-disk", metavar="PATH", type=str,
                        help="path to an existing disk image to boot (skip build)")
    parser.add_argument("--rebuild", action="store_true",
                        help="force-rebuild the disk image even if one already exists")
    parser.add_argument("--work-dir", metavar="DIR", type=str,
                        help="directory for the disk image (default: auto-created temp dir)")
    args = parser.parse_args()

    ovmf_path = args.ovmf
    if not ovmf_path:
        for test_ovmf_path in OVMF_CODE_LOCATIONS:
            if Path(test_ovmf_path).exists():
                ovmf_path = test_ovmf_path
                break
        if not ovmf_path:
            print("No OVMF file found. You can specify one using option --ovmf.", file=sys.stderr)
            sys.exit(1)

    # Create startup.nsh
    start_cmd = None
    if args.main is not None:
        start_cmd = [PYTHON_EFI_COMMAND, "chipsec_main.py"] + unescape_arguments(args.main)
    elif args.python is not None:
        start_cmd = [PYTHON_EFI_COMMAND] + unescape_arguments(args.python)
    elif args.util is not None:
        start_cmd = [PYTHON_EFI_COMMAND, "chipsec_util.py"] + unescape_arguments(args.util)

    if start_cmd:
        startup_nsh = "fs0:\ncd chipsec\n" + " ".join(shlex.quote(arg) for arg in start_cmd) + "\nreset\n"
    else:
        startup_nsh = INTERACTIVE_NSH

    # Locate OVMF VARS for split CODE/VARS firmware
    vars_template = _find_ovmf_vars(ovmf_path)
    vars_copy = None
    if vars_template:
        fd, vars_copy = tempfile.mkstemp(prefix="ovmf_vars_", suffix=".fd")
        os.close(fd)
        shutil.copy2(vars_template, vars_copy)

    qemu_cmd = [
        "qemu-system-x86_64",
        # Make OVMF boot directly in UEFI shell instead of trying network boot (PXE)
        "-nic", "none",
        # Enable exiting by entering "reset" in UEFI shell
        "-no-reboot",
        # Start OVMF
        "-drive", "if=pflash,format=raw,readonly=on,file=" + ovmf_path,
    ]
    if vars_copy:
        qemu_cmd += ["-drive", "if=pflash,format=raw,file=" + vars_copy]

    if not args.gui:
        qemu_cmd += ["-nographic"]

    if args.memory:
        qemu_cmd += ["-m", args.memory]

    if args.host_cpu:
        qemu_cmd += ["-cpu", "host", "-enable-kvm"]
    else:
        qemu_cmd += ["-cpu", "qemu64,vendor=GenuineIntel"]

    if args.machine:
        qemu_cmd += ["-machine", args.machine]

    if args.qemu_arg:
        qemu_cmd += unescape_arguments(args.qemu_arg)

    # Determine disk path based on lifecycle options
    try:
        if args.reuse_disk:
            disk_path = args.reuse_disk
            if not os.path.exists(disk_path):
                print("ERROR: disk image not found: {}".format(disk_path), file=sys.stderr)
                sys.exit(1)
            print("Reusing existing disk image: {}".format(disk_path))
            qemu_cmd += ["-drive", "format=qcow2,file=" + disk_path]

            print("Launching {}".format(" ".join(qemu_cmd)))
            subprocess.run(qemu_cmd, check=True)

        elif args.work_dir:
            os.makedirs(args.work_dir, exist_ok=True)
            disk_path = os.path.join(args.work_dir, "chipsec_uefi.qcow2")
            if os.path.exists(disk_path) and not args.rebuild:
                print("Disk image already exists: {}".format(disk_path))
                print("  (use --rebuild to force recreation)")
            else:
                create_efi_disk(disk_path, startup_nsh)

            qemu_cmd += ["-drive", "format=qcow2,file=" + disk_path]

            print("Launching {}".format(" ".join(qemu_cmd)))
            subprocess.run(qemu_cmd, check=True)

        else:
            # Default: ephemeral disk in a temporary file
            with tempfile.NamedTemporaryFile(prefix="efidisk_", suffix=".qcow2") as tmpdisk:
                create_efi_disk(tmpdisk.name, startup_nsh)
                qemu_cmd += ["-drive", "format=qcow2,file=" + tmpdisk.name]

                print("Launching {}".format(" ".join(qemu_cmd)))
                subprocess.run(qemu_cmd, check=True)
    finally:
        if vars_copy and os.path.exists(vars_copy):
            os.unlink(vars_copy)


if __name__ == "__main__":
    main()
