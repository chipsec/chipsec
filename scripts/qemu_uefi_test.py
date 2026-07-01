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
"""Test chipsec_main.py execution in QEMU UEFI shell.

This test creates a FAT32 virtual drive, populates it with the UEFI Python
interpreter and chipsec source, boots QEMU with OVMF firmware, runs
chipsec_main.py via startup.nsh, and verifies that the resulting logs
contain no fatal errors.

Requirements (install via apt on Ubuntu):
    sudo apt install ovmf qemu-system-x86 mtools dosfstools

Usage:
    # Run directly (defaults to the i440fx "pc" machine)
    python scripts/qemu_uefi_test.py

    # Run against the QEMU Q35 machine / CHIPSEC Q35 config
    python scripts/qemu_uefi_test.py --platform q35

    # Run via pytest (skips if dependencies are missing)
    pytest scripts/qemu_uefi_test.py -v
"""
import argparse
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request
import zipfile
from pathlib import Path

CHIPSEC_BASE = Path(__file__).resolve().parent.parent
PYTHON_INSTALL_ZIP = CHIPSEC_BASE / '__install__' / 'UEFI' / 'chipsec_py368_uefi_x64.zip'
DISK_SIZE_MB = 512
QEMU_TIMEOUT_SECONDS = 300

# Prebuilt UEFI Shell used as the disk's fallback boot loader
# (\EFI\BOOT\BOOTX64.EFI). OVMF's default boot path launches it automatically,
# and the shell then auto-runs fs0:\startup.nsh. Cached locally after the first
# download so the test can run offline afterwards. The SHA256 is pinned so the
# binary is verified before it is ever used.
SHELL_EFI_URL = ('https://raw.githubusercontent.com/tianocore/edk2/'
                 'UDK2018/ShellBinPkg/UefiShell/X64/Shell.efi')
SHELL_EFI_SHA256 = '04c89f19efee2a22660fd4650ff9add88e962d102b1b713e535f4e32a07c5185'
SHELL_EFI_CACHE = CHIPSEC_BASE / '__install__' / 'UEFI' / 'Shell.efi'

OVMF_CODE_LOCATIONS = (
    '/usr/share/edk2-ovmf/x64/OVMF_CODE.fd',
    '/usr/share/OVMF/OVMF_CODE_4M.fd',
    '/usr/share/OVMF/OVMF_CODE.fd',
    '/usr/share/edk2/ovmf/OVMF_CODE.fd',
    '/usr/share/qemu/OVMF.fd',
)

OVMF_VARS_LOCATIONS = (
    '/usr/share/edk2-ovmf/x64/OVMF_VARS.fd',
    '/usr/share/OVMF/OVMF_VARS_4M.fd',
    '/usr/share/OVMF/OVMF_VARS.fd',
    '/usr/share/edk2/ovmf/OVMF_VARS.fd',
)

# Supported QEMU machine configurations. Each entry maps a friendly platform
# name (used by --platform) to the CHIPSEC platform code passed to
# chipsec_main.py and the matching QEMU '-machine' type.
PLATFORMS = {
    'i440fx': {'machine': 'pc'},
    'q35': {'machine': 'q35'},
}
DEFAULT_PLATFORM = 'i440fx'


def build_startup_nsh():
    """Return the startup.nsh contents that run chipsec_main for a platform."""
    return (
        '@echo -off\n'
        'fs0:\n'
        'cd chipsec\n'
        f'\\efi\\Tools\\Python.efi chipsec_main.py -vv\n'
        'reset\n'
    )


def _find_ovmf():
    """Locate OVMF firmware on the system."""
    ovmf_env = os.environ.get('OVMF_CODE')
    if ovmf_env and Path(ovmf_env).exists():
        return ovmf_env
    for path in OVMF_CODE_LOCATIONS:
        if Path(path).exists():
            return path
    return None


def _find_ovmf_vars(ovmf_code_path=None):
    """Locate the writable OVMF variable store (VARS) template.

    Prefers the VARS file that matches the selected CODE file (e.g. the 4M
    split build) before falling back to the known search locations.
    """
    ovmf_env = os.environ.get('OVMF_VARS')
    if ovmf_env and Path(ovmf_env).exists():
        return ovmf_env
    # Try to derive the VARS path from the CODE path (CODE -> VARS).
    if ovmf_code_path:
        candidate = ovmf_code_path.replace('OVMF_CODE', 'OVMF_VARS')
        if candidate != ovmf_code_path and Path(candidate).exists():
            return candidate
    for path in OVMF_VARS_LOCATIONS:
        if Path(path).exists():
            return path
    return None


def _get_uefi_shell():
    """Return a path to a UEFI Shell binary, downloading and caching it once.

    The shell is placed on the disk as the default boot loader so OVMF boots
    it without manual Boot Manager interaction. The binary is verified against
    the pinned SHA256 both when freshly downloaded and when reused from cache;
    a mismatch is treated as a hard error.
    """
    # Reuse the cache only if it still matches the pinned hash.
    if SHELL_EFI_CACHE.exists() and SHELL_EFI_CACHE.stat().st_size > 0:
        cached_digest = hashlib.sha256(SHELL_EFI_CACHE.read_bytes()).hexdigest()
        if cached_digest == SHELL_EFI_SHA256:
            return SHELL_EFI_CACHE
        print(f'WARNING: cached UEFI Shell SHA256 mismatch (got {cached_digest}); '
              're-downloading.')

    print(f'Downloading UEFI Shell from {SHELL_EFI_URL}')
    SHELL_EFI_CACHE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix='shell_', suffix='.efi',
                                    dir=str(SHELL_EFI_CACHE.parent))
    os.close(fd)
    try:
        with urllib.request.urlopen(SHELL_EFI_URL) as resp:
            data = resp.read()
        # Sanity check: UEFI applications are PE binaries starting with 'MZ'.
        if data[:2] != b'MZ':
            raise ValueError('Downloaded shell is not a PE/EFI binary')
        # Verify the pinned SHA256 before trusting the binary.
        digest = hashlib.sha256(data).hexdigest()
        if digest != SHELL_EFI_SHA256:
            raise ValueError(
                f'UEFI Shell SHA256 mismatch: expected {SHELL_EFI_SHA256}, got {digest}')
        with open(tmp_path, 'wb') as f:
            f.write(data)
        os.replace(tmp_path, str(SHELL_EFI_CACHE))
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    print(f'Cached verified UEFI Shell at {SHELL_EFI_CACHE}')
    return SHELL_EFI_CACHE


def _check_command(cmd):
    """Return True if a command is available on PATH."""
    return shutil.which(cmd) is not None


def _run(cmd, **kwargs):
    """Run a subprocess command, raising on failure."""
    print(f'+ {" ".join(cmd)}')
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        print(f'STDOUT: {result.stdout}')
        print(f'STDERR: {result.stderr}')
        result.check_returncode()
    return result


def create_virtual_drive(disk_path, chipsec_base, startup_nsh):
    """Create a FAT32 virtual drive image populated with chipsec and UEFI Python.

    Steps:
        1. Create a zeroed disk image file
        2. Format as FAT32 using mkfs.fat
        3. Extract UEFI Python zip into /EFI/ on the disk
        4. Copy chipsec source files into /chipsec/ on the disk
        5. Write startup.nsh to the disk root
    """
    disk_path = str(disk_path)

    # Step 1: Create disk image
    print(f'Creating {DISK_SIZE_MB}MB disk image: {disk_path}')
    _run(['dd', 'if=/dev/zero', f'of={disk_path}',
          'bs=1M', f'count={DISK_SIZE_MB}', 'status=none'])

    # Step 2: Format as FAT32
    print('Formatting as FAT32...')
    _run(['mkfs.fat', '-F', '32', '-n', 'CHIPSEC', disk_path])

    # Step 3: Extract UEFI Python zip
    print('Extracting UEFI Python to virtual drive...')
    with tempfile.TemporaryDirectory(prefix='uefi_extract_') as extract_dir:
        with zipfile.ZipFile(str(PYTHON_INSTALL_ZIP)) as zf:
            zf.extractall(extract_dir)

        # Create EFI directories on disk
        _run(['mmd', '-i', disk_path, '::/EFI'])
        _run(['mmd', '-i', disk_path, '::/EFI/StdLib'])
        _run(['mmd', '-i', disk_path, '::/EFI/Tools'])

        # Copy EFI/Tools
        tools_dir = os.path.join(extract_dir, 'EFI', 'Tools')
        if os.path.isdir(tools_dir):
            _run(['mcopy', '-i', disk_path, '-s',
                  os.path.join(tools_dir, '.'), '::/EFI/Tools'])

        # Copy EFI/StdLib
        stdlib_dir = os.path.join(extract_dir, 'EFI', 'StdLib')
        if os.path.isdir(stdlib_dir):
            _run(['mcopy', '-i', disk_path, '-s',
                  os.path.join(stdlib_dir, '.'), '::/EFI/StdLib'])

    # Step 4: Copy chipsec files
    print('Copying chipsec source files to virtual drive...')
    _run(['mmd', '-i', disk_path, '::/chipsec'])
    _run(['mmd', '-i', disk_path, '::/chipsec/logs'])

    with tempfile.TemporaryDirectory(prefix='chipsec_stage_') as stage_dir:
        # Copy relevant chipsec files to staging directory
        extensions = ('.py', '.xml', '.xsd', '.ini', '.json')
        for ext in extensions:
            for filepath in chipsec_base.rglob(f'*{ext}'):
                # Skip test files, docs, and hidden directories
                rel = filepath.relative_to(chipsec_base)
                parts = rel.parts
                if any(p.startswith('.') for p in parts):
                    continue
                if parts[0] in ('tests', 'docs', 'drivers', 'scripts', 'logs'):
                    continue
                dest = Path(stage_dir) / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(filepath), str(dest))

        # Copy VERSION file
        version_file = chipsec_base / 'chipsec' / 'VERSION'
        if version_file.exists():
            dest = Path(stage_dir) / 'chipsec' / 'VERSION'
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(version_file), str(dest))

        # Use mcopy to copy staged files into disk
        _run(['mcopy', '-i', disk_path, '-s',
              os.path.join(stage_dir, '.'), '::/chipsec'])

    # Step 5: Write startup.nsh
    print('Writing startup.nsh...')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.nsh', delete=False) as f:
        f.write(startup_nsh)
        nsh_path = f.name
    try:
        _run(['mcopy', '-i', disk_path, nsh_path, '::/startup.nsh'])
    finally:
        os.unlink(nsh_path)

    # Step 6: Install the UEFI Shell as the fallback boot loader so OVMF boots
    # it automatically (\EFI\BOOT\BOOTX64.EFI), which then runs startup.nsh.
    print('Installing UEFI Shell as fallback boot loader...')
    shell_path = _get_uefi_shell()
    _run(['mmd', '-i', disk_path, '::/EFI/BOOT'])
    _run(['mcopy', '-i', disk_path, str(shell_path), '::/EFI/BOOT/BOOTX64.EFI'])

    print(f'Virtual drive created successfully: {disk_path}')


def run_qemu(disk_path, ovmf_path, machine=None, timeout=QEMU_TIMEOUT_SECONDS):
    """Start QEMU with UEFI shell support and the virtual drive.

    Streams the serial console to stdout in real time so progress can be
    tracked, while capturing the full output for later verification.

    ``machine`` selects the QEMU '-machine' type (e.g. 'pc' or 'q35'); when
    omitted QEMU uses its built-in default.

    Returns a CompletedProcess with the captured console in ``stdout``.
    """
    # The internal UEFI Shell in OVMF can only boot (and auto-run
    # startup.nsh) when a writable variable store is present. Split CODE/VARS
    # builds (e.g. the 4M firmware) require the matching VARS pflash unit, so
    # make a writable copy of the VARS template for this run.
    vars_template = _find_ovmf_vars(ovmf_path)
    vars_copy = None
    if vars_template:
        fd, vars_copy = tempfile.mkstemp(prefix='ovmf_vars_', suffix='.fd')
        os.close(fd)
        shutil.copy2(vars_template, vars_copy)
    else:
        print('WARNING: OVMF VARS template not found; the UEFI shell may not '
              'boot. Set the OVMF_VARS environment variable to the VARS file.')

    qemu_cmd = [
        'qemu-system-x86_64',
        '-drive', f'if=pflash,format=raw,readonly=on,file={ovmf_path}',
        '-cpu', 'qemu64,vendor=GenuineIntel',
    ]
    if machine:
        qemu_cmd += ['-machine', machine]
    if vars_copy:
        qemu_cmd += ['-drive', f'if=pflash,format=raw,file={vars_copy}']
    qemu_cmd += [
        '-drive', f'format=raw,file={disk_path}',
        '-nic', 'none',
        '-no-reboot',
        '-nographic',
        '-m', '512M',
    ]
    print(f'Launching QEMU: {" ".join(qemu_cmd)}')
    print('=== QEMU CONSOLE (live) ===', flush=True)

    # Merge stderr into stdout so the serial console can be streamed as a
    # single line-buffered stream while the guest is running.
    proc = subprocess.Popen(
        qemu_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    # Watchdog: kill QEMU if it exceeds the timeout, even if it produces no
    # further output (which would otherwise block the readline loop forever).
    timed_out = {'value': False}

    def _kill_on_timeout():
        timed_out['value'] = True
        proc.kill()

    watchdog = threading.Timer(timeout, _kill_on_timeout)
    watchdog.start()

    captured = []
    try:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            captured.append(line)
        proc.wait()
    finally:
        watchdog.cancel()
        if proc.stdout:
            proc.stdout.close()
        if vars_copy and os.path.exists(vars_copy):
            os.unlink(vars_copy)

    if timed_out['value']:
        print(f'=== QEMU TIMED OUT after {timeout}s ===')
    print(f'QEMU exited with code: {proc.returncode}')

    return subprocess.CompletedProcess(
        qemu_cmd, proc.returncode, stdout=''.join(captured), stderr='')


def extract_logs(disk_path, output_dir):
    """Extract log files from the virtual drive after QEMU execution."""
    output_dir = str(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    # List the logs directory on disk
    result = subprocess.run(
        ['mdir', '-i', disk_path, '::/chipsec/logs'],
        capture_output=True, text=True,
    )
    print('Log directory listing:')
    print(result.stdout)
    # Copy all log files out
    subprocess.run(
        ['mcopy', '-i', disk_path, '-s', '::/chipsec/logs/.', output_dir],
        capture_output=True, text=True,
    )
    return output_dir


def verify_logs(log_dir, console_output):
    """Verify no errors occurred in chipsec logs or console output.

    Returns a list of error strings found. Empty list means success.
    """
    errors = []

    # Check console output for Python/UEFI fatal errors
    fatal_patterns = [
        'Traceback (most recent call last)',
        'FATAL ERROR',
        'Python.efi: not found',
        'chipsec_main.py: not found',
        'Exception occurred during',
    ]
    if console_output:
        for pattern in fatal_patterns:
            if pattern in console_output:
                errors.append(f'Console output contains: {pattern}')                    # Check log files in the output directory. mcopy preserves the source
    # directory, so files land under <log_dir>/logs/*.log; search recursively.
    log_files = glob.glob(os.path.join(log_dir, '**', '*.log'), recursive=True)
    if not log_files:
        # If no log files, check console output for evidence of successful execution
        if console_output and 'chipsec' in console_output.lower():
            print('WARNING: No log files found on disk, but chipsec output detected in console.')
        else:
            errors.append(f'No log files found in {log_dir} and no chipsec output in console')
        return errors

    for log_file in log_files:
        print(f'Checking log file: {log_file}')
        with open(log_file, 'r', errors='replace') as f:
            content = f.read()
        # Check for Python exceptions in log
        if 'Traceback (most recent call last)' in content:
            errors.append(f'Python traceback found in {os.path.basename(log_file)}')
        if 'EXCEPTION' in content:
            errors.append(f'EXCEPTION found in {os.path.basename(log_file)}')
            # Check for module errors (import or run failures)
        for line in content.splitlines():
            if 'Exception occurred during' in line:
                errors.append(f'Module error in {os.path.basename(log_file)}: {line.strip()}')

    return errors


def _dependencies_available():
    """Check if all required tools are available."""
    required = ['qemu-system-x86_64', 'mkfs.fat', 'mtools', 'mcopy', 'mmd', 'mdir', 'dd']
    missing = [cmd for cmd in required if not _check_command(cmd)]
    if missing:
        return False, f'Missing commands: {", ".join(missing)}'
    ovmf = _find_ovmf()
    if not ovmf:
        return False, 'OVMF firmware not found'
    if not PYTHON_INSTALL_ZIP.exists():
        return False, f'UEFI Python zip not found: {PYTHON_INSTALL_ZIP}'
    return True, ''


# --- standalone execution ---

def main():
    """Run the QEMU UEFI test standalone."""
    parser = argparse.ArgumentParser(
        description='Run chipsec_main.py in a QEMU UEFI shell and verify the logs.')
    parser.add_argument('-p', '--platform', choices=sorted(PLATFORMS),
                        default=DEFAULT_PLATFORM,
                        help='platform/machine to test (default: %(default)s)')
    parser.add_argument('-M', '--machine', type=str, default=None,
                        help="override the QEMU '-machine' type for the "
                             "selected platform (e.g. 'q35,smm=on')")
    args = parser.parse_args()

    platform = PLATFORMS[args.platform]
    machine = args.machine or platform['machine']

    deps_ok, reason = _dependencies_available()
    if not deps_ok:
        print(f'ERROR: {reason}', file=sys.stderr)
        sys.exit(1)

    ovmf_path = _find_ovmf()

    # Use a persistent directory so CI (e.g. GitHub Actions) can upload logs
    # after the script exits.  The directory is NOT auto-deleted.
    work_dir = tempfile.mkdtemp(prefix='qemu_uefi_test_')
    print(f'Working directory: {work_dir}')
    disk_path = os.path.join(work_dir, 'chipsec_uefi.img')
    log_output_dir = os.path.join(work_dir, 'logs')

    startup_nsh = build_startup_nsh()
    create_virtual_drive(disk_path, CHIPSEC_BASE, startup_nsh)
    result = run_qemu(disk_path, ovmf_path, machine=machine)
    extract_logs(disk_path, log_output_dir)

    console_output = (result.stdout or '') + (result.stderr or '')
    errors = verify_logs(log_output_dir, console_output)

    if errors:
        print('\nTEST FAILED with errors:')
        for err in errors:
            print(f'  - {err}')
        sys.exit(1)
    else:
        print('\nTEST PASSED: chipsec_main.py ran successfully in QEMU UEFI shell.')


if __name__ == '__main__':
    main()
