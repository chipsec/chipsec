.. _Windows-Exceptions:

Windows Exception Errors
========================

Windows exception errors have many different causes and at least as many possible solutions.
The below 'fixes' may need to be used in combination to fix any of these issues.


STATUS_PRIVILEGED_INSTRUCTION (0xC0000096)
------------------------------------------

This type of error often occurs on newer Windows OSes, often caused by the Windows `Device Guard` feature.
THIS IS A KNOWN ISSUE WITH WINDOWS AND NOT A CHIPSEC BUG.

For CHIPSEC to work, the Windows `Device Guard` feature needs to be disabled.

Example errors:

::

  ERROR: HW Access Violation: DeviceIoControl returned STATUS_PRIVILEGED_INSTRUCTION (0xC0000096)

  chipsec.helper.oshelper.HWAccessViolationError: HW Access Violation: DeviceIoControl returned STATUS_PRIVILEGED_INSTRUCTION (0xC0000096)


**Device Guard and Credential Guard hardware readiness tool**

`Device Guard and Credential Guard hardware readiness tool <https://www.microsoft.com/en-us/download/details.aspx?id=53337>`_

Steps to disable Device Guard:
  #. Download the Microsoft `Device Guard and Credential Guard hardware readiness tool`
  #. Extract zip contents
  #. Run this command (via PowerShell): ``DG_Readiness.ps1 -Disable``
  #. Reboot system and press **<F3>** when prompted (twice)
  #. May take several reboots before finishing

.. note::

  Microsoft seems to no longer use “Device Guard”, instead now uses WDAC (Windows Defender Application Control).


**If the readiness tool doesn't work...**

Workaround:

1. Launch `Local Group Policy Editor`

  a. Run -> ``gpedit.msc``

2. Change `Device Guard` setting to `Disabled`

  a. Computer Configuration > Administrative Templates > System > Device Guard
  b. Switch `Device Guard` from "Not Configured" to "Disabled"

3. Save changes and exit `Group Policy Editor`

  4. Reboot

.. note::

  Windows Home version may NOT have `Group Policy Editor` loaded by default.


**Windows Home workaround:**

There is no guarantee that these steps will work.  If they don't, it is recommended to use `Windows Pro` or `Windows Enterprise` versions that include the `Group Policy Editor`.

1. From a Windows PowerShell, `Run as Administrator`, run these commands sequentially:

::

  FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (
  DISM /Online /NoRestart /Add-Package:"%F"
  )

  FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (
  DISM /Online /NoRestart /Add-Package:"%F"
  )

2. After these commands complete, reboot the system.  The `Group Policy Editor` should now be installed and ready to run the above steps to disable `Device Guard`.

.. note::

  Occasionally Windows does not include the needed `Administrative template` for `Device Guard` to be visible and the template will have to be updated.
  In this case, download the below update and run it on the system.  Reboot the system and verify that `Device Guard` is now visible.

  Updated Windows 10 Administrative Template:
  https://www.microsoft.com/en-us/download/100591

  It is possible that the template update does NOT have the needed permissions to properly update the template.
  A manual update may be needed.  Don't forget to reboot after.

3. Manually copy the **.admx** and **.adml** files from the update folder
**C:\\Program Files (x86)\\Microsoft Group Policy\\Windows 10 November 2019 Update (1909)\\PolicyDefinitions\\** to **C:\\Windows\\PolicyDefinitions**

If this last step does not work, you will have to use a different OS.


**ERROR: Exception occurred during …**

This error, like the previous issue, appears to be related to a Windows Server OS and its security protections.  Often happening when trying to read an MSR, MMIO, or device.
Windows Server OS appears to be blocking read access to them.  MSR and MMIO reads will simply fail with this error message.
Device (PCI) reads appear to mask the device and return all 0xF's, causing an error parsing them.

One or more of the above mentioned solutions *may* fix this.

Example MSR/MMIO error:

::

  ERROR: Exception occurred during chipsec.modules.common.smm_dma.run(): ''TSEGMB''

Example PCI error:

::

  ERROR: Exception occurred during chipsec.modules.common.bios_smi.run(): 'integer out of range for 'H' format code'


Windows driver: StartService error
----------------------------------

A Windows security feature called HVCI can cause issues running CHIPSEC.  HVCI should be disabled.
Follow the steps described above to disable HVCI.

Follow these steps to disable HVCI:

  `How to disable HVCI <https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity#how-to-turn-off-hvci>`_

  `Full details on HVCI <https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity>`_


Example error messages:

::

  ERROR: service 'chipsec' didn't start: The parameter is incorrect. (87)
  [-] Traceback (most recent call last):
    File "\chipsec\helper\win\win32helper.py", line 434, in start
      win32serviceutil.StartService( SERVICE_NAME )
    File "\lib\site-packages\win32\lib\win32serviceutil.py", line 417, in StartService
      win32service.StartService(hs, args)
  pywintypes.error: (87, 'StartService', 'The parameter is incorrect.')


And...

::

  chipsec.helper.oshelper.OsHelperError: service 'chipsec' didn't start: The parameter is incorrect. (87)



Additional details
------------------

  `Windows Device Guard <https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control>`_

  `Windows Credential Guard <https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard>`_

  `WDAC – Windows Defender Application Control <https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control>`_

  `Hypervisor-Protected Code Integrity (HVCI) <https://docs.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard>`_


