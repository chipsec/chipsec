CHIPSEC
=======
Welcome to the CHIPSEC documentation!

CHIPSEC is a framework for analyzing platform level security of hardware, devices, system firmware, low-level protection mechanisms, and the configuration of various platform components.

It contains a set of modules, including simple tests for hardware protections and correct configuration, tests for vulnerabilities in firmware and platform components, security assessment and fuzzing tools for various platform devices and interfaces, and tools acquiring critical firmware and device artifacts.

CHIPSEC can run on *Windows*, *Linux*, *Mac OS* and *UEFI shell*. Mac OS support is Alpha.

.. warning:: 
    Chipsec should only be used on test systems! 
    
    It should not be installed/deployed on production end-user systems.

    There are multiple reasons for that:

    1. Chipsec kernel drivers provide direct access to hardware resources to
    user-mode applications (for example, access to physical memory). When installed on
    production systems this could allow malware to access privileged hardware resources.

    2. The driver is distributed as source code. In order to load it on Operating System
    which requires kernel drivers to be signed (for example, 64 bit versions of
    Microsoft Windows 7 and higher), it is necessary to enable TestSigning (or equivalent)
    mode and sign the driver executable with test signature. Enabling TestSigning
    (or equivalent) mode turns off an important OS kernel protection and should not be done
    on production systems.

    3. Due to the nature of access to hardware, if any chipsec module issues incorrect access
    to hardware resources, Operating System can hang or panic.
