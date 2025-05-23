# Upcoming Requirement: Signed Commits Starting Q3 2025

Dear contributors,
To enhance the security and integrity of our codebase, we will begin requiring signed commits for all contributions starting in Quarter 3 of 2025.

What This Means for You
Beginning in Q3 2025, all commits to this repository must be GPG, SSH, or S/MIME-signed and verified. Unsigned or unverified commits will be rejected during the review or merge process.

Why Signed Commits?
Signed commits help ensure that contributions are verifiably made by trusted individuals and have not been tampered with, aligning with best practices in secure software development.

How to Prepare
If you haven’t already, please set up commit signing in your Git configuration. Here's how:
[GitHub: Signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
We encourage you to start signing your commits now so you're fully prepared by the time the policy takes effect.
Thank you for helping us maintain a secure and trustworthy development environment!

— Chipsec Team

CHIPSEC: Platform Security Assessment Framework
===============================================

[![Build Status](https://github.com/chipsec/chipsec/actions/workflows/tests.yml/badge.svg?query=branch%3Amain)](https://github.com/chipsec/chipsec/actions/workflows/tests.yml?query=branch%3Amain)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8259/badge)](https://www.bestpractices.dev/projects/8259)

CHIPSEC is a framework for analyzing the security of PC platforms including hardware, system firmware (BIOS/UEFI), and platform components. It includes a security test suite, tools for accessing various low level interfaces, and forensic capabilities. It can be run on Windows, Linux, and UEFI shell. Instructions for installing and using CHIPSEC can be found in the [manual](chipsec-manual.pdf).

NOTE: This software is for security testing purposes. Use at your own risk. Read [WARNING.txt](chipsec/WARNING.txt) before using.

First version of CHIPSEC was released in March 2014:
[Announcement at CanSecWest 2014](https://www.c7zero.info/stuff/Platform%20Firmware%20Security%20Assessment%20wCHIPSEC-csw14-final.pdf)

Recent presentation on how to use CHIPSEC to find vulnerabilities in firmware, hypervisors and hardware configuration, explore low level system assets and even detect firmware implants:
[Exploring Your System Deeper](https://www.slideshare.net/CanSecWest/csw2017-bazhaniuk-exploringyoursystemdeeperupdated)

Release Convention
------------------

  * CHIPSEC uses a major.minor.patch release version number
  * Changes to the arguments or calling conventions will be held for a minor version update


Projects That Include CHIPSEC
-----------------------------
 
 * [ArchStrike](https://archstrike.org)
 
 * [BlackArch Linux](https://www.blackarch.org/index.html)

 * [Linux UEFI Validation (LUV) (Archived)](https://github.com/intel/luv-yocto)

Contact Us
----------

For any questions or suggestions please contact us at: chipsec@intel.com

Discord:

 * [CHIPSEC Discord Server](https://discord.gg/NvxdPe8RKt)

Twitter:

 * For CHIPSEC release alerts: Follow us at [CHIPSEC Release](https://twitter.com/ChipsecR)
 * For general CHIPSEC info: Follow [CHIPSEC](https://twitter.com/Chipsec)

Mailing list:

 * [CHIPSEC discussion list on kernel.org (oe-chipsec)](https://subspace.kernel.org/lists.linux.dev.html?highlight=oe-chipsec)

For AMD related questions or suggestions please contact Gabriel Kerneis at: Gabriel.Kerneis@ssi.gouv.fr
