Chipsec 1.1.0
=======================
 1.  We have support for uefi variables on Windows and Linux but not UEFI shell. 
 2.  Decompression of images in SPI flash parsing is only supported in Windows.
 3.	UEFI - Support for IA32 and i586 (Quark) 
 4.	Added capability to use modules from an arbitrary path with the -I / --import command line option 
 5.	Module functionality encapsulated in class inheriting BaseModule 
 6.	Fixed  loading platform specific configuration 
 7.	Fixed issue with modules which run on multiple logical CPUs hanging on Bay Trail (Windows/Linux). The issue still exist when running from UEFI shell
 8.	Added template for a module - module_template.py 
 9.	Added options to flush log files 
 10.	Added ability to define custom platforms 

Driver changes:
 1.	Windows - Added IOCTL_ALLOC_PHYSMEM to allocate physical memory buffer 
 2.	Linux - Fix wrpci defect 

 
 Chipsec 1.0.2689
 ===================
 Initial Release