
- Command Line Usage
	``# chipsec_main.py [options]``

Options
-------
====================== =====================================================
-m --module             specify module to run (example: -m common.bios_wp)
-a --module_args        additional module arguments, format is 'arg0,arg1..'
-v --verbose            verbose mode
-d --debug              show debug output
-l --log                output to log file
====================== =====================================================

Advanced Options
----------------
======================== ========================================================================================================
-p --platform             explicitly specify platform code. Should be among the supported platforms:
                          [ CFL | SNB | IVB | KBL | JKT | BYT | QRK | BDW | IVT | AVN | DNV | CHT | HSW | APL | SKL | HSX | BDX ]
   --pch                  explicitly specify PCH code. Should be among the supported PCH:
                          [ PCH_3XX | PCH_C620 | PCH_1XX | PCH_2XX | PCH_C61X | PCH_C60X ]
-n --no_driver            chipsec won't need kernel mode functions so don't load chipsec driver
-i --ignore_platform      run chipsec even if the platform is not recognized
-j --json                 specify filename for JSON output.
-x --xml                  specify filename for xml output (JUnit style).
-t --moduletype           run tests of a specific type (tag).
   --list_tags            list all the available options for -t,--moduletype
-I --include              specify additional path to load modules from
   --failfast             fail on any exception and exit (don't mask exceptions)
   --no_time              don't log timestamps
   --deltas               specifies a JSON log file to compute result deltas from
======================== ========================================================================================================

Exit Code
---------
CHIPSEC returns an integer exit code:

- Exit code is 0:       all modules ran successfully and passed
- Exit code is not 0:   each bit means the following:

    - Bit 0: NOT IMPLEMENTED at least one module was not implemented for the platform
    - Bit 1: WARNING         at least one module had a warning
    - Bit 2: DEPRECATED      at least one module uses deprecated API
    - Bit 3: FAIL            at least one module failed
    - Bit 4: ERROR           at least one module wasn't able to run
    - Bit 5: EXCEPTION       at least one module threw an unexpected exception
    - Bit 6: INFORMATION     at least one module contained information
    - Bit 7: NOT APPLICABLE  at least one module was not applicable for the platform
