::

  usage: chipsec_main.py [options]
  
  Options:
    -h, 
    --help            show this message and exit
    -m _MODULE, 
    --module _MODULE
                          specify module to run (example: -m common.bios_wp)
    -a [_MODULE_ARGV [_MODULE_ARGV ...]], 
    --module_args [_MODULE_ARGV [_MODULE_ARGV ...]]
                          additional module arguments
    -v, 
    --verbose         verbose mode
    -d, 
    --debug           debug mode
    -l LOG, 
    --log LOG     output to log file
  
  Advanced Options:
    -p {CFL,SNB,IVB,KBL,JKT,BYT,QRK,BDW,IVT,AVN,DNV,CHT,HSW,APL,SKL,HSX,BDX}, 
    --platform {CFL,SNB,IVB,KBL,JKT,BYT,QRK,BDW,IVT,AVN,DNV,CHT,HSW,APL,SKL,HSX,BDX}
                          explicitly specify platform code
    --pch {PCH_3XX,PCH_C620,PCH_1XX,PCH_2XX,PCH_C61X,PCH_C60X}
                          explicitly specify PCH code
    -n, 
    --no_driver       chipsec won't need kernel mode functions so don't load
                          chipsec driver
    -i, 
    --ignore_platform
                          run chipsec even if the platform is not recognized
    -j _JSON_OUT, 
    --json _JSON_OUT
                          specify filename for JSON output
    -x _XML_OUT, 
    --xml _XML_OUT
                          specify filename for xml output (JUnit style)
    -t USER_MODULE_TAGS, 
    --moduletype USER_MODULE_TAGS
                          run tests of a specific type (tag)
    --list_tags           list all the available options for -t,--moduletype
    -I IMPORT_PATHS, 
    --include IMPORT_PATHS
                          specify additional path to load modules from
    --failfast            fail on any exception and exit (don't mask exceptions)
    --no_time             don't log timestamps
    --deltas _DELTAS_FILE
                          specifies a JSON log file to compute result deltas
                          from
  
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

