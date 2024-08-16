Sample module code template
===========================

.. code-block:: python

    from chipsec.module_common import BaseModule
    from chipsec.library.returncode import ModuleResult

    class ModuleClass(BaseModule):
        """Class name aligns with file name, eg ModuleClass.py"""
        def __init__(self):
            BaseModule.__init__(self)

        def is_supported(self) -> bool:
            """Module prerequisite checks"""
            if some_module_requirement():
                return True  # Module is applicable
            self.res = ModuleResult.NOTAPPLICABLE
            return False  # Module is not applicable

        def action(self) -> int:
            """Module test logic and methods as needed"""
            self.logger.log_passed('Module was successful!')
            return ModuleResult.PASSED

        def run(self, module_argv) -> int:
            """Primary module execution and result handling"""
            self.logger.start_test('Module Description')
            self.res = self.action()
            return self.res
