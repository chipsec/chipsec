Sample Module Code
==================

This template shows the minimum structure for a module named
``common.example``. Save it as ``chipsec/modules/common/example.py`` and
replace ``ExampleControl`` with a control defined for the platforms the
module supports. The class name must match the file's base name.

.. code-block:: python

   from typing import List

   from chipsec.library.returncode import ModuleResult
   from chipsec.module_common import BaseModule


   class example(BaseModule):
       def __init__(self):
           super().__init__()

       def is_supported(self) -> bool:
           return self.cs.control.is_defined('ExampleControl')

       def run(self, module_argv: List[str]) -> int:
           self.logger.start_test('Example control check')
           control = self.cs.control.get_list_by_name('ExampleControl')
           control.read_and_verbose_print()

           if control.is_all_value(1):
               self.logger.log_passed('Example control is set.')
               result = ModuleResult.PASSED
           else:
               self.logger.log_failed('Example control is not set.')
               result = ModuleResult.FAILED

           return self.result.getReturnCode(result)

Run the module with ``python chipsec_main.py -m common.example``. Modules
that accept arguments receive them as a list in ``module_argv``; invoke them
with ``-a``. For module APIs, result handling, safety practices and
debugging, see :doc:`Developing`.
