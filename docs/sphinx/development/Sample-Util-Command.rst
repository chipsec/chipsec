Sample Util Command
===================

.. code-block:: python

    # chipsec_util.py commands live in chipsec/utilcmd/
    # Example file name: <command_display_name>_cmd.py

    from argparse import ArgumentParser
    from time import time

    from chipsec.command import BaseCommand

    class CommandClass(BaseCommand):
        """
            >>> chipsec_util command_display_name action
        """

        def requires_driver(self):
            parser = ArgumentParser(prog='chipsec_util command_display_name', usage=CommandClass.__doc__)
            subparsers = parser.add_subparsers()
            parser_entrypoint = subparsers.add_parser('action')
            parser_entrypoint.set_defaults(func=self.action)
            parser.parse_args(self.argv[2:], namespace=self)
            return True

        def action(self):
            return

        def run(self):
            t = time()
            self.func()
            self.logger.log('[CHIPSEC] (command_display_name) time elapsed {:.3f}'.format(time() - t))

    commands = {'command_display_name': CommandClass}
