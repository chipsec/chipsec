Util Command
============

.. code-block:: python

    # chipsec_util.py commands live in chipsec/utilcmd/
    # Example file name: <command_display_name>_cmd.py

    from argparse import ArgumentParser

    from chipsec.command import BaseCommand, toLoad

    class CommandClass(BaseCommand):
        """
            >>> chipsec_util command_display_name action
        """
        def requirements(self) -> toLoad:
            return toLoad.All

        def parse_arguments(self):
            parser = ArgumentParser(prog='chipsec_util command_display_name', usage=CommandClass.__doc__)
            subparsers = parser.add_subparsers()
            parser_entrypoint = subparsers.add_parser('action')
            parser_entrypoint.set_defaults(func=self.action)
            parser.parse_args(self.argv, namespace=self)

        def action(self):
            return

        def run(self):
            self.func()

    commands = {'command_display_name': CommandClass}
