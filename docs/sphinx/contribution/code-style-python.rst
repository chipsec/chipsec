Python Coding Style Guide
=========================

CHIPSEC mostly follows the PEP8 with some exceptions.  This attempts to highlight those as well as clarify others.

Consistency and readability are the goal but not at the expense of readability or functionality.

If in doubt, follow the existing code style and formatting.


#. PEP8

    PEP 8 is a set of recommended code style guidelines (conventions) for Python.

    `PEP 8 <https://www.python.org/dev/peps/pep-0008/>`_


#. Linting tools

    CHIPSEC includes a Flake8 configuration file

    `CHIPSEC flake8 config <https://github.com/chipsec/chipsec/blob/master/.flake8>`_


#. Zen of Python

    Great philosophy around Python building principles.

    `PEP 20 <https://www.python.org/dev/peps/pep-0020/>`_


#. Headers and Comments

    Use single line comments, a single hash/number sign/octothorpe '#'.

    Should contain a space immediately after the '#'.

    .. code-block:: python

        # Good header comment


#. Single vs Double Quotes

    Single quotes are encouraged but can vary with use case.

    Avoid using backslashes '\\' in strings.

    .. code-block:: python

        'This is a preferred "string".'
        "Also an acceptable 'string'."

        "Avoid making this \"string\"."


#. Imports

    Import order:
        #. Python standard library
        #. Third-party imports
        #. CHIPSEC and local application imports

    Avoid using ``import *`` or ``from import *``.  This could pollute the namespace.

    .. code-block:: python

        # Good
        import sys
        from chipsec.module_common import BaseModule, ModuleResult

        # Bad - using '*' and importing sys after local imports
        import *
        from chipsec.module_common import *
        import sys

    Avoid using ``from __future__ imports``.  These may not work on older or all interpreter versions required in all supported environments.


#. Line Length

    Maximum line length should be 120 characters.

    If at or near this limit, consider rewriting (eg simplifying) the line instead of breaking it into multiple lines.

    Long lines can be an indication that too many things are happening at once and/or difficult to read.


#. Class Names

    ``HAL`` and ``utilcmd`` **classes** should use **UpperCamelCase** (**PascalCase**)
    Words and acronyms are capitalized with no spaces or underscores.

    Test **module** class names MUST match the module name which are typically **snake_case**


#. Constants

    Constants should use **CAPITALIZATION_WITH_UNDERSCORES**


#. Variable Names

    Variable names should use **snake_case**

    Lower-case text with underscores between words.


#. Local Variable Names (private)

    Prefixed with an underscore, **_private_variable**

    Not a hard rule but will help minimize any variable name collisions with upstream namespace.


#. Dunder (double underscore)

    Avoid using ``__dunders__`` when naming variables.  Should be used for functions that overwrite or add to classes and only as needed.

    Dunders utilize double (two) underscore characters before and after the name.


#. Code Indents

    CHIPSEC uses 4 space 'tabbed' indents.

    No mixing spaces and tabs.

    - 1 indent = 4 spaces
    - No tabs

    Recommend updating any IDE used to use 4 space indents by default to help avoid mixing tabs with spaces in the code.


#. Operator Precedence, Comparisons, and Parentheses

    If in doubt, wrap evaluated operators into logical sections if using multiple operators or improves readability.

    While not needed in most cases, it can improve readability and limit the possibility of 'left-to-right chaining' issues.

    .. code-block:: python

        # Preferred
        if (test1 == True) or (test2 in data_list):
            return True

        # Avoid.  Legal but behavior may not be immediately evident.
        if True is False == False:
            return False


#. Whitespace

    No whitespace inside parentheses, brackets, or braces.

    No whitespace before a comma, colon, or semicolons.

    Use whitespace after a comma, colon, or semicolon.

    Use whitespace around operators: +, -, \*, \**, /, //, %, =, ==, <, >, <=, >=, <>, !=, is, in, is not, not in, <<, >>, &, \|, ^

    No trailing whitespace.


#. Non-ASCII Characters

    If including any non-ASCII characters anywhere in a python file, include the python encoding comment at the beginning of the file.

    .. code-block:: python

        # -*- coding: utf-8 -*-

    No non-ASCII class, function, or variable names.


#. Docstrings

    Use three double-quotes for all docstrings.

    .. code-block:: python

        """String description docstring."""


#. Semicolons

    Do not use semicolons.


#. Try Except

    Avoid using nested try-except.

    The routine you are calling, may already be using one.



