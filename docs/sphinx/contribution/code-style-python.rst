.. _Code-Style-Python:

Python Version
==============

All Python code, and PEP support, must to be limited to the features supported by **Python 3.6.8**.

This is earliest version of Python utilized by CHIPSEC, the version of the EFI Shell Python.


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
        from chipsec.module_common import BaseModule
        from chipsec.library.returncode import ModuleResult

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


#. Avoid for-else and while-else loops

    The loop behavior for these can be counterintuitive.

    If they have to be used, make sure to properly document the expected behavior / work-flow.


f-Strings
=========

.. list-table:: PEP versions supported by CHIPSEC
   :widths: 12 23 25 12 12
   :header-rows: 1

   * - PEP / bpo
     - Title
     - Summary
     - Python Version
     - Supported
   * - `PEP 498 <https://www.python.org/dev/peps/pep-0498/>`_
     - Literal String Interpolation
     - Adds a new string formatting mechanism: Literal String Interpolation, f-strings
     - 3.6
     - Yes
   * - `bpo 36817 <https://github.com/python/cpython/issues/80998>`_
     - Add = to f-strings for easier debugging
     - f-strings support = for self-documenting expressions
     - 3.8
     - No
   * - `PEP 701 <https://www.python.org/dev/peps/pep-0701/>`_
     - Syntactic formalization of f-strings
     - Lift some restrictions from PEP 498 and formalize grammar for f-strings
     - 3.12
     - No


Type Hints
==========

For more information on Python Type Hints:
  `PEP 483 - The Theory of Type Hints <https://peps.python.org/pep-0483/>`_


This table lists which Type Hint PEPs are in scope for CHIPSEC.

.. list-table:: PEP versions supported by CHIPSEC
   :widths: 12 23 25 12 12
   :header-rows: 1

   * - PEP
     - Title
     - Summary
     - Python Version
     - Supported
   * - `PEP 3107 <https://www.python.org/dev/peps/pep-3107/>`_
     - Function Annotations
     - Syntax for adding arbitrary metadata annotations to Python functions
     - 3.0
     - Yes
   * - `PEP 362 <https://www.python.org/dev/peps/pep-0362/>`_
     - Function Signature Object
     - Contains all necessary information about a function and its parameters
     - 3.3
     - Yes
   * - `PEP 484 <https://www.python.org/dev/peps/pep-0484/>`_
     - Type Hints
     - Standard syntax for type annotations
     - 3.5
     - Yes
   * - `PEP 526 <https://www.python.org/dev/peps/pep-0526/>`_
     - Syntax for Variable Annotations
     - Adds syntax for annotating the types of variables
     - 3.6
     - Yes
   * - `PEP 544 <https://www.python.org/dev/peps/pep-0544/>`_
     - Protocols: Structural subtyping (static duck typing)
     - Specify type metadata for static type checkers and other third-party tools
     - 3.8
     - No
   * - `PEP 585 <https://www.python.org/dev/peps/pep-0585/>`_
     - Type Hinting Generics In Standard Collections
     - Enable support for the generics syntax in all standard collections currently available in the typing module
     - 3.9
     - No
   * - `PEP 586 <https://www.python.org/dev/peps/pep-0586/>`_
     - Literal Types
     - Literal types indicate that some expression has literally a specific value(s).
     - 3.8
     - No
   * - `PEP 589 <https://www.python.org/dev/peps/pep-0589/>`_
     - TypedDict: Type Hints for Dictionaries with a Fixed Set of Keys
     - Support dictionary object with a specific set of string keys, each with a value of a specific type
     - 3.8
     - No
   * - `PEP 593 <https://www.python.org/dev/peps/pep-0593/>`_
     - Flexible function and variable annotations
     - Adds an Annotated type to the typing module to decorate existing types with context-specific metadata.
     - 3.9
     - No
   * - `PEP 604 <https://www.python.org/dev/peps/pep-0604/>`_
     - Allow writing union types as X | Y
     - Overload the | operator on types to allow writing Union[X, Y] as X | Y
     - 3.10
     - No
   * - `PEP 612 <https://www.python.org/dev/peps/pep-0612/>`_
     - Parameter Specification Variables
     - Proposes typing.ParamSpec and typing.Concatenate to support forwarding parameter types of one callable over to another callable
     - 3.10
     - No
   * - `PEP 613 <https://www.python.org/dev/peps/pep-0613/>`_
     - Explicit Type Aliases
     - Formalizes a way to explicitly declare an assignment as a type alias
     - 3.10
     - No
   * - `PEP 646 <https://www.python.org/dev/peps/pep-0646/>`_
     - Variadic Generics
     - Introduce TypeVarTuple, enabling parameterisation with an arbitrary number of types
     - 3.11
     - No
   * - `PEP 647 <https://www.python.org/dev/peps/pep-0647/>`_
     - User-Defined Type Guards
     - Specifies a way for programs to influence conditional type narrowing employed by a type checker based on runtime checks
     - 3.11
     - No
   * - `PEP 655 <https://www.python.org/dev/peps/pep-0655/>`_
     - Marking individual TypedDict items as required or potentially-missing
     - Two new notations: Required[], which can be used on individual items of a TypedDict to mark them as required, and NotRequired[]
     - 3.11
     - No
   * - `PEP 673 <https://www.python.org/dev/peps/pep-0673/>`_
     - Self Type
     - Methods that return an instance of their class
     - 3.10
     - No
   * - `PEP 675 <https://www.python.org/dev/peps/pep-0675/>`_
     - Arbitrary Literal String Type
     - Introduces supertype of literal string types: LiteralString
     - 3.11
     - No
   * - `PEP 681 <https://www.python.org/dev/peps/pep-0681/>`_
     - Data Class Transforms
     - Provides a way for third-party libraries to indicate that certain decorator functions, classes, and metaclasses provide behaviors similar to dataclasses
     - 3.11
     - No
   * - `PEP 692 <https://www.python.org/dev/peps/pep-0692/>`_
     - Using TypedDict for more precise kwargs typing
     - A new syntax for specifying kwargs type as a TypedDict without breaking current behavior
     - 3.12
     - No
   * - `PEP 695 <https://www.python.org/dev/peps/pep-0695/>`_
     - Type Parameter Syntax
     - A syntax for specifying type parameters within a generic class, function, or type alias. And introduces a new statement for declaring type aliases.
     - 3.12
     - No
   * - `PEP 698 <https://www.python.org/dev/peps/pep-0698/>`_
     - Override Decorator for Static Typing
     - Adds @override decorator to allow type checkers to prevent a class of bugs that occur when a base class changes methods that are inherited by derived classes.
     - 3.12
     - No


Underscores in Numeric Literals
===============================

Underscores in Numeric Literals are supported, even encouraged, but not required.  For consistency, follow the grouping examples presented in the PEP abstract.

.. list-table:: PEP versions supported by CHIPSEC
   :widths: 12 23 25 12 12
   :header-rows: 1

   * - PEP
     - Title
     - Summary
     - Python Version
     - Supported
   * - `PEP 515 <https://peps.python.org/pep-0515/>`_
     - Underscores in Numeric Literals
     - Extends Python's syntax so that underscores can be used as visual separators for grouping purposes in numerical literals
     - 3.6
     - Yes


Walrus Operator (:=)
====================

At this time, Assignment Expressions (Walrus operator) are not supported.

.. list-table:: PEP versions supported by CHIPSEC
   :widths: 12 23 25 12 12
   :header-rows: 1

   * - PEP
     - Title
     - Summary
     - Python Version
     - Supported
   * - `PEP 572 <https://peps.python.org/pep-0572/>`_
     - Assignment Expressions
     - Adds a way to assign to variables within an expression
     - 3.8
     - No


Deprecate distutils module support
==================================

Python 3.12 will deprecate and remove the distutils module.  In order for CHIPSEC to support this and furture versions of Python, setuptools should be used instead of distutils.

The setuptools module has been updated to fully replace distutils but requires an up-to-date version.

- Minimum setuptools version: `62.0.0 <https://pypi.org/project/setuptools/62.0.0/>`_ (requires Python >= 3.8)

- Recommended setuptools version: latest

**Note**: If you get any `setuptools.command.build` errors, verify that you have (at least) the minimum setuptools version.

.. list-table:: PEP versions supported by CHIPSEC
   :widths: 12 23 25 12 12
   :header-rows: 1

   * - PEP / bpo
     - Title
     - Summary
     - Python Version
     - Supported
   * - `PEP 632 <https://peps.python.org/pep-0632/>`_
     - Deprecate distutils module
     - Mark the distutils module as deprecated (3.10) and then remove it (3.12)
     - 3.12
     - Yes

