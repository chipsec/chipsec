---
name: 'Python Standards'
description: 'Coding conventions for Python files'
applyTo: '**/**.py'
---

# Python Version

All Python code, and PEP support, must be limited to the features supported by Python 3.6.8.

This is the earliest version of Python utilized by CHIPSEC, the version of the EFI Shell Python.

# Python Coding Style Guide

CHIPSEC mostly follows PEP 8 with some exceptions. Consistency and readability are the goal but not at the expense of readability or functionality.

If in doubt, follow the existing code style and formatting.

## 1. PEP 8

Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines with the CHIPSEC-specific exceptions noted below.

## 2. Linting Tools

CHIPSEC includes a Flake8 configuration file. Use it to lint code before submitting.

## 3. Zen of Python

Follow the principles of [PEP 20](https://www.python.org/dev/peps/pep-0020/).

## 4. Headers and Comments

- Use single-line comments with a single `#` (hash/octothorpe).
- Include a space immediately after the `#`.

```python
# Good header comment
```

## 5. Single vs Double Quotes

- Single quotes are encouraged but can vary with use case.
- Avoid using backslashes `\` in strings.

```python
'This is a preferred "string".'
"Also an acceptable 'string'."

# Avoid:
"Avoid making this \"string\"."
```

## 6. Imports

- **Import order:**
  1. Python standard library
  2. Third-party imports
  3. CHIPSEC and local application imports

- Avoid `import *` or `from x import *` — this pollutes the namespace.
- Avoid `from __future__ import` — may not work on all supported interpreter versions.

```python
# Good
import sys
from chipsec.module_common import BaseModule
from chipsec.library.returncode import ModuleResult

# Bad - using '*' and importing sys after local imports
import *
from chipsec.module_common import *
import sys
```

## 7. Line Length

- Maximum line length is **120 characters**.
- If at or near this limit, consider rewriting/simplifying the line rather than breaking it.
- Long lines can indicate too many things happening at once and/or be difficult to read.

## 8. Class Names

- Classes should use **UpperCamelCase** (PascalCase) with the exception of Test Modules. Words and acronyms are capitalized with no spaces or underscores.
- Test module (files under `chipsec/modules/`) class names **MUST** match the module name, which are typically `snake_case`.

## 9. Constants

- Constants should use `CAPITALIZATION_WITH_UNDERSCORES`.

## 10. Variable Names

- Variable names should use `snake_case` — lower-case text with underscores between words.

## 11. Local Variable Names (private)

- Prefixed with an underscore: `_private_variable`.
- Not a hard rule, but helps minimize variable name collisions with upstream namespace.

## 12. Dunder (Double Underscore)

- Avoid using `__dunders__` when naming variables.
- Should only be used for functions that overwrite or add to classes.

## 13. Code Indents

- Use **4 spaces** per indent level. No tabs. No mixing spaces and tabs.
- 1 indent = 4 spaces.

## 14. Operator Precedence, Comparisons, and Parentheses

- When using multiple operators, wrap evaluated operators into logical sections if it improves readability.
- Can limit 'left-to-right chaining' issues.

```python
# Preferred
if (test1 == True) or (test2 in data_list):
    return True

# Avoid — legal but behavior may not be immediately evident
if True is False == False:
    return False
```

## 15. Whitespace

- No whitespace inside parentheses, brackets, or braces.
- No whitespace before a comma, colon, or semicolon.
- Use whitespace after a comma, colon, or semicolon.
- Use whitespace around operators: `+`, `-`, `*`, `**`, `/`, `//`, `%`, `=`, `==`, `<`, `>`, `<=`, `>=`, `<>`, `!=`, `is`, `in`, `is not`, `not in`, `<<`, `>>`, `&`, `|`, `^`.
- No trailing whitespace.

## 16. Non-ASCII Characters

- If including any non-ASCII characters anywhere in a Python file, include the Python encoding comment at the beginning of the file:

```python
# -*- coding: utf-8 -*-
```

- No non-ASCII class, function, or variable names.

## 17. Docstrings

- Use three double-quotes for all docstrings.

```python
"""String description docstring."""
```

## 18. Semicolons

- Do not use semicolons.

## 19. Try Except

- Avoid using nested try-except. The routine you are calling may already be using one.

## 20. Avoid for-else and while-else Loops

- The loop behavior for these can be counterintuitive.
- If they must be used, properly document the expected behavior/work-flow.

# f-Strings

- Use f-strings (PEP 498, Python 3.6+) for string interpolation. The following f-string features are in scope:

| PEP | Description | Min Version | In Scope |
|-----|-------------|-------------|----------|
| PEP 498 | Literal String Interpolation (f-strings) | 3.6 | Yes |
| bpo 36817 | `=` specifier in f-strings for debugging | 3.8 | No |
| PEP 701 | Syntactic formalization of f-strings | 3.12 | No |

- Avoid using `'string'.format(...)` for string interpolation; prefer f-strings instead.

# Type Hints

For more information: [PEP 483 - The Theory of Type Hints](https://peps.python.org/pep-0483/)

The following table defines whether Type Hint PEPs are in or out of scope for Chipsec:

| PEP | Description | Min Version | In Scope |
|-----|-------------|-------------|----------|
| PEP 3107 | Function Annotations | 3.0 | Yes |
| PEP 362 | Function Signature Object | 3.3 | Yes |
| PEP 484 | Type Hints | 3.5 | Yes |
| PEP 526 | Syntax for Variable Annotations | 3.6 | Yes |
| PEP 544 | Protocols: Structural subtyping | 3.8 | No |
| PEP 585 | Type Hinting Generics In Standard Collections | 3.9 | No |
| PEP 586 | Literal Types | 3.8 | No |
| PEP 589 | TypedDict | 3.8 | No |
| PEP 593 | Flexible function and variable annotations | 3.9 | No |
| PEP 604 | Union types as `X \| Y` | 3.10 | No |
| PEP 612 | Parameter Specification Variables | 3.10 | No |
| PEP 613 | Explicit Type Aliases | 3.10 | No |
| PEP 646 | Variadic Generics | 3.11 | No |
| PEP 647 | User-Defined Type Guards | 3.11 | No |
| PEP 655 | Required/NotRequired in TypedDict | 3.11 | No |
| PEP 673 | Self Type | 3.10 | No |
| PEP 675 | Arbitrary Literal String Type | 3.11 | No |
| PEP 681 | Data Class Transforms | 3.11 | No |
| PEP 692 | TypedDict for kwargs typing | 3.12 | No |
| PEP 695 | Type Parameter Syntax | 3.12 | No |
| PEP 698 | Override Decorator for Static Typing | 3.12 | No |

# Underscores in Numeric Literals

Underscores in numeric literals are supported and encouraged (but not required). Follow the grouping examples in PEP 515.

| PEP | Description | Min Version | In Scope |
|-----|-------------|-------------|----------|
| PEP 515 | Underscores in Numeric Literals | 3.6 | Yes |

# Walrus Operator (:=)

Assignment Expressions (Walrus operator) are **not supported** at this time. Do not use them.

| PEP | Description | Min Version | In Scope |
|-----|-------------|-------------|----------|
| PEP 572 | Assignment Expressions (`:=`) | 3.8 | No |

# Deprecate distutils Module Support

Python 3.12 deprecates and removes the `distutils` module. Use `setuptools` instead.

- Minimum setuptools version: **62.0.0** (requires Python >= 3.8)
- Recommended setuptools version: latest

If you get any `setuptools.command.build` errors, verify you have at least the minimum setuptools version.

| PEP | Description | Min Version | In Scope |
|-----|-------------|-------------|----------|
| PEP 632 | Deprecate distutils module | 3.12 | Yes |

