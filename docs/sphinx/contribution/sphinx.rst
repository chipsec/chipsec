.. _Sphinx:

Sphinx Version
==============

The versions of Sphinx that can be utilized to generate CHIPSEC's documentation are 6.X.X, 7.X.X and 8.X.X.


Generating Documentation
========================

Use the script in the docs folder to automatically generate CHIPSEC's documentation using Sphinx.
It generates PDF plus either HTML or JSON formats.

    ``python3 create_manual.py [format]``

    ``format`` - html or json

    ``python3 create_manual.py``
    
    ``python3 create_manual.py html``
    
    ``python3 create_manual.py json``


References
==========

  - `Sphinx Apidoc <https://www.sphinx-doc.org/en/master/man/sphinx-apidoc.html>`_
  - `Sphinx Build <https://www.sphinx-doc.org/en/master/man/sphinx-build.html>`_
  - `Autodoc <https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html>`_