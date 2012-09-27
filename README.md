Overview
========
A simple cross-platform module to determine if the current Python process is running under root/Administrator privileges


Usage
-----

One way to use this module is with a decorator:
```python
from infi.run_as_root import exit_if_not_root, ensure_root
@exit_if_not_root
def requires_root_privileges():
    pass
```

Another way is by a simple function call:
```python
from infi.run_as_root import exit_if_not_root, ensure_root
def requires_root_privileges():
    ensure_root()
```

Checking out the code
=====================

This project uses buildout, and git to generate setup.py and __version__.py.
In order to generate these, run:

    python -S bootstrap.py -d -t
    bin/buildout -c buildout-version.cfg
    python setup.py develop

In our development environment, we use isolated python builds, by running the following instead of the last command:

    bin/buildout install development-scripts

