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

Run the following:

    easy_install -U infi.projector
    projector devenv build

Python 3 support is experimental and not fully tested.