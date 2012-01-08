__import__("pkg_resources").declare_namespace(__name__)

import sys
import os
from logging import getLogger
from infi.pyutils.decorators import wraps

BYPASS_KEY = "ROOT_BYPASS"
logger = getLogger()

class RootPermissions(object):
    def _nt(self):
        from ctypes import windll
        # http://msdn.microsoft.com/en-us/library/windows/desktop/bb776463(v=vs.85).aspx
        return windll.shell32.IsUserAnAdmin()

    def _posix(self):
        return os.getuid() == 0

    def _bypass(self):
        return os.environ.get(BYPASS_KEY, False)

    def is_root(self):
        if self._bypass():
            return True

        if os.name != "nt":
            return self._posix()
        return self._nt()

def exit_if_not_root(func):
    @wraps(func)
    def callee(*args, **kwargs):
        if not RootPermissions().is_root():
            username = "an Administrator" if os.name == "nt" else "root"
            msg = "You must be {} to run this tool".format(username)
            sys.stderr.write("{}\n".format(msg))
            logger.error(msg)
            sys.stderr.flush()
            sys.exit(5)
        return func(*args, **kwargs)
    return callee

@exit_if_not_root
def ensure_root():
    pass
