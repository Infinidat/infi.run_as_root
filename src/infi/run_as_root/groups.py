# Since UAC was introduced, Administrators may not be elevated.
# The correct way to check if the process is running with Administrator privileges, is to
# enumerate the groups of the process token, find the Administrator group, and make sure its
# SE_GROUP_USE_FOR_DENY_ONLY bit is off. This is always true for "Administrator" account, and for other
# users it's true only if the process is run with "Run as Administrator" and/or UAC was passed

from ctypes import byref, c_ubyte, c_ulong, c_void_p, cast, POINTER, Structure, windll
from infi.pyutils.contexts import contextmanager

OpenProcessToken = windll.advapi32.OpenProcessToken
GetCurrentProcess = windll.kernel32.GetCurrentProcess
EqualSid = windll.advapi32.EqualSid
CreateWellKnownSid = windll.advapi32.CreateWellKnownSid
LocalAlloc = windll.kernel32.LocalAlloc
LocalFree = windll.kernel32.LocalFree
CloseHandle = windll.kernel32.CloseHandle
GetLastError = windll.kernel32.GetLastError
GetTokenInformation = windll.advapi32.GetTokenInformation
TOKEN_QUERY = 0x0008
TokenGroups = 2
WinBuiltinAdministratorsSid = 26
ERROR_INSUFFICIENT_BUFFER = 122
SECURITY_MAX_SID_SIZE = 68
SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010

class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [('Sid', POINTER(c_void_p)), ('Attributes', c_ulong)]

def token_groups(count):
    class TOKEN_GROUPS(Structure):
        _fields_ = [('GroupCount', c_ulong), ('Groups', SID_AND_ATTRIBUTES * count)]
    return TOKEN_GROUPS

def get_token_groups():
    hToken = c_void_p()
    dwLengthNeeded = c_ulong()

    hProcess = c_void_p(GetCurrentProcess())
    bResult = OpenProcessToken(hProcess, TOKEN_QUERY, byref(hToken))
    assert bResult
    try:
        bResult = GetTokenInformation(hToken, TokenGroups, None, 0, byref(dwLengthNeeded))
        assert not bResult and GetLastError() == ERROR_INSUFFICIENT_BUFFER
        pGroups = LocalAlloc(0, dwLengthNeeded)
        assert pGroups
        try:
            bResult = GetTokenInformation(hToken, TokenGroups, pGroups, dwLengthNeeded, byref(dwLengthNeeded))
            groups_count = cast(pGroups, POINTER(c_ulong))[0]
            groups = cast(pGroups, POINTER(token_groups(groups_count)))[0]
            for i in range(groups.GroupCount):
                group = groups.Groups[i]
                yield group.Sid, group.Attributes
        finally:
            LocalFree(pGroups)
    finally:
        CloseHandle(hToken)

@contextmanager
def get_builtin_administrators_sid():
    cbSidSize = c_ulong(SECURITY_MAX_SID_SIZE)
    pSid = LocalAlloc(0, SECURITY_MAX_SID_SIZE)
    assert pSid
    Sid = cast(pSid, POINTER(c_void_p))
    try:
        bResult = CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Sid, byref(cbSidSize))
        assert bResult
        yield Sid
    finally:
        LocalFree(pSid)

def is_admin():
    with get_builtin_administrators_sid() as admin_sid:
        for sid, attributes in get_token_groups():
            if EqualSid(sid, admin_sid):
                return not bool(attributes & SE_GROUP_USE_FOR_DENY_ONLY)
        else:
            return False
