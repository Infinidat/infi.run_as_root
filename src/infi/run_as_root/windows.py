# Since UAC was introduced, Administrators may not be elevated.
# The correct way to check if the process is running with Administrator privileges, is to
# enumerate the groups of the process token, find the Administrator group, and make sure its
# SE_GROUP_USE_FOR_DENY_ONLY bit is off. This is always true for "Administrator" account, and for other
# users it's true only if the process is run with "Run as Administrator" and/or UAC was passed
# This function can be used even on older Windows versions where UAC is not available - the bit
# will never be set, and we only check that the token has the Administrators group

from ctypes import byref, cast, POINTER, Structure, windll, wintypes
from infi.pyutils.contexts import contextmanager

SID = wintypes.LPVOID

OpenProcessToken = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, POINTER(wintypes.HANDLE))
OpenProcessToken.restype = wintypes.BOOL

GetCurrentProcess = windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = wintypes.HANDLE

EqualSid = windll.advapi32.EqualSid
EqualSid.argtypes = (POINTER(SID), POINTER(SID))
EqualSid.restype = wintypes.BOOL

CreateWellKnownSid = windll.advapi32.CreateWellKnownSid
CreateWellKnownSid.argtypes = (wintypes.UINT, POINTER(SID), POINTER(SID), POINTER(wintypes.DWORD))
CreateWellKnownSid.restype = wintypes.BOOL

LocalAlloc = windll.kernel32.LocalAlloc
LocalAlloc.argtypes = (wintypes.UINT, wintypes.UINT)
LocalAlloc.restype = wintypes.HLOCAL

LocalFree = windll.kernel32.LocalFree
LocalFree.argtypes = (wintypes.HLOCAL, )
LocalFree.restype = wintypes.HLOCAL

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = (wintypes.HANDLE, )
CloseHandle.restype = wintypes.BOOL

GetLastError = windll.kernel32.GetLastError
GetLastError.restype = wintypes.DWORD

GetTokenInformation = windll.advapi32.GetTokenInformation
GetTokenInformation.argtypes = (wintypes.HANDLE, wintypes.UINT, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD))
GetTokenInformation.restype = wintypes.BOOL


TOKEN_QUERY = 0x0008
TokenGroups = 2
WinBuiltinAdministratorsSid = 26
ERROR_INSUFFICIENT_BUFFER = 122
SECURITY_MAX_SID_SIZE = 68
SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010


class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [('Sid', POINTER(SID)), ('Attributes', wintypes.DWORD)]


def token_groups(count):
    class TOKEN_GROUPS(Structure):
        _fields_ = [('GroupCount', wintypes.DWORD), ('Groups', SID_AND_ATTRIBUTES * count)]
    return TOKEN_GROUPS


def get_token_groups():
    hToken = wintypes.HANDLE()
    dwLengthNeeded = wintypes.UINT()

    hProcess = GetCurrentProcess()
    bResult = OpenProcessToken(hProcess, TOKEN_QUERY, byref(hToken))
    assert bResult
    try:
        bResult = GetTokenInformation(hToken, TokenGroups, None, 0, byref(dwLengthNeeded))
        assert not bResult and GetLastError() == ERROR_INSUFFICIENT_BUFFER
        pGroups = LocalAlloc(0, dwLengthNeeded)
        assert pGroups
        try:
            bResult = GetTokenInformation(hToken, TokenGroups, pGroups, dwLengthNeeded, byref(dwLengthNeeded))
            groups_count = cast(pGroups, POINTER(wintypes.ULONG))[0]
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
    cbSidSize = wintypes.DWORD(SECURITY_MAX_SID_SIZE)
    pSid = LocalAlloc(0, SECURITY_MAX_SID_SIZE)
    assert pSid
    Sid = cast(pSid, POINTER(SID))
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
    # admin SID not found in token groups
    return False
