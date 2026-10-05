"""Create private local objects without a window of inherited Windows access.

Windows objects have a protected DACL granting the process token's user and
SYSTEM only. POSIX objects use owner-only modes. Existing objects are checked,
never silently chmod'ed or assigned a new DACL. These controls do not isolate
an application from another process running as the same user, SYSTEM/root, or
an administrator able to take ownership.
"""

from __future__ import annotations

import ctypes
import os
import stat
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO


class PrivateStorageError(OSError):
    """A local storage object cannot be proven private and unlinked."""


def _path(value: str | Path) -> Path:
    if "\x00" in str(value):
        raise PrivateStorageError("Invalid private storage path.")
    candidate = Path(value)
    if ".." in candidate.parts:
        raise PrivateStorageError("Parent traversal is not supported for private storage.")
    result = Path(os.path.abspath(candidate))
    if os.name == "nt":
        if not result.drive or result.drive.startswith("\\\\") or not result.root:
            raise PrivateStorageError("Private storage requires a local drive path.")
        devices = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        devices.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10))
        devices.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "¹²³")
        for part in result.parts[1:]:
            if ":" in part or part.endswith((" ", ".")) or part.split(".")[0].upper() in devices:
                raise PrivateStorageError("Ambiguous Windows paths are not supported.")
    return result


@lru_cache(maxsize=1)
def _windows() -> _Windows:
    return _Windows()


class _Windows:
    """Small, typed Win32 surface; no username lookup or command execution."""

    DIRECTORY = 0x10
    REPARSE = 0x400
    READ_CONTROL = 0x20000
    FILE_ALL_ACCESS = 0x1F01FF
    SYSTEM_SID = "S-1-5-18"

    def __init__(self) -> None:
        from ctypes import wintypes as wt

        self.wt = wt
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("length", wt.DWORD), ("descriptor", wt.LPVOID), ("inherit", wt.BOOL)]

        class TokenUser(ctypes.Structure):
            _fields_ = [("sid", wt.LPVOID), ("attributes", wt.DWORD)]

        class FileInfo(ctypes.Structure):
            _fields_ = [("attributes", wt.DWORD), ("created", wt.FILETIME),
                       ("accessed", wt.FILETIME), ("written", wt.FILETIME),
                       ("volume", wt.DWORD), ("size_high", wt.DWORD),
                       ("size_low", wt.DWORD), ("links", wt.DWORD),
                       ("index_high", wt.DWORD), ("index_low", wt.DWORD)]

        class Acl(ctypes.Structure):
            _fields_ = [("revision", wt.BYTE), ("reserved", wt.BYTE),
                       ("size", wt.WORD), ("count", wt.WORD), ("reserved2", wt.WORD)]

        class Ace(ctypes.Structure):
            _fields_ = [("kind", wt.BYTE), ("flags", wt.BYTE), ("size", wt.WORD),
                       ("mask", wt.DWORD)]

        class Disposition(ctypes.Structure):
            _fields_ = [("delete", wt.BOOL)]

        self.SecurityAttributes, self.TokenUser = SecurityAttributes, TokenUser
        self.FileInfo, self.Acl, self.Ace, self.Disposition = FileInfo, Acl, Ace, Disposition
        voidp, handle, dword = wt.LPVOID, wt.HANDLE, wt.DWORD
        self._bind(self.kernel, "GetCurrentProcess", [], handle)
        self._bind(self.kernel, "CloseHandle", [handle], wt.BOOL)
        self._bind(self.kernel, "LocalFree", [voidp], voidp)
        self._bind(self.kernel, "CreateFileW", [wt.LPCWSTR, dword, dword,
                   ctypes.POINTER(SecurityAttributes), dword, dword, handle], handle)
        self._bind(self.kernel, "CreateDirectoryW", [wt.LPCWSTR,
                   ctypes.POINTER(SecurityAttributes)], wt.BOOL)
        self._bind(self.kernel, "GetFileInformationByHandle", [handle,
                   ctypes.POINTER(FileInfo)], wt.BOOL)
        self._bind(self.kernel, "SetFileInformationByHandle", [handle, ctypes.c_int,
                   voidp, dword], wt.BOOL)
        self._bind(self.advapi, "OpenProcessToken", [handle, dword,
                   ctypes.POINTER(handle)], wt.BOOL)
        self._bind(self.advapi, "GetTokenInformation", [handle, ctypes.c_int, voidp,
                   dword, ctypes.POINTER(dword)], wt.BOOL)
        self._bind(self.advapi, "ConvertSidToStringSidW", [voidp,
                   ctypes.POINTER(wt.LPWSTR)], wt.BOOL)
        self._bind(self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                   [wt.LPCWSTR, dword, ctypes.POINTER(voidp), ctypes.POINTER(dword)], wt.BOOL)
        self._bind(self.advapi, "GetSecurityInfo", [handle, ctypes.c_int, dword,
                   ctypes.POINTER(voidp), ctypes.POINTER(voidp), ctypes.POINTER(voidp),
                   ctypes.POINTER(voidp), ctypes.POINTER(voidp)], dword)
        self._bind(self.advapi, "GetSecurityDescriptorControl", [voidp,
                   ctypes.POINTER(wt.WORD), ctypes.POINTER(dword)], wt.BOOL)
        self._bind(self.advapi, "GetAce", [voidp, dword, ctypes.POINTER(voidp)], wt.BOOL)
        self.invalid_handle = ctypes.c_void_p(-1).value

    @staticmethod
    def _bind(library, name, arguments, result) -> None:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result

    @staticmethod
    def _require(success) -> None:
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    def sid_string(self, sid) -> str:
        value = self.wt.LPWSTR()
        self._require(self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)))
        try:
            return value.value
        finally:
            self.kernel.LocalFree(ctypes.cast(value, self.wt.LPVOID))

    def current_sid(self) -> str:
        token = self.wt.HANDLE()
        self._require(self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x8,
                                                ctypes.byref(token)))
        try:
            length = self.wt.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
            if ctypes.get_last_error() != 122 or not 1 <= length.value <= 65536:
                raise PrivateStorageError("Cannot determine the process user SID.")
            buffer = ctypes.create_string_buffer(length.value)
            self._require(self.advapi.GetTokenInformation(token, 1, buffer,
                                                         length, ctypes.byref(length)))
            user = ctypes.cast(buffer, ctypes.POINTER(self.TokenUser)).contents
            return self.sid_string(user.sid)
        finally:
            self.kernel.CloseHandle(token)

    @contextmanager
    def attributes(self, *, directory: bool):
        sid = self.current_sid()
        flags = "OICI" if directory else ""
        trustees = dict.fromkeys((sid, self.SYSTEM_SID))
        acl = "".join(f"(A;{flags};FA;;;{trustee})" for trustee in trustees)
        descriptor = self.wt.LPVOID()
        self._require(self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{sid}D:P{acl}", 1, ctypes.byref(descriptor), None))
        attributes = self.SecurityAttributes(ctypes.sizeof(self.SecurityAttributes), descriptor, False)
        try:
            yield ctypes.byref(attributes)
        finally:
            self.kernel.LocalFree(descriptor)

    def open_directory(self, path: Path, *, check_acl: bool, created: bool = False):
        access = 0x80 | (self.READ_CONTROL if check_acl else 0) | (0x10000 if created else 0)
        handle = self.kernel.CreateFileW(str(path), access, 3, None, 3, 0x02200000, None)
        if handle == self.invalid_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def metadata(self, handle, *, directory: bool) -> None:
        information = self.FileInfo()
        self._require(self.kernel.GetFileInformationByHandle(handle, ctypes.byref(information)))
        if information.attributes & self.REPARSE or bool(information.attributes & self.DIRECTORY) != directory:
            raise PrivateStorageError("Private storage requires ordinary, unlinked objects.")
        if not directory and information.links != 1:
            raise PrivateStorageError("Hard-linked private files are not supported.")

    def acl_entries(self, handle) -> tuple[str, int, list[tuple[int, int, int, str]]]:
        owner, acl, descriptor = self.wt.LPVOID(), self.wt.LPVOID(), self.wt.LPVOID()
        error = self.advapi.GetSecurityInfo(handle, 1, 0x5, ctypes.byref(owner), None,
                                          ctypes.byref(acl), None, ctypes.byref(descriptor))
        if error:
            raise ctypes.WinError(error)
        try:
            control, revision = self.wt.WORD(), self.wt.DWORD()
            self._require(self.advapi.GetSecurityDescriptorControl(descriptor,
                         ctypes.byref(control), ctypes.byref(revision)))
            if not owner or not acl or not control.value & 0x4:
                raise PrivateStorageError("Private storage requires an explicit DACL and owner.")
            entries = []
            count = ctypes.cast(acl, ctypes.POINTER(self.Acl)).contents.count
            if not 1 <= count <= 2:
                raise PrivateStorageError("Private storage grants access to an unexpected principal.")
            for index in range(count):
                pointer = self.wt.LPVOID()
                self._require(self.advapi.GetAce(acl, index, ctypes.byref(pointer)))
                ace = ctypes.cast(pointer, ctypes.POINTER(self.Ace)).contents
                if ace.kind != 0 or ace.size < ctypes.sizeof(self.Ace) + 8:
                    raise PrivateStorageError("Private storage requires simple allow entries.")
                entries.append((ace.kind, ace.flags, ace.mask,
                                self.sid_string(pointer.value + ctypes.sizeof(self.Ace))))
            return self.sid_string(owner), control.value, entries
        finally:
            self.kernel.LocalFree(descriptor)

    def private(self, handle, *, directory: bool) -> None:
        self.metadata(handle, directory=directory)
        owner, control, entries = self.acl_entries(handle)
        sid = self.current_sid()
        expected = {(0, 3 if directory else 0, self.FILE_ALL_ACCESS, trustee)
                    for trustee in (sid, self.SYSTEM_SID)}
        if owner != sid or not control & 0x1000 or set(entries) != expected or len(entries) != len(expected):
            raise PrivateStorageError("Private storage must grant only its process user and SYSTEM.")

    def mark_delete(self, handle) -> None:
        information = self.Disposition(True)
        self._require(self.kernel.SetFileInformationByHandle(handle, 4,
                       ctypes.byref(information), ctypes.sizeof(information)))


def _posix_private(descriptor: int, *, directory: bool) -> None:
    information = os.fstat(descriptor)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(information.st_mode) or information.st_uid != os.geteuid():
        raise PrivateStorageError("Private storage must be an ordinary object owned by its process user.")
    if information.st_mode & 0o077 or (not directory and information.st_nlink != 1):
        raise PrivateStorageError("Private storage must have owner-only access and no hard links.")


@contextmanager
def _directories(path: Path, *, create: bool = False, check_final: bool = False):
    """Hold ancestor objects throughout lookup/creation, rejecting every link.

    Windows handles disallow delete/rename sharing. POSIX operations are relative
    to no-follow directory descriptors rather than a second path resolution.
    """
    opened = []
    try:
        if os.name == "nt":
            api = _windows()
            root = api.open_directory(Path(path.anchor), check_acl=False)
            opened.append(root)
            api.metadata(root, directory=True)
            current = Path(path.anchor)
            for index, name in enumerate(path.parts[1:]):
                current = current / name
                final = index == len(path.parts) - 2
                created = False
                try:
                    handle = api.open_directory(current, check_acl=check_final and final)
                except FileNotFoundError:
                    if not create:
                        raise
                    with api.attributes(directory=True) as attributes:
                        api._require(api.kernel.CreateDirectoryW(str(current), attributes))
                    created = True
                    handle = api.open_directory(current, check_acl=True, created=True)
                opened.append(handle)
                try:
                    api.metadata(handle, directory=True)
                    if created or (final and check_final):
                        api.private(handle, directory=True)
                except BaseException:
                    if created:
                        api.mark_delete(handle)
                    raise
            if check_final and len(path.parts) == 1:
                raise PrivateStorageError("A drive root cannot be an application private directory.")
        else:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            descriptor = os.open(path.anchor, flags)
            opened.append(descriptor)
            for index, name in enumerate(path.parts[1:]):
                try:
                    descriptor = os.open(name, flags, dir_fd=opened[-1])
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(name, mode=0o700, dir_fd=opened[-1])
                    descriptor = os.open(name, flags, dir_fd=opened[-1])
                    _posix_private(descriptor, directory=True)
                opened.append(descriptor)
                if check_final and index == len(path.parts) - 2:
                    _posix_private(descriptor, directory=True)
            if check_final and len(path.parts) == 1:
                _posix_private(descriptor, directory=True)
        yield opened[-1]
    finally:
        for handle in reversed(opened):
            if os.name == "nt":
                _windows().kernel.CloseHandle(handle)
            else:
                os.close(handle)


def check_private_directory(path: str | Path) -> None:
    """Fail closed unless an existing local directory has the private policy."""
    with _directories(_path(path), check_final=True):
        pass


def prepare_private_directory(path: str | Path, *, parents: bool = True) -> Path:
    """Create missing private directories; never change an existing DACL/mode."""
    destination = _path(path)
    if parents:
        with _directories(destination, create=True, check_final=True):
            pass
    else:
        try:
            create_private_directory(destination)
        except FileExistsError:
            check_private_directory(destination)
    return destination


def create_private_directory(path: str | Path) -> Path:
    """Create a NEW private directory atomically under an existing parent."""
    destination = _path(path)
    with _directories(destination.parent) as parent:
        if os.name == "nt":
            api = _windows()
            with api.attributes(directory=True) as attributes:
                api._require(api.kernel.CreateDirectoryW(str(destination), attributes))
            handle = api.open_directory(destination, check_acl=True, created=True)
            try:
                api.private(handle, directory=True)
            except BaseException:
                api.mark_delete(handle)
                raise
            finally:
                api.kernel.CloseHandle(handle)
        else:
            os.mkdir(destination.name, mode=0o700, dir_fd=parent)
            descriptor = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                 dir_fd=parent)
            try:
                _posix_private(descriptor, directory=True)
            finally:
                os.close(descriptor)
    return destination


def create_private_file(path: str | Path) -> BinaryIO:
    """Create a NEW private binary file; never overwrite or inherit a broad DACL."""
    destination = _path(path)
    with _directories(destination.parent) as parent:
        if os.name == "nt":
            import msvcrt

            api = _windows()
            with api.attributes(directory=False) as attributes:
                handle = api.kernel.CreateFileW(str(destination), 0xC0030000, 0,
                                                attributes, 1, 0x00200080, None)
            if handle == api.invalid_handle:
                raise ctypes.WinError(ctypes.get_last_error())
            descriptor = None
            try:
                api.private(handle, directory=False)
                descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
                return os.fdopen(descriptor, "w+b")
            except BaseException:
                api.mark_delete(handle)
                if descriptor is None:
                    api.kernel.CloseHandle(handle)
                else:
                    os.close(descriptor)
                raise
        descriptor = os.open(destination.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        try:
            _posix_private(descriptor, directory=False)
            return os.fdopen(descriptor, "w+b")
        except BaseException:
            os.unlink(destination.name, dir_fd=parent)
            os.close(descriptor)
            raise


def check_private_file(path: str | Path) -> None:
    """Validate an existing private regular file, including its hard-link count."""
    destination = _path(path)
    with _directories(destination.parent) as parent:
        if os.name == "nt":
            api = _windows()
            handle = api.kernel.CreateFileW(str(destination), api.READ_CONTROL | 0x80,
                                            3, None, 3, 0x00200080, None)
            if handle == api.invalid_handle:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                api.private(handle, directory=False)
            finally:
                api.kernel.CloseHandle(handle)
        else:
            descriptor = os.open(destination.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=parent)
            try:
                _posix_private(descriptor, directory=False)
            finally:
                os.close(descriptor)


def read_regular_file(path: str | Path) -> BinaryIO:
    """Open an ordinary, unlinked file on a checked path; no owner ACL policy.

    Secret mounts can be owned by a service or root. The returned read-only
    handle refers to the validated object even if a credential rotates through
    atomic replacement. Callers must bound bytes read before decoding content.
    """
    source = _path(path)
    with _directories(source.parent) as parent:
        if os.name == "nt":
            import msvcrt

            api = _windows()
            handle = api.kernel.CreateFileW(str(source), 0x80000000, 7, None, 3,
                                            0x02200000, None)
            if handle == api.invalid_handle:
                raise ctypes.WinError(ctypes.get_last_error())
            descriptor = None
            try:
                api.metadata(handle, directory=False)
                descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
                return os.fdopen(descriptor, "rb")
            except BaseException:
                if descriptor is None:
                    api.kernel.CloseHandle(handle)
                else:
                    os.close(descriptor)
                raise
        descriptor = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        try:
            information = os.fstat(descriptor)
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                raise PrivateStorageError("Private storage requires an ordinary, unlinked file.")
            return os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
