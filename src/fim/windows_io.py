"""Windows handles for safe scanning without traversing reparse points.

Only imported on Windows. Directory handles omit FILE_SHARE_DELETE so that
an ancestor cannot be renamed/replaced while its children are being read.
"""

import ctypes
import msvcrt
import os
from contextlib import ExitStack, contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import Iterator

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_SHARE_READ_WRITE = 0x3
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000


class FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation", wintypes.FILETIME),
        ("access", wintypes.FILETIME),
        ("write", wintypes.FILETIME),
        ("volume", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE,
                                               ctypes.POINTER(FileInformation)]
kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def _open_handle(path: Path, *, directory: bool) -> int:
    """Open the entry itself and reject links/junctions before reading data."""
    handle = kernel32.CreateFileW(
        # Metadata-only opens do not enforce share restrictions on Windows.
        # GENERIC_READ is required even for directory handles.
        str(path), GENERIC_READ,
        FILE_SHARE_READ_WRITE, None, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = FileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(f"Refusing reparse point: {path}")
        if bool(info.attributes & FILE_ATTRIBUTE_DIRECTORY) != directory:
            raise OSError(f"Unexpected file type: {path}")
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
    return handle


@contextmanager
def pin_directory(path: Path) -> Iterator[None]:
    """Hold a directory in place while enumerating and reading descendants."""
    handle = _open_handle(path, directory=True)
    try:
        yield
    finally:
        kernel32.CloseHandle(handle)


@contextmanager
def pin_directory_chain(directory: Path) -> Iterator[None]:
    """Pin ancestors from the drive/share root down to the target directory."""
    with ExitStack() as stack:
        for path in [*reversed(directory.parents), directory]:
            stack.enter_context(pin_directory(path))
        yield


def open_file_fd(path: Path) -> int:
    """Transfer a verified native handle to a Python binary file descriptor."""
    handle = _open_handle(path, directory=False)
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
