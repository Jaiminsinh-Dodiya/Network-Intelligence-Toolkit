"""Platform backend selection factory.

Centralized platform factory mapping the operating system to the appropriate backend.
"""

from __future__ import annotations

import platform
from backends.base import BasePlatformBackend
from core.errors import PlatformNotSupportedError

_CACHED_BACKEND: BasePlatformBackend | None = None


def get_platform_backend(system_override: str | None = None) -> BasePlatformBackend:
    """Detect operating system and return the appropriate PlatformBackend.

    Args:
        system_override: Optional system name override ('Windows', 'Linux') for testing.

    Returns:
        Instance of BasePlatformBackend (WindowsBackend or LinuxBackend).

    Raises:
        PlatformNotSupportedError: If operating system is not supported.
    """
    global _CACHED_BACKEND
    system = system_override or platform.system()

    if system_override is None and _CACHED_BACKEND is not None:
        return _CACHED_BACKEND

    if system == "Windows":
        from backends.windows import WindowsBackend
        backend = WindowsBackend()
    elif system == "Linux":
        from backends.linux import LinuxBackend
        backend = LinuxBackend()
    else:
        raise PlatformNotSupportedError(
            f"Operating system '{system}' is not currently supported. "
            "Supported platforms are Windows 10/11 and Kali Linux / Linux."
        )

    if system_override is None:
        _CACHED_BACKEND = backend

    return backend


__all__ = ["BasePlatformBackend", "get_platform_backend"]
