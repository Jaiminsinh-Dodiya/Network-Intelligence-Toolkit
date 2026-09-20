"""Unit tests for platform factory and backend abstractions."""

import pytest
from core.errors import PlatformNotSupportedError
from backends import get_platform_backend, BasePlatformBackend
from backends.windows import WindowsBackend
from backends.linux import LinuxBackend


def test_platform_factory_windows_override():
    backend = get_platform_backend(system_override="Windows")
    assert isinstance(backend, WindowsBackend)
    assert isinstance(backend, BasePlatformBackend)
    assert backend.get_platform_name() == "Windows"


def test_platform_factory_linux_override():
    backend = get_platform_backend(system_override="Linux")
    assert isinstance(backend, LinuxBackend)
    assert isinstance(backend, BasePlatformBackend)
    assert backend.get_platform_name() == "Linux"


def test_platform_factory_unsupported():
    with pytest.raises(PlatformNotSupportedError):
        get_platform_backend(system_override="Solaris")


def test_windows_backend_capabilities_non_empty():
    backend = WindowsBackend()
    caps = backend.detect_capabilities()
    assert "interface_info" in caps
    assert "linux_kernel_info" in caps
    assert caps["linux_kernel_info"].status.value == "NOT_APPLICABLE"


def test_linux_backend_capabilities_non_empty():
    backend = LinuxBackend()
    caps = backend.detect_capabilities()
    assert "interface_info" in caps
    assert "linux_kernel_info" in caps


def test_linux_kernel_info_capability_distinction():
    """Verify linux_kernel_info is NOT_APPLICABLE on Windows and PLANNED on Linux."""
    win_caps = WindowsBackend().detect_capabilities()
    assert win_caps["linux_kernel_info"].status.value == "NOT_APPLICABLE"
    assert win_caps["linux_kernel_info"].toolkit_status == "NOT_APPLICABLE"

    linux_caps = LinuxBackend().detect_capabilities()
    assert linux_caps["linux_kernel_info"].status.value in ("AVAILABLE", "PARTIAL")
    assert linux_caps["linux_kernel_info"].toolkit_status == "PLANNED"
