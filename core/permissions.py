"""Cross-platform privilege and permission detection."""

import os
import platform
import getpass
from typing import Any


def is_privileged() -> bool:
    """Check if the current process has elevated/root/administrator privileges."""
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        # Linux / Unix
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def get_current_user() -> str:
    """Get the current username safely."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
