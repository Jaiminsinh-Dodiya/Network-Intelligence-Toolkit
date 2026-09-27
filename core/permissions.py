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


def check_permissions() -> dict[str, Any]:
    """Inspect current privilege level and collect advisory notices."""
    privileged = is_privileged()
    user = get_current_user()
    system = platform.system()

    advisories: list[str] = []
    if not privileged:
        if system == "Windows":
            advisories.append(
                "Running without Administrator privileges. "
                "Process names for sockets owned by system or other accounts may be restricted."
            )
        else:
            advisories.append(
                "Running without root privileges (UID != 0). "
                "Socket process names, raw ICMP sockets, and certain DHCP lease paths (/var/lib/dhcp) may be restricted."
            )

    return {
        "is_privileged": privileged,
        "user": user,
        "platform": system,
        "advisories": advisories,
    }
