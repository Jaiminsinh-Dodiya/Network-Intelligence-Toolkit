"""Unit tests for safe command execution."""

import sys
import pytest
from core.errors import CommandExecutionError, CommandNotFoundError, CommandTimeoutError
from core.execution import run_command, is_tool_available


def test_run_command_success():
    cmd = [sys.executable, "-c", "import sys; sys.stdout.write('net-intel-ok')"]
    result = run_command(cmd, timeout=5.0)
    assert result.success is True
    assert result.returncode == 0
    assert result.stdout == "net-intel-ok"


def test_run_command_failure_with_check():
    cmd = [sys.executable, "-c", "import sys; sys.exit(42)"]
    with pytest.raises(CommandExecutionError) as exc_info:
        run_command(cmd, timeout=5.0, check=True)
    assert exc_info.value.returncode == 42


def test_run_command_failure_without_check():
    cmd = [sys.executable, "-c", "import sys; sys.exit(42)"]
    result = run_command(cmd, timeout=5.0, check=False)
    assert result.success is False
    assert result.returncode == 42


def test_run_command_missing_binary():
    cmd = ["nonexistent_binary_xyz_12345", "--version"]
    with pytest.raises(CommandNotFoundError):
        run_command(cmd, timeout=2.0)


def test_run_command_timeout():
    cmd = [sys.executable, "-c", "import time; time.sleep(3.0)"]
    with pytest.raises(CommandTimeoutError):
        run_command(cmd, timeout=0.5, check=True)


def test_run_empty_command_raises():
    with pytest.raises(ValueError):
        run_command([], timeout=1.0)


def test_is_tool_available():
    assert is_tool_available("python") or is_tool_available("python3")
    assert not is_tool_available("definitely_not_a_real_binary_abc_123")
