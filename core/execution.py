"""Safe subprocess execution utilities for external commands."""

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Mapping

from .errors import CommandExecutionError, CommandNotFoundError, CommandTimeoutError

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of an executed external command."""
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def is_tool_available(binary_name: str) -> bool:
    """Check if an executable binary exists in the current system PATH."""
    return shutil.which(binary_name) is not None


def run_command(
    command: list[str],
    timeout: float = 5.0,
    check: bool = True,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
) -> CommandResult:
    """Run an external command safely without shell=True.

    Args:
        command: List of command arguments.
        timeout: Maximum seconds to wait before raising CommandTimeoutError.
        check: If True, raises CommandExecutionError on non-zero return code.
        env: Optional environment variables dictionary.
        cwd: Optional working directory.

    Returns:
        CommandResult with returncode, stdout, and stderr.

    Raises:
        CommandNotFoundError: If binary does not exist in PATH.
        CommandTimeoutError: If execution exceeds timeout.
        CommandExecutionError: If check=True and returncode != 0.
    """
    if not command:
        raise ValueError("Cannot run empty command list.")

    binary = command[0]
    if not is_tool_available(binary):
        raise CommandNotFoundError(binary)

    logger.debug("Executing command: %s (timeout=%.1fs)", " ".join(command), timeout)

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
            shell=False,
        )
        result = CommandResult(
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
        if check and proc.returncode != 0:
            raise CommandExecutionError(
                command=command,
                returncode=proc.returncode,
                stderr=proc.stderr,
                stdout=proc.stdout,
            )
        return result

    except subprocess.TimeoutExpired as err:
        logger.warning("Command timed out: %s", " ".join(command))
        if check:
            raise CommandTimeoutError(command=command, timeout_seconds=timeout) from err
        return CommandResult(
            command=command,
            returncode=-1,
            stdout=err.stdout.decode() if isinstance(err.stdout, bytes) else (err.stdout or ""),
            stderr=err.stderr.decode() if isinstance(err.stderr, bytes) else (err.stderr or ""),
            timed_out=True,
        )
    except FileNotFoundError as err:
        raise CommandNotFoundError(binary) from err
