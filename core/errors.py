"""Custom exception hierarchy for Network Intelligence Toolkit."""


class ToolkitError(Exception):
    """Base exception for all toolkit errors."""
    pass


class PlatformNotSupportedError(ToolkitError):
    """Raised when running on an unsupported operating system."""
    pass


class CommandExecutionError(ToolkitError):
    """Raised when an external command fails with a non-zero exit status."""

    def __init__(self, command: list[str], returncode: int, stderr: str = "", stdout: str = "") -> None:
        cmd_str = " ".join(command)
        message = f"Command '{cmd_str}' failed with exit code {returncode}: {stderr.strip() or stdout.strip()}"
        super().__init__(message)
        self.command = command
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


class CommandNotFoundError(ToolkitError):
    """Raised when an external executable is missing from PATH."""

    def __init__(self, binary_name: str) -> None:
        super().__init__(f"Required binary '{binary_name}' was not found in system PATH.")
        self.binary_name = binary_name


class CommandTimeoutError(ToolkitError):
    """Raised when an external command times out."""

    def __init__(self, command: list[str], timeout_seconds: float) -> None:
        cmd_str = " ".join(command)
        super().__init__(f"Command '{cmd_str}' timed out after {timeout_seconds}s.")
        self.command = command
        self.timeout_seconds = timeout_seconds


class ParsingError(ToolkitError):
    """Raised when failing to parse command output or system file."""

    def __init__(self, source: str, details: str) -> None:
        super().__init__(f"Failed to parse data from {source}: {details}")
        self.source = source
        self.details = details


class CapabilityUnavailableError(ToolkitError):
    """Raised when an explicitly requested feature is unavailable on this platform."""

    def __init__(self, feature_name: str, reason: str) -> None:
        super().__init__(f"Capability '{feature_name}' is unavailable: {reason}")
        self.feature_name = feature_name
        self.reason = reason


class InterfaceNotFoundError(ToolkitError):
    """Raised when the specified or requested interface does not exist."""

    def __init__(self, interface_name: str) -> None:
        super().__init__(f"Interface '{interface_name}' not found on this system.")
        self.interface_name = interface_name


class PcapAnalysisError(ToolkitError):
    """Raised when PCAP parsing fails or tshark encounter fatal errors."""
    pass


class SnapshotError(ToolkitError):
    """Raised when saving or loading snapshot files fails."""
    pass
