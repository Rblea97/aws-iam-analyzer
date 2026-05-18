"""Scanner-specific exception types."""


class ScannerError(Exception):
    """Base class for scanner failures safe to surface to CLI callers."""


class CredentialError(ScannerError):
    """Raised when AWS credentials cannot be resolved or validated."""


class ScannerConnectionError(ScannerError):
    """Raised when AWS service endpoints cannot be reached."""


class ScannerConfigurationError(ScannerError):
    """Raised when scanner configuration prevents a safe scan."""
