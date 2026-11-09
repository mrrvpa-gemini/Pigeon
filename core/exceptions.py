"""Custom exception types for the project."""


class RvpaToolkitError(Exception):
    """Base exception for the toolkit."""


class ValidationError(RvpaToolkitError):
    """Raised when user-provided input cannot be validated."""


class NetworkError(RvpaToolkitError):
    """Raised when a network operation fails."""
