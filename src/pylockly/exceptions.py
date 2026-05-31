"""Exceptions for the Lockly API client."""


class LocklyError(Exception):
    """Base exception for all Lockly errors."""


class LocklyAuthError(LocklyError):
    """Authentication failed (bad credentials, expired token, etc.)."""


class LocklyApiError(LocklyError):
    """REST API returned a non-200 cod value."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Lockly API error {code}: {message}")


class LocklyMqttError(LocklyError):
    """MQTT connection or command error."""


class LocklyTimeoutError(LocklyError):
    """A request or MQTT response timed out."""
