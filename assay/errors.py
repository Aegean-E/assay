"""Failures that carry the Error/Why/Fix triad printed by the command line."""


class AssayError(Exception):
    """A user-actionable failure; `exit_code` follows the 0/1/2 contract."""

    def __init__(self, message: str, why: str, fix: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.message = message
        self.why = why
        self.fix = fix
        self.exit_code = exit_code


class ValidationError(AssayError):
    """An event or policy document breaks the declared contract."""


class LedgerError(AssayError):
    """The ledger cannot be read, appended or verified."""
