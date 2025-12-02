from poetry_audit_plugin.constants import (
    EXIT_CODE_OPTION_INVALID,
    EXIT_CODE_SAFETY_DB_ACCESS_ERROR,
    EXIT_CODE_SAFETY_DB_SESSION_BUILD_ERROR,
)


class ValidationError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        return EXIT_CODE_OPTION_INVALID


class SafetyDBSessionBuildError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        return EXIT_CODE_SAFETY_DB_SESSION_BUILD_ERROR


class SafetyDBAccessError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        return EXIT_CODE_SAFETY_DB_ACCESS_ERROR
