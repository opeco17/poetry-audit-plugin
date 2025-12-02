import copy
import json
from typing import Any, Dict, List, Tuple

from cleo.helpers import option
from poetry.console.commands.command import Command

from poetry_audit_plugin import __version__
from poetry_audit_plugin.constants import EXIT_CODE_OK, EXIT_CODE_VULNERABILITY_FOUND
from poetry_audit_plugin.errors import (
    SafetyDBAccessError,
    SafetyDBSessionBuildError,
    ValidationError,
)
from poetry_audit_plugin.safety import (
    Package,
    Vulnerability,
    VulnerablePackage,
    build_safety_db_session,
    check_vulnerable_packages,
)


class AuditCommand(Command):
    name = "audit"
    description = "Check vulnerabilities in dependencies"

    options = [
        option(
            long_name="json",
            description="Generate a JSON payload with the information of vulnerable packages.",
            flag=True,
        ),
        option(
            long_name="ignore-code",
            description="Ignore specified vulnerability codes.",
            flag=False,
        ),
        option(
            long_name="ignore-package",
            description="Ignore specified packages.",
            flag=False,
        ),
        option(
            long_name="proxy-protocol",
            description="Protocol of proxy to access Safety DB.",
            flag=False,
            value_required=False,
            default="http",
        ),
        option(
            long_name="proxy-host",
            description="Host of proxy to access Safety DB.",
            flag=False,
            value_required=False,
        ),
        option(
            long_name="proxy-port",
            description="Port of proxy to access Safety DB.",
            flag=False,
            value_required=False,
            default="80",
        ),
        option(
            long_name="cache-sec",
            description="How long Safety DB can be cached locally.",
            flag=False,
            value_required=False,
            default="0",
        ),
        option(
            long_name="db-path",
            description="Path to a local or remote vulnerability database of Safety.",
            flag=False,
            value_required=False,
            default=None,
        ),
    ]

    def handle(self) -> int:
        self.is_quiet = self.option("json")

        self.line("<b># poetry audit report</b>")
        self.line("")

        try:
            self.validate_options()
        except ValidationError as e:
            self.chatty_line_error("<error>Command line option(s) are invalid</error>")
            self.chatty_line_error("")
            self.chatty_line_error(str(e))
            return e.get_exit_code()

        self.validate_lock_file()

        self.line("<info>Loading...</info>")

        locked_repo = self.poetry.locker.locked_repository()
        packages: List[Package] = []
        for locked_package in locked_repo.packages:
            packages.append(Package(name=str(locked_package.name), version=str(locked_package.version)))

        self.line(f"<info>Scanning {len(packages)} packages...</info>")
        self.line("")

        ignored_packages: List[str] = self.option("ignore-package").split(",") if self.option("ignore-package") else []
        ignored_codes: List[str] = self.option("ignore-code").split(",") if self.option("ignore-code") else []
        is_ignore = bool(len(ignored_packages) or len(ignored_codes))
        try:
            # TODO: Pass auth key to build_client_session function for advanced safety usage.
            session = build_safety_db_session(
                proxy_protocol=self.option("proxy-protocol"),
                proxy_host=self.option("proxy-host"),
                proxy_port=int(self.option("proxy-port")) if self.option("proxy-port") else None,
            )
        except SafetyDBSessionBuildError as e:
            self.chatty_line_error("<error>Error occured while building Safety DB session.</error>")
            self.chatty_line_error("")
            self.chatty_line_error(str(e))
            return e.get_exit_code()
        try:
            all_vulnerable_packages = check_vulnerable_packages(
                packages,
                session,
                int(self.option("cache-sec")) if self.option("cache-sec") else 0,
                self.option("db-path"),
            )
        except SafetyDBAccessError as e:
            self.chatty_line_error("<error>Error occured while accessing Safety DB.</error>")
            self.chatty_line_error("")
            self.chatty_line_error(str(e))
            return e.get_exit_code()

        vulnerable_packages, amount_of_ignored_vulnerabilities = self.filter_vulnerable_packages(
            all_vulnerable_packages,
            ignored_packages,
            ignored_codes,
        )
        max_line_lengths = self.calculate_line_length(vulnerable_packages)
        amount_of_vulnerable_packages = len(vulnerable_packages)
        if self.option("json"):
            json_report = self.get_json_report(vulnerable_packages)
            self.chatty_line(json_report)
            if amount_of_vulnerable_packages > 0:
                return EXIT_CODE_VULNERABILITY_FOUND
            else:
                return EXIT_CODE_OK
        else:
            amount_of_vulnerabilities = 0
            for vulnerable_package in vulnerable_packages:
                for vulnerability in vulnerable_package.vulnerabilities:
                    vulnerability_message = (
                        "  <options=bold>•</> "
                        f"<c1>{vulnerable_package.name:{max_line_lengths['name']}}</c1>"
                        f"  installed <success>{vulnerable_package.version:{max_line_lengths['version']}}</success>"
                        f"  affected <success>{vulnerability.spec:{max_line_lengths['spec']}}</success>"
                        f"  CVE <success>{vulnerability.cve:{max_line_lengths['cve']}}</success>"
                    )
                    self.line(vulnerability_message)
                    amount_of_vulnerabilities += 1

            if amount_of_vulnerable_packages > 0:
                self.line("")

            if is_ignore:
                self.line(
                    f"<error>{amount_of_ignored_vulnerabilities}</error> <b>vulnerabilities found but ignored</b>"
                )

            if amount_of_vulnerable_packages > 0:
                self.line(
                    f"<error>{amount_of_vulnerabilities}</error> <b>vulnerabilities found in {amount_of_vulnerable_packages} packages</b>"
                )
                return EXIT_CODE_VULNERABILITY_FOUND
            else:
                self.line("<b>No vulnerabilities found</b> ✨✨")
                return EXIT_CODE_OK

    def line(self, *args: Any, **kwargs: Any) -> None:
        if not self.is_quiet:
            super().line(*args, **kwargs)

    def line_error(self, *args: Any, **kwargs: Any) -> None:
        if not self.is_quiet:
            super().line_error(*args, **kwargs)

    def chatty_line(self, *args: Any, **kwargs: Any) -> None:
        super().line(*args, **kwargs)

    def chatty_line_error(self, *args: Any, **kwargs: Any) -> None:
        super().line_error(*args, **kwargs)

    def validate_options(self) -> None:
        errors: List[str] = []
        if self.option("proxy-host") and (not self.option("proxy-protocol") or not self.option("proxy-port")):
            errors.append("proxy-protocol and proxy-port should not be empty when proxy-host is specified.")

        if self.option("proxy-protocol") and (self.option("proxy-protocol") not in ["http", "https"]):
            errors.append("proxy-protocol should be http or https.")

        if self.option("proxy-port") and not self.option("proxy-port").isnumeric():
            errors.append("proxy-port should be number.")

        if self.option("cache-sec") and not self.option("cache-sec").isnumeric():
            errors.append("cache-sec be number")

        if errors:
            raise ValidationError("\n".join(errors))

    def validate_lock_file(self) -> None:
        # Ref: https://github.com/python-poetry/poetry/blob/1.2.0b1/src/poetry/console/commands/export.py#L40
        locker = self.poetry.locker
        if not locker.is_locked():
            self.line_error("<comment>The lock file does not exist. Locking.</comment>")
            option = "quiet" if self.is_quiet else None
            self.call("lock", option)
            self.line("")

        if not locker.is_fresh():
            self.line_error(
                "<warning>"
                "Warning: The lock file is not up to date with "
                "the latest changes in pyproject.toml. "
                "You may be getting outdated dependencies. "
                "Run update to update them."
                "</warning>"
            )
            self.line("")

    def calculate_line_length(self, vulnerable_packages: List[VulnerablePackage]) -> Dict[str, int]:
        keys = ["name", "version", "spec", "cve"]
        max_line_lengths = {key: 0 for key in keys}
        for vulnerable_package in vulnerable_packages:
            for vulnerability in vulnerable_package.vulnerabilities:
                for key in keys:
                    if getattr(vulnerable_package, key, None):
                        line_length = len(getattr(vulnerable_package, key))
                    else:
                        line_length = len(getattr(vulnerability, key))

                    if line_length > max_line_lengths[key]:
                        max_line_lengths[key] = line_length

        return max_line_lengths

    def get_json_report(self, vulnerable_packages: List[VulnerablePackage]) -> str:
        locker = self.poetry.locker
        formatted_vulnerable_packages = [vulnerable_package.format() for vulnerable_package in vulnerable_packages]
        json_report_dict = {
            "vulnerabilities": formatted_vulnerable_packages,
            "metadata": {
                "auditVersion": __version__,
                "poetry.lock": {
                    "updated": not locker.is_locked(),
                    "fresh": locker.is_fresh(),
                },
            },
        }
        return json.dumps(json_report_dict, indent=2)

    def filter_vulnerable_packages(
        self, vulnerable_packages: List[VulnerablePackage], ignored_packages: List[str], ignored_codes: List[str]
    ) -> Tuple[List[VulnerablePackage], int]:
        filtered_vulnerable_packages: List[VulnerablePackage] = []
        amount_of_ignored_vulnerabilities = 0

        is_ignore_packages = len(ignored_packages) > 0
        is_ignore_codes = len(ignored_codes) > 0

        for vulnerable_package in vulnerable_packages:
            filtered_vulnerable_package = copy.copy(vulnerable_package)
            if is_ignore_packages:
                if vulnerable_package.name in ignored_packages:
                    amount_of_ignored_vulnerabilities += len(vulnerable_package.vulnerabilities)
                    continue

            if is_ignore_codes:
                filtered_vulnerabilities: List[Vulnerability] = []
                for vulnerability in vulnerable_package.vulnerabilities:
                    if vulnerability.cve not in ignored_codes:
                        filtered_vulnerabilities.append(vulnerability)
                    else:
                        amount_of_ignored_vulnerabilities += 1

                if len(filtered_vulnerabilities):
                    filtered_vulnerable_package.vulnerabilities = filtered_vulnerabilities
                else:
                    continue

            filtered_vulnerable_packages.append(filtered_vulnerable_package)

        return filtered_vulnerable_packages, amount_of_ignored_vulnerabilities


def factory():
    return AuditCommand()
