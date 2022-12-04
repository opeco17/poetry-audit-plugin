import json
import sys
from typing import Any, Dict, List

from cleo.helpers import option
from poetry.console.commands.command import Command

from poetry_audit_plugin import __version__
from poetry_audit_plugin.safety import (
    Package,
    VulnerablePackage,
    check_vulnerable_packages,
    suppress_vulnerable_packages,
)


class AuditCommand(Command):
    name = "audit"
    description = "Check vulnerabilities in dependencies"

    options = [
        option("json", None, "Generate a JSON payload with the information of vulnerable packages.", flag=True),
        option("ignore-code", None, "Ignore specified vulnerability codes", flag=False),
        option("ignore-package", None, "Ignore specified packages", flag=False),
    ]

    def handle(self) -> None:
        self.is_quiet = self.option("json")

        self.validate_lock_file()

        self.line("<b># poetry audit report</b>")
        self.line("<info>Loading...</info>")

        locked_repo = self.poetry.locker.locked_repository()
        packages: List[Package] = []
        for locked_package in locked_repo.packages:
            packages.append(Package(name=str(locked_package.name), version=str(locked_package.version)))

        self.line(f"<info>Scanning {len(packages)} packages...</info>")
        self.line("")

        all_vulnerable_packages = check_vulnerable_packages(packages)

        ignored_packages: List[str] = self.option("ignore-package").split(",") if self.option("ignore-package") else []
        ignored_codes: List[str] = self.option("ignore-code").split(",") if self.option("ignore-code") else []
        is_ignore = bool(len(ignored_packages) or len(ignored_codes))
        vulnerable_packages, amount_of_ignored_vulnerabilities = suppress_vulnerable_packages(
            all_vulnerable_packages, ignored_packages, ignored_codes
        )

        max_line_lengths = self.calculate_line_length(vulnerable_packages)
        amount_of_vulnerable_packages = len(vulnerable_packages)
        if self.option("json"):
            json_report = self.get_json_report(vulnerable_packages)
            self.chatty_line(json_report)
            if amount_of_vulnerable_packages > 0:
                sys.exit(1)
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
                sys.exit(1)
            else:
                self.line("<b>Vulnerabilities not found</b> ✨✨")
                sys.exit(0)

    def line(self, *args: Any, **kwargs: Any) -> None:
        if not self.is_quiet:
            super().line(*args, **kwargs)

    def line_error(self, *args: Any, **kwargs: Any) -> None:
        if not self.is_quiet:
            super().line_error(*args, **kwargs)

    def chatty_line(self, *args: Any, **kwargs: Any) -> None:
        super().line(*args, **kwargs)

    def chatty_line_error(self, *args: Any, **kwargs: Any) -> None:
        super().line(*args, **kwargs)

    def validate_lock_file(self) -> None:
        locker = self.poetry.locker
        if not locker.is_locked():
            self.line_error("<comment>The lock file does not exist. Locking.</comment>")
            option = "quiet" if self.is_quiet() else None
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

                    max_line_length = max_line_lengths[key]
                    if line_length > max_line_length:
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


def factory():
    return AuditCommand()
