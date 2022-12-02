import json
import sys
from typing import Any, Dict, List

from cleo.helpers import option
from poetry.console.commands.command import Command

from poetry_audit_plugin import __version__
from poetry_audit_plugin.safety import Package, Vulnerability, check_vulnerabilities


class AuditCommand(Command):
    name = "audit"
    description = "Check vulnerabilities in dependencies"

    options = [
        option("json", None, "Generate a JSON payload with the information of vulnerable packages.", flag=True),
        option("ignore-code", None, "Ignore vulnerability code", flag=False),
        option("ignore-package", None, "Ignore packages", flag=False),
    ]

    def handle(self) -> None:
        self.validate_lock_file()

        self.line("<b># poetry audit report</b>")
        self.line("<info>Loading...</info>")

        locked_repo = self.poetry.locker.locked_repository()
        packages: List[Package] = []
        for locked_package in locked_repo.packages:
            packages.append(Package(name=str(locked_package.name), version=str(locked_package.version)))

        self.line(f"<info>Scanning {len(packages)} packages...</info>")
        self.line("")

        all_vulnerabilities = check_vulnerabilities(packages)
        vulnerabilities, amount_ignored = self.iter_vulner(all_vulnerabilities)
        max_line_lengths = self.calculate_line_length(vulnerabilities)
        amount_vulner = len(vulnerabilities)
        if self.option("json"):
            json_report = self.get_json_report(vulnerabilities)
            self.chatty_line(json_report)
            if amount_vulner > 0:
                sys.exit(1)
        else:
            vulnerability_num = 0
            for vulnerability in vulnerabilities:
                for detail in vulnerability.details:
                    vulnerability_message = (
                        "  <options=bold>•</> "
                        f"<c1>{vulnerability.name:{max_line_lengths['name']}}</c1>"
                        f"  installed <success>{vulnerability.version:{max_line_lengths['version']}}</success>"
                        f"  affected <success>{detail.spec:{max_line_lengths['spec']}}</success>"
                        f"  CVE <success>{detail.cve:{max_line_lengths['cve']}}</success>"
                    )
                    self.line(vulnerability_message)
                    vulnerability_num += 1
            if amount_vulner > 0:
                self.line("")
                self.line(
                    f"<error>{vulnerability_num}</error> <b>vulnerabilities found in {amount_vulner} packages</b>"
                )
                self.line(f"<error>{amount_ignored}</error> <b>vulnerabilities found but ignored</b>")
                sys.exit(1)
            else:
                self.line("<b>Vulnerabilities not found</b> ✨✨")
                self.line(f"<error>{amount_ignored}</error> <b>vulnerabilities found but ignored</b>")
                sys.exit(0)

    def line(self, *args: Any, **kwargs: Any) -> None:
        if not self.is_quiet():
            super().line(*args, **kwargs)

    def line_error(self, *args: Any, **kwargs: Any) -> None:
        if not self.is_quiet():
            super().line_error(*args, **kwargs)

    def chatty_line(self, *args: Any, **kwargs: Any) -> None:
        super().line(*args, **kwargs)

    def chatty_line_error(self, *args: Any, **kwargs: Any) -> None:
        super().line(*args, **kwargs)

    def is_quiet(self) -> bool:
        if self.option("json"):
            return True
        return False

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

    def calculate_line_length(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        keys = ["name", "version", "spec", "cve"]
        max_line_lengths = {key: 0 for key in keys}
        for vulnerability in vulnerabilities:
            for detail in vulnerability.details:
                for key in keys:
                    if getattr(vulnerability, key, None):
                        line_length = len(getattr(vulnerability, key))
                    else:
                        line_length = len(getattr(detail, key))

                    max_line_length = max_line_lengths[key]
                    if line_length > max_line_length:
                        max_line_lengths[key] = line_length

        return max_line_lengths

    def get_json_report(self, vulnerabilities: List[Vulnerability]) -> str:
        locker = self.poetry.locker
        formatted_vulnerabilities = [vulnerability.format() for vulnerability in vulnerabilities]
        json_report_dict = {
            "vulnerabilities": formatted_vulnerabilities,
            "metadata": {
                "auditVersion": __version__,
                "poetry.lock": {
                    "updated": not locker.is_locked(),
                    "fresh": locker.is_fresh(),
                },
            },
        }
        return json.dumps(json_report_dict, indent=2)

    def get_suppressions(self):
        ignored_packages = []
        codes = []
        if self.option("ignore-package"):
            ignored_packages = self.option("ignore-package").split(",")
        if self.option("ignore-code"):
            codes = self.option("ignore-code").split(",")
        return ignored_packages, codes

    def check_details(self, vulner, codes):
        new_details = []
        ignored_vulns = 0
        for detail in vulner.details:
            if detail.cve not in codes:
                new_details.append(detail)
            else:
                ignored_vulns += 1
        return ignored_vulns, new_details

    def iter_vulner(self, vulnerabilities):
        filtered = []
        ignored_vulns = 0
        ignored_packages, codes = self.get_suppressions()
        is_ignore_packages = self.option("ignore-package")
        is_ignore_codes = self.option("ignore-code")
        for vulner in vulnerabilities:
            new_ignored = 0
            if is_ignore_packages:
                if vulner.name in ignored_packages:
                    ignored_vulns += 1
                    continue
            if is_ignore_codes:
                new_ignored, vulner.details = self.check_details(vulner, codes)
            if len(vulner.details) > 0:
                filtered.append(vulner)
            ignored_vulns += new_ignored
        return filtered, ignored_vulns


def factory():
    return AuditCommand()
