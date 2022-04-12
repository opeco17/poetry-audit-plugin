from typing import Dict, List

from poetry.console.commands.command import Command

from poetry_audit_plugin.safety import Package, Vulnerability, check_vulnerabilities


class AuditCommand(Command):
    name = "audit"
    description = "Check vulnerabilities in dependencies"

    def handle(self) -> None:
        self.line("<b># poetry audit report</b>")
        self.line("<info>Loading...</info>")

        locked_repo = self.poetry.locker.locked_repository(True)
        packages: List[Package] = []
        for locked_package in locked_repo.packages:
            packages.append(Package(str(locked_package.name), str(locked_package.version)))
        self.line(f"<info>Scanning {len(packages)} packages...</info>")
        self.line("")

        vulnerabilities = check_vulnerabilities(packages)
        max_line_lengths = self.calculate_line_length(vulnerabilities)
        for vulnerability in vulnerabilities:
            vulnerability_message = (
                "  <fg=blue;options=bold>•</> "
                f"<c1>{vulnerability.name:{max_line_lengths['name']}}</c1>"
                f"  installed <success>{vulnerability.version:{max_line_lengths['version']}}</success>"
                f"  affected <success>{vulnerability.spec:{max_line_lengths['spec']}}</success>"
                f"  CVE <success>{vulnerability.cve:{max_line_lengths['cve']}}</success>"
            )
            self.line(vulnerability_message)

        if vulnerabilities:
            self.line("")
            self.line(f"<error>{len(vulnerabilities)}</error> <b>vulnerabilities found</b>")
        else:
            self.line("<b>Vulnerabilities not found</b> ✨✨")

    def calculate_line_length(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        keys = ["name", "version", "spec", "cve"]
        max_line_lengths = {key: 0 for key in keys}
        for vulnerability in vulnerabilities:
            for key in keys:
                max_line_length = max_line_lengths[key]
                line_length = len(getattr(vulnerability, key))
                if line_length > max_line_length:
                    max_line_lengths[key] = line_length

        return max_line_lengths


def factory():
    return AuditCommand()
