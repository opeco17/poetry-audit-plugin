from collections import namedtuple
from typing import List

import safety as safety_package
from packaging import version
from poetry.console.commands.command import Command
from safety import safety

Package = namedtuple("Package", ["key", "version"])


class Vulnerability(namedtuple("Vulnerability", ["name", "spec", "version", "advisory", "vuln_id"])):
    pass


def check_vulnerabilities(packages: List[Package]) -> List[Vulnerability]:
    safety_version = version.parse(safety_package.__version__)
    checker_args = {"packages": packages, "key": False, "db_mirror": False, "cached": False}
    if safety_version >= version.parse("1.4.0"):
        checker_args["ignore_ids"] = []
    if safety_version >= version.parse("1.8.5"):
        checker_args["proxy"] = {}
    return safety.check(**checker_args)


class AuditCommand(Command):
    name = "audit"
    description = "Check vulnerabilities in dependencies"

    def handle(self) -> None:
        self.line("<b># poetry audit report</b>")
        self.line("<info>Loading...</info>")

        root = self.poetry.package.without_optional_dependency_groups()
        packages: List[Package] = []
        for dependency_package in self.poetry.locker.get_project_dependency_packages(
            project_requires=root.all_requires
        ):
            packages.append(Package(str(dependency_package.package.name), str(dependency_package.package.version)))
        self.line(f"<info>Scanning {len(packages)} packages...</info>")
        self.line("")

        vulnerabilities = check_vulnerabilities(packages)
        for vulnerability in vulnerabilities:
            vulnerability_message = (
                "  <fg=blue;options=bold>•</> "
                f"Package <c1>{vulnerability.name}</c1>"
                f"  installed <success>{vulnerability.version}</success>"
                f"  affected <success>{vulnerability.spec}</success>"
                f"  ID <success>{vulnerability.vuln_id}</success>"
            )
            self.line(vulnerability_message)

        if vulnerabilities:
            self.line("")
            self.line(f"<error>{len(vulnerabilities)}</error> vulnerabilities found")
        else:
            self.line("<b>Vulnerabilities not found</b> ✨✨")


def factory():
    return AuditCommand()
