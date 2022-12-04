from typing import Any, Dict, Iterator, List, Tuple

from packaging.specifiers import SpecifierSet
from safety.safety import fetch_database


class Package:
    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version


class Vulnerability:
    def __init__(self, cve: str, spec: str, advisory: str) -> None:
        self.cve = cve
        self.spec = spec
        self.advisory = advisory

    def format(self) -> Dict[str, Any]:
        return {"cve": self.cve, "affectedVersion": self.spec, "advisory": self.advisory}


class VulnerablePackage:
    def __init__(self, name: str, version: str, vulnerabilities: List[Vulnerability]) -> None:
        self.name = name
        self.version = version
        self.vulnerabilities = vulnerabilities

    def format(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "installedVersion": self.version,
            "vulns": [vulnerability.format() for vulnerability in self.vulnerabilities],
        }


def get_vulnerable_entry(pkg_name: str, spec: str, db_full: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    for entry in db_full.get(pkg_name, []):
        for entry_spec in entry.get("specs", []):
            if entry_spec == spec:
                yield entry


def check_vulnerable_packages(packages: List[Package]) -> List[VulnerablePackage]:
    db: Dict[str, Any] = fetch_database()
    db_full: Dict[str, Any] = {}
    vulnerable_packages: List[VulnerablePackage] = []
    for pkg in packages:
        name = pkg.name.replace("_", "-").lower()
        vulnerabilities: List[Vulnerability] = []
        if name in frozenset(db.keys()):
            specifiers: List[str] = db[name]
            for specifier in specifiers:
                spec_set = SpecifierSet(specifiers=specifier)
                if spec_set.contains(pkg.version):
                    if not db_full:
                        db_full = fetch_database(full=True)
                    for data in get_vulnerable_entry(pkg_name=name, spec=specifier, db_full=db_full):
                        cve = data.get("cve")
                        if cve:
                            cve = cve.split(",")[0].strip()
                        if data.get("id"):
                            vulnerabilities.append(
                                Vulnerability(advisory=data.get("advisory", ""), cve=cve, spec=specifier)
                            )

        if vulnerabilities:
            vulnerable_packages.append(
                VulnerablePackage(name=name, version=pkg.version, vulnerabilities=vulnerabilities)
            )

    return vulnerable_packages


def suppress_vulnerable_packages(
    vulnerable_packages: List[VulnerablePackage], ignored_packages: List[str], ignored_codes: List[str]
) -> Tuple[List[VulnerablePackage], int]:
    filtered_vulnerable_packages: List[VulnerablePackage] = []
    amount_of_ignored_vulnerabilities = 0

    is_ignore_packages = len(ignored_packages) > 0
    is_ignore_codes = len(ignored_codes) > 0

    for vulnerable_package in vulnerable_packages:
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
                vulnerable_package.vulnerabilities = filtered_vulnerabilities
            else:
                continue

        filtered_vulnerable_packages.append(vulnerable_package)

    return filtered_vulnerable_packages, amount_of_ignored_vulnerabilities
