from typing import Any, Dict, Iterator, List

from packaging.specifiers import SpecifierSet
from safety.safety import fetch_database


class Package:
    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version


class VulnerabilityDetail:
    def __init__(self, cve: str, spec: str, advisory: str) -> None:
        self.cve = cve
        self.spec = spec
        self.advisory = advisory

    def format(self) -> Dict[str, Any]:
        return {"cve": self.cve, "affectedVersion": self.spec, "advisory": self.advisory}


class Vulnerability:
    def __init__(self, name: str, version: str, details: List[VulnerabilityDetail]) -> None:
        self.name = name
        self.version = version
        self.details = details

    def format(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "installedVersion": self.version,
            "vulns": [detail.format() for detail in self.details],
        }


def get_vulnerable_entry(pkg_name: str, spec: str, db_full: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    for entry in db_full.get(pkg_name, []):
        for entry_spec in entry.get("specs", []):
            if entry_spec == spec:
                yield entry


def check_vulnerabilities(packages: List[Package]) -> List[Vulnerability]:
    db: Dict[str, Any] = fetch_database()
    db_full: Dict[str, Any] = {}
    vulnerable_packages: List[Vulnerability] = []
    for pkg in packages:
        name = pkg.name.replace("_", "-").lower()
        details: List[VulnerabilityDetail] = []
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
                            details.append(
                                VulnerabilityDetail(advisory=data.get("advisory", ""), cve=cve, spec=specifier)
                            )

        if details:
            vulnerable_packages.append(Vulnerability(name=name, version=pkg.version, details=details))

    return vulnerable_packages
