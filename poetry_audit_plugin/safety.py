from collections import namedtuple
from typing import Any, Dict, Iterator, List

from packaging.specifiers import SpecifierSet
from safety.safety import fetch_database

Package = namedtuple("Package", ["key", "version"])
Vulnerability = namedtuple("Vulnerability", ["name", "spec", "version", "advisory", "cve"])


def get_vulnerable_entry(pkg_name: str, spec: str, db_full: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    for entry in db_full.get(pkg_name, []):
        for entry_spec in entry.get("specs", []):
            if entry_spec == spec:
                yield entry


def check_vulnerabilities(packages: List[Package]) -> List[Vulnerability]:
    db: Dict[str, Any] = fetch_database()
    db_full: Dict[str, Any] = {}
    vulnerable_packages = frozenset(db.keys())
    vulnerable = []
    for pkg in packages:
        name = pkg.key.replace("_", "-").lower()

        if name in vulnerable_packages:
            for specifier in db[name]:
                spec_set = SpecifierSet(specifiers=specifier)
                if spec_set.contains(pkg.version):
                    if not db_full:
                        db_full = fetch_database(full=True)
                    for data in get_vulnerable_entry(pkg_name=name, spec=specifier, db_full=db_full):
                        cve = data.get("cve")
                        if cve:
                            cve = cve.split(",")[0].strip()
                        if data.get("id"):
                            vulnerable.append(
                                Vulnerability(
                                    name,
                                    specifier,
                                    pkg.version,
                                    data.get("advisory"),
                                    cve,
                                )
                            )
    return vulnerable
