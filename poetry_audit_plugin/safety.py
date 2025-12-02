from typing import Any, Dict, Iterator, List, Optional

from packaging.specifiers import SpecifierSet
from safety.auth import build_client_session
from safety.safety import fetch_database

from poetry_audit_plugin.errors import SafetyDBAccessError, SafetyDBSessionBuildError


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


def build_safety_db_session(
    key: Optional[str] = None,
    proxy_protocol: Optional[str] = None,
    proxy_host: Optional[str] = None,
    proxy_port: Optional[int] = None,
) -> Any:
    # Ref: https://github.com/pyupio/safety/blob/3.0.1/safety/auth/cli_utils.py#L130
    proxy_config: Optional[Dict[str, str]] = None
    if proxy_host and proxy_port and proxy_protocol:
        proxy_config = {"https": f"{proxy_protocol}://{proxy_host}:{str(proxy_port)}"}
    try:
        # Note: proxy_config is ignored when it's invalid or inaccessible inside build_client_session
        session, _ = build_client_session(api_key=key, proxies=proxy_config)
    except Exception as e:
        raise SafetyDBSessionBuildError(str(e))

    return session


def get_vulnerable_entry(pkg_name: str, spec: str, db_full: Dict[str, Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    for entry in db_full.get("vulnerable_packages", {}).get(pkg_name, []):
        for entry_spec in entry.get("specs", []):
            if entry_spec == spec:
                yield entry


def check_vulnerable_packages(
    packages: List[Package], session: Any, cache_sec: int = 0, dp_path: Optional[str] = None
) -> List[VulnerablePackage]:
    """
    Check vulnerabilities in given packages by checking Safety DB.

    If cache_sec is not 0, Safety DB is cached in $HOME/.safety/200/ and it can be used for next scan.
    """
    # Ref: https://github.com/pyupio/safety/blob/2.3.5/safety/safety.py#L320
    # Ref: https://github.com/pyupio/safety/blob/3.0.1/safety/scan/finder/handlers.py#L50
    try:
        db: Dict[str, Dict[str, Any]] = fetch_database(
            session, full=False, db=dp_path, cached=cache_sec, telemetry=False, from_cache=True
        )
        db_full: Dict[str, Dict[str, Any]] = fetch_database(
            session, full=True, db=dp_path, cached=cache_sec, telemetry=False, from_cache=True
        )
    except Exception as e:
        raise SafetyDBAccessError(str(e))

    vulnerable_packages: List[VulnerablePackage] = []
    for pkg in packages:
        name = pkg.name.replace("_", "-").lower()
        vulnerabilities: List[Vulnerability] = []
        if name not in db.get("vulnerable_packages", {}).keys():
            continue

        specifiers: List[str] = db["vulnerable_packages"][name]
        for specifier in specifiers:
            spec_set = SpecifierSet(specifiers=specifier)
            if not spec_set.contains(pkg.version):
                continue

            for entry in get_vulnerable_entry(pkg_name=name, spec=specifier, db_full=db_full):
                for cve in entry.get("ids", []):
                    if cve.get("type") in ["cve", "pve"] and cve.get("id"):
                        vulnerabilities.append(
                            Vulnerability(advisory=entry.get("advisory", ""), cve=cve["id"], spec=specifier)
                        )

        if vulnerabilities:
            vulnerable_packages.append(
                VulnerablePackage(name=name, version=pkg.version, vulnerabilities=vulnerabilities)
            )

    return vulnerable_packages
