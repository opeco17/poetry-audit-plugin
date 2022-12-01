import json
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from typing import List

main_vulnerability = "ansible-tower-cli"
dev_vulnerability = "ansible-runner"

testing_assets = Path(__file__).parent / "assets"
plugin_source_dir = Path(__file__).parent.parent / "poetry_version_plugin"


def copy_assets(source_name: str, testing_dir: Path) -> None:
    package_path = testing_assets / source_name
    shutil.copytree(package_path, testing_dir)


def run_audit(testing_dir: Path, args: List[str] = []) -> CompletedProcess:
    result = subprocess.run(
        [
            "poetry",
            "audit",
        ]
        + args,
        cwd=testing_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    return result


def test_no_vulnerabilities_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir=testing_dir)

    assert "poetry audit report" in result.stdout
    assert "Vulnerabilities not found" in result.stdout
    assert result.returncode == 0


def test_vulnerabilities_in_main_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir=testing_dir)

    assert "poetry audit report" in result.stdout
    assert main_vulnerability in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_dev_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir)

    assert "poetry audit report" in result.stdout
    assert dev_vulnerability in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_main_dev_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir)

    assert "poetry audit report" in result.stdout
    assert dev_vulnerability in result.stdout
    assert main_vulnerability in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert result.returncode == 1


def test_no_vulnerabilities_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert len(vulnerabilitie_names) == 0
    assert result.returncode == 0


def test_vulnerabilities_in_main_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert main_vulnerability in vulnerabilitie_names
    assert result.returncode == 1


def test_vulnerabilities_in_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert dev_vulnerability in vulnerabilitie_names
    assert result.returncode == 1


def test_vulnerabilities_in_main_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert dev_vulnerability in vulnerabilitie_names
    assert main_vulnerability in vulnerabilitie_names
    assert result.returncode == 1


def test_supressed_vulnerabilities_in_main( tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--ignore-code=CVE-2020-1735"])

    assert "poetry audit report" in result.stdout
    assert main_vulnerability in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert "CVE-2020-1735" not in result.stdout
    assert result.returncode == 1

def test_supressed_vulnerabilities_in_dev( tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--ignore-code=CVE-2020-1735"])

    assert "poetry audit report" in result.stdout
    assert dev_vulnerability in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert "CVE-2020-1735" not in result.stdout
    assert result.returncode == 1

def test_supressed_vulnerabilities_in_main_dev( tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--ignore-code=CVE-2020-1735"])

    assert "poetry audit report" in result.stdout
    assert dev_vulnerability in result.stdout
    assert main_vulnerability in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert "CVE-2020-1735" not in result.stdout
    assert result.returncode == 1

def test_supressed_packages_in_main( tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--ignore-package=ansible-tower-cli"])

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert "ansible-tower-cli" not in result.stdout
    assert result.returncode == 0

def test_supressed_packages_in_main_dev( tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--ignore-package=ansible-tower-cli"])

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert "ansible-tower-cli" not in result.stdout
    assert dev_vulnerability in result.stdout
    assert result.returncode == 1


def test_supressed_vulnerabilities_in_main_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json", "--ignore-code=CVE-2020-1735"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    vulnerabilitie_cve = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])
        for detail in vuln["vulns"]:
            vulnerabilitie_cve.append(detail["cve"])

    assert dev_vulnerability in vulnerabilitie_names
    assert main_vulnerability in vulnerabilitie_names
    assert "CVE-2020-1735" not in vulnerabilitie_cve
    assert result.returncode == 1


def test_ignored_packages_in_main_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json", "--ignore-package=ansible-tower-cli"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    vulnerabilitie_cve = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])

    assert dev_vulnerability in vulnerabilitie_names
    assert "ansible-tower-cli" not in vulnerabilitie_names
    assert result.returncode == 1