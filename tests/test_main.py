import json
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from typing import List

# At least there're following vulnerabilities in these packages.
DEV_VULNERABILITY_PACKAGE = "ansible-runner"
DEV_VULNERABILITY_CODE1 = "PVE-2021-36995"
MAIN_VULNERABILITY_PACKAGE = "ansible-tower-cli"
MAIN_VULNERABILITY_CODE1 = "CVE-2020-1735"
MAIN_VULNERABILITY_CODE2 = "CVE-2020-1738"

TESTING_ASSETS_PATH = Path(__file__).parent / "assets"


def copy_assets(source_name: str, testing_dir: Path) -> None:
    package_path = TESTING_ASSETS_PATH / source_name
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
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_dev_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir)

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_main_dev_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir)

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
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

    assert MAIN_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_main_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert MAIN_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_code_in_main_basic_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(
        testing_dir=testing_dir, args=[f"--ignore-code={MAIN_VULNERABILITY_CODE1},{MAIN_VULNERABILITY_CODE2}"]
    )

    assert "poetry audit report" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_CODE1 not in result.stdout
    assert MAIN_VULNERABILITY_CODE2 not in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_main_dev_basic_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(
        testing_dir=testing_dir, args=[f"--ignore-code={MAIN_VULNERABILITY_CODE1},{MAIN_VULNERABILITY_CODE2}"]
    )

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_CODE1 not in result.stdout
    assert MAIN_VULNERABILITY_CODE2 not in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_dev_basic_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(
        testing_dir=testing_dir, args=["--ignore-code={MAIN_VULNERABILITY_CODE1},{MAIN_VULNERABILITY_CODE2}"]
    )

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_main_dev_basic_report_with_ignoring_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=[f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}"])

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE not in result.stdout
    assert result.returncode == 1


def test_vulnerabilities_in_main_dev_json_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(
        testing_dir=testing_dir, args=["--json", f"--ignore-code={MAIN_VULNERABILITY_CODE1},{MAIN_VULNERABILITY_CODE2}"]
    )
    result_dict = json.loads(result.stdout)
    vulnerability_names: List[str] = []
    vulnerability_codes: List[str] = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerability_names.append(vuln["name"])
        for detail in vuln["vulns"]:
            vulnerability_codes.append(detail["cve"])

    assert DEV_VULNERABILITY_PACKAGE in vulnerability_names
    assert MAIN_VULNERABILITY_PACKAGE in vulnerability_names
    assert MAIN_VULNERABILITY_CODE1 not in vulnerability_codes
    assert MAIN_VULNERABILITY_CODE2 not in vulnerability_codes
    assert result.returncode == 1


def test_no_vulnerabilities_in_main_basic_report_with_ignoring_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=[f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}"])

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE not in result.stdout
    assert result.returncode == 0


def test_vulnerabilities_in_main_dev_json_report_with_ignoring_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json", f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])

    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert MAIN_VULNERABILITY_PACKAGE not in vulnerabilitie_names
    assert result.returncode == 1


def test_no_vulnerabilities_in_main_json_report_with_ignoring_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir=testing_dir, args=["--json", f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}"])
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])

    assert MAIN_VULNERABILITY_PACKAGE not in vulnerabilitie_names
    assert result.returncode == 0
