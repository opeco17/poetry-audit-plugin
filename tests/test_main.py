import json
import shutil
import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from typing import List
from poetry_audit_plugin.constants import *

# At least there're following vulnerabilities in these packages.
DEV_VULNERABILITY_PACKAGE = "ansible-runner"
DEV_VULNERABILITY_CODE1 = "PVE-2021-36995"
DEV_VULNERABILITY_CODE2 = "CVE-2021-4041"
MAIN_VULNERABILITY_PACKAGE = "ansible-tower-cli"
MAIN_VULNERABILITY_CODE1 = "CVE-2020-1735"
MAIN_VULNERABILITY_CODE2 = "CVE-2020-1738"

TESTING_ASSETS_PATH = Path(__file__).parent / "assets"


def copy_assets(source_name: str, testing_dir: Path) -> None:
    package_path = TESTING_ASSETS_PATH / source_name
    shutil.copytree(package_path, testing_dir)


def run_audit(testing_dir: Path, *args: str) -> CompletedProcess:
    result = subprocess.run(
        [
            "poetry",
            "audit",
        ]
        + list(args),
        cwd=testing_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    return result


def test_no_vulnerabilities_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir)

    assert "poetry audit report" in result.stdout
    assert "No vulnerabilities found" in result.stdout
    assert result.returncode == EXIT_CODE_OK


def test_vulnerabilities_in_main_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir)

    assert "poetry audit report" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert "No vulnerabilities found" not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_dev_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir)

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert "No vulnerabilities found" not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_basic_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir)

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert "No vulnerabilities found" not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_no_vulnerabilities_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--json")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert "poetry audit report" not in result.stdout
    assert "metadata" in result_dict.keys()
    assert len(vulnerabilitie_names) == 0
    assert result.returncode == EXIT_CODE_OK


def test_vulnerabilities_in_main_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir, "--json")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert "poetry audit report" not in result.stdout
    assert "metadata" in result_dict.keys()
    assert MAIN_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir, "--json")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert "poetry audit report" not in result.stdout
    assert "metadata" in result_dict.keys()
    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_json_report(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir, "--json")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert "poetry audit report" not in result.stdout
    assert "metadata" in result_dict.keys()
    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert MAIN_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_code_in_main_basic_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main", testing_dir)
    result = run_audit(testing_dir, f"--ignore-code={MAIN_VULNERABILITY_CODE1}")

    assert "poetry audit report" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_CODE1 not in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_basic_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(
        testing_dir, f"--ignore-code={MAIN_VULNERABILITY_CODE1},{DEV_VULNERABILITY_CODE1}"
    )

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_CODE1 not in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert DEV_VULNERABILITY_CODE1 not in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_dev_basic_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_dev", testing_dir)
    result = run_audit(testing_dir, f"--ignore-code={DEV_VULNERABILITY_CODE1}")

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 not in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_json_report_with_ignoring_codes(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(
        testing_dir, "--json", f"--ignore-code={MAIN_VULNERABILITY_CODE1},{DEV_VULNERABILITY_CODE1}"
    )
    result_dict = json.loads(result.stdout)
    vulnerability_names: List[str] = []
    vulnerability_codes: List[str] = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerability_names.append(vuln["name"])
        for detail in vuln["vulns"]:
            vulnerability_codes.append(detail["cve"])

    assert "poetry audit report" not in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in vulnerability_names
    assert DEV_VULNERABILITY_PACKAGE in vulnerability_names
    assert MAIN_VULNERABILITY_CODE1 not in vulnerability_codes
    assert MAIN_VULNERABILITY_CODE2 in vulnerability_codes
    assert DEV_VULNERABILITY_CODE1 not in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_basic_report_with_ignoring_main_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir, f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}")

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE not in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_basic_report_with_ignoring_dev_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir, f"--ignore-package={DEV_VULNERABILITY_PACKAGE}")

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_PACKAGE not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_json_report_with_ignoring_main_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir, "--json", f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])

    assert "poetry audit report" not in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE not in vulnerabilitie_names
    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_json_report_with_ignoring_dev_packages(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("vulnerabilities_in_main_dev", testing_dir)
    result = run_audit(testing_dir, "--json", f"--ignore-package={DEV_VULNERABILITY_PACKAGE}")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])

    assert "poetry audit report" not in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert DEV_VULNERABILITY_PACKAGE not in vulnerabilitie_names
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_no_vulnerabilities_basic_report_with_valid_proxy_config(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--proxy-protocol=http", "--proxy-host=localhost", "--proxy-port=3128")

    assert "poetry audit report" in result.stdout
    assert result.returncode == EXIT_CODE_OK


def test_no_vulnerabilities_basic_report_with_invalid_string_proxy_port(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--proxy-host=localhost", "--proxy-port=string")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_basic_report_with_invalid_empty_proxy_port(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--proxy-host=localhost", "--proxy-port=''")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_basic_report_with_invalid_string_proxy_protocol(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--proxy-host=localhost", "--proxy-protocol='tcp'")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_basic_report_with_invalid_empty_proxy_protocol(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--proxy-host=localhost", "--proxy-protocol=''")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_json_report_with_valid_proxy_config(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--json", "--proxy-protocol=http", "--proxy-host=localhost", "--proxy-port=3128")

    assert "poetry audit report" not in result.stdout
    assert result.returncode == EXIT_CODE_OK


def test_no_vulnerabilities_basic_report_with_invalid_string_proxy_port(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--json", "--proxy-host=localhost", "--proxy-port=string")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_basic_report_with_invalid_empty_proxy_port(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--json", "--proxy-host=localhost", "--proxy-port=''")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_basic_report_with_invalid_string_proxy_protocol(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--json", "--proxy-host=localhost", "--proxy-protocol='tcp'")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_basic_report_with_invalid_empty_proxy_protocol(tmp_path: Path) -> None:
    testing_dir = tmp_path / "testing_package"
    copy_assets("no_vulnerabilities", testing_dir)
    result = run_audit(testing_dir, "--json", "--proxy-host=localhost", "--proxy-protocol=''")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID
