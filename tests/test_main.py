import json
import subprocess
from pathlib import Path
from subprocess import CompletedProcess
from typing import List

from poetry_audit_plugin.constants import (
    EXIT_CODE_OK,
    EXIT_CODE_OPTION_INVALID,
    EXIT_CODE_VULNERABILITY_FOUND,
)

# At least there're following vulnerabilities in these packages.
DEV_VULNERABILITY_PACKAGE = "ansible-runner"
DEV_VULNERABILITY_CODE1 = "PVE-2021-36995"
DEV_VULNERABILITY_CODE2 = "CVE-2021-4041"
MAIN_VULNERABILITY_PACKAGE = "ansible-tower-cli"
MAIN_VULNERABILITY_CODE1 = "CVE-2020-1735"
MAIN_VULNERABILITY_CODE2 = "CVE-2020-1738"

TESTING_ASSETS_PATH = Path(__file__).parent / "assets"


def run_audit(testing_dir: Path, use_cache: bool, *args: str) -> CompletedProcess:
    commands = [
        "poetry",
        "audit",
    ] + list(args)
    if use_cache:
        commands.append("--cache-sec=60")
    result = subprocess.run(
        commands,
        cwd=testing_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    return result


def test_no_vulnerabilities_tool_poetry_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True)

    assert "poetry audit report" in result.stdout
    assert "No vulnerabilities found" in result.stdout
    assert result.returncode == EXIT_CODE_OK


def test_no_vulnerabilities_project_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_project"
    result = run_audit(testing_dir, True)

    assert "poetry audit report" in result.stdout
    assert "No vulnerabilities found" in result.stdout
    assert result.returncode == EXIT_CODE_OK


def test_vulnerabilities_in_main_tool_poetry_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_tool_poetry"
    result = run_audit(testing_dir, True)

    assert "poetry audit report" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert "No vulnerabilities found" not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_project_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_project"
    result = run_audit(testing_dir, True)

    assert "poetry audit report" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert "No vulnerabilities found" not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_dev_tool_poetry_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_dev_tool_poetry"
    result = run_audit(testing_dir, True)

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert "No vulnerabilities found" not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_dev_project_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_dev_project"
    result = run_audit(testing_dir, True)

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found" in result.stdout
    assert "No vulnerabilities found" not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_tool_poetry_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(testing_dir, True)

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


def test_vulnerabilities_in_main_dev_project_basic_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_project"
    result = run_audit(testing_dir, True)

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


def test_no_vulnerabilities_tool_poetry_json_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--json")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert "poetry audit report" not in result.stdout
    assert "metadata" in result_dict.keys()
    assert len(vulnerabilitie_names) == 0
    assert result.returncode == EXIT_CODE_OK


def test_vulnerabilities_in_main_tool_poetry_json_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_tool_poetry"
    result = run_audit(testing_dir, True, "--json")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert "poetry audit report" not in result.stdout
    assert "metadata" in result_dict.keys()
    assert MAIN_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert MAIN_VULNERABILITY_CODE1 in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_dev_tool_poetry_json_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_dev_tool_poetry"
    result = run_audit(testing_dir, True, "--json")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = [vulnerability["name"] for vulnerability in result_dict["vulnerabilities"]]

    assert "poetry audit report" not in result.stdout
    assert "metadata" in result_dict.keys()
    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert DEV_VULNERABILITY_CODE1 in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_tool_poetry_json_report() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(testing_dir, True, "--json")
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


def test_vulnerabilities_code_in_main_tool_poetry_basic_report_with_ignoring_codes() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_tool_poetry"
    result = run_audit(testing_dir, True, f"--ignore-code={MAIN_VULNERABILITY_CODE1}")

    assert "poetry audit report" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_CODE1 not in result.stdout
    assert MAIN_VULNERABILITY_CODE2 in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_tool_poetry_basic_report_with_ignoring_codes() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(testing_dir, True, f"--ignore-code={MAIN_VULNERABILITY_CODE1},{DEV_VULNERABILITY_CODE1}")

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


def test_vulnerabilities_in_dev_tool_poetry_basic_report_with_ignoring_codes() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_dev_tool_poetry"
    result = run_audit(testing_dir, True, f"--ignore-code={DEV_VULNERABILITY_CODE1}")

    assert "poetry audit report" in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_CODE1 not in result.stdout
    assert DEV_VULNERABILITY_CODE2 in result.stdout
    assert "vulnerabilities found in" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_tool_poetry_json_report_with_ignoring_codes() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(
        testing_dir, True, "--json", f"--ignore-code={MAIN_VULNERABILITY_CODE1},{DEV_VULNERABILITY_CODE1}"
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


def test_vulnerabilities_in_main_dev_tool_poetry_basic_report_with_ignoring_main_packages() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(testing_dir, True, f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}")

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE not in result.stdout
    assert DEV_VULNERABILITY_PACKAGE in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_tool_poetry_basic_report_with_ignoring_dev_packages() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(testing_dir, True, f"--ignore-package={DEV_VULNERABILITY_PACKAGE}")

    assert "poetry audit report" in result.stdout
    assert "vulnerabilities found but ignored" in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in result.stdout
    assert DEV_VULNERABILITY_PACKAGE not in result.stdout
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_tool_poetry_json_report_with_ignoring_main_packages() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(testing_dir, True, "--json", f"--ignore-package={MAIN_VULNERABILITY_PACKAGE}")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])

    assert "poetry audit report" not in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE not in vulnerabilitie_names
    assert DEV_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_vulnerabilities_in_main_dev_tool_poetry_json_report_with_ignoring_dev_packages() -> None:
    testing_dir = TESTING_ASSETS_PATH / "vulnerabilities_in_main_dev_tool_poetry"
    result = run_audit(testing_dir, True, "--json", f"--ignore-package={DEV_VULNERABILITY_PACKAGE}")
    result_dict = json.loads(result.stdout)
    vulnerabilitie_names = []
    for vuln in result_dict["vulnerabilities"]:
        vulnerabilitie_names.append(vuln["name"])

    assert "poetry audit report" not in result.stdout
    assert MAIN_VULNERABILITY_PACKAGE in vulnerabilitie_names
    assert DEV_VULNERABILITY_PACKAGE not in vulnerabilitie_names
    assert result.returncode == EXIT_CODE_VULNERABILITY_FOUND


def test_no_vulnerabilities_tool_poetry_basic_report_with_valid_proxy_config() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, False, "--proxy-protocol=http", "--proxy-host=localhost", "--proxy-port=3128")

    assert "poetry audit report" in result.stdout
    assert result.returncode == EXIT_CODE_OK


def test_no_vulnerabilities_tool_poetry_basic_report_with_invalid_string_proxy_port() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--proxy-host=localhost", "--proxy-port=string")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_tool_poetry_basic_report_with_invalid_empty_proxy_port() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--proxy-host=localhost", "--proxy-port=''")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_tool_poetry_basic_report_with_invalid_string_proxy_protocol() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--proxy-host=localhost", "--proxy-protocol='tcp'")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_tool_poetry_basic_report_with_invalid_empty_proxy_protocol() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--proxy-host=localhost", "--proxy-protocol=''")

    assert "poetry audit report" in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_tool_poetry_json_report_with_valid_proxy_config() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(
        testing_dir, False, "--json", "--proxy-protocol=http", "--proxy-host=localhost", "--proxy-port=3128"
    )

    assert "poetry audit report" not in result.stdout
    assert result.returncode == EXIT_CODE_OK


def test_no_vulnerabilities_tool_poetry_json_report_with_invalid_string_proxy_port() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--json", "--proxy-host=localhost", "--proxy-port=string")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_tool_poetry_json_report_with_invalid_empty_proxy_port() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--json", "--proxy-host=localhost", "--proxy-port=''")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_tool_poetry_json_report_with_invalid_string_proxy_protocol() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--json", "--proxy-host=localhost", "--proxy-protocol='tcp'")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID


def test_no_vulnerabilities_tool_poetry_json_report_with_invalid_empty_proxy_protocol() -> None:
    testing_dir = TESTING_ASSETS_PATH / "no_vulnerabilities_tool_poetry"
    result = run_audit(testing_dir, True, "--json", "--proxy-host=localhost", "--proxy-protocol=''")

    assert "poetry audit report" not in result.stdout
    assert "Command line option(s) are invalid" in result.stderr
    assert result.returncode == EXIT_CODE_OPTION_INVALID
