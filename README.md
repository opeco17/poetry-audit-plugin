# Poetry Audit Plugin

Poetry plugin for checking security vulnerabilities in dependencies based on [safety](https://github.com/pyupio/safety).

```
$ poetry audit
Scanning 19 packages...

  • ansible-runner     installed 1.1.2  affected <1.3.1   CVE PVE-2021-36995
  • ansible-tower-cli  installed 3.1.8  affected <3.2.0   CVE CVE-2020-1733 
  • jinja2             installed 2.0    affected <2.11.3  CVE CVE-2020-28493

3 vulnerabilities found
```

## Installation

The easiest way to install the `audit` plugin is via the `self add` command of Poetry.

```bash
poetry self add poetry-audit-plugin
```

If you used `pipx` to install Poetry you can add the plugin via the `pipx inject` command.

```bash
pipx inject poetry poetry-audit-plugin
```

Otherwise, if you used `pip` to install Poetry you can add the plugin packages via the `pip install` command.

```bash
pip install poetry-audit-plugin
```

## Available options

* `--json`: Export the result in JSON format.

```bash
poetry audit --json
```

* `--ignore-code`: Ignore some vulnerabilities IDs. Receive a list of IDs. For example:

```bash
poetry audit --ignore-code=CVE-2022-42969,CVE-2020-10684
```

* `--ignore-package`: Ignore some packages. Receive a list of packages. For example:

```bash
poetry audit --ignore-package=ansible-tower-cli
```

* `--proxy-protocol`, `--proxy-host`, `--proxy-port`: Proxy to access Safety DB. For example:

```bash
poetry audit --proxy-protocol=http --proxy-host=localhost --proxy-port=3128
```

* `--cache-sec`: How long Safety DB can be cached locally. For example:

```bash
poetry audit --cache-sec=60
```

* `--db`: Path to a local or remote vulnerability database of Safety. For example:

```bash
poetry audit --db=/path/to/safety.json
```

## Exit codes

`poetry audit` will exit with a code indicating its status.

* `0`: Vulnerabilities were not found.
* `1`: One or more vulnerabilities were found.
* Others: Something wrong happened.

## Develop poetry-audit-plugin

You can read this document to setup an environment to develop poetry-audit-plugin.

First step is to install Poetry. Please read [official document](https://python-poetry.org/docs/) and install Poetry in your machine.

Then, you can install dependencies of poetry-audit-plugin and activate the environment with the following command.

```sh
poetry install
source .venv/bin/activate
```

Once you've done it, you can start developing poetry-audit-plugin. You can use test assets for the testing.

```sh
cd tests/assets/no_vulnerabilities_project
poetry audit
```

Please lint, format, and test your changes before creating pull request to keep the quality.

```sh
./scripts/lint.sh
./scripts/format.sh
./scripts/test.sh
```

## Contribution

Help is always appreciated. Please feel free to create issue and pull request!

## License

This project is licensed under the terms of the MIT license.
