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

The easiest way to install the `export` plugin is via the `plugin add` command of Poetry.

```bash
poetry plugin add poetry-audit-plugin
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

## Exit codes

`poetry audit` will exit with a code indicating its status.

* `0`: Vulnerabilities were not found.
* `1`: One or more vulnerabilities were found.

## License

This project is licensed under the terms of the MIT license.
