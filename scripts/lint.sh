#!/usr/bin/env bash

set -e
set -x

mypy poetry_audit_plugin
flake8 poetry_audit_plugin tests
black poetry_audit_plugin tests --check
isort poetry_audit_plugin tests --check-only