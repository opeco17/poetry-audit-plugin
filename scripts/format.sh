#!/usr/bin/env bash

set -e
set -x

black poetry_audit_plugin tests
isort poetry_audit_plugin tests
