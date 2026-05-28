#!/usr/bin/env bash
set -ex
exec "$(dirname "$0")/run_pytest.sh" test_decorators.py
