#!/usr/bin/env bash
set -ex

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <test-module-or-path under ceph_volume/tests/>" >&2
    exit 2
fi

CV_TEST=$(python3 -c "import ceph_volume.tests; import os; print(os.path.dirname(ceph_volume.tests.__file__))")
python3 -m pytest -v "${CV_TEST}/$1"
