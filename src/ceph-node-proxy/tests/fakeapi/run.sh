#!/bin/sh
set -x

TMPDIR=$(mktemp -d)
python3 -m venv "${TMPDIR}"
# shellcheck source=/dev/null
. "${TMPDIR}"/bin/activate
pip3 install --upgrade pip
pip3 install -r ./fake-api-requirements.txt
PYTHONPATH=$PYTHONPATH:../.. python3 ./fakeapi.py
rm -rf "${TMPDIR}"
