#!/bin/bash
set -eu
if [ ! -d .python ]; then
    virtualenv -p python3 .python
    . .python/bin/activate
    pip install -r requirements.txt
else
    . .python/bin/activate
fi
rm -rfv generated
mkdir generated
python genproto.py
protoc --python_out=generated generated/fields.proto
python generated/fields.py
