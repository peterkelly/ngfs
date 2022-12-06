#!/bin/bash
set -eu
/usr/local/Cellar/openssl\@1.1/1.1.1i/bin/openssl s_client -showcerts -servername localhost -connect localhost:443
