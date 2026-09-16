#!/bin/sh
cd "$(dirname "$0")"
echo "ORBIT  http://127.0.0.1:8787"
exec python3 -m http.server 8787
