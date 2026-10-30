#!/bin/sh
# Live capture and GOOSE/SV publishing need raw sockets -> root (or CAP_NET_RAW).
cd "$(dirname "$0")"
if [ "$(id -u)" -ne 0 ]; then exec sudo python3 run.py "$@"; else exec python3 run.py "$@"; fi
