#!/bin/zsh

APP_DIR="${0:A:h}"
cd "$APP_DIR" || exit 1
python3 "$APP_DIR/install_geoip.py"
echo
echo "Press Return to close this window."
read
