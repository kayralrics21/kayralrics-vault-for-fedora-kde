#!/usr/bin/env bash
set -euo pipefail
# Initial dependency installation may use Fedora repositories.
# The application itself never makes network requests.
sudo dnf install -y python3 python3-tkinter python3-cryptography python3-pillow
cd "$(dirname "$(readlink -f "$0")")"
python3 - <<'PY'
import tkinter
import cryptography
from PIL import Image
print("Runtime dependencies OK")
PY
printf '\nInstallation complete. Run ./run.sh\n'
