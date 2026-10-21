"""Catch stale launcher hashes before publishing."""
import hashlib
from pathlib import Path
import re

root = Path(__file__).resolve().parent.parent
scanner = root / "phplume.py"
digest = hashlib.sha256(scanner.read_bytes()).hexdigest()
version = re.search(r'^VERSION = "([^"]+)"', scanner.read_text(encoding="utf-8"), re.M).group(1)
for name in ("run.sh", "run.ps1"):
    content = (root / name).read_text(encoding="utf-8")
    if digest not in content or f"/v{version}/phplume.py" not in content:
        raise SystemExit(f"{name} must pin v{version} with SHA-256 {digest}")
print(f"Both launchers pin phplume {version}: {digest}")
