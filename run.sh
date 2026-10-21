#!/bin/sh
# phplume launcher. Downloads the versioned single-file scanner, verifies it, runs it.
set -eu

phplume_url='https://raw.githubusercontent.com/daMustermann/phplume/v0.3.1/phplume.py'
phplume_sha='9cedf4bddd872b01f08815d39c4b2272670586e3ece92ab6e3ad74369fecded8'
phplume_python=''
for phplume_candidate in python3 python; do
    if command -v "$phplume_candidate" >/dev/null 2>&1 && "$phplume_candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
        phplume_python=$phplume_candidate
        break
    fi
done
if [ -z "$phplume_python" ]; then
    printf '%s\n' 'phplume needs Python 3.10 or newer. Install Python from python.org or your package manager, then run this command again.' >&2
    exit 3
fi
if ! command -v curl >/dev/null 2>&1; then
    printf '%s\n' 'phplume needs curl to download the scanner. Install curl, or download phplume.py from GitHub and run it with Python.' >&2
    exit 3
fi
phplume_tmp=$(mktemp -d "${TMPDIR:-/tmp}/phplume.XXXXXXXX")
trap 'rm -f "$phplume_tmp/phplume.py"; rmdir "$phplume_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 --retry 2 "$phplume_url" -o "$phplume_tmp/phplume.py"
"$phplume_python" -c 'import hashlib,pathlib,sys; actual=hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest(); sys.exit(0 if actual == sys.argv[2] else "Scanner checksum mismatch. Download stopped; please check the GitHub release.")' "$phplume_tmp/phplume.py" "$phplume_sha"
# A curl | sh entry point must restore terminal input for the guided wizard.
phplume_exit=0
if ( : </dev/tty ) 2>/dev/null; then
    "$phplume_python" "$phplume_tmp/phplume.py" "$@" </dev/tty || phplume_exit=$?
else
    "$phplume_python" "$phplume_tmp/phplume.py" "$@" || phplume_exit=$?
fi
exit "$phplume_exit"
