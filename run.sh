#!/bin/sh
set -eu

for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      if [ "$#" -eq 0 ]; then
        set -- demo
      fi
      exec "$candidate" -m assay "$@"
    fi
  fi
done

printf '%s\n' 'Error: Assay needs Python 3.10 or newer.' >&2
printf '%s\n' 'Why: no working Python 3.10+ interpreter was found on PATH.' >&2
printf '%s\n' 'Fix: install Python 3.10+ and rerun ./run.sh.' >&2
exit 2
