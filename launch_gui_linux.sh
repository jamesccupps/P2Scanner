#!/usr/bin/env bash
# ============================================================
#  P2 Scanner GUI Launcher (Linux / macOS)
#  Launches p2_gui.py from this script's own directory.
#  Pass-through args go to p2_gui.py:
#      ./launch_gui.sh --config mysite.json
# ============================================================

set -u

# Resolve the directory containing this script, even if the user
# launched it via a symlink. Avoids surprises with cron / desktop
# entries / sudo etc.
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
while [ -L "$SCRIPT_PATH" ]; do
    SCRIPT_DIR=$(cd -P "$(dirname "$SCRIPT_PATH")" && pwd)
    SCRIPT_PATH=$(readlink "$SCRIPT_PATH")
    case "$SCRIPT_PATH" in
        /*) ;;                                  # absolute, leave alone
        *)  SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_PATH" ;;  # relative, re-anchor
    esac
done
SCRIPT_DIR=$(cd -P "$(dirname "$SCRIPT_PATH")" && pwd)

cd "$SCRIPT_DIR" || exit 1

if [ ! -f "p2_gui.py" ]; then
    echo "ERROR: p2_gui.py not found in $SCRIPT_DIR" >&2
    echo "Place launch_gui.sh in the same folder as p2_gui.py." >&2
    exit 1
fi

# Pick the first available Python 3 interpreter.
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        # Reject Python 2 if 'python' happens to be 2.x.
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: No Python 3 interpreter found on PATH." >&2
    echo "Install python3 (apt/brew/dnf) and try again." >&2
    exit 1
fi

# Tk / tkinter is required by the GUI; bail early with a useful
# message rather than a Python traceback if it is missing. This is
# a common gotcha on Ubuntu (apt install python3-tk) and on the
# stock macOS python3 (use python.org's installer or 'brew install python-tk').
if ! "$PYTHON" -c 'import tkinter' 2>/dev/null; then
    echo "ERROR: tkinter is not available for $PYTHON." >&2
    echo "  Debian/Ubuntu:  sudo apt install python3-tk" >&2
    echo "  Fedora:         sudo dnf install python3-tkinter" >&2
    echo "  macOS:          brew install python-tk  (or use python.org's installer)" >&2
    exit 1
fi

exec "$PYTHON" p2_gui.py "$@"
