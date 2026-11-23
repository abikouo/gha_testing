#!/usr/bin/env python3
"""Keep counter.txt in sync with the repository's commit count.

Two design choices here are load-bearing; changing either one breaks convergence.

1. The count comes from HEAD, never from ``--all``.

   ``git rev-list --count --all`` walks *every* ref: local branches,
   remote-tracking branches, tags and the stash. That set differs between any
   two clones -- in this repository it currently reports 435 against HEAD's 422,
   purely because of stale branches. A value derived from ``--all`` could never
   agree between a contributor's machine and CI, so the check would fail forever.

2. Commits produced by this script are excluded from the count, via
   COUNTER_MARKER in their commit message.

   counter.txt stores a number that counts the commits containing counter.txt,
   which is self-referential. If the correcting commit were itself counted, the
   value would be stale the instant it was written and an autofixer would push a
   correction, then a correction to the correction, forever. Excluding those
   commits makes the correct value a fixed point.

The file is only rewritten when the stored value differs from the computed one,
so running this repeatedly is a no-op once the repository is in sync.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

COUNTER_FILE = "counter.txt"

# Must appear in the commit message of every commit that carries this script's
# output. Keep in sync with `ci.autofix_commit_msg` in .pre-commit-config.yaml.
COUNTER_MARKER = "[counter]"


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


def commit_count() -> int:
    """Commits reachable from HEAD, ignoring counter-bump commits."""
    out = subprocess.run(
        [
            "git",
            "rev-list",
            "--count",
            "HEAD",
            # --fixed-strings is required. Without it "[counter]" is parsed as a
            # regex character class matching any of c/o/u/n/t/e/r, which excludes
            # nearly every commit (422 -> 4 in this repository).
            "--fixed-strings",
            "--grep",
            COUNTER_MARKER,
            "--invert-grep",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return int(out.stdout.strip())


def read_stored(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync counter.txt with the repository commit count."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift without writing; exit 1 if out of sync",
    )
    # pre-commit passes matched filenames positionally; accept and ignore them.
    parser.add_argument("filenames", nargs="*", help=argparse.SUPPRESS)
    args = parser.parse_args()

    path = repo_root() / COUNTER_FILE
    expected = commit_count()
    stored = read_stored(path)

    if stored == expected:
        return 0

    if args.check:
        print(
            f"{COUNTER_FILE} is out of sync: found {stored}, expected {expected}.\n"
            f"Run 'pre-commit run --all-files' (or 'python scripts/update_counter.py') "
            f"and commit the result.",
            file=sys.stderr,
        )
        return 1

    path.write_text(f"{expected}\n")
    print(f"{COUNTER_FILE}: {stored} -> {expected}")
    # Non-zero so pre-commit reports "files were modified by this hook".
    return 1


if __name__ == "__main__":
    sys.exit(main())
