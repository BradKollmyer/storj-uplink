#!/usr/bin/env python3
"""Drop CodeQL results that sit in test code.

Removes:
  * paths under a `tests/` directory
  * locations at or after a column-0 `#[cfg(test)]` in the same file
    (unit tests in this repo live in a trailing module, not mixed in)

Keeps production alerts, including protocol zero-nonces above that marker.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def test_cutoff(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for i, line in enumerate(text.splitlines(), 1):
        if line.startswith("#[cfg(test)]"):
            return i
    return None


def uri_path(uri: str) -> str:
    if uri.startswith("file://"):
        uri = uri[len("file://") :]
    return uri


def is_tests_dir(uri: str) -> bool:
    p = uri_path(uri).replace("\\", "/")
    return "/tests/" in p or p.endswith("/tests")


def location_in_tests(loc: dict, cutoffs: dict[str, int | None], repo: Path) -> bool:
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri") or ""
    if is_tests_dir(uri):
        return True
    start = (phys.get("region") or {}).get("startLine")
    if start is None:
        return False
    if uri not in cutoffs:
        cutoffs[uri] = test_cutoff(repo / uri_path(uri))
    cutoff = cutoffs[uri]
    return cutoff is not None and start >= cutoff


def result_in_tests(result: dict, cutoffs: dict[str, int | None], repo: Path) -> bool:
    locs = result.get("locations") or []
    if not locs:
        return False
    return all(location_in_tests(loc, cutoffs, repo) for loc in locs)


def filter_sarif(data: dict, repo: Path) -> tuple[int, int]:
    kept = 0
    dropped = 0
    cutoffs: dict[str, int | None] = {}
    for run in data.get("runs") or []:
        results = run.get("results") or []
        filtered = []
        for result in results:
            if result_in_tests(result, cutoffs, repo):
                dropped += 1
            else:
                filtered.append(result)
                kept += 1
        run["results"] = filtered
    return kept, dropped


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: filter-test-alerts.py <file.sarif>", file=sys.stderr)
        return 2
    sarif_path = Path(sys.argv[1])
    repo = Path.cwd()
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    kept, dropped = filter_sarif(data, repo)
    sarif_path.write_text(json.dumps(data), encoding="utf-8")
    print(f"filter-test-alerts: kept {kept}, dropped {dropped} test-only result(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
