#!/usr/bin/env python3
"""Drop CodeQL results that sit in test code or documented false positives.

Removes:
  * paths under a `tests/` directory
  * locations at or after a trailing item-level `#[cfg(test)] mod ...`
  * `rust/hard-coded-cryptographic-value` on `pub const ZERO_NONCE` or
    inside `csprng_bytes` (Go `storj.Nonce{}` / CSPRNG scratch buffer)

The hard-coded-crypto query stays enabled for every other production site.
String literals and comments are ignored when finding the test-mod cutoff.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_CRYPTO_RULE = "hard-coded-cryptographic-value"
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _is_ident_start(ch: str) -> bool:
    """Return True if `ch` can start a Rust identifier."""
    return ch.isalpha() or ch == "_"


def _is_ident_cont(ch: str) -> bool:
    """Return True if `ch` can continue a Rust identifier."""
    return ch.isalnum() or ch == "_"


class _RustScan:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.line = 1

    def eof(self) -> bool:
        """Return True when the cursor is past the last character."""
        return self.i >= len(self.s)

    def ch(self) -> str:
        """Return the current character, or empty string at EOF."""
        return self.s[self.i] if self.i < len(self.s) else ""

    def starts(self, token: str) -> bool:
        """Return True if `token` starts at the cursor."""
        return self.s.startswith(token, self.i)

    def bump(self) -> str:
        ch = self.ch()
        self.i += 1
        if ch == "\n":
            self.line += 1
        return ch

    def skip_line_comment(self) -> None:
        while not self.eof() and self.ch() != "\n":
            self.bump()

    def skip_block_comment(self) -> None:
        # caller already saw /*
        self.bump()
        self.bump()
        while not self.eof():
            if self.starts("*/"):
                self.bump()
                self.bump()
                return
            self.bump()

    def skip_normal_string(self) -> None:
        quote = self.bump()  # "
        while not self.eof():
            ch = self.bump()
            if ch == "\\":
                if not self.eof():
                    self.bump()
            elif ch == quote:
                return

    def skip_raw_string(self) -> None:
        # r#*" ... "#*  (optional b/c prefix already consumed)
        hashes = 0
        if self.ch() == "r":
            self.bump()
        while self.ch() == "#":
            hashes += 1
            self.bump()
        if self.ch() != '"':
            return
        self.bump()
        close = '"' + ("#" * hashes)
        while not self.eof():
            if self.starts(close):
                for _ in close:
                    self.bump()
                return
            self.bump()

    def skip_char_or_lifetime(self) -> None:
        # 'ident  => lifetime; otherwise char literal
        self.bump()  # '
        if _is_ident_start(self.ch()):
            self.bump()
            while _is_ident_cont(self.ch()):
                self.bump()
            return
        while not self.eof():
            ch = self.bump()
            if ch == "\\":
                if not self.eof():
                    self.bump()
            elif ch == "'":
                return

    def skip_trivia(self) -> None:
        while not self.eof():
            ch = self.ch()
            if ch.isspace():
                self.bump()
                continue
            if self.starts("//"):
                self.skip_line_comment()
                continue
            if self.starts("/*"):
                self.skip_block_comment()
                continue
            return

    def skip_literal_or_ident_prefix(self) -> bool:
        """Skip a string/byte/c/raw string if one starts here. Return True if skipped."""
        i = self.i
        s = self.s
        if i < len(s) and s[i] in "bc":
            i += 1
        if i < len(s) and s[i] == "r":
            j = i + 1
            while j < len(s) and s[j] == "#":
                j += 1
            if j < len(s) and s[j] == '"':
                while self.i < i:
                    self.bump()
                self.skip_raw_string()
                return True
            return False
        if i < len(s) and s[i] == '"':
            while self.i < i:
                self.bump()
            self.skip_normal_string()
            return True
        return False

    def try_ident(self, want: str) -> bool:
        """Consume `want` if it is the next identifier; otherwise leave the cursor."""
        if not self.starts(want):
            return False
        end = self.i + len(want)
        if end < len(self.s) and _is_ident_cont(self.s[end]):
            return False
        for _ in want:
            self.bump()
        return True

    def try_cfg_test_attr(self) -> bool:
        """Consume a `#[cfg(test)]` attribute at the cursor, if present."""
        if self.ch() != "#":
            return False
        saved = (self.i, self.line)
        self.bump()
        self.skip_trivia()
        if self.ch() != "[":
            self.i, self.line = saved
            return False
        self.bump()
        self.skip_trivia()
        if not self.try_ident("cfg"):
            self.i, self.line = saved
            return False
        self.skip_trivia()
        if self.ch() != "(":
            self.i, self.line = saved
            return False
        self.bump()
        self.skip_trivia()
        if not self.try_ident("test"):
            self.i, self.line = saved
            return False
        self.skip_trivia()
        if self.ch() != ")":
            self.i, self.line = saved
            return False
        self.bump()
        self.skip_trivia()
        if self.ch() != "]":
            self.i, self.line = saved
            return False
        self.bump()
        return True

    def skip_balanced_braces(self) -> None:
        """Skip a `{ ... }` group, ignoring braces inside strings and comments."""
        if self.ch() != "{":
            return
        depth = 0
        while not self.eof():
            if self.skip_literal_or_ident_prefix():
                continue
            ch = self.ch()
            if ch == "/" and self.starts("//"):
                self.skip_line_comment()
                continue
            if ch == "/" and self.starts("/*"):
                self.skip_block_comment()
                continue
            if ch == "'":
                self.skip_char_or_lifetime()
                continue
            if ch == "{":
                depth += 1
                self.bump()
                continue
            if ch == "}":
                depth -= 1
                self.bump()
                if depth == 0:
                    return
                continue
            self.bump()


def _item_level_cfg_test_mods(text: str) -> list[tuple[int, int]]:
    """Return (start_line, end_index) for item-level `#[cfg(test)] mod ... { ... }`."""
    sc = _RustScan(text)
    depth = 0
    found: list[tuple[int, int]] = []
    while not sc.eof():
        sc.skip_trivia()
        if sc.eof():
            break
        if sc.skip_literal_or_ident_prefix():
            continue
        if sc.ch() == "'":
            sc.skip_char_or_lifetime()
            continue
        if sc.ch() == "{":
            depth += 1
            sc.bump()
            continue
        if sc.ch() == "}":
            depth = max(0, depth - 1)
            sc.bump()
            continue
        if depth == 0:
            start_line = sc.line
            start_i = sc.i
            if sc.try_cfg_test_attr():
                sc.skip_trivia()
                if sc.try_ident("mod"):
                    sc.skip_trivia()
                    while _is_ident_cont(sc.ch()):
                        sc.bump()
                    sc.skip_trivia()
                    if sc.ch() == "{":
                        sc.skip_balanced_braces()
                        found.append((start_line, sc.i))
                        continue
                sc.i, sc.line = start_i, start_line
        sc.bump()
    return found


def _is_trivia(text: str) -> bool:
    """Return True if `text` is only whitespace and comments."""
    sc = _RustScan(text)
    sc.skip_trivia()
    return sc.eof()


def test_cutoff(path: Path) -> int | None:
    """First line of a trailing `#[cfg(test)] mod` in `path`, if any."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return test_cutoff_text(text)


def test_cutoff_text(text: str) -> int | None:
    """First line of a trailing `#[cfg(test)] mod` in source text, if any."""
    spans = _item_level_cfg_test_mods(text)
    if not spans:
        return None
    if not _is_trivia(text[spans[-1][1] :]):
        return None
    k = len(spans) - 1
    while k > 0:
        prev_end = spans[k - 1][1]
        cur_start_idx = _span_start_idx(text, spans[k][0])
        if _is_trivia(text[prev_end:cur_start_idx]):
            k -= 1
        else:
            break
    return spans[k][0]


def _span_start_idx(text: str, line: int) -> int:
    """Byte offset of the start of 1-based `line` in `text`."""
    if line <= 1:
        return 0
    seen = 1
    for i, ch in enumerate(text):
        if ch == "\n":
            seen += 1
            if seen == line:
                return i + 1
    return len(text)


def uri_path(uri: str) -> str:
    """Strip a `file://` prefix from a SARIF artifact URI."""
    if uri.startswith("file://"):
        uri = uri[len("file://") :]
    return uri


def is_tests_dir(uri: str) -> bool:
    """Return True if the URI is under a `tests/` directory."""
    p = uri_path(uri).replace("\\", "/")
    return "/tests/" in p or p.endswith("/tests")


def location_in_tests(loc: dict, cutoffs: dict[str, int | None], repo: Path) -> bool:
    """Return True if this SARIF location is in tests/ or a trailing test module."""
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
    """Return True if every location on this result is in test code."""
    locs = result.get("locations") or []
    if not locs:
        return False
    return all(location_in_tests(loc, cutoffs, repo) for loc in locs)


def _code_ident_spans(line: str) -> list[tuple[int, int, str]]:
    """0-based [start, end) identifier spans in code, skipping comments/strings."""
    spans: list[tuple[int, int, str]] = []
    i = 0
    n = len(line)
    while i < n:
        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            end = line.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        ch = line[i]
        if ch in "bc" and i + 1 < n and line[i + 1] in '"r':
            i += 1
            ch = line[i]
        if ch == "r" and i + 1 < n and line[i + 1] in '#"':
            i += 1
            hashes = 0
            while i < n and line[i] == "#":
                hashes += 1
                i += 1
            if i < n and line[i] == '"':
                i += 1
                close = '"' + ("#" * hashes)
                j = line.find(close, i)
                i = n if j < 0 else j + len(close)
            continue
        if ch == '"':
            i += 1
            while i < n:
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "'":
            i += 1
            continue
        m = _IDENT_RE.match(line, i)
        if m:
            spans.append((m.start(), m.end(), m.group()))
            i = m.end()
            continue
        i += 1
    return spans


def _region_hits_ident(
    line: str, ident: str, start_col: int | None, end_col: int | None
) -> bool:
    """Return True if `ident` is a code token overlapping the SARIF columns."""
    spans = [s for s in _code_ident_spans(line) if s[2] == ident]
    if not spans:
        return False
    if start_col is None:
        return True
    a = start_col - 1
    b = (end_col - 1) if end_col is not None else a + 1
    if b <= a:
        b = a + 1
    return any(s < b and e > a for s, e, _ in spans)


def _item_fn_body_lines(text: str, name: str) -> tuple[int, int] | None:
    """Line range (inclusive) of an item-level `fn name ... { ... }`."""
    sc = _RustScan(text)
    depth = 0
    while not sc.eof():
        sc.skip_trivia()
        if sc.eof():
            break
        if sc.skip_literal_or_ident_prefix():
            continue
        if sc.ch() == "'":
            sc.skip_char_or_lifetime()
            continue
        if sc.ch() == "{":
            depth += 1
            sc.bump()
            continue
        if sc.ch() == "}":
            depth = max(0, depth - 1)
            sc.bump()
            continue
        if depth == 0:
            saved = (sc.i, sc.line)
            start_line = sc.line
            if sc.try_ident("pub"):
                sc.skip_trivia()
                if sc.ch() == "(":
                    while not sc.eof() and sc.ch() != ")":
                        sc.bump()
                    if sc.ch() == ")":
                        sc.bump()
                    sc.skip_trivia()
            if sc.try_ident("fn"):
                sc.skip_trivia()
                ident_i = sc.i
                while _is_ident_cont(sc.ch()):
                    sc.bump()
                ident = sc.s[ident_i : sc.i]
                if ident == name:
                    while not sc.eof():
                        if sc.skip_literal_or_ident_prefix():
                            continue
                        if sc.ch() in " \t\r\n":
                            sc.skip_trivia()
                            continue
                        if sc.starts("//"):
                            sc.skip_line_comment()
                            continue
                        if sc.starts("/*"):
                            sc.skip_block_comment()
                            continue
                        if sc.ch() == "{":
                            sc.skip_balanced_braces()
                            return (start_line, sc.line)
                        sc.bump()
                    return None
            sc.i, sc.line = saved
        sc.bump()
    return None


def is_documented_crypto_fp_text(
    text: str,
    start_line: int,
    start_col: int | None = None,
    end_col: int | None = None,
) -> bool:
    """Return True if this span is `ZERO_NONCE` or inside `csprng_bytes`."""
    lines = text.splitlines()
    if start_line < 1 or start_line > len(lines):
        return False
    line = lines[start_line - 1]
    if _region_hits_ident(line, "ZERO_NONCE", start_col, end_col):
        return True
    rng = _item_fn_body_lines(text, "csprng_bytes")
    if rng is None:
        return False
    lo, hi = rng
    return lo <= start_line <= hi


def is_documented_crypto_fp(
    path: Path,
    start_line: int,
    start_col: int | None = None,
    end_col: int | None = None,
) -> bool:
    """File-backed wrapper for `is_documented_crypto_fp_text`."""
    try:
        return is_documented_crypto_fp_text(
            path.read_text(encoding="utf-8"), start_line, start_col, end_col
        )
    except OSError:
        return False


def _result_rule_id(result: dict) -> str:
    """Read a SARIF result's rule id from `ruleId` or nested `rule`."""
    if isinstance(result.get("ruleId"), str):
        return result["ruleId"]
    rule = result.get("rule")
    if isinstance(rule, dict):
        return str(rule.get("id") or "")
    if isinstance(rule, str):
        return rule
    return ""


def location_documented_crypto_fp(loc: dict, repo: Path) -> bool:
    """Return True if this SARIF location is a documented crypto false positive."""
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri") or ""
    region = phys.get("region") or {}
    start = region.get("startLine")
    if start is None:
        return False
    return is_documented_crypto_fp(
        repo / uri_path(uri),
        start,
        region.get("startColumn"),
        region.get("endColumn"),
    )


def result_documented_crypto_fp(result: dict, repo: Path) -> bool:
    """Return True if this hard-coded-crypto result is a documented false positive."""
    if _CRYPTO_RULE not in _result_rule_id(result):
        return False
    locs = result.get("locations") or []
    if not locs:
        return False
    return all(location_documented_crypto_fp(loc, repo) for loc in locs)


def filter_sarif(data: dict, repo: Path) -> tuple[int, int]:
    """Drop test-only and documented-FP results. Return (kept, dropped)."""
    kept = 0
    dropped = 0
    cutoffs: dict[str, int | None] = {}
    for run in data.get("runs") or []:
        results = run.get("results") or []
        filtered = []
        for result in results:
            if result_in_tests(result, cutoffs, repo) or result_documented_crypto_fp(
                result, repo
            ):
                dropped += 1
            else:
                filtered.append(result)
                kept += 1
        run["results"] = filtered
    return kept, dropped


def _self_test() -> None:
    """In-process regressions for test-mod cutoff and documented crypto FPs."""
    # String / raw-string / comment markers must not hide later production.
    src = '''
fn prod_before() {}
const DOCS: &str = r#"
#[cfg(test)]
mod tests {
}
"#;
fn prod_after() { let _ = "#[cfg(test)]"; }
// #[cfg(test)]
/* #[cfg(test)] mod tests {} */
fn still_prod() {}
'''
    assert test_cutoff_text(src) is None, test_cutoff_text(src)

    src2 = """
fn production() {}
#[cfg(test)]
mod tests {
    fn t() {}
}
"""
    assert test_cutoff_text(src2) == 3, test_cutoff_text(src2)

    src3 = """
fn production() {}
#[cfg(test)]
mod piece_size_tests {
    fn a() {}
}
#[cfg(test)]
mod tests {
    fn b() {}
}
"""
    assert test_cutoff_text(src3) == 3, test_cutoff_text(src3)

    src4 = """
fn production() {}
#[cfg(test)]
fn only_a_test_fn() {}
fn more_production() {}
"""
    assert test_cutoff_text(src4) is None, test_cutoff_text(src4)

    # Regression: string marker, then a real trailing test mod — cutoff is the mod.
    src5 = '''
fn prod() {}
const S: &str = "#[cfg(test)]";
fn still_prod() {}
#[cfg(test)]
mod tests {
    fn t() {}
}
'''
    line = test_cutoff_text(src5)
    assert line == 5, line

    crypto = """
pub const ZERO_NONCE: [u8; 24] = [0; 24];
fn other() {
    let key = [0u8; 32];
}
fn csprng_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    bytes
}
const KEY: [u8; 32] = [0; 32];
"""
    assert is_documented_crypto_fp_text(crypto, 2)
    assert not is_documented_crypto_fp_text(crypto, 4)
    assert is_documented_crypto_fp_text(crypto, 7)
    assert not is_documented_crypto_fp_text(crypto, 10)
    assert is_documented_crypto_fp_text("encrypt(&ZERO_NONCE)\n", 1)
    # Comment beside an unrelated key must not match ZERO_NONCE.
    assert not is_documented_crypto_fp_text(
        "let key = [0u8; 32]; // ZERO_NONCE protocol constant\n", 1
    )
    assert not is_documented_crypto_fp_text(
        "let key = [0u8; 32]; // ZERO_NONCE protocol constant\n",
        1,
        start_col=11,
        end_col=20,
    )

    import tempfile

    td = Path(tempfile.mkdtemp())
    (td / "lib.rs").write_text(crypto)
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "rust/hard-coded-cryptographic-value",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "lib.rs"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "rust/hard-coded-cryptographic-value",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "lib.rs"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                    },
                ]
            }
        ]
    }
    kept, dropped = filter_sarif(sarif, td)
    assert dropped == 1 and kept == 1, (kept, dropped)
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "region"
    ]["startLine"] == 10

    print("filter-test-alerts: self-test ok")


def main() -> int:
    """Run `--self-test` or filter the SARIF file given as argv[1]."""
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        _self_test()
        return 0
    if len(sys.argv) != 2:
        print(
            "usage: filter-test-alerts.py <file.sarif> | --self-test",
            file=sys.stderr,
        )
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
