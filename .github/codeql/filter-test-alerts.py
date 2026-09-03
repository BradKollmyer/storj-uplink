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

_FN_RE = re.compile(r"^(?:pub(?:\([^)]+\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
_CRYPTO_RULE = "hard-coded-cryptographic-value"


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_cont(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


class _RustScan:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.line = 1

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def ch(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def starts(self, token: str) -> bool:
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
        if not self.starts(want):
            return False
        end = self.i + len(want)
        if end < len(self.s) and _is_ident_cont(self.s[end]):
            return False
        for _ in want:
            self.bump()
        return True

    def try_cfg_test_attr(self) -> bool:
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
    sc = _RustScan(text)
    sc.skip_trivia()
    return sc.eof()


def test_cutoff(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return test_cutoff_text(text)


def test_cutoff_text(text: str) -> int | None:
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


def _enclosing_fn_name(lines: list[str], start_line: int) -> str | None:
    for i in range(start_line, 0, -1):
        m = _FN_RE.match(lines[i - 1])
        if m:
            return m.group(1)
    return None


def is_documented_crypto_fp_text(text: str, start_line: int) -> bool:
    lines = text.splitlines()
    if start_line < 1 or start_line > len(lines):
        return False
    line = lines[start_line - 1]
    # Named protocol constant (Go storj.Nonce{}), including call sites.
    if "ZERO_NONCE" in line:
        return True
    return _enclosing_fn_name(lines, start_line) == "csprng_bytes"


def is_documented_crypto_fp(path: Path, start_line: int) -> bool:
    try:
        return is_documented_crypto_fp_text(path.read_text(encoding="utf-8"), start_line)
    except OSError:
        return False


def _result_rule_id(result: dict) -> str:
    if isinstance(result.get("ruleId"), str):
        return result["ruleId"]
    rule = result.get("rule")
    if isinstance(rule, dict):
        return str(rule.get("id") or "")
    if isinstance(rule, str):
        return rule
    return ""


def location_documented_crypto_fp(loc: dict, repo: Path) -> bool:
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    uri = art.get("uri") or ""
    start = (phys.get("region") or {}).get("startLine")
    if start is None:
        return False
    return is_documented_crypto_fp(repo / uri_path(uri), start)


def result_documented_crypto_fp(result: dict, repo: Path) -> bool:
    if _CRYPTO_RULE not in _result_rule_id(result):
        return False
    locs = result.get("locations") or []
    if not locs:
        return False
    return all(location_documented_crypto_fp(loc, repo) for loc in locs)


def filter_sarif(data: dict, repo: Path) -> tuple[int, int]:
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
"""
    assert is_documented_crypto_fp_text(crypto, 2)
    assert not is_documented_crypto_fp_text(crypto, 4)
    assert is_documented_crypto_fp_text(crypto, 7)
    assert is_documented_crypto_fp_text("encrypt(&ZERO_NONCE)\n", 1)

    print("filter-test-alerts: self-test ok")


def main() -> int:
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
