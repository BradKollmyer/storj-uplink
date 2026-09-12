# Native restore scheduler experiments

Worktree branch: `perf/native-storj-iterations`, starting from `e635fba`.

## Test 01: hedge deadline under trickling completions

The simulated production layout needs 29 pieces, launches 30 initially, and has
a total 35-attempt speculative cap. Twenty-seven initial pieces finish every
900 ms; three take 60 s. Unused spare pieces take 10 ms once launched.

Before the change, the regression test fails: the first spare starts at 25.3 s,
despite the 1 s hedge setting. Each completion recreates the sleep in `select!`.
The candidate keeps a persistent timer and resets it only after launching a
spare. Ready completions retain priority, and missed timer ticks do not trigger
catch-up bursts. The spare budget, failed-piece replacements, zero-delay disable
setting and abort/drain behavior remain unchanged.

Tradeoff: healthy pieces taking longer than the hedge interval can now trigger
spares despite making progress. The existing cap limits this traffic, but wire
cost is not assumed unchanged. Live tests must verify the latency benefit.

After the change the regression passes: the first spare starts at 1 s, the
download finishes before 22 s, and exactly 35 attempts launch. SDK validation:
62 uplink unit tests,52 public SDK unit tests,13 API-contract tests and 9
mock-fault tests pass; one pre-existing mock test remains ignored. The first
sandboxed suite had one unrelated loopback-bind permission failure; rerunning
with local socket permission passed. Formatting checks pass.

Regression command:

```sh
cargo test --offline -p storj-uplink --lib \
  trickling_completions_do_not_postpone_the_hedge_deadline
```

Live benchmark runner and per-test results live in the sibling CLI worktree,
`../rustic-native-iterations/benchmarks/native-storj/`.

## Live validation

The fixed 100-photo subset (1,849,631,128 bytes) was tested in interleaved runs:

| Scheduler | Object connections | First run | Repeat |
|---|---:|---:|---:|
| Previous resettable timer | 5 | 160.92 s | 154.03 s |
| Fixed cadence | 5 | 100.88 s | 100.31 s |
| Fixed cadence | 10 | 53.99 s | 61.10 s |
| Fixed cadence | 20 | 35.56 s | 32.61 s |

Every restored byte matched the reference. The code change alone reduced mean
wall time by 36.1% at the same five connections. The first baseline included
brief CPU/network profiling; its unprofiled repeat was similar. CPU samples
were dominated by waits, which motivated the subsequent concurrency sweep.

Full-day confirmation at 20 connections restored and verified all 814 files
(15,107,783,814 bytes) in 201.46 s (3.36 min), with no errors or warnings.
Maximum RSS was 3.95 GB. The earlier native five-connection full-day run took
1151.26 s; this combined improvement includes concurrency tuning as well as
the scheduler change. The default connection count remains five. The earlier
OpenDAL gateway result (689.17 s) also used five connections and is not an
equal-concurrency comparison against this tuned native run.

All nine live test results are committed individually in the CLI worktree.
SDK Clippy passes for all targets with warnings denied, as do formatting checks.
Speculative bytes were not measured; earlier bounded launches may increase
egress even though the attempt cap is unchanged. No repository writes or arc
deployment were performed.
