# Native restore scheduler experiments

Worktree branch: `perf/native-storj-iterations`, starting from `e635fba`.

## Test01: hedge deadline under trickling completions

The simulated production layout needs29 pieces, launches30 initially, and has
a total35-attempt speculative cap. Twenty-seven initial pieces finish every
900ms; three take60s. Unused spare pieces take10ms once launched.

Before the change, the regression test fails: the first spare starts at25.3s,
despite the1s hedge setting. Each completion recreates the sleep in `select!`.
The candidate keeps a persistent timer and resets it only after launching a
spare. Ready completions retain priority, and missed timer ticks do not trigger
catch-up bursts. The spare budget, failed-piece replacements, zero-delay disable
setting and abort/drain behavior remain unchanged.

Tradeoff: healthy pieces taking longer than the hedge interval can now trigger
spares despite making progress. The existing cap limits this traffic, but wire
cost is not assumed unchanged. Live tests must verify the latency benefit.

After the change the regression passes: the first spare starts at1s, the
download finishes before22s, and exactly35 attempts launch. SDK validation:
62 uplink unit tests,52 public SDK unit tests,13 API-contract tests and9
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
