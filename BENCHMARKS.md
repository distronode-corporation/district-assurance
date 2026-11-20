# Benchmarks

What the engine itself costs in time, measured, not guessed.

**These are engine costs on memory adapters, not call latency.** Every case runs on
`MemorySessionStore`, `MemoryAuditLedger` and the fakes of `district-assurance/testing`, in one
process, with nothing on the network. In a real call the host's session store, ledger and record
store, the carrier and the providers (texts, payment links, identity checks) take far longer than
the engine's own work, and they dominate. Use these numbers to see what the engine adds on top of
your adapters, and to catch a change that makes the engine slower, not to predict how long a call
takes.

## Running them

```sh
npm run bench                                       # about 1.1 seconds per case
npm run bench -- --budget-ms 5000                   # longer, steadier
npm run bench -- --out bench.json                   # also write the results as JSON
node bench/compare.ts previous.json current.json    # compare two result files
```

`--budget-ms` is the time spent measuring each case (default 1000), after a warm-up of a tenth of
that; `--min-iterations` is the fewest operations measured whatever the budget (default 5). Each
operation is awaited before the next starts, so the numbers are the time of one operation on an
idle engine, not throughput under concurrency. Timing uses `node:perf_hooks` only
(`performance.now()` and `createHistogram()`): no dependency, runtime or development.

Every case checks its own result once before it is timed (the PIN grants `owner.command`, the
verification reaches level 2, the receipt verifies, the config has no problem), so a case that
stops doing its work fails the run instead of looking faster.

## The cases

| Case | One operation |
|---|---|
| owner-command flow | the whole `owner-command` flow: `startCall`, `beginVerification` with the owner's subject key, `submitPin` (two Argon2id record checks), `finishVerification`, `authorize("owner.command")` and `endCall` (no receipt) |
| PIN record check | one `checkPinRecord`: Argon2id (19 MiB, 2 passes, 1 lane) of a keyed PIN, compared with its record in constant time (ADR-29); the PIN factor runs two at once per entry, the PIN's and the duress PIN's |
| level 2 verification | the `deposit` flow's first step: `startCall`, `beginVerification` by account number, `submitKeypad`, `checkCarrier` (an identity match) and `finishVerification` at level 2 |
| ledger append | one `MemoryAuditLedger.append`: canonical JSON, SHA-256, chained to the last entry |
| receipt sign | `signReceipt`: ES256 (P-256) over the canonical JSON of a receipt with a record, a payment and a consent |
| receipt verify | `verifyReceipt` against a one-key set: import the public JWK, check the signature |
| validateConfig, large | `validateConfig` on a valid config with 502 flows, 51 forms (50 of 20 fields) and 51 consent wordings |

The engine cases include what every engine step does with a session store: a read, a pure change,
a compare-and-set write and the ledger entries for it. Their cost grows with the number of steps,
not with the size of the workspace.

## Results

One run of `npm run bench` (budget 1000 ms per case) at commit `3f3168f`, on an
Intel Core i5-8265U at 1.60 GHz (8 cores), Linux 7.0 x64, Node v24.19.0. Times are per operation,
in microseconds. Another machine gives other numbers; compare runs on the same machine only.

| Case | ops/s | mean (µs) | p50 (µs) | p99 (µs) |
|---|---:|---:|---:|---:|
| owner-command flow | 875.5 | 1142.15 | 1075.20 | 1912.83 |
| level 2 verification | 893.7 | 1118.97 | 1077.25 | 2187.26 |
| ledger append | 57063.3 | 17.52 | 15.56 | 37.47 |
| receipt sign | 12121.8 | 82.50 | 76.73 | 145.53 |
| receipt verify | 5241.5 | 190.78 | 173.69 | 337.41 |
| validateConfig, large | 831.3 | 1202.95 | 1167.36 | 1617.92 |

So on this machine the engine added about a millisecond to a whole owner-command call or a level 2
verification, a receipt costs well under a millisecond to sign or check, and even a very large
config validates in about a millisecond, at save time.

That run predates PIN records in Argon2id (ADR-29), which make the PIN the one deliberately slow
step. One run on the same machine with the PIN record check, while other jobs shared it (so every
case read slower than above): `PIN record check` 30.2 ms mean (p99 32.2 ms), and `owner-command
flow` 40.8 ms mean (p99 45.4 ms), its two PIN record checks running at once. The other cases do
not touch a PIN record.

## The results file

`--out` writes one JSON document (here from the run above, with one of its six cases):

```json
{
  "format": 1,
  "commit": "3f3168fc7a986ed26712ac8bc647a57b49515766",
  "node": "v24.19.0",
  "os": { "type": "Linux", "platform": "linux", "release": "7.0.0-43-generic", "arch": "x64" },
  "cpu": { "model": "Intel(R) Core(TM) i5-8265U CPU @ 1.60GHz", "cores": 8 },
  "runner": null,
  "date": "2026-11-19T04:47:52.521Z",
  "budgetMs": 1000,
  "results": [
    { "name": "ledger append", "unit": "one entry, hashed and chained", "iterations": 56247,
      "opsPerSec": 57063.3, "meanUs": 17.52, "p50Us": 15.56, "p99Us": 37.47, "minUs": 14.43, "maxUs": 5013.5 }
  ]
}
```

`commit` is `git rev-parse HEAD` (or `GITHUB_SHA` outside a checkout), and `runner` is the
`BENCH_RUNNER` variable CI sets, null elsewhere. `format` changes when the shape does; the
comparison refuses a format it does not know. Case names are stable: the comparison matches cases
by name, so renaming a case shows it as removed and new.

## In CI

- **Every push and pull request** (`ci.yml`) runs `npm run bench -- --budget-ms 25` on every
  system and Node version of the matrix, so the scripts cannot rot. The numbers of a run that short
  are not used.
- **Every release** (`release.yml`, the `bench` job) checks out the previous release tag and runs
  its own benchmarks, then this release's, one after the other on the same `ubuntu-24.04` runner,
  and runs `bench/compare.ts` on the two. The comparison table goes to the run summary, and a case
  whose mean is more than 20% slower is marked there and raised as a warning. Shared runners are
  noisy, so one run never fails a release: no job needs the `bench` job, and it continues on
  error. A slowdown is a reason to run the benchmarks again, and to look, not a verdict. The two
  result files are kept as the `bench-results` artifact for 90 days.

Measuring both releases in the same job, rather than keeping each release's numbers for the next
one, means the two runs always share a runner type, a machine and a Node version, and no result
has to outlive an artifact's retention. A release from before the benchmarks has none to run, and
the summary says there is nothing to compare with.
