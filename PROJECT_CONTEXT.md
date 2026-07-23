# Jedi Pairing / M-HIBE Project Context

Updated: 2026-07-21

The historical import below condenses 10 JSONL files found under `C:\Users\Administrator\.codex\sessions` (27.7 MB at the time of that import). Eight sessions directly concern this repository, one session concerns a related but separate blockchain-traceability paper, and one concerns chemistry/mass spectrometry and is intentionally excluded from project guidance. Tool logs, system prompts, duplicated context, and aborted intermediate output were not copied.

## Latest Session Scan (2026-07-21)

In the current Linux environment, the requested Windows path resolves to `/home/xing/.codex/sessions`. At the start of this import, the directory contained these two files (111,026 bytes total at that snapshot):

- `rollout-2026-07-21T15-01-31-019f837a-cf2e-7380-a26e-4617dc02220b.jsonl`
- `rollout-2026-07-21T15-09-24-019f8382-04d3-7fd1-af3b-ddf02640b11d.jsonl`

Every JSONL record present in the import snapshot parsed successfully. The second file is the active session and continues to grow while this task runs. The two sessions contain a prior `hello` exchange and the current context-import request, plus system/developer prompts and tool traces. They add no repository edits, M-HIBE protocol decisions, benchmark measurements, test results, or unresolved engineering tasks. The established guidance below therefore remains the active project context.

## Project Focus

The active research work is under `lang/go/mhibe`. It evaluates WKD-IBE/M-HIBE-based confidentiality, access control, and completeness proofs for multidimensional range queries, together with a ZK accumulator for authenticity. The main workload uses TPC-H `lineitem_120K.tbl` (historically referenced at `/home/xing/poneglyphdb/src/data/lineitem_120K.tbl`).

The user prefers Chinese explanations, concrete examples, rigorous complexity analysis, and benchmark changes that preserve old files by creating named variants.

## Established Protocol Semantics

The old Multi-Sweep design was rejected. Do not generate covers by permuting all dimension orders and taking their union. The accepted fixed-order construction recursively handles dimensions: cover empty ranges in the first dimension; for occupied prefixes, descend into the next dimension and supplement their empty children; continue until the final dimension.

Empty-region key material must be query independent at database setup time:

1. The data owner builds a database-wide sparse prefix occupancy structure.
2. Global empty parent regions and their WKD-IBE parent keys are materialized or represented offline.
3. After a query arrives, the server selects global parents intersecting the query.
4. It intersects/crops them to query-scoped empty patterns.
5. It delegates query-scoped child keys from the global parent keys.
6. The client verifies returned records plus empty-region coverage; the ZK accumulator authenticates the result.

Generating empty keys directly from query results, or building only a query-touched index while calling it full offline initialization, is not a complete implementation of the intended protocol.

`-upload-keys` materializes a WKD-IBE key for every real database row. Historical discussion concluded that this is optional record-level access-control/stress-test work, not a required cost of the main empty-region completeness protocol unless the paper explicitly claims per-record keys. `UPLOAD STAGE: SKIPPED` therefore means that optional materialization was not run.

## Dimensional Mapping and Queries

Historical benchmark mappings used TPC-H fields such as:

- 2D: ship date, discount.
- 3D: ship date, discount, quantity.
- 4D: ship date, discount, quantity, tax.
- Higher-dimensional files add further lineitem attributes.

The 4D query was corrected so the added dimension is a range, not a singleton. A representative query used date `[731,1095]`, discount `[5,7]`, quantity `[0,23]`, and tax `[2,6]`. Verify each file before quoting exact bounds.

Uniform 12-bit domains are convenient but wasteful. Historical optimization work introduced real per-dimension widths, for example date 12-bit, discount 4-bit, quantity 6-bit, tax 4-bit. Dimension ordering affects cover count and runtime; `dry_run_dimension_order_test.go` estimates all 3D orders without generating keys.

## Complexity and Scaling Conclusions

For `n` records and roughly `l` prefix levels per dimension, explicit prefix-combination indexing behaves approximately as:

- 2D: `O(n*l)`
- 3D: `O(n*l^2)`
- dD: `O(n*l^(d-1))`

More exactly, the work includes sums/products of `(bitLength_i + 1)` over parent dimensions. It is polynomial for fixed dimension but exponential in growing dimension. The scheme avoids enumerating every point in the full coordinate universe, but explicit materialization of all parent-prefix combinations still suffers a dimensional explosion.

Consequences established in prior sessions:

- 2D is practical in the current prototype; 3D may be expensive; 4D full-domain materialization can run for hours or exhaust memory; 5D/10D complete materialization is generally not credible with the current representation.
- Parallelism reduces constants but cannot remove the dimensional growth.
- A long-running or OOM 4D experiment is an algorithm/data-structure scalability result, not merely a slow Go implementation.
- Claims such as "arbitrary multidimensional queries are engineering-feasible" or "exponential to polynomial" need qualification. The defensible claim is improved sparse representation for fixed low dimension, with explicit high-dimensional limitations.

## Benchmark Accounting

Keep these categories separate:

- Total setup: cryptographic setup, query-independent database offline initialization, and ZK commitment when applicable.
- Online server proving: query-scoped M-HIBE extraction/delegation plus ZK proving.
- Client protocol verification: geometric completeness checks plus ZK verification.
- Experimental audits: exhaustive encrypt/decrypt checks, full cover enumeration, or other validation not required in the deployed protocol.

Historical changes separated audit time from `Total Client Verification Time`. Do not fold trusted-data-owner offline audits into client cost. When the data owner is assumed trusted, several exhaustive audits were removed from 3D/4D/5D/10D variants; retain enough correctness tests to validate implementation behavior.

The 2D full parallel historical baseline (120,515 rows, 20 workers, with ZK) reported approximately: offline initialization 634 ms, 597 global parents, 142 KB parent-key material, Engine A 22 ms, ZK commitment 22.4 s, ZK prover 2.46 s, ZK verifier 2.42 ms, and full crypto audit 1.27 s. Treat these as historical measurements, not reproducible current results until rerun.

## File Families

Important current files include:

- Baselines: `cmd_bench_2d.go`, `cmd_bench_3d.go`, `cmd_bench_4d.go`, `cmd_bench_5d.go`, `cmd_bench_10d.go`.
- Parallel variants: corresponding `*_parallel.go` files plus `cmd_bench_3d_full_parallel.go`.
- Full/offline variants: `cmd_bench_2d_offline_serial.go`, `cmd_bench_2d_full_audit.go`, `cmd_bench_2d_offline_full_crypto_parallel.go`, and `cmd_bench_{3d,4d,5d,10d}_full_audit{,_parallel}.go`.
- 4D experiments: `cmd_bench_4d_order_opt.go`, `cmd_bench_4d_varbits.go`, and `cmd_bench_4d_memopt.go`.
- Tests/docs: `dry_run_dimension_order_test.go`, `empty_region_test.go`, `integration_test.go`, `mhibe_test.go`, `mhibe_empty_key_algorithms.tex`, and related PDFs/Markdown.

Some historical session summaries refer to filenames that may have since changed or been overwritten. Inspect the current source before relying on a session statement.

## Parallelism and Memory Findings

The useful parallel boundaries are independent index partitions, parent-region generation partitions, independent key generation/delegation, and independent cryptographic verification checks. Greedy set cover has sequential dependency and is not directly parallelizable without changing the algorithm.

Prior experiments found poor scaling from shared Go maps and random memory access. More workers can increase memory pressure without saturating CPU. One parallel implementation also changed the reduction strategy by performing local maximal-pattern elimination per partition before a final merge; comparisons against a serial baseline must use the same algorithmic work, otherwise the speedup is not attributable purely to parallelism.

The 4D OOM diagnosis identified these amplifiers:

- Every record expands into many combinations of prefixes across the first three dimensions.
- Workers hold private nested-map shards concurrently.
- Merge phases retain shards and the final index at the same time.
- String keys and nested `map[int64]struct{}` values have high overhead.
- Candidate pattern slices, deduplication, sorting, and parent `SecretKey` objects coexist at peak memory.

Preferred remediation directions, in order of structural value:

1. Deduplicate coordinate tuples before indexing.
2. Use real per-dimension domains and bit widths.
3. Separate index worker count from crypto worker count.
4. Merge bounded shards incrementally and release them promptly.
5. Replace string/nested-map keys with compact encoded prefix IDs and compressed occupancy structures.
6. Stream candidate generation and reduction instead of retaining all local candidates.
7. Persist parent keys and load only query-touched keys.
8. Partition the computation into bounded batches with checkpointed output when full materialization is still required.

Lowering `max-parent-dim` changes completeness semantics and must not be presented as the same protocol. Capping global regions is acceptable only as an explicitly incomplete diagnostic run.

## Current Open Problem

The latest project request before this context import was analysis, not implementation: large `-limit` values cause OOM, and the user asked to evaluate three approaches before changing code:

1. Release unused memory more aggressively and determine whether retained garbage is the cause.
2. Remove data not participating in the current computation or keep only the active working set in memory.
3. Split work into batches, record partial results, release memory, and continue.

Future work should first profile peak allocation and retained heap in the relevant executable, then distinguish temporary garbage from intrinsically live index/key material. The likely durable solution is bounded, streaming/batched construction with compact representations; forcing GC alone will not solve an oversized live set.

## Related but Separate Session

A 2026-06-16 session edited responses for the paper "Verifiable Bidirectional Traceability Queries for Multi-Source Blockchain Databases" (DAG/cycle limitations, query-node and consensus-node roles, index upload through consensus, SMPT novelty, complexity trade-offs). It may be relevant to paper-writing style but is not authoritative context for the M-HIBE implementation.

## Working Rules Derived from History

- Read the exact target file before editing; many similarly named experimental variants exist.
- Preserve baseline files and create a new variant when requested.
- Do not label query-dependent preprocessing as query-independent offline setup.
- Do not compare serial and parallel timings unless both perform equivalent algorithmic work.
- Report incomplete/capped runs explicitly.
- Keep protocol costs and experimental audit costs separate.
- Rerun tests or benchmarks before presenting historical numbers as current results.
