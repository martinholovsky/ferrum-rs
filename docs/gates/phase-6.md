# Phase 6: mitigating the CWEs that remain under Rust and Corten

Status: **in progress** (started 2026-11-01). The plan is [`../residual-mitigation.md`](../residual-mitigation.md); the per-CWE map is [`../residual-cwes.md`](../residual-cwes.md). Owner decisions on 2026-11-01: spec section 8, questions 13 to 15, the recommendation on all three. Nothing below is a result until its row says so.

Each item ships the way earlier phases did:
- a corpus case per CWE it claims, with every known way of writing the weakness as a `bad-*.rs`;
- detection and false-rejection rates with their totals (AGENTS.md rule 2);
- mutation checks for each new control;
- the Linux checks in the container (AGENTS.md).

A strategy that only strengthens C moves no bucket.

## Batches

| Batch | Strategies (proposal numbers) | Status | Blocked on |
| --- | --- | --- | --- |
| 1 | Decision 3: the ledger's `strategy` column, checked by `corten-ledger check` | **done** (2026-11-01, below) | |
| 2 | 15 lints; 9 labels on errors, logs and debug output | not started | |
| 3 | 4 budgets and timeouts; 3 safe deserialization and `ConfigCap`; 8 DirCap extensions | not started | |
| 4 | 2 authorization and authentication proof types: prototype, adopt only at 0 false rejections (question 14) | not started | |
| 5 | 10 cryptography and randomness; 7 TLS and network capabilities (question 13) | not started | The owner approving the crates, after the licence and supply-chain review |
| 6 | 6 web types; 11 credentials; 12 strict parsers; 13 contracts; 5 runtime; 14 supply chain | not started | |
| — | 1 the independent encoder review (25 rows) | blocked | The owner naming a reviewer (AGENTS.md rule 1: not the encoders' author; the AI pre-review is not the review of record) |
| — | 16 code-quality metrics; 17 assurance tooling; 18 out of scope | reported, not gated | Spec section 7 |

## Batch 1 result (2026-11-01)

- **Ledger.** `ledger/cwe-ledger.csv` gains a `strategy` column. 641 rows carry one of the 18 strategies in `audit/residual/strategies.csv`; the other 303 are empty. Apart from the new column, the ledger is byte-identical (checked by removing the column again).
- **Gate.** `corten-ledger check` now also requires a known strategy on every CWE safe Rust can still write under Corten, and refuses one on a CWE safe Rust cannot write. A verified E row may keep its strategy, so `--mark-verified` never leaves the gate failing.
- **Gate refusals, each watched on a copy of the real ledger:**
  - blanking the 16 `authz-types` rows: 16 problems, exit 1;
  - a strategy on CWE-787, which safe Rust cannot write: exit 1;
  - renaming `budgets` to an unknown value: 24 problems, exit 1;
  - removing `strategies.csv`: exit 2.
- **Unit tests.** They cover each rule and the missing-column error.
- **Single source.** The first assignment file (`audit/residual/assignment.csv`) was folded into the ledger and removed. `scripts/residual-map.py` now reads the ledger, and its output is unchanged apart from its header.
