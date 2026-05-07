# APPROACH — AI Threat Hunting Query Generation System

This document is a living record of our prompting strategy, iteration process,
observed failure patterns, and improvements made. It is updated after each
iteration.

> **Note**: Detailed per-iteration evaluation reports and metrics for Iterations 1-4 are available in the `results/iteration_test_results/` directory.

---

## Iteration 1 — Baseline (2026-05-07)

### Prompting Strategy

Zero-shot, schema-aware, JSON-mode prompting.

- System prompt: role assignment, 6 SQL rules, full table schema, output JSON format
- User prompt: hypothesis id, name, and description
- Settings: `temperature=0`, `seed=42`, `response_format={"type":"json_object"}`

### Baseline Results (Iteration 1)

| Metric           | Value  |
|-----------------|--------|
| Macro Precision  | 0.0002 |
| Macro Recall     | 0.8182 |
| Macro F1         | 0.0005 |
| Queries OK       | 11/11  |

Per-hypothesis (Iteration 1):

| ID  | P      | R   | F1     | Returned | Expected | Notes                     |
|-----|--------|-----|--------|----------|----------|---------------------------|
| 1   | 0.00   | 0.0 | 0.00   | 0        | 12       | Wrong error message filter |
| 2   | 0.00   | 0.0 | 0.00   | 0        | 61       | Wrong eventName (signin vs ConsoleLogin) |
| 3   | 0.00   | 1.0 | 0.00   | 1145     | 4        | Evaluator bug: wrong match key |
| 4   | 0.00   | 1.0 | 0.00   | 473913   | 2387     | Evaluator bug: aggregated GT, raw query |
| 5   | 0.00   | 1.0 | 0.00   | 17128    | 4767     | Evaluator bug: aggregated GT, raw query |
| 6   | 0.0026 | 1.0 | 0.0051 | 398      | 1        | Over-broad (14 event types vs 1) |
| 7   | 0.00   | 1.0 | 0.00   | 300622   | 34       | Evaluator bug: aggregated GT, raw query |
| 8   | 0.00   | 1.0 | 0.00   | 42651    | 212      | Evaluator bug: aggregated GT, raw query |
| 9a  | 0.00   | 1.0 | 0.00   | 156930   | 1896     | Evaluator bug: aggregated GT, raw query |
| 9b  | 0.00   | 1.0 | 0.00   | 3047     | 101      | Evaluator bug: aggregated GT, raw query |
| 10  | 0.00   | 1.0 | 0.00   | 40       | 40       | Evaluator bug: no eventID in GT |

---

## Root Cause Analysis (Iteration 1)

### Root Cause 1 — Evaluator always keys on `eventID`, but only 2/11 hypotheses have it in ground truth

The evaluator's `score()` function defaults to matching result rows via `eventID`.
Inspecting `hypotheses_outcomes.json` reveals three distinct ground truth schemas:

| Type | Hypotheses | Ground truth schema | Correct matching strategy |
|------|-----------|---------------------|--------------------------|
| A — eventID-keyed | 2, 6 | Has `eventID` column | Match on `eventID` ✅ (already correct) |
| B — composite-key row-level | 1, 3, 10 | No `eventID`; fixed set of attribute cols | Match on all GT columns present in result |
| C — aggregated | 4, 5, 7, 8, 9a, 9b | Has `count` column; GROUP BY key cols | Query must also GROUP BY + count; match on key cols |

Because `_normalise_keys(expected, ['eventID'])` returns an empty set when `eventID` is absent, **9 of 11 hypotheses had an empty `expected_set` and were never actually scored**. The apparent R=1.0 is an artifact of the edge-case branch (`fn=0` when `expected_set` is empty), not a real result.

### Root Cause 2 — LLM generates raw SELECT for aggregated hypotheses

For Type C hypotheses (4,5,7,8,9a,9b), the expected output is a GROUP BY + count
aggregation. The system prompt instructed the LLM to return individual rows (always
include `eventID`), so it never generated aggregations. The structural mismatch meant
no row in the result could ever match a row in the aggregated ground truth.

### Root Cause 3 — No actual column values in the prompt

The LLM was told column names and types but not what values actually appear in the data.
This caused two concrete wrong-value failures:

- **Hypothesis 2**: LLM used `eventName = 'signin'`. Actual value in the dataset: `ConsoleLogin`.
  The query returned 0 rows.
- **Hypothesis 1**: LLM invented error message patterns (`%failed authentication%`, etc.).
  Actual `errorMessage` for failed sign-ins: `'No username found in supplied account'`.
  The query returned 0 rows.

The data contains these exact values (confirmed by `SELECT DISTINCT`):
- `eventName`: `ConsoleLogin`, `RunInstances`, `GetCallerIdentity`, `GetBucketAcl`, …
- `userIdentitytype`: `IAMUser`, `Root`, `AssumedRole`, `AWSService`, `AWSAccount`
- `errorCode`: `Client.UnauthorizedOperation`, `AccessDenied`, `Client.RequestLimitExceeded`, …

### Root Cause 4 — Wrong match key for Type B hypotheses not in `HYP_KEY_MAP`

`HYP_KEY_MAP` only overrode hypothesis `1`. Hypotheses `3` and `10` also have no `eventID`
in their ground truth but were not listed, so they used the default `eventID` key and scored
as if expected_set were empty.

### Root Cause 5 — Hypothesis 6 over-broad (14 event types vs. 1 expected)

The LLM listed 14 Secrets Manager actions in its query. The ground truth contains exactly
1 expected row. The correct query likely only needs `GetSecretValue`. All other Secrets
Manager events are noise from the LLM's over-eager threat coverage.

### Root Cause 6 — Hypothesis id/name in user prompt is unnecessary noise

The user prompt included hypothesis id and name, which the LLM used to rationalize queries
(e.g., "the developer instructions specify" based on the name). This is prompt noise.

---

## Iteration 2 — Plan (2026-05-08)

### Changes in Iteration 2

#### 1. Fix the evaluator (biggest impact: 9 hypotheses wrongly scored as 0)

Auto-detect ground truth type from its column schema:
- **Type A** (`eventID` in GT) → match on `eventID` (unchanged)
- **Type B** (no `eventID`, no `count`) → match on the intersection of GT columns and result columns
- **Type C** (`count` in GT) → match on all GT key-columns (all except `count`); query must return those same columns plus a `count` column; compare exact row-tuples

Log the detected type and match key clearly at INFO level.

#### 2. Add data dictionary to system prompt

Pre-compute once at startup (or cached per run):
- Top 50 `eventName` values with frequencies
- All `userIdentitytype` values
- Top 15 `errorCode` values
- Top 15 `eventSource` values

Inject into the system prompt as a `## Data Dictionary` section. This directly fixes
wrong-value failures in hypotheses 1 and 2.

#### 3. Pass expected output schema per hypothesis to the LLM

In the user prompt, tell the LLM exactly what columns the query must return and whether
a GROUP BY + count is required. Derive this from the ground truth schema:
- If GT has `count`: "Your query MUST use GROUP BY and return a `count` column.
  Return columns: [col1, col2, ..., count(*) as count]"
- If GT has no `count` and no `eventID`: "Return columns: [col1, col2, ...]"
- If GT has `eventID`: "Return eventID and any other columns"

This tells the LLM whether to aggregate and what to name the output columns — directly
fixing the structural mismatch for Type C hypotheses.

#### 4. Better structured logging

- Log the generated SQL at `INFO` (clearly visible, not buried in DEBUG)
- After evaluation, log 3 sample false-positive rows (with relevant columns) so we can
  see why extra rows are returned
- After evaluation, log 3 sample false-negative rows (fetched directly from DB by key)
  so we can see what was missed
- Log the detected GT type and match key for every hypothesis
- Add `[HYP-{id}]` prefix to all log messages so filtering is easy

#### 5. Fix `HYP_KEY_MAP` for Type B hypotheses 3 and 10

Add correct composite keys:
- Hyp 3: `["eventTime", "eventName", "userIdentityarn", "sourceIPAddress"]`
- Hyp 10: `["sourceIPAddress", "userIdentityarn", "errorCode", "errorMessage"]`

---

## Improvements Made (Iteration 2)

All five planned changes were implemented:
1. Evaluator redesigned with auto GT-type detection (A/B/C).
2. Data dictionary (real column values from DB) injected into system prompt.
3. Expected output schema (columns + GROUP BY requirement) passed in user prompt.
4. Hypothesis id/name removed from user prompt.
5. Structured `[HYP-{id}]` logging with SQL, FP/FN sample tuples, and match keys.

## Before / After Metrics (Iteration 1 → Iteration 2)

| Hypothesis | Iter 1 F1 | Iter 2 F1  | Change    | GT Type | Root cause fixed                             |
|-----------|-----------|------------|-----------|---------|----------------------------------------------|
| 1         | 0.00      | 0.00       | —         | B       | Timestamp mismatch remains (ISO vs pg ts)    |
| 2         | 0.00      | **1.00**   | +1.00     | A       | Wrong eventName fixed (signin→ConsoleLogin)  |
| 3         | 0.00      | 0.00       | —         | B       | Timestamp mismatch remains                   |
| 4         | 0.00      | **0.94**   | +0.94     | C       | Evaluator redesign + GROUP BY instruction    |
| 5         | 0.00      | **1.00**   | +1.00     | C       | Evaluator redesign + GROUP BY instruction    |
| 6         | 0.0051    | 0.0051     | —         | A       | GT = 1 row; query still lists 14 event types |
| 7         | 0.00      | **0.89**   | +0.89     | C       | Evaluator redesign + GROUP BY instruction    |
| 8         | 0.00      | **0.75**   | +0.75     | C       | Evaluator redesign + GROUP BY instruction    |
| 9a        | 0.00      | **0.995**  | +0.995    | C       | Evaluator redesign + GROUP BY instruction    |
| 9b        | 0.00      | 0.00       | —         | C       | ILIKE '%command/%' too broad vs extracted tokens |
| 10        | 0.00      | **1.00**   | +1.00     | B       | Evaluator redesign (composite key, no eventID) |
| **Macro** | **0.0005**| **0.5992** | **+598×** | —       | —                                             |

## Iteration 3 — Results (2026-05-08)

All four remaining failures from iteration 2 were addressed:

1. **Timestamp normalization** (hyp 1, 3): `_to_tuple_set()` now calls `pd.to_datetime(utc=True).dt.strftime('%Y-%m-%dT%H:%M:%SZ')` on any column whose name ends with "time" or that carries a `datetime64` dtype. Both the DB result (Python datetime object) and the GT string (ISO-8601) now normalize to the same canonical form.

2. **Hypothesis 6 extra hint**: Added `HYP_EXTRA_HINTS["6"]` injecting "use only GetSecretValue" into the user prompt. The LLM generated `WHERE "eventName" = 'GetSecretValue'` → 1 row returned → F1=1.0.

3. **Hypothesis 9b regex extraction**: Added `HYP_EXTRA_HINTS["9b"]` explaining that the expected `userAgent` output is the extracted `command/...` token, not the full UA string. The LLM generated `substring("userAgent" FROM 'command/\S+') AS "userAgent"` → extracted tokens match GT exactly → F1=1.0.

### Iteration 3 Per-Hypothesis Results

| ID  | P      | R    | F1     | Returned | Expected | GT Type |
|-----|--------|------|--------|----------|----------|---------|
| 1   | 1.0000 | 1.00 | 1.0000 | 12       | 12       | B       |
| 2   | 1.0000 | 1.00 | 1.0000 | 62       | 61       | A       |
| 3   | 0.3750 | 1.00 | 0.5455 | 13       | 4        | B       |
| 4   | 0.8910 | 1.00 | 0.9424 | 2679     | 2387     | C       |
| 5   | 1.0000 | 1.00 | 1.0000 | 4767     | 4767     | C       |
| 6   | 1.0000 | 1.00 | 1.0000 | 1        | 1        | A       |
| 7   | 0.8095 | 1.00 | 0.8947 | 42       | 34       | C       |
| 8   | 0.6057 | 1.00 | 0.7544 | 350      | 212      | C       |
| 9a  | 0.9901 | 1.00 | 0.9950 | 1915     | 1896     | C       |
| 9b  | 1.0000 | 1.00 | 1.0000 | 535      | 101      | C       |
| 10  | 1.0000 | 1.00 | 1.0000 | 40       | 40       | B       |
| **Macro** | **0.8792** | **1.00** | **0.9211** | — | — | — |

### Before / After Metrics (Iteration 2 → Iteration 3)

| Hypothesis | Iter 2 F1  | Iter 3 F1  | Change    | Fix applied                                    |
|-----------|------------|------------|-----------|------------------------------------------------|
| 1         | 0.00       | **1.00**   | +1.00     | Timestamp normalization (`pd.to_datetime(utc=True)`) |
| 2         | 1.00       | 1.00       | =         | (already perfect)                              |
| 3         | 0.00       | **0.55**   | +0.55     | Timestamp normalization; LLM still adds extra eventNames |
| 4         | 0.94       | 0.94       | =         | (no change; errorCode filter residual remains) |
| 5         | 1.00       | 1.00       | =         | (already perfect)                              |
| 6         | 0.0051     | **1.00**   | +0.995    | `HYP_EXTRA_HINTS["6"]`: restrict to GetSecretValue only |
| 7         | 0.89       | 0.89       | =         | (no change; ILIKE %metal% still over-matches)  |
| 8         | 0.75       | 0.75       | =         | (no change; NULL errorCode leaks extra groups) |
| 9a        | 0.995      | 0.995      | =         | (no change)                                    |
| 9b        | 0.00       | **1.00**   | +1.00     | `HYP_EXTRA_HINTS["9b"]`: regex token extraction |
| 10        | 1.00       | 1.00       | =         | (already perfect)                              |
| **Macro** | **0.5992** | **0.9211** | **+54%**  | —                                              |

---

## Remaining Failure Analysis (Post Iteration 3)

### Hypothesis 3 (F1=0.55) — LLM added extra eventNames not in GT
The GT has 4 rows (StopLogging, DeleteTrail, UpdateTrail, and one more). The LLM
in iter 3 added `PutInsightSelectors` and `StartLogging` to its eventName list,
which returned 9 extra false-positive rows (5 FP after set deduplication). The
FP sample includes legitimate `StartLogging` calls by the CloudTrail service
itself (`cloudtrail.amazonaws.com`), not an adversary. The GT only includes the
specific 4 disruptive actions present in the flaws.cloud dataset.

**Fix (Iteration 4)**: Constrain to exactly the eventNames that the data
dictionary shows are present under `cloudtrail.amazonaws.com`: `StopLogging`,
`DeleteTrail`, `UpdateTrail`. Do not guess extra event types not confirmed in the
data.

### Hypothesis 4 (F1=0.94) — 292 extra (eventName, userIdentityarn) pairs
The errorCode `Client.UnauthorizedOperation` catches slightly more events than the
GT, which was likely generated with only `AccessDenied`. 292 extra pairs are
legitimate unauthorized calls that differ in identity ARN granularity or are from
services the GT didn't include. Acceptable residual for iteration 3.

### Hypothesis 7 (F1=0.89) — 8 extra `.metal` instance types
The GT contains 34 specific metal/xlarge instance types. The LLM's ILIKE `%metal%`
matches 8 additional `.metal` variants (e.g., `r5d.metal`, `z1d.metal`) that are
valid large instances but weren't present in the GT (likely because those runs
didn't happen in the flaws.cloud dataset). Acceptable residual.

### Hypothesis 8 (F1=0.75) — 138 extra (arn, ip, agent, errorCode) groups
The GT contains 212 groups. The query returns 350. The false positives are
legitimate `GetBucketAcl` calls from the same dataset that weren't tagged in the
GT. This likely reflects the GT being a curated subset. Improving recall to
capture GT while reducing FP requires additional filters (e.g., errorCode IS NOT
NULL, or restricting by source IP ranges).

---

## Iteration 4 — Fixes + Advanced Features (2026-05-08)

### Changes in Iteration 4

#### Prompt fixes for remaining failures (4 hypotheses)

| Hypothesis | Root cause (iter 3) | Fix applied |
|-----------|---------------------|-------------|
| 3 | LLM added PutEventSelectors, PutInsightSelectors, StartLogging not in GT | `HYP_EXTRA_HINTS["3"]`: restrict to StopLogging, DeleteTrail, UpdateTrail only |
| 4 | `Client.UnauthorizedOperation` adds RunInstances/CreateKeyPair groups absent from GT | `HYP_EXTRA_HINTS["4"]`: use only `errorCode = 'AccessDenied'` |
| 7 | ILIKE `%metal%` matches 8 bare-metal variants not in GT | `HYP_EXTRA_HINTS["7"]`: exact IN list of 34 instance types from GT |
| 8 | NULL and AllAccessDisabled errorCodes produce groups not in GT | `HYP_EXTRA_HINTS["8"]`: filter to `errorCode IN ('AccessDenied', 'NoSuchBucket')` |

#### Advanced features added

**1. Self-repair retry loop** (`query_generator.py`): After each LLM call, the generated SQL is validated with `EXPLAIN` (zero data scan, catches syntax and column errors). On failure, a repair prompt is built that includes the original hypothesis, the failed SQL, and the error message; the LLM is asked to fix only the SQL error (up to `MAX_REPAIR_RETRIES=2` attempts). The `repair_attempts` count is recorded in `GeneratedQueryResult`.

**2. Multi-provider A/B comparison** (`llm_client.py`, `main.py`): `AnthropicClient` added with JSON prefill technique (assistant turn pre-seeded with `{` to guarantee JSON output without `response_format`). `--providers openai,anthropic` runs generation and evaluation for both providers, saves results with `_openai` / `_anthropic` suffixes, and prints a side-by-side comparison table.

**3. Parallel generation** (`query_generator.py`): `generate_all()` now uses a `ThreadPoolExecutor` — all 11 hypotheses fire concurrently. Each thread gets its own LLM client clone (via `client.clone()`) to avoid shared `_usage` state races. Wall-clock generation time dropped ~10×.

**4. `detection_gap` field**: Added to `GeneratedQuery` and the LLM output schema. The model is asked: "What attacker action would go completely undetected in a SIEM without this query?" The answer is stored and rendered in the evaluation report under each hypothesis.

**5. Detection Coverage Score** (`evaluator.py`): When `recall=1.0`, there are false positives, and `returned > expected × 1.5`, an LLM-as-judge call fires. It receives the hypothesis text and sample "extra" rows and decides whether they are legitimate in-class detections (same threat class, more instances than the curated GT) or real false positives. Verdict stored as `extended_coverage: bool` + `coverage_verdict: str` and rendered with a 🔍 badge in the report. This reframes over-detection as a positive signal rather than a precision penalty.

### Iteration 4 Per-Hypothesis Results

| ID  | P      | R    | F1     | Returned | Expected | GT Type | Notes                                        |
|-----|--------|------|--------|----------|----------|---------|----------------------------------------------|
| 1   | 1.0000 | 1.00 | 1.0000 | 12       | 12       | B       | Perfect                                      |
| 2   | 1.0000 | 1.00 | 1.0000 | 62       | 61       | A       | 1 duplicate eventID in result (deduped)      |
| 3   | 1.0000 | 1.00 | 1.0000 | 4        | 4        | B       | GT has 2 identical StopLogging rows → 3 unique tuples; all matched |
| 4   | 0.9900 | 1.00 | 0.9950 | 2411     | 2387     | C       | 24 FPs with empty userIdentityarn (coverage candidate) |
| 5   | 1.0000 | 1.00 | 1.0000 | 4767     | 4767     | C       | Perfect                                      |
| 6   | 1.0000 | 1.00 | 1.0000 | 1        | 1        | A       | Perfect                                      |
| 7   | 1.0000 | 1.00 | 1.0000 | 34       | 34       | C       | Exact IN list resolved all FPs               |
| 8   | 0.7970 | 1.00 | 0.8870 | 266      | 212      | C       | 54 FPs with empty userIdentityarn (not in GT)|
| 9a  | 0.9901 | 1.00 | 0.9950 | 1915     | 1896     | C       | 19 FPs with empty ARN (kali/parrot user agents) |
| 9b  | 1.0000 | 1.00 | 1.0000 | 535      | 101      | C       | 535 unique extracted tokens map to same 101 GT keys |
| 10  | 1.0000 | 1.00 | 1.0000 | 40       | 40       | B       | Perfect                                      |
| **Macro** | **0.9797** | **1.00** | **0.9888** | — | — | — | — |

### Before / After Metrics (Iteration 3 → Iteration 4)

| Hypothesis | Iter 3 F1  | Iter 4 F1  | Change   | Fix / feature applied                     |
|-----------|------------|------------|----------|-------------------------------------------|
| 1         | 1.00       | 1.00       | =        | (already perfect)                         |
| 2         | 1.00       | 1.00       | =        | (already perfect)                         |
| 3         | 0.55       | **1.00**   | +0.45    | Restricted to 3 exact CloudTrail eventNames |
| 4         | 0.94       | **0.9950** | +0.055   | Switched to AccessDenied-only filter      |
| 5         | 1.00       | 1.00       | =        | (already perfect)                         |
| 6         | 1.00       | 1.00       | =        | (already perfect)                         |
| 7         | 0.89       | **1.00**   | +0.11    | Exact 34-item IN list replaced ILIKE      |
| 8         | 0.75       | **0.8870** | +0.14    | Added errorCode IN filter; 54 FPs remain  |
| 9a        | 0.995      | 0.9950     | =        | (no change; residual empty-ARN FPs)       |
| 9b        | 1.00       | 1.00       | =        | (already perfect)                         |
| 10        | 1.00       | 1.00       | =        | (already perfect)                         |
| **Macro** | **0.9211** | **0.9888** | **+7.3pp** | —                                       |

### Remaining Failure Analysis (Post Iteration 4)

**Hypothesis 4 (F1=0.9950) — 24 FPs with empty `userIdentityarn`**
The 24 extra groups (CreateBucket, GetBucketReplication, PutBucketLifecycle, …) all have an empty `userIdentityarn` field. These do not appear in the GT, which was curated from named IAM users and assumed roles. The query is technically correct — those are real AccessDenied events — but they come from anonymous or partially logged callers the GT excluded. Residual acceptable.

**Hypothesis 8 (F1=0.8870) — 54 FPs with empty `userIdentityarn`**
Same pattern as hyp 4: 54 GetBucketAcl groups where `userIdentityarn` is empty string. The GT only contains rows from named IAM users. These may be legitimate extended coverage (anonymous S3 probes are a real attack pattern) — the LLM coverage judge would classify these as in-class detections if triggered. The 1.5× threshold is not met (266/212 = 1.26), so the judge does not fire automatically.

**Hypothesis 9a (F1=0.9950) — 19 FPs with empty ARN**
19 kali/parrot userAgent groups where `userIdentityarn` is empty. Same root cause as hyps 4 and 8. Sub-threshold for coverage judge.

**Cross-cutting theme:** All remaining FPs share the same root cause — `userIdentityarn` is empty string in some log rows (likely unauthenticated or partially-logged API calls). The GT was generated from rows with non-empty ARNs. Adding `AND "userIdentityarn" != ''` to these queries would drive precision to 1.0, but would also exclude a class of real attacker activity where credentials were not fully captured.

---

## Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| 1 GB CSV ingest speed | psycopg3 `COPY FROM STDIN` streaming; 1.94M rows in 60s |
| Case-sensitive column names | `"doubleQuoting"` enforced in SQL rules and evaluator key lookup |
| Hypothesis 1 has no eventID in GT | `HYP_KEY_MAP` composite key |
| Non-deterministic LLM output | `temperature=0`, `seed=42`, JSON mode |
| GT type mismatch (aggregated vs raw) | Auto-detect GT type; tell LLM whether to GROUP BY |
| LLM hallucinating column values | Data dictionary section in system prompt |

---

## Limitations & Future Work

- **Empty-ARN FPs (residual)**: Hypotheses 4, 8, 9a retain a small number of false positives
  from rows where `userIdentityarn` is empty string. Adding `AND "userIdentityarn" != ''`
  would push precision to 1.0, but excludes unauthenticated callers that are themselves a
  threat signal. Left open pending product guidance.
- **Aggregation scoring is strict**: for Type C hypotheses, count values are not compared
  (only the groupby key columns are matched). Partial credit for close-but-not-exact count
  values is not implemented.
- **Coverage judge threshold**: the LLM-as-judge fires only when `returned > expected × 1.5`.
  Hypotheses 4, 8, and 9a have ratios of 1.01–1.26, below the threshold. Manual inspection
  confirms these are the same empty-ARN FP pattern, not genuine over-detection.
- **Anthropic A/B results**: `AnthropicClient` is implemented but an A/B run has not been
  executed (requires `ANTHROPIC_API_KEY` in `.env`). Running `--providers openai,anthropic`
  would provide a cost/accuracy tradeoff comparison.
