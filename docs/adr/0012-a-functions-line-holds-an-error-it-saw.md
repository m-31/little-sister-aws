# ADR-0012 — A function's line holds an error it saw

- **Status:** Accepted
- **Date:** 2026-10-10
- **Related:** [ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md)
  (the function's reading, the newest bucket's count, and the windows a function is
  asked in — its context and §3 are amended here), [ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md)
  (§1, the `function` kind's fields, amended here), [ADR-0003](0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md)
  (a rule owns names and inherits what it does not say), little-sister **ADR-0086**
  (a grading reads what it is handed, the configuration and the clock), little-sister
  **ADR-0113** (what a check kept is for deciding what to ask, and for nothing else),
  little-sister **ADR-0083** (a node may wait before it escalates — the other
  direction)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

The `lambda` line says what the function's newest run did: the count of the newest
`Errors` bucket, and its time as the last run ([ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md),
its context). *1 error, last run 1m ago* grades ERROR; after a clean run, *no errors,
last run 2m ago* grades OK. `error_max_age` gates the age of the newest **point**, not
of the newest **error**, so it never holds an error that a clean run has followed. A
function that errs once between two clean runs is ERROR for one poll and OK the next.

**What that looks like on an estate.** In 38 hours of one deployment's local instance,
two functions that run every five minutes did it three and four times: seven blips of
one poll each, fourteen events, and every one of the fourteen lines right. The error is
kept in the run's record, *1 error in 1 invocation*, where the line has forgotten it;
with `series_keep: 30` those functions keep two and a half hours of runs, so six of the
seven errors had left the history as well, and the events view was their only trace. A
reader of the node saw a function that was fine; a reader of the events saw one that
failed every few hours; both read the same estate. It is the shape the family's round
answered for the engine's memory line and for a GitHub read: a verdict that stands one
tick is two events and no information.

**What the first call already answers.** `GetMetricData` answers every `Errors` point
of a function in the window it is asked, newest first, and the reading kept `found[0]`,
the newest point. The newest error in that window, how many clean buckets follow it,
and what the buckets inside any span count together are in the same answer at no
request more. The smallest window any function is asked at one minute is its last hour
(ADR-0006 §3), so anything within an hour is in hand for every function.

**What binds the grading.** A grading reads what it is handed, the configuration and
the clock (little-sister ADR-0086 decision 6), and what a check kept is for deciding
what to ask and for nothing else (little-sister ADR-0113). So whatever holds an error on
the line is a fact the measuring half hands back and a comparison the grading makes
against the clock — never state kept beside the check, and never a reading of the
history.

## Decision

### 1. The line holds the newest error it saw, in this type

The measuring half hands back, beside the newest run, **the newest error** it found in
the window it asked — its time, how many clean buckets followed it, and what the
buckets inside the function's hold count together — as `error.at`, `error.clean_since`
and `error.held` of the `function` reading, from the answer it already has; `null` where
the window holds no error, and the newest run itself where that run failed. The grading
keeps the line at ERROR while the newest error is younger than the function's hold, and
says so: *3 errors in the last 1h, the newest 23m ago · 2 clean runs since, the last 2m
ago*, with `error_reason` as for the newest run. The newest run being the error reads
as it always did — *1 error, last run 2m ago* — and names what the hold holds beside it
where that is more: *· 3 in the last 1h*. Past the hold the line is *no errors, last
run 2m ago*, as before.

The hold lives here and not in the library, because what an error means for a function
is this type's judgment — the gate lives beside it — and because a hold at the node
would show ERROR over a line that reads *no errors*: a line is a claim and carries its
code. The family took the same shape for GitHub's reads, in the type.

### 2. The hold is a duration, an hour by default

`error_hold` is a duration, `1h` unless the configuration says otherwise. An hour costs
no request anywhere, since the hour is the smallest window a function is asked, and the
engine holds its own lines' worst for a window for the same reason. The window a function
is asked in reaches the hold as well as its series (amending ADR-0006 §3): a hold of a
day moves that function to the day window, by the arithmetic the window rule already
does. `error_hold: 0s` is no hold — the newest run alone decides, as before.

A written hold longer than the gate that applies to the same function is **refused**
where the check loads, rather than capped: an error older than the gate is not graded at
all, so the hold's tail would never stand, and a knob capped silently stops meaning what
it says. So is a hold longer than the fifteen days CloudWatch keeps a one-minute point
for: an error is held beside the clean runs that followed it only where both are
one-minute points, and past that the hold would end where the points end.

**A hold nobody wrote is never longer than the gate.** Where neither the block nor a
rule writes one, a function's hold is an hour or the gate that applies to it, whichever
is shorter, so a configuration whose `error_max_age` is under an hour loads as it did
before the hold existed, and holds an error for as long as it grades one. Only a written
hold is held against the gate, since only a written one says something the gate
contradicts.

### 3. The block says it, and a rule may say otherwise

`error_hold` is a key of the `lambda:` block and of every rule in it, inherited by a
rule that does not name it, as `error_max_age`, `expect_invocations` and
`read_log_status` are. A written hold, the rule's own or the one it inherits, is held
against the gate that applies to its functions — its own or the block's — once both are
known. The card shows the block's hold beside its gate, and each rule's effect names
both.

### 4. What stays as it was

The gate keeps its meaning: how old an error may be to be graded at all, a fact about
CloudWatch's resolution. A run's record keeps its own errors and its own verdict
whatever the line holds (ADR-0006 §9). A held error is ERROR, as the newest run's is;
no code of the line changed.

### 5. What is not decided here

A severity of its own for a held error — ERROR while the newest run is the error, WARN
once a clean run has followed — which would make three events of each error instead of
two, and which is the question of what a status means per function, open elsewhere. A
hold measured in clean runs rather than time, which scales with a function's cadence
and is bounded by a window that depends on it.

## Consequences

- **An error between two clean runs stands on the node for an hour**, saying when it
  was and what ran clean since, where it stood for one poll. On the estate above, the
  node is ERROR for an hour after each failure and OK between failures hours apart, and
  a deployment that finds that too loud for a function it lets fail now and then writes
  `error_hold: 0s` on its rule, or a longer hold where an hour is too short.
- **A grading change**: what an installation reports changes on its next run after it
  takes the release, with nothing configured — a function's node may stand ERROR for an
  hour where it stood two minutes. Nothing configured or pinned moves; the key is new
  and optional.
- **No request more within the hour**, for any function. A longer hold moves that
  function to the day or the fifteen-day window at one minute, which is what its series
  would have done at that depth.
- **The `function` reading carries one field more**, `error`, nested so that its
  instant is under `at` (amending ADR-0005 §1). A record of this kind has no history, so
  nothing kept has to be read differently.
- **The suite grades the line poll by poll** over buckets a fixture hands it: an error
  followed by clean runs held for the hour and not past it, counted inside the hold and
  not outside it, the newest run's error read as before, a hold of nothing, a rule's own
  hold over the block's, and every refusal.

## Alternatives considered

- **A hold in the library** — a node keeping a worse verdict for a window, the downward
  twin of a wait before escalating (little-sister ADR-0083). Rejected: that wait is the
  one rule that transforms a contribution and publishes *what was published before*, so
  node and line still agree; a hold the other way shows ERROR over a line that reads *no
  errors*. It would need a library record and release first, and the library chose a
  held record inside its own memory line rather than a transform at the node.
- **Nothing in the verdict**, errors read where they are kept and `series_keep` set
  deep. Rejected: the node still flips within one poll, so the events stay, and
  `series_keep` is one number per check — the estate's five-minute functions would need
  some three hundred kept runs to hold a day.
- **A hold measured in clean runs since.** It says what *recovered* means and scales
  with cadence, but a fast function's three runs are three minutes, barely longer than
  the blip; it is a new kind of value in a configuration of durations and thresholds;
  and the window it needs depends on each function's cadence.
- **The gate as the hold** — the newest error graded while younger than
  `error_max_age`, which is what the README's sentence once said. Rejected: fourteen
  days of ERROR for a five-minute function that failed once, and the gate was argued
  from CloudWatch's resolution, not from how long a verdict should stand.
- **Capping a hold at the gate** instead of refusing it. Rejected for a hold that is
  written: a knob that quietly means less than it says, where the type refuses
  contradictions elsewhere. The default is no knob, and is capped (§2).
- **The default refused against a shorter gate**, as a written hold is. Rejected on
  Lex's word of 2026-10-10: a configuration that loaded before the release would not
  load after it, for a value nobody wrote.
- **A severity for the held state** (§5).

