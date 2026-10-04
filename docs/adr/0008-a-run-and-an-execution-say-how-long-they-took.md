# ADR-0008 — A run and an execution say how long they took

- **Status:** Accepted
- **Date:** 2026-10-04
- **Related:** [ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md)
  (the record of a Batch run and of a pipeline's reading, and the bound of every field —
  its §1 and §8 are amended here),
  [ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) (a number's
  name carries its unit, and the type declares a run's durations as measures — its §6
  and §7, which this record applies to the two records they named),
  [ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md) (the node a run's and an
  execution's stems stand on, and which of a pipeline's executions a poll reads),
  little-sister **ADR-0092** (a check declares its measures), little-sister **ADR-0085** (a measure
  is read out of a record), little-sister **ADR-0111** (a run's mark, and its stem
  under a measure), little-sister **ADR-0106** (the node a series is shown on),
  little-sister **ADR-0087** (a record replaced in place by its identity)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

A deployment that keeps a series keeps each Batch job's runs and each pipeline's
executions (ADR-0005 §3). little-sister draws a run as a mark at its own time, and as a
stem to a number where the run's check declares a measure (little-sister ADR-0111,
little-sister ADR-0092). A measure is a field of the record: a page draws what a record
holds and computes nothing of its own (little-sister ADR-0085).

Neither record holds a number. A run has three instants — `created.at`, `started` and
`ended` — and a pipeline's reading has one, `started`. So nothing a page draws says how
long a run took, which is the first thing asked of one: a nightly job that crept from
twenty minutes to two hours, a deployment that takes forty minutes where it took eight.

The sources answer it already, in the calls the two aspects make. `list_jobs` gives a
job's `createdAt`, `startedAt` and `stoppedAt`. `list_pipeline_executions` gives, beside
an execution's `startTime`, its `lastUpdateTime` — the last change CodePipeline recorded
of it — which the aspect did not read.

A record's field names are keys once shipped, as a slug is (ADR-0005, in its
consequences). So which numbers a record carries, under which names, and when each
stands are decided here.

## Decision

### 1. A Batch run carries how long it waited and how long it ran

`wait_s` is from when the job was created to when it started: how long it sat in its
queue. `duration_s` is from when it started to when it stopped. They are the two spans
the aspect grades a job in flight by, as `max_wait_time` and `max_run_time`, kept as
what they came to.

### 2. A pipeline's execution carries how long it took

`duration_s` is from the execution's `startTime` to its `lastUpdateTime`. The last
change of an execution that is over is its end. The record keeps the span, and no second
instant beside `started`.

### 3. A span stands once both its instants are known, and an execution's once it is over

**Nothing is counted to a poll's clock.** A run that waits has neither number; one that
is running has waited, and has no duration yet; one that stopped before it ever started
has neither. A run's record is replaced in place as the run moves on (ADR-0005 §5), so
a number arrives with the reading that sees both its instants. Until then the record
holds a null in its place, and the run has no stem under that measure (little-sister
ADR-0111 decision 5).

**An execution is over in the five statuses in which CodePipeline says so**:
`Succeeded`, `Failed`, `Stopped`, `Superseded` and `Cancelled`. In `InProgress` and in
`Stopping` it is on its way, and its last change is the last step it took, which is no
end. What is listed is the words that end an execution, so a word CodePipeline adds ends
nothing until this type knows it, as a metric's status answers nothing until it is
listed (ADR-0006 §3). A status is read as `state_map` reads one, whatever its case.

**The number is the reading's.** Should an execution that was over be read `InProgress`
again, its record says so, and has no duration until the execution is over again.

**A span is nothing where the second instant lies before the first.** That is no span,
and it is not kept as one of no length, which would draw a run that took no time.

### 4. Whole seconds, and the unit in the name

ADR-0006 §6 gives the rule and names a run's two fields: a number's name carries its
unit, and a record keeps a whole number. A function's duration is CloudWatch's own
number, in the unit it comes in. A span is no number of its source's: it is counted
here, between two instants the source stamps finer than a second, and a run's or an
execution's is read in minutes and hours. So it is kept in seconds, and in the seconds
that were completed, as a job's line counts how long a run took: a second that was begun
is not counted, and less than a second is `0`.

### 5. The type declares them as measures

`duration_s` and `wait_s` are declared in `s`, labeled *Duration* and *Wait*, beside a
function's `duration_ms` (ADR-0006 §7; little-sister ADR-0092 decisions 1 and 2). A
declaration is keyed by its field, so the one for `duration_s` holds for a run and for
an execution alike. A deployment takes one away by its name, `wait_s: null` in its
`measures:` block.

## Consequences

- **ADR-0005 §1 is amended**: the kind `job` gains `wait_s` and `duration_s`, and the
  kind `pipeline` gains `duration_s`. Both are additive — no field moves, and none
  changes what it means.
- **No line changes.** The grading reads neither number: it counts a job's ages from the
  record's instants to the instant it is handed, as it did, so a record kept before this
  one grades to the line it had.
- **The stems stand where little-sister shows the series** (little-sister ADR-0106
  decisions 2 and 4, little-sister ADR-0111 decision 5): on the node that stands for the
  subject, which is a job name's own node and a pipeline's own
  ([ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md)), and on the check's own node
  for a subject that has none at the moment — a job name none of whose runs Batch still
  lists. A plot stands once a run gives it a number: a job name whose runs only wait has
  none, and one that has only ever run has its *Wait* alone. A deployment that wants a
  run or an execution drawn as a tick takes the measure away (§5).
- **ADR-0005 §8's measure moves for a run**: with the longest queue name, job name and
  reason, and two spans of two hundred days, a run's record weighs 1213 bytes where it
  weighed 1169 — and 1241 where its instants carry the milliseconds Batch stamps them
  with, a fraction that section did not weigh. The heaviest reading stays the alarm's,
  at 1330.
- **A record kept before this carries no span**, and draws no stem. A run that is read
  again gains its numbers, since Batch lists a finished job for seven days at least. Of
  the executions a pipeline's history holds finished, the newest is read again and
  gains its number; the others are not (ADR-0009 §5), and do not.
- **An execution that is overtaken while it runs is read to its end** where the check
  keeps a series, and carries its duration then (ADR-0009 §5).
- **Nothing more is asked of AWS**, and no permission is added: both calls were made
  already.

## Alternatives considered

- **No measure for a pipeline**, its executions drawn as ticks. Refused in §2: how long
  a deployment took is the first number asked of a pipeline, and the call the aspect
  makes answers it.
- **A span counted to the poll for a run in flight** — its duration so far. Refused in
  §3: the record would say what one poll's clock said, and the next poll would replace
  it with another number as provisional. The line already says how long a job has run,
  to the instant it is graded.
- **An execution's end kept as an instant**, `ended`, beside its `started`. Not taken in
  §2: `lastUpdateTime` is an end only where the execution is over, and a second stored
  key would say nothing the span does not.
- **Every status but `InProgress` taken for an end.** Refused in §3: `Stopping` is none,
  and a word CodePipeline adds would end an execution on this type's guess.
- **A span of no length where the instants lie the wrong way round.** Refused in §3.
- **Fractions of a second**, or milliseconds as a function's run has them. Refused in
  §4, by ADR-0006 §6: a cell full of decimals, for runs that take minutes.
- **The nearest second.** Not taken in §4: a job's line counts the seconds that were
  completed, and two counts of one span would differ by one.

