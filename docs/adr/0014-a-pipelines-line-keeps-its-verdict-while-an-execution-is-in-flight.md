# ADR-0014 — A pipeline's line keeps its verdict while an execution is in flight

- **Status:** Accepted
- **Date:** 2026-10-10
- **Related:** [ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md) (a pipeline's
  line, the executions a poll reads and what is said of each for the record — its §5
  and §6 are amended here),
  [ADR-0003](0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md) (a graded
  threshold is a pair, and a rule owns names — its §3 is amended here),
  [ADR-0008](0008-a-run-and-an-execution-say-how-long-they-took.md) (the words that end
  an execution), little-sister **ADR-0042** (decision 6, a line marked as work in
  flight), little-sister **ADR-0032** (rule 4, the closed vocabulary of statuses; rule
  7, an unknown state not taken for one), little-sister **ADR-0111** (a run's mark, and
  a line written for the record alone), little-sister **ADR-0113** (decision 3, what a
  check kept decides what it asks for)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

`codepipeline`'s `state_map` graded `InProgress` a warning by default, kept from the
dashboard this type was ported from, so a pipeline stood yellow for as long as it
deployed and every deployment was a warning: an event when it started and another when
it ended. A Batch job that runs has been `OK` since the port, warning only once it has
run for longer than `max_run_time`, and little-sister has no status for work in flight
(little-sister ADR-0032 rule 4).

What the yellow said is worth seeing: that a pipeline deploys. little-sister marks a
line whose subject has work in flight as running — an italic, display only, which leaves
the line's code what the last completed run made it (little-sister ADR-0042 decision 6)
— and its guide to a check type makes that every type's. A job name's line carries the
mark ([ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md) §3), and so does a GitHub
workflow's line in `little-sister-github`.

The yellow was also the one thing that said an execution was stuck. An execution held at
a manual approval, or at an action that does not return, warned from its first second,
along with every deployment that went well.

And a pipeline's line was its newest execution's (ADR-0009 §5): written from that
execution and carrying it. With `InProgress` passing and the line as it was, a pipeline
whose last execution failed would have turned green the moment a new one started, for as
long as it ran — the failure gone while somebody is most likely to look, and every new
execution after a failure two events. That is what ADR-0009 §4 refused for a job name's
line, and what little-sister ADR-0042 refused for a status of its own.

Read under the library's engine, one pipeline walked a poll at a time through three
stories. Before this record: a failed pipeline run again went from red to yellow at the
new execution's start and to green at its end, two changes; a healthy pipeline that
deployed went yellow and back, two changes; and one whose execution hung was yellow from
its first poll. After it: the first stays red and italic while the new execution runs
and turns green once, one change; the second stays green, in italics while it deploys,
none; and the third stays green until its execution has been in flight for thirty
minutes and warns from then on.

A retry of a stage takes a failure off the page. CodePipeline retries a failed or
stopped execution under its own id and from the start it had, so while the retry runs
that execution is `InProgress` again and the page the aspect reads holds no failure,
where a new execution leaves the failed one on it. Walked as the three were, a failed
stage retried after a fix, its execution two hours old: before this record the line went
from red to yellow at the retry's first poll and to green at its end; with §2 alone it
went from red to yellow as well, in italics, written from the success before the failed
execution and raised past `max_run_time` by a bound counted from the execution's first
start; with §5 it stays red and italic while the retry runs and turns green once, when
the retry has succeeded — one change where each of the others made two.

## Decision

### 1. `InProgress` passes

The default `state_map` maps `InProgress` to `OK`, and every other status as it did. A
deployment that wants the warning back says `InProgress: WARN` in its `state_map`, and
has it (§2).

### 2. While an execution is in flight, the line keeps the newest finished verdict

An execution is **in flight** while it is `InProgress` or `Stopping`, the two words of
one on its way ([ADR-0008](0008-a-run-and-an-execution-say-how-long-they-took.md) §3). A
word CodePipeline adds is not taken for work in flight until this type knows it
(little-sister ADR-0032 rule 7): it is a verdict, a warning by default, as it was.

**The line is written from the newest execution, as it was, unless that one is in
flight.** Then it is written from the newest that has a verdict to keep: one neither in
flight nor superseded — an execution a newer one overtook is no verdict (ADR-0009 §6) —
or one in flight on a retry, which keeps the status it had ended in (§5). Where none
has, it is written from the newest after all: a pipeline whose first execution runs has
nothing else to say.

**Beside that verdict the line says what is in flight**, every execution on the page
that is, in one phrase for each status: the status and when the one started, or how many
and when the oldest of them did.

```
deploy-api: Failed, started 3h ago · InProgress, started 2m ago
deploy-api: Succeeded, started 1d ago · 2 InProgress, the oldest started 20m ago
deploy-api: InProgress, started 12m ago
```

**What is in flight can make the line worse, and never better.** Its status counts as
`state_map` says, so a deployment that maps `InProgress: WARN` has its yellow back and a
`Stopping` execution, an error by default, turns the line red at once, as it did; and an
execution in flight for longer than `max_run_time` counts (§3). A failure on the page
stays a failure whatever runs beside it, and a success stays a success while its
successor deploys.

**While anything is in flight, the line is marked running** (little-sister ADR-0042
decision 6), and its words say what runs, which is the rule the italic rides on.

How old a success may get (`max_age`) is asked of the execution the line is written
from, as it was of the newest: a stale success stays a warning until a newer execution
has finished.

**Nothing more is asked of AWS but what §5 asks of a retry.** The execution the line is
written from and every execution in flight come out of the one page of executions the
aspect already asks for (ADR-0009 §5), with a series kept or without one; where a series
is kept, so do the executions ADR-0009 §5 reads behind the newest. An execution
CodePipeline sent without an id is read for the line all the same, and where a series is
kept it is a new record at every poll, as the newest without one always was.

### 3. An execution in flight warns past `max_run_time`, thirty minutes by default

`max_run_time` is a pair on `codepipeline`, written as `max_age` is: `max_run_time_warn`
and `max_run_time_error`, `max_run_time_reason` beside them, a rule's own levels for the
pipelines it matches, and `max_run_time: null` for a pipeline that waits at an approval
for as long as it takes. A level is compared strictly above
([ADR-0003](0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md) §1), and a block
that writes one level of the pair takes the pair as it is written, whole, as a rule's is
taken over its block's (ADR-0003 §4): `max_run_time_error: 2h` alone warns at nothing.

On the line the bound is held against the oldest execution in flight in each status, and
once it fires the line says so: `InProgress, started 45m ago, past max_run_time`, and
the sentence beside it, the pair's or the rule's name, as `max_age` says its own. For
the record it is held against each execution in flight (§4).

**Its default is a warning above thirty minutes, and no error level** — the first pair
of this type that has a default, which amends ADR-0003 §3. That section's reason stands:
a threshold is a judgment about somebody's estate. But this one replaces a judgment the
type already shipped. `InProgress` warned from an execution's first second; dropping
that to nothing would have taken the one sign of a stuck execution from every
installation that writes nothing, and thirty minutes takes no warning from an
installation that had one and gives it none it did not have. Batch's `max_run_time`
keeps its two hours: a Batch job is a different kind of work, and how long one runs
depends on the job.

The card lists the pair as it is in force, the default included, and each rule's.

### 4. The line carries the execution it is written from

This amends ADR-0009 §5, under which a pipeline's line carried its newest execution: it
carries the one it is written from (§2), the newest unless the newest is in flight. What
is kept of that execution while the line is written from it is what the line says
(ADR-0009 §6): its staleness, as before, and now what is in flight beside it, a raise by
an overrun included. Every other execution the poll read is said for the record by its
own status, raised past `max_run_time` while it is in flight.

**The execution read once more is the one the history holds as the line's.** ADR-0009 §5
read once more the kept execution that started last, where the page's newest was
another. Now it is found as §2 finds the line's, over the statuses the records keep —
the kept execution that started last, unless it was in flight, and then the newest
behind it that was neither in flight nor superseded — and it is read once more where the
line is written from another. Of several that started at one instant each is taken for
it, as before, and none is read while the line is written from one of them. So a success
marked a warning because it was stale, or because an execution overran beside it, is
said to be a success again by the poll that finds the line on a newer one.

### 5. A retried execution keeps its failure while it runs again

A retry of a stage is the execution it failed in, running again: CodePipeline retries a
failed or stopped execution under its own id and from the start it had, so while the
retry runs the execution is `InProgress` and its failure is on no page. The page cannot
tell a retry from a first run. The history can: it holds the execution as it ended.

**Where a series is kept, an execution the history holds `Failed` or `Stopped` and the
page holds in flight is asked about**, and so is one the history already holds on a
retry: one page of its action executions, `ListActionExecutions`, at every poll while it
runs again. Nothing else is asked, and nothing at all where no series is kept. What the
check kept decides what it asks and nothing else (little-sister ADR-0113 decision 3):
the execution's record holds its status as the page has it, and beside it the answer, in
a `retry` block — how many action executions failed and how many were abandoned, when
the retry began, and a refusal's words.

**The answer says what the execution had ended in**: `Failed` where one of its action
executions failed, and otherwise `Stopped` where one was abandoned, as stopping an
execution without waiting for its actions leaves them. Where it shows neither — an
execution stopped by letting its actions finish, all of which succeeded — nothing says
that it had ended, and it is read as a first run, as §2 reads one.

**The line is written from the execution on its retry and keeps the status it had ended
in**, graded as `state_map` grades that status, marked running, with the retry beside
it, and turns green once the execution succeeds. What is in flight still makes the line
worse and never better (§2).

```
deploy-api: Failed, started 2h ago · InProgress, retried 3m ago
deploy-api: Failed, started 2h ago · InProgress, retried
```

**`max_run_time` counts from the retry's own start** — when the first action execution
that started after the last failed or abandoned one had ended began — and not from the
execution's, which may be hours before it (§3). A retry none of whose actions has
started yet has no start: it is said without one, and held to no bound until it has one.
For the record, an execution on a retry that the line is not written from is said by its
own status, raised past `max_run_time` from the same start.

**A refusal is said.** Where `ListActionExecutions` is refused — a role without
`codepipeline:ListActionExecutions` — nothing is known of the retry: the line is written
as §2 writes it, from the execution before, and warns, the refusal's words beside what
is in flight, at every poll until the call is answered or the retry has ended.

**What it does not see:** a retry begun before any poll read its execution ended — one
CodePipeline makes on its own, for a stage set to retry when it fails — finds nothing in
the history that says the execution had ended, and is read as a first run; and where no
series is kept, every retry is. Each is then what §2 says of an execution in flight.

## Consequences

- **A deploying pipeline keeps its color, in italics.** A failure stays red while a new
  execution runs and turns green once, when an execution succeeds; a healthy pipeline
  that deploys changes nothing an event records. A retry of the failed stage keeps it
  red as well, where a series is kept (§5); where none is, while the retry runs the line
  is the execution before it.
- **A pipeline held at a manual approval warns once its execution has been in flight for
  thirty minutes**, the wait at the approval included, unless a rule gives it its own
  bound or `max_run_time: null`. It warned from the first second before.
- **An installation that writes `InProgress: WARN`** keeps a yellow deployment, and it
  is now the worse of that and the last verdict: a failed pipeline being run again is
  red there too.
- **The record of the execution the line is written from is marked as the line stands**,
  so while an execution overruns beside a success, the success is kept marked a warning
  until the line moves on (§4) — as a stale success has been.
- **One more call while a retry runs, and one more permission.** Each poll asks
  `ListActionExecutions` for every execution on a retry, one page each, which needs
  `codepipeline:ListActionExecutions` beside the two actions the aspect had; a role
  without it has a line that warns and says why while a retry runs, and nothing else
  changes for it (§5).
- **The words grow** by a phrase while anything is in flight, and the record of a
  pipeline's line keeps them.
- **The suite holds each**: the line kept red through a new execution after a failure
  and green through a deployment, the superseded execution looked past, the raise by
  `Stopping` and by a configured `InProgress: WARN`, the bound at twenty-nine, thirty
  and thirty-one minutes on the line and for the record, a rule's bound and its `null`,
  a block's one level, several in flight counted, one in flight behind a finished one,
  what is read with a series and without, the execution read once more when the line
  moves and not before, and the card's rows — and of a retry, the line kept red, the
  call made at every poll and only where the history holds the execution ended, the
  bound from the retry's start, one none of whose actions has started yet, a stopped
  execution retried, a retry beside a first run, an answer that shows no end, a refusal,
  and the line's execution found in the history on a retry (§5).

## Alternatives considered

- **The newest execution's own verdict**, `InProgress` passing and the line as it was.
  Declined in §2: a failed pipeline turns green while a new execution runs, which is
  when somebody is most likely to look, and every new execution after a failure is two
  events.
- **No bound on an execution in flight**, or one with no default. Declined in §3: the
  one sign of a stuck execution would have gone from every installation that writes
  nothing.
- **A default of two hours**, Batch's. Declined in §3: a Batch job is a different kind
  of work, and how long one runs depends on the job; a pipeline's execution is a
  deployment, and thirty minutes is the bound given it.
- **A retry read as a first run**, from the page alone: the line written from the
  execution before it while the retry runs, the bound counted from the execution's first
  start, and nothing more asked. Built first, and declined on Lex's answer (§5): a
  pipeline is retried after a fix made outside it, most often to a permission, and one
  that failed is red until it has succeeded.
- **Every execution in flight asked about**, at every poll, a series kept or not.
  Declined for its price: it would see a retry the history never saw ended, and one
  where no series is kept, for a call at every poll of every deployment, where the
  history makes it a call at every poll of a retry (§5).
- **A line that carries no execution while one is in flight**, as a job name's carries
  none (ADR-0009 §3). Declined in §4: the verdict the line keeps, with its staleness, is
  one execution's, and the history keeps what a line says on the execution it is written
  from; carrying none would keep it nowhere for the length of a deployment.

