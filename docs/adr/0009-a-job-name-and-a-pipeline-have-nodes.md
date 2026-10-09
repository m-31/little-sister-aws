# ADR-0009 — A job name and a pipeline have nodes

- **Status:** Accepted
- **Date:** 2026-10-10 (accepted 2026-10-04)
- **Related:** [ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md)
  (which readings have a history, the event each is of, what the configuration spares
  and what a line carries — its §2, §3, §5 and §7 are amended here),
  [ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) (a function's
  node, whose answers hold here: a line that names what its node stands for, a run said
  for the record, and a poll that reads what its history lacks),
  [ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) (where a
  subject's node hangs, and a line that prints no region on its subject's own node — a
  queue's level is what that record left open),
  [ADR-0008](0008-a-run-and-an-execution-say-how-long-they-took.md) (the numbers a run
  and an execution carry, and when an execution is over),
  [ADR-0001](0001-the-aws-check-type.md) (the region in every slug),
  little-sister **ADR-0106** (a subject with a history has a node of its own),
  little-sister **ADR-0109** (a node says that its children are complete, and such a
  statement need not be exact), little-sister **ADR-0111** (a run's mark, a line written
  for the record alone, and the mark that claims nothing), little-sister **ADR-0113** (a
  check's measuring half reads what the check kept), little-sister **ADR-0087** (a
  subject's series, and the identity that keeps an event in it once),
  little-sister **ADR-0118** (a node a run names says so), little-sister **ADR-0063**
  (declining the density trade), little-sister **ADR-0042** (decision 6, a line marked
  as work in flight),
  [ADR-0014](0014-a-pipelines-line-keeps-its-verdict-while-an-execution-is-in-flight.md)
  (the execution a pipeline's line is written from, and what is in flight beside it)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

With `series_keep` set, this check keeps each Batch job name's runs and each pipeline's
executions (ADR-0005 §3), and each carries how long it took (ADR-0008). little-sister
shows a subject's series on the node that stands for it, one whose lines name that
subject and no other, and on the check's own node where none does (little-sister
ADR-0106). A job name and a pipeline were each a line on their aspect's node, beside
every other job name's and pipeline's. So their runs were listed on the check's History
page, a table for each, and their plots stood on the check's own node wherever an aspect
named more than one of them.

A function has a node of its own
([ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) §9), hung by
[ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md)'s rule.
This record gives one to a job name and to a pipeline. Where that round answered a
question for a function, the answer holds here. Five things are a job name's or a
pipeline's own:

- **A job name runs in a queue, and AWS names the queue.** No configuration does.
  ADR-0007 gives a level to what a configuration names several of, and left a queue
  open.
- **A job name's line is written from all of its runs** and carries none of them
  (ADR-0005 §7), so a kept run was stored with no verdict at all.
- **A pipeline's reading was of its newest execution alone** (ADR-0005 §5, before this
  record). An execution that a newer one overtook while it ran kept the record of its
  last read, and a pipeline's series began with whatever was newest at its first poll.
- **CodePipeline calls an execution a newer one overtook `Superseded`**, and the
  default `state_map` grades that word an error — which it is, where the newest
  execution carries it.
- **A job name `ignore_name_patterns` hides was kept all the same** (ADR-0005 §3,
  before this record), and drew its plots on the check's own node.

AWS settles how such a node is named. A queue's name and a job's hold letters, digits,
`-` and `_`, and a pipeline's `.` and `@` as well. None of them holds `/`, the one
character a path's segment cannot hold, and none is long enough to be clipped
(ADR-0005 §8).

## Decision

### 1. A job name has a node beneath its queue's, and a pipeline one beneath `codepipeline`

Every job name and every pipeline a poll read has a node: a job name whose newest run
succeeded, one whose failed and one that only waits alike, and a pipeline that never ran
like one that deployed. Each is **named by what AWS calls it**. A display-name rule
(`shorten`) gives the node its title and never reaches its path, as it never reaches a
slug. Each says that a run names it (little-sister ADR-0118), so a pipeline its account
calls `batch` is shown under its own name, and not under what this type declares for the
`batch` aspect.

They hang by ADR-0007's rule, beneath their aspect where the account reads one region
and beneath their region's node where it reads several:

```
<path>/codepipeline/<pipeline>                one account, which reads one region
<path>/codepipeline/<region>/<pipeline>       one account, which reads several
<path>/batch/<queue>/<job name>               one account, which reads one region
<path>/batch/<region>/<queue>/<job name>      one account, which reads several
```

Where a check names several accounts, the account's level stands before the aspect, as
it does for a function. A path may then name neither the account nor the region, so
each node's description names both.

### 2. A queue is a level in every Batch path

`…/batch/<queue>/<job name>`, also where an account holds one queue alone. A queue is
nothing a configuration names, so ADR-0007's rule has nothing to count: a level that
came and went with the queues AWS answers would move every job name's path on a day
nobody edited anything, which that record's §1 refuses. And a job name may run in two
queues, so without the level its node could not be named by what AWS calls it.

**The queue's node carries what the queue says of itself**: that it is `INVALID` or
`DISABLED`, that it holds no jobs, or that it was read only as far as `max_jobs`
reaches. It is the line the queue had, written from the queue's reading and carrying it,
under the slug it had. A queue with nothing to say grades nothing and says nothing.

**It says that its job names are complete in every run that lists it** (little-sister
ADR-0109). So a job name leaves with the first run in which Batch lists no run of it,
which is about a week after its last one: Batch keeps a finished job for at least seven
days (ADR-0005 §5).

That holds for a queue read at its cap as well. A name none of whose runs is among the
newest `max_jobs` of a status is not read, and whether it stopped running or fell
behind the cap the reading cannot tell. Left unsaid there, such a name's node would
stay, go stale and warn every node above it for as long as its queue is at the cap,
which for a busy queue is always. Read under the library's engine, a job name whose one
run fell behind two newer ones at `max_jobs: 2` stood stale five minutes later, and
`batch` warned. A statement need not be exact (little-sister ADR-0109 decision 3): the
name returns with its next run, and with everything that was kept of it. What could not
be read at all is a region's, and the node its queues hang on says nothing then (§8).

**What it costs** is that a name behind the cap has no node, so its kept runs are listed
and drawn on the check's own node until it runs again (see *Consequences*), and that a
name which fell behind with a failure nobody mended loses its red node, as it lost its
red line.

**A queue's node declines the density trade**, as a region's does (ADR-0007 §3,
little-sister ADR-0063): it is the box its job names stand in. A job name's node and a
pipeline's declare nothing of it. Quiet, each is a chip.

### 3. A job name's line is written from its runs, and carries none

One sentence of the name's newest finished run, of those that run and of those that
wait, graded so: an error where the newest finished run failed, and a warning where a
run is past `max_run_time` or a wait past `max_wait_time`. It carries none of the runs
it was written from (ADR-0005 §7), and **it names the job name as its subject**, which
is what makes the node stand for the job name (little-sister ADR-0106 decision 2). That
is the answer a function's line has (ADR-0006 §9).

**Batch is asked for every status it has, seven, and the line's words stay three.** A
queue's node says that its job names are complete in every run that lists it (§2), so a
name whose only listed job was in a status nobody asked for would leave the tree for
that poll and come back with the next: an event that says *removed* and its return, its
plots on the check's own node, a pin on it suspended. A job passes `STARTING` between
`RUNNABLE` and `RUNNING`, and one not yet placed, or held by a job it depends on, is
`SUBMITTED` or `PENDING` — so is an array job's parent, for as long as its children run.
Read under the library's engine, a name whose one listed job walked through the seven, a
poll each, lost its node and its pin at `SUBMITTED`, `PENDING` and `STARTING` where four
statuses were asked for; asked for all seven, it stood pinned at every poll and no event
was written of it.

**`STARTING` is running, and `SUBMITTED` and `PENDING` are waiting**, in the line's
words and in what a run says for the record (§4). A job that is starting has no start to
count from, so it is counted among those running and not timed, and `max_run_time` holds
nothing against it. A job that is submitted or held waits as a `RUNNABLE` one waits,
counted from its submission and held against `max_wait_time`, so a dependency's wait and
an array's run warn past it as a wait for capacity does. The line says *waiting for
capacity* where every job it counts as waiting is `RUNNABLE`, and *waiting* where one is
not. A name whose runs are in none of the seven, which only a status Batch adds can
show, has its node and its line all the same: `no run finished, running or waiting`,
graded `OK`.

**The line is marked as work in flight** while one of the name's jobs waits or runs: an
italic, display only, which leaves its code what the newest finished run made it
(little-sister ADR-0042 decision 6). So a name whose last run failed and that runs again
stays red, visibly rebuilding, and its words say what runs.

**Each status is a `ListJobs` call of its own**, seven for every queue on every poll,
each under the same `max_jobs`.

**The line prints neither its region nor its queue.** The levels above it say both
where an account reads several regions, and nothing has to say the region where it reads
one (ADR-0007 §3). A queue's line and a pipeline's print no region for the same reason.
A slug keeps every part — the region, and for a job name its queue (ADR-0007 §5) — so a
line's slug is the one it had.

### 4. Every run a poll read is said for the record

No run has a line of its own. How each one stood, the grading says for the record
alone (little-sister ADR-0111 decision 7), on a line that carries the run's record:

| The run | Its verdict | Its sentence |
|---|---|---|
| `SUCCEEDED` | `OK` | `SUCCEEDED, waited 10m, ran 50m` |
| `FAILED` | `ERROR` | `FAILED, waited 2m, ran 13m` |
| `RUNNING` | `OK`, and `WARN` once it has run for more than `max_run_time` | `RUNNING for 4m`, `RUNNING for 3h, past max_run_time` |
| `STARTING` | `OK`: it has no start to count from | `STARTING` |
| `RUNNABLE`, `SUBMITTED`, `PENDING` | `OK`, and `WARN` once it has waited for more than `max_wait_time` | `RUNNABLE for 5m`, `PENDING for 35m, past max_wait_time` |

A finished run says how long it waited and how long it ran, each where both of its
instants are known. A run in flight says for how long, counted to the instant the
grading is handed: a run from when it started, and a wait from when the job was created,
since a job that waits never started. A job that is starting says only that, since it
has no start yet. Both are counted from the record's instants, as the job name's line
counts them, and the grading reads neither `wait_s` nor `duration_s` (ADR-0008). The two
bounds are the ones the job name's line is graded by, held against this run alone.

**A run takes its last verdict from the poll that reads it finished.** Each poll says
of every run it reads what holds then, and a run read again is the same record
(ADR-0005 §5). So one that warned while it ran passes or fails once it has ended, and a
run the check reads no longer keeps what was last said of it.

That is why the line is not the newest run's. Such a line would turn a job name green
the moment a retry was submitted after a failure, and would have no place for how many
run and wait; and the line as it is, carrying the newest finished run, would keep that
run under a code another run set.

This amends ADR-0005 §5, where a kept run was stored with no verdict and graded again
from its record, and §7, which gains the line written for the record.

### 5. A poll reads the executions its pipeline's history lacks

**A pipeline's line carries the execution it is written from**: its newest, unless that
one is in flight on a first run, and then the newest behind it with a verdict to keep
([ADR-0014](0014-a-pipelines-line-keeps-its-verdict-while-an-execution-is-in-flight.md) §2,
§4) — the reading's record as its `data`, and the pipeline as its subject, which is the
reading's own. Beside that verdict the line says what is in flight, and while anything
is, it is marked running (little-sister ADR-0042 decision 6). `InProgress` passes by
default, and an execution in flight warns once it has run longer than `max_run_time`
(ADR-0014 §1, §3).

**Where the check keeps a series, a poll reads more than the newest.** Out of the page
of executions the aspect already asks for, it reads every execution the pipeline's
history lacks, and every one the history holds in a status that ends nothing
(ADR-0008 §3) — of the newest in the page, as many as the series keeps, the newest
itself among them, since an older one would leave the series the moment it was kept —
and every execution in flight on the page, so one the history held finished and that
runs again, its failed stage retried, is read while a poll finds it running, and to its
end (ADR-0014 §5). That is the rule a function's runs follow (ADR-0006 §3). The
measuring half reads what the check kept (little-sister ADR-0113), and what it finds
there decides what is read and nothing else: a record holds what CodePipeline answered.

So an execution that a newer one overtook while it ran is read to its end, where it kept
the record of its last read; a pipeline's series is whole from its first poll, as far as
one page reaches, which is a hundred executions; and an execution the history holds
finished is not handed back again, but for the two below: the one the history holds as
the line's, read once more, and one in flight again.

**One finished execution is read once more: the one the history holds as the line's,
where the line is now written from another.** What stood for it was the pipeline's line:
its sentence with an age that has stopped, and its verdict, which is a warning or an
error for a success that had grown stale (`max_age`) or that an execution in flight
beside it raised. Read again, it is said for the record by its own status (§6). The poll
after that finds the line on the other one, and leaves it alone.

The history's line is found as the line is (ADR-0014 §4): the kept execution that
started last, unless it was in flight, and then the newest behind it that was neither in
flight nor superseded. Where several started at one instant, when they started does not
say which of them carried the line, so each is taken for it and read once more, as far
as the bound above reaches — and none of them while the line is written from one of
them, which would be at every poll.

Each execution read is a reading of the kind `pipeline`, as the newest's is
(ADR-0005 §1): it names its own id as the event it is of, and stands in the series where
it started. Three are not read for the history. An execution CodePipeline sent without a
start has no place among the others, one without an id would be a new record at every
poll, and one without a status says nothing; the one the line is written from and one in
flight are read all the same (ADR-0014 §2).

**Where the check keeps no series, the newest is read**, and the execution the line is
written from and every one in flight with it, and nothing else (ADR-0014 §2).

This amends ADR-0005 §5, which read the newest execution and not the page.

### 6. An execution the line is not written from takes its status's verdict, a superseded one none

Each execution a poll reads other than the one the line is written from is said for the
record alone: the verdict its status has in `state_map`, as the line's has, in a
sentence that is the status, and one in flight raised past `max_run_time` (ADR-0014 §3).
How old a success may get (`max_age`) is asked of the execution the line is written from
alone: while it is, what is kept of it is what its pipeline's line says, and from the
poll that finds the line on another (§5), what its status means.

**Nothing is said for the record of an execution that was superseded.** A newer
execution overtook it, so it neither failed nor deployed. It gets no line, whatever the
map says of the word, and its mark is the one that claims nothing
(little-sister ADR-0111 decision 1). The map's word for it stays as it is: `Superseded`
is an error where it is the status of the newest execution, which it rarely is, and for
as long as it is the newest.

### 7. A job name the list hides is not kept

The measuring half leaves out the runs of a name `ignore_name_patterns` hides. Such a
name has no series, no plots, no rows on a History page and no node, as a function or a
pipeline that a rule ignores has none. The list spares no request, which is why
ADR-0005 §2 gave it to the grading. What it spares is the keeping, so it is read where
the runs are read. The grading reads it too, for a run that was read before the list
named its name: nothing is said of that run, and its name has no node.

A name the list hides no longer is kept from the run that next reads it. What was kept
of a name before the list hid it stays, and is shown on the check's own node as it was,
until the series lets it go (little-sister ADR-0087 decision 10).

This amends ADR-0005 §2 and §3.

### 8. An aspect's own node keeps what `lambda` keeps

How many queues or pipelines are in scope, its roster, and, where its regions have no
nodes of their own, a region that could not be read (ADR-0006 §9). Where an account
reads several regions, a region's node stands beneath `codepipeline` and beneath `batch`
as it does beneath `lambda`, and it is what ADR-0007 §3 says of one.

**The node the pipelines or the queues hang on says that its children are complete**
where their listing was read (little-sister ADR-0109): the aspect's node, or a region's.
A pipeline or a queue that was deleted, and one the configuration now ignores, leave
with the next good run. Where the listing could not be read the node leaves that
unsaid, and everything beneath it stays as it was.

## Consequences

- **A pipeline's line, a queue's and a job name's move to nodes of their own** with the
  release that carries this, so a pin on such a line stops matching at its old path. A
  pin on a job name or on a pipeline is a pin on a node. That release's notes say so
  first.
- **ADR-0005 §2, §3, §5 and §7 are amended, and ADR-0001 §2**, whose aspect was flat:
  `codepipeline` and `batch` hand back nodes, as `lambda` does since ADR-0006. The point
  ADR-0007 left open is answered, and what ADR-0008 said of where a run's plots stand
  is rewritten: a job name's *Wait* and *Duration* and a pipeline's *Duration* stand on
  the node of the job name or the pipeline.
- **A subject that has no node at the moment is shown on the check's own node.** A job
  name none of whose runs Batch still lists, one that fell behind its queue's cap, and a
  pipeline that was deleted keep what was kept of them until the series lets it go.
  little-sister lists those readings on the check's History page and draws their plots
  on the check's own node (little-sister ADR-0106 decision 4), as it did for every job
  name and pipeline before this record. A job that runs once a month stands there for
  three weeks of four.
- **With `series_keep` set, a kept run and a kept execution carry a verdict and a
  sentence**, and their marks say how they stood. An execution that was superseded is
  drawn without one, once a newer one has started. A record an earlier release kept is
  what it was kept as, until it is read again or leaves the series.
- **A pipeline's first poll keeps as many of its executions as the series keeps**, out
  of the one page it asked for — so a hundred at the most — where it kept the newest.
  Nothing more is asked of AWS for it.
- **A job name `ignore_name_patterns` hides is no longer kept.** A deployment that hid a
  name and read its runs on the check's History page finds no new ones there.
- **A queue costs seven `ListJobs` calls on every poll**, each under `max_jobs` (§3),
  and a job name being started keeps its node and its pin.
- **A queue read at its cap shows the job names of the runs it read**, as its lines
  did. A name that fell behind the cap has no node until it runs again (§2).
- **An execution the history holds finished is read again only by a poll that finds the
  line moved on from it, or finds it in flight again** (§5): a failed stage retried is
  read while it runs, and to its end. One that is retried and ends between two polls
  keeps what its last read said.
- **The wall holds a node for every queue, every job name and every pipeline**, where
  it held a line for each on two nodes. Nearly all of them are quiet, and quiet they
  are chips.
- **`codepipeline` is tested with its kept executions handed to it**, and no engine,
  as `lambda` is with its kept runs (little-sister ADR-0113 decision 4).

## Alternatives considered

- **A queue's level only where a region holds several queues.** Refused in §2: a path
  would move by what AWS answers.
- **The queue in the job name's node name, and no level.** Refused in §2: a node that
  is no longer named by what AWS calls the job, which ADR-0007 refused for a region.
- **A queue's node that says nothing of its job names where it was read at its cap**,
  which is what the round first had. Refused in §2: a busy queue would hold a stale
  node for every name that fell behind the cap, and warn for as long.
- **`STARTING` asked alone**, beside the four statuses first asked. Refused in §3: it
  mends the case that was seen and leaves the waits that last longer.
- **A queue that says its names are complete only in a run with nothing being started.**
  Refused in §3: the same calls, and it says less.
- **A node kept for a poll past its last run.** Refused in §3: a memory the grading does
  not have, and it hides what the job does.
- **One call with a filter for every status.** Refused in §3: it answers newest first
  across all of them, so in a busy queue a job that has run or waited for long falls
  behind newer ones that finished — the job this aspect is there to see — and `max_jobs`
  would bound a queue rather than a status.
- **An execution that was the newest left with what its line said.** Refused in §5: in a
  pipeline that runs less often than its `max_age`, every success would be kept as the
  warning its line showed before the next one started.
- **A line that is the newest run's, and carries it**, with every other run said for
  the record. Refused in §4: green the moment a retry is submitted, and no place for
  how many run and wait.
- **The line as it is, carrying the newest finished run.** Refused in §4: a run that
  succeeded would be kept as a warning because another one waits too long.
- **Every execution of the page read on every poll.** Refused in §5, as ADR-0005 §5
  refused it: a hundred readings a pipeline on every poll, where a poll that reads what
  its history lacks hands back the newest and, rarely, one more.
- **The page read by a check that keeps no series.** Refused in §5: nothing would keep
  what was read.
- **A kind of its own for an execution read behind the newest.** Not taken in §5: it is
  the record the newest's reading is.
- **A superseded execution graded by `state_map`**, or the map's default changed for
  the word. Refused in §6: the first marks as failed what did not fail, and the second
  changes what the line says of a pipeline whose newest execution was superseded.
- **A hidden job name kept, and given no node.** Refused in §7: plots on the check's own
  node and rows on its History page, for a name its deployment asked not to see.

