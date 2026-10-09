# ADR-0006 — A function's runs are kept, and a function has a node

- **Status:** Accepted
- **Date:** 2026-10-10 (accepted 2026-10-03)
- **Related:** [ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md)
  (one reading per thing a run read, which readings have a history, how a subject is
  spelled and what a line carries — its §1, §3, §4, §5 and §7 are amended here),
  [ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) (where
  beneath `lambda` a function's node hangs), [ADR-0001](0001-the-aws-check-type.md) (the
  region in every slug),
  [ADR-0003](0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md) (the rules a
  function's line is graded by, unchanged), little-sister **ADR-0113** (a check's
  measuring half reads what the check kept), little-sister **ADR-0087** (a subject's
  series, and the identity that keeps an event in it once), little-sister **ADR-0106**
  (a subject with a history has a node of its own), little-sister **ADR-0109** (a node
  says that its children are complete), little-sister **ADR-0111** (a run's mark, and a
  line written for the record alone), little-sister **ADR-0092** (a check declares its
  measures), little-sister **ADR-0086** (a line's subject is its reading's — the rule
  little-sister ADR-0106 amends for the line of §9), little-sister **ADR-0118** (a node
  a run names says so, and takes nothing declared for its name),
  [ADR-0012](0012-a-functions-line-holds-an-error-it-saw.md) (the error a function's
  line holds)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

The `lambda` aspect reads one thing of each function: the newest bucket of CloudWatch's
`Errors` metric that holds a data point — its count, and its time, which the line calls
the last run — and, where a rule asks, the status word of the function's newest log
line. ADR-0005 §3 gave that reading no history: `series_keep` is one number per check,
and a function that runs every minute would have appended a record at every poll.

Three things have changed since. little-sister shows a subject that has a history on a
node of its own, and draws its runs as marks at their own times (little-sister ADR-0106,
little-sister ADR-0111). A run can remove a node its check no longer reports, so a
function that is deleted leaves no stale node behind (little-sister ADR-0109). And a
check's measuring half can read what the check kept (little-sister ADR-0113). What an
operator asks of this aspect first is then within reach, and it is the one thing the
aspect cannot show: what the functions ran, when, and how it went.

The source decides most of what follows, so it is stated first.

- **AWS lists no invocations.** What it keeps of a function's runs is CloudWatch's
  metrics — `Invocations`, `Errors` and `Duration` among them — and the function's log.
- **A metric is kept in one-minute points for fifteen days**, and coarser after that.
  Lambda stamps a point with the moment the function was **invoked** and emits it when
  the invocation ends, so a point can appear as late as its function ran — fifteen
  minutes at the most, a function's longest run — and CloudWatch may deliver it later
  still.
- **`get_metric_data` answers many metrics in one call**, five hundred queries, **over
  one window**, the newest points first, **and in pages**: a page ends where its part of
  the window could hold 100,800 points — the queries times the periods in that part —
  whatever the metrics hold, and hands back a token for the next. The fifteen days at
  one minute are 21,600 points a function by that count: three pages for every fourteen
  functions, however seldom they run.
- **CloudWatch bills that call by the metric requested, and not by the call**: about
  $0.01 for a thousand when this was written, and no part of the free tier. At one poll
  a minute a function costs some $0.43 a month for every metric asked of it. The aspect
  asks one. Whether a metric is billed again for each page of its answer, neither
  CloudWatch's pricing nor its billing page says, and it was not measured: this record
  counts a metric once for each call that asks it.

So six questions: what a run is; what a poll asks, and what that costs; which numbers a
run carries, and under which names; what a function's line says once its runs are kept;
what a function is in the tree; and what becomes of a function that is invoked all the
time.

## Decision

### 1. A run is a one-minute bucket of the metric

Every one-minute bucket in which a function was invoked is **one run**, and one record:
its invocations, its errors and its duration. A run **failed** where its errors are
above zero.

It names its function as its subject, spelled as ADR-0005 §4 spells one — the kind
first, the account by its configured name, and `/` between the parts:

```
lambda/<account>/<region>/<function>             a function's run
```

And it names its bucket's start as the event it is of: the instant its record keeps as
`at`, so a bucket read again is one record however often it is read (little-sister
ADR-0087 decision 3). That instant is its place on a time axis — when the function was
invoked.

This answers what ADR-0005 §3 refused a function's history for. A run names an event, so
a poll that reads it again replaces its record and appends nothing, and §8 says what
becomes of a function that fills every bucket. It amends ADR-0005 §3, §4 and §5: a
function's runs are a fourth history, with a subject and an event of their own.

Two things a bucket cannot do: tell two invocations within one minute apart, and stand
for one run where a function is invoked all the time.

### 2. The function's reading stays one reading, and a run is a record of its own

**Every poll reads each function's newest bucket, as it does today, and a run is read in
full once it exists.** So the aspect hands back two kinds of record for a function:

| kind | fields | subject |
|---|---|---|
| `function` | `name`, `errors`, `at`, `error`, `log_status`, `log_note`, `log_error` | none: read and graded, and kept no longer than its node |
| `run` | `name`, `at`, `invocations`, `errors`, `duration_ms` | the function, by §1: kept as its series |

The function's reading is what it was — the newest bucket's count and its time — and
beside them the newest error in the window it was asked: its time, the clean buckets
since, and what the buckets inside the function's `error_hold` count together, from the
same answer ([ADR-0012](0012-a-functions-line-holds-an-error-it-saw.md)). Its line is
written from it (§9). It is asked for on every poll because the line needs the
function's newest run on every poll — *no errors, last run 3 d ago* — and nothing else
can supply it. A poll that asked only for what is new would read nothing of a function
that did not run, and a kept record is never handed back as a reading
(little-sister ADR-0113 decision 3).

A run's invocations and its duration are two more metrics, each billed for each function
on each poll that asks it. So they are asked only of the functions that have a run to
read (§3), in a second call, and their answer becomes the run's record together with the
`Errors` count the first call already holds.

**What that costs.** A function that did not run is asked nothing more: one metric a
poll, where it has run within the fifteen days. One that runs once a day costs about 8%
more at a poll a minute, two metrics on each poll of the hour after its run and on the
first that follows it (§4). One that runs at least hourly costs three times as much.

This amends ADR-0005 §1, which gains the kind `run`.

### 3. A poll asks for what its history lacks, in the window its series reaches into

The measuring half reads each function's kept runs (little-sister ADR-0113) and holds
them against what the first call answered. **A bucket the kept runs lack, and one no
poll has read since it was as old as the overlap (§4), is read in full**: a second
`get_metric_data` call asks `Invocations` and `Duration` of the functions that have such
a bucket, and of no others. In an ordinary poll that is the newest bucket of the
functions that just ran, and nothing before it. A poll reads in full none but the newest
buckets its first call answered, as many as the series keeps: an older one would leave
the series the moment it was kept, so it is no reason to ask.

**A function is asked in one of three windows: the last hour, the last day, or the
fifteen days.** Where its kept runs fill the series it is the smallest of the three that
reaches back to the oldest of those runs and to the start of its hold (§9), and where
they do not it is the fifteen days. One call has one window, so a region's functions are
asked in at most three calls, five hundred queries to a call, and a metric is asked
once, whichever call holds it. No call then asks a function further back than its series
and its hold reach into. With thirty runs kept, a function that fills every bucket
answers its last hour and not the 21,600 points of fifteen days, one that runs every
five minutes answers a day — 288 points, where thirty kept runs reach back two and a
half hours — and one that runs once a day is asked as far back as it is today. **How far
a series reaches is how many runs it keeps times how seldom its function runs**, so the
hour is nothing a busy function is promised: one that fills every bucket answers its
last day once the series keeps an hour of it, some sixty runs, and its fifteen days once
the series keeps a day of it, 1,440. A series that is not full — at a deployment's first
poll, or after `series_keep` was raised — is asked the fifteen days until it is. The
window decides how much CloudWatch answers, and in how many pages — and, by the count
this record takes of a metric, never what it bills. Either way a call asks the coarser
periods where its window holds no point, as it does today, and follows CloudWatch's
token from page to page. The windows are constants of this type, as the overlap is (§4).

**The second call starts at the oldest bucket it is to read.** It holds the functions of
one window, as the first does, so that a function whose bucket is minutes old is not
asked with one whose bucket is days old. Asked in the window of the first call, it would
answer every point of that window again, for each of its two metrics, where the poll
reads a few buckets of it: a function that fills every bucket under a series of 1,440
runs would answer 43,200 points where it answers its last hour's, some 120.

**A call follows CloudWatch's answer to its last page**, decided on what a deployment's
regions list: two to five functions each, where an answer takes a second page at a
region's first poll after a start alone. What a poll takes follows how many functions a
region lists, and not how busy they are: a hundred functions asked their fifteen days
are 22 requests and some seven seconds a poll, and five hundred are 108 requests and
some five minutes, more than the minute a deployment may poll in. Two shapes that ask
less were weighed for a region of hundreds and not built, and what a page is billed is
still not measured.

**The first poll after a start reads in full again the buckets its first call
answered**, the newest and as many as the series keeps, and its second call reaches as
far back as they do. A bucket whose numbers grew after the last poll that read it in
full (§4) is repaired then. It is each region's own first poll: a region that could not
be read when the process started is read in full again by the poll that first reads it.
A bucket that only appears after its hour waits for no start: the next poll's first call
answers it, and the kept runs lack it.

**Where a check keeps no series, no history is asked for**, and the aspect reads what it
reads today. The measuring half reads how many readings its check keeps, and sets
nothing (little-sister ADR-0087 decision 7).

What a poll reads again merges into the series by its identity, and a bucket that
arrives late stands where its time puts it, not where it arrived (little-sister ADR-0087
decision 3). A kept run decides what is asked and nothing else: a run's record holds
what CloudWatch answered in the poll that wrote it.

**A query CloudWatch did not answer is a read that failed.** `get_metric_data` answers
each query of a call on its own, and says of each whether it did: `Complete`,
`PartialData` with a token for the rest — or a word that says it could not,
`InternalError` and `Forbidden` being the two it has, in a call that itself succeeds.
Such a result carries no point. Read as an answer it is a function that never ran, or a
run kept with an empty number, which stays empty where that read found its bucket an
hour old (§4), until the process starts again. So it is taken for what it is: the region
says that its functions could not be read, and which metric of which function CloudWatch
did not answer, as it does where the call itself fails; no reading and no run of that
poll is kept; and the next poll asks again. What is listed is the words that answer, so
a word CloudWatch adds is no answer until this type knows it.

### 4. A bucket is read again until a poll has read it an hour old

**The overlap is one hour, and a constant of this type.** A bucket's numbers may still
grow after it first appears — an invocation that began in its minute and ended later —
so a bucket is read in full on every poll until one has read it at an hour old. Lambda
itself delays a point by no more than a function's longest run, fifteen minutes, and an
hour is four times that. How late CloudWatch delivers is a fact about CloudWatch and
nothing a deployment has a reason to choose, so it is no setting, as the retention
periods the aspect reads by are none.

**What counts is how old the bucket was when it was last read, and never how old it is
now.** A kept run says when it was read (little-sister ADR-0113 decision 2), and a
bucket read again is that same record, read later (little-sister ADR-0087 decision 3),
so what the check kept answers it. Counted by the bucket's age at the poll, a bucket
would be read again only by the polls that fall within its first hour, and where none
does it would keep what its first read found. With a `frequency` of an hour, or after an
hour in which its region could not be read — a login that expired, a machine asleep — a
bucket read while an invocation of its minute was still running would stay what that
read made of it until the process starts again: a run that passed, where the invocation
then failed, under a function whose line names the error. Counted by the last read, the
next poll that reads the region reads the bucket again, however late it comes. That is
one read more of each bucket than its hour holds.

### 5. A run's duration is the maximum

`duration_ms` is the `Maximum` of CloudWatch's `Duration` over the bucket: the slowest
invocation of the minute. It is the time the function's code ran, and leaves out a cold
start. For a bucket with one invocation — a scheduled function's — it is that
invocation's own duration; where a minute holds forty, it is the number that shows a
function nearing its timeout, which an average would hide. `invocations` and `errors`
are the `Sum` of their metrics.

### 6. A number's name carries its unit

`duration_ms` is milliseconds, CloudWatch's own unit, as a whole number. The unit stands
in the name, as little-sister's own types write it (`response_ms`): a record renders as
its keys, and a table of readings shows a value as it is stored. **Each record uses the
unit its values are read in**, so the rule reaches past this record: a Batch run's
duration and its wait are `duration_s` and `wait_s`, and a pipeline's execution's
duration is `duration_s`
([ADR-0008](0008-a-run-and-an-execution-say-how-long-they-took.md)).

`invocations` and `errors` are counts and carry no unit. A run's `name` is its
function's and its `at` its bucket's start, under the names the function's reading
already uses.

### 7. The type declares a run's durations as measures

`duration_ms` is declared in `ms` as the type's default (little-sister ADR-0092
decisions 1 and 2), so a deployment that keeps a series draws a function's runs as stems
to their duration with no key of its own (little-sister ADR-0111 decision 5). A count is
a column of the readings table and no plot. A deployment takes the plot away with
`duration_ms: null` in its `measures:` block, which leaves a run a tick, or adds a count
there. ADR-0008 §5 declares the spans of §6's other records the same way.

### 8. A function that is invoked all the time gets nothing of its own

It shows its newest buckets like any other function, as many as the series keeps: half
an hour of them where `series_keep` is 30, against a month of a daily function's. It
costs three metrics on every poll, since it always has a bucket younger than the
overlap, and §3 bounds what it answers. Nothing is configured for it.

### 9. A function has a node, and its line names it

**Every function the aspect reads has a node beneath `lambda`** — one that ran well, one
that failed and one that was never invoked alike — named by what AWS calls the function.
[ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) says where
beneath `lambda` it hangs. A display-name rule (`shorten`) gives the node its title and
never reaches its path, as it never reaches a slug. The node says that a run names it
(little-sister ADR-0118), so a function its account calls `batch` is shown under its own
name, and not under what this type declares for the `batch` aspect.

**The function's line stands on that node and says what it says today** — the last run,
its errors, the log's status word, the sentence of the rule that graded it — and holds
an error it saw at ERROR while that error is younger than `error_hold`, an hour by
default, once clean runs have followed it
([ADR-0012](0012-a-functions-line-holds-an-error-it-saw.md)); it is written from the
function's reading, under the slug it has. **It names the function as its subject,
though its reading names none.** That is what makes the node stand for the function
(little-sister ADR-0106 decision 2), so that the node's page and its Series view draw
the function's runs and its History page lists them; and it is what keeps the function's
reading out of the series, which would otherwise gain a record at every poll. A line's
subject is otherwise its reading's (little-sister ADR-0086 decision 2), and
little-sister ADR-0106 decision 2 has this case: a line on a subject's own node names
the subject where its reading names none. It amends ADR-0005 §7 for a function's line.

**No run has a line of its own.** How each run a poll read in full stood, the grading
says for the record alone (little-sister ADR-0111 decision 7): `ERROR` where its errors
are above zero and `OK` where they are not, in a sentence that says its errors and its
invocations. A run's verdict is its own at any age; the gate that keeps an old error
from being graded (`error_max_age`) is the line's, and so is the hold, which a run's
record knows nothing of.

**The node the functions hang on says that its children are complete** where their
listing was read whole (little-sister ADR-0109), so a function that was deleted, or that
a rule now ignores, leaves with the next good run. Where the listing could not be read
the node leaves that unsaid, and the functions stay.

**`lambda` keeps what is its own**: how many functions are in scope and, where its
regions have no nodes of their own, a region that could not be read. Its Series view is
then the overview: every function's runs, on one time axis.

## Consequences

- **A function's line moves to a node of its own** with the release that carries this,
  so a pin on the line stops matching at its old path, and a pin on a function is a pin
  on a node. That release's notes say so first.
- **With `series_keep` set, a deployment keeps four histories**, and as many more series
  as it has functions. What it keeps of each is `series_keep` runs, the one count a
  check has for every subject (little-sister ADR-0087 decision 4).
- **The package's floor rises** to the little-sister release that lets a check read what
  it kept, write a line for the record, remove what a run no longer reports and say that
  a run names a node.
- **A run's record is small** — some 200 bytes with ordinary names — so the heaviest
  record of ADR-0005 §8 stays the heaviest.
- **CloudWatch's bill for this aspect** is one metric a poll for a function that did not
  run, where it ran within the fifteen days, and up to three times that for a busy one
  (§2). Nothing is asked of a function a rule ignores, as before.
- **The first call's answer is bounded by the window a function's series and its hold
  reach into** (§3) where it was bounded by fifteen days: with thirty runs kept, a
  function that fills every bucket answers its last hour where it answered 21,600
  points. A deeper series reaches further, and from 1,440 kept runs on such a function
  answers its fifteen days again. The second call's answer is bounded by the buckets it
  reads, however deep the series: ordinarily such a function's last hour or so.
- **How many requests an answer takes follows the window, and not what the functions
  hold**, by the count a page ends at (*Context*): one for the functions asked their
  hour, one for every seventy asked their day, and three for every fourteen asked their
  fifteen days — which is every function whose kept runs do not fill its series or reach
  back past a day, or whose hold does, and every function of a check that keeps none,
  however seldom it runs.
- **ADR-0005 §1, §3, §4, §5 and §7 are amended**: a kind, a history, a subject, an
  event, and a line that names what its reading does not.
- **The aspect is tested with its kept runs handed to it**, and no engine: a type's test
  binds what the measuring half is to find (little-sister ADR-0113 decision 4).

## Alternatives considered

- **Each invocation read from its log's `REPORT` line.** Refused in §1: a read for every
  function on every poll, which grows with how busy the function is. It can follow for a
  function whose single invocations matter.
- **Every function read in full on every poll.** Refused in §2: the simplest model — one
  kind of record, and a line that carries the newest run — at three times the aspect's
  bill.
- **A run that is only what the one metric gives**, its errors and its time. Refused in
  §2: its history is free, and its mark says no more than that the function ran.
- **The kept run handed back** as the function's reading where nothing is new. Refused
  in §2: a record would then depend on what one instance happens to hold (little-sister
  ADR-0113 decision 3).
- **A line that carries the newest run.** Refused in §9 with §2: it takes every function
  read in full on every poll.
- **The process remembering where it read to.** Refused in §3: its mark can run ahead of
  what was kept, and a restart forgets it.
- **Every function's fifteen days read in full on every poll.** Refused in §3: the
  answer grows with how busy a function is.
- **Every function asked from its own oldest kept run**, or the hour and the fifteen
  days alone. Refused in §3: the first is a call for nearly every function whose series
  is full, each a round trip inside the poll; the second leaves a function whose series
  reaches past the hour its fifteen days — 21,600 points by the count a page ends at,
  however seldom it runs, so five of them pass one page where the day's window takes
  seventy.
- **The second call asked in the window of the first.** Refused in §3: it answers that
  whole window for both metrics, where the poll reads a few buckets of it.
- **A first call at a period of a day**, fifteen points a function, with the one-minute
  period asked of the days that hold something. Not built in §3: whether CloudWatch
  answers a period of a day as that needs was not tried. It can follow for a region of
  hundreds of functions.
- **No function asked further back than its newest kept run**, one page for a region of
  hundreds. Not built in §3: a reading would lean on what an instance holds, which two
  of the alternatives above were refused for. It can follow for a region of hundreds of
  functions.
- **The one function's line saying that its metric was not answered**, and the rest of
  its region read. Refused in §3: a function's reading would need a field for it, which
  is a key once shipped, and its line a verdict for a read that did not happen. A region
  that could not be read is what the aspect already has for a read that failed.
- **An overlap of twenty minutes**, or a key for it. Refused in §4: the first covers
  Lambda's own delay and leaves next to nothing for CloudWatch's; the second is one more
  thing to explain, for a number no deployment has a reason to choose.
- **A bucket read again while it is younger than an hour**, counted at the poll.
  Refused in §4: it repairs a bucket only where a poll falls within its first hour, and
  the kept run already says when it was read.
- **The average**, or both as two fields. Refused in §5: in the first, one slow
  invocation disappears among the fast ones; the second costs a third billed metric for
  each function that ran, a second curve and one more stored key.
- **Seconds for the whole package**, or a plain `duration`. Refused in §6: the first
  converts what CloudWatch reports and puts decimals into every cell; the second leaves
  a record that does not say its unit.
- **No measure by default**, or every number a run carries. Refused in §7: the first
  draws no duration until a deployment asks; the second draws three plots for each
  function, two of them flat for a scheduled one.
- **A rule that spares a busy function its runs**, or coarser buckets for it. Not taken
  in §8: the first is additive, and can follow the day such a function bothers a
  deployment; the second is the most machinery — an identity for each period, and a
  second history beside the first where the period changes.

