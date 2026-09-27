# ADR-0005 — A run is its readings, and only the runs and the estate keep a history

- **Status:** Accepted
- **Date:** 2026-09-26
- **Related:** [ADR-0001](0001-the-aws-check-type.md) (account first, aspect second —
  the tree this keeps — and the account id kept off every slug and link),
  [ADR-0003](0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md) (the
  configuration vocabulary this splits between the two halves), little-sister
  **ADR-0086** (a check measures and then grades what it measured — the split this is
  the conversion to), little-sister **ADR-0087** (a subject's readings kept as its
  series, the identity or the state that says whether a reading is a new record, and
  what a kept reading keeps of where it stood), little-sister **ADR-0085** (one shape
  for every reading), little-sister **ADR-0082** (a line's `data` and `subject`, and
  the typed times), `little-sister-github` ADR-0013 and ADR-0014 and
  `little-sister-wiz` ADR-0003 (the packages through the split before this one —
  their readings, their configuration split and their line rule, taken here in this
  vocabulary)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

little-sister ADR-0086 replaced a check's `run()` with two halves. `measure()` reads
the world and hands back `Measurement`s — records, and the objects they were read
from — and `grade(measurements, now)` builds the tree a check has always returned out
of those records, the configuration and the clock it is handed, and nothing else. The
check API epoch moved to 3 with it, and a type written for 2 refuses at import. Until
this record, this one did, and every deployment that imports this package with it.

An `aws` run reads many objects of many kinds in one run: every alarm, instance,
function, pipeline, job queue and Batch job of every account it watches, in each of
that account's regions, through five aspects. The split asks the questions it asked
the packages before this one, in this vocabulary — what one reading is, which readings
name a subject, since a subject is what gives a reading a history (little-sister
ADR-0087 decision 2), and what event each of those names, or, where the source keeps
no event, what state (its decision 3). And it asks one no package before this one had
to answer, because this is the first whose objects are reached through names a
deployment gave them: how an account is named inside a subject.

## Decision

### 1. One reading per thing the run read

A run hands back, in this order: the **estate** (§6); each account's own reading, in
configuration order; then, for each account that opened, each aspect's readings in
the order the aspect read them — one per alarm, instance, function, pipeline, job queue
and Batch job run, and one per region the aspect could not read.

Every record names the **`aspect`** it was read for — `null` for the estate and an
account's own reading — and its **`kind`**, the shape the rest of it has; one about one
account names it as **`account`**, by its configured name (§4), and one about one region
names the **`region`**. What the rest holds is what its line is written from, and
nothing the line does not need but what a kept run should carry:

| kind | aspect | fields |
|---|---|---|
| `estate` | `null` | `credentials` — what AWS answered where the credentials did not open; `accounts` — each account's `name` and `outcome`, in configuration order, empty where none was tried |
| `account` | `null` | `outcome` — `read`, `unreachable` or `expired`; `error`; `renewal` — for an expired login, why it was not renewed or what renewing it did |
| `unreadable` | each | `error` |
| `alarm` | `cloudwatch` | `name`, `state`, `description`, `composite` |
| `instance` | `ec2` | `id`, `name`, `state`, `started` |
| `function` | `lambda` | `name`, `errors`, `at`, `log_status`, `log_note`, `log_error` |
| `pipeline` | `codepipeline` | `name`, `execution`, `status`, `started`, `at` |
| `queue` | `batch` | `name`, `state`, `status`, `reason`, `capped` |
| `job` | `batch` | `queue`, `name`, `id`, `status`, `reason`, `created.at`, `started`, `ended`, `at` |

A value AWS did not send stands as `null`, so every reading of one kind has one shape
(little-sister ADR-0085 decision 3). A time is ISO 8601 in UTC, and always under one of
the names little-sister reads as an instant — `at`, `started` or `ended`, at the top of
the record or nested (little-sister ADR-0082) — since under any other name it is only
a string to every surface that shows a record: an instance's launch is its `started`, a
function's newest invocation its `at`, the instant its line reports, as a pipeline's
is, and a job's creation, which has no such name of its own, `created.at`. A job's
`reason` is Batch's `statusReason`: no line says it, and a kept run is poorer without
it.

**EC2 is read per instance, although its lines are per name.** A name's line gives the
age of every box that carries it as a range, and the grading may read nothing but
records; the launch times of a fleet pass the 2 KB `record_limit` at about sixty boxes,
and dropping some would be a lie about what was read. So a name is the grouping the
grading makes, as it always was, and has no reading of its own.

### 2. The configuration is split by what it spares

`little-sister-github` ADR-0014 §5's rule: a setting that **spares a request** stays in
the measuring half, because the reading it saves is never taken; one that only
**chooses what is said** moves to the grading, because a reading that left something
out would be a reading of the configuration rather than of AWS.

The measuring half keeps `enabled`, the regions and credentials, `include_composite`
(it changes what `describe_alarms` is asked), a `lambda` rule's `ignore` and
`read_log_status` (they spare the metric and the log reads), a `codepipeline` rule's
`ignore` (it spares the execution list), `ignore_queue_patterns` (it spares a queue's
job listings) and `max_jobs` (the size of the ask). Everything else is the grading's:
`ignore_name_patterns` on alarms and on job names, `show_healthy`,
`expect_min_alarms`, `tag_prefix`, every `state_map`, `ignore_states`, every `ec2`
rule, every graded pair and sentence, the `lambda` gate, `expect_invocations`,
`expect_jobs`, `max_run_time`, `max_wait_time` and `shorten`.

So an alarm the ignore list hides, a terminated box and a job name nobody wants listed
are readings, and are neither listed nor counted, exactly as before. Which rules
matched a name is still said in the log — from the measuring half, because that line
is said when the set changes, which is state kept between runs, and the grading may
keep none.

### 3. Only the runs and the estate have a history

A subject is what gives a reading a series, so which readings name one is a decision
about what is to have a history. Three kinds do: a **Batch job's run**, a **pipeline**
and the **estate**. Alarms, instances, functions, queues, accounts and the regions that
could not be read name none: they are read and graded and kept no longer than their
node.

**The deciding reason is that `series_keep` is one number per check** (little-sister
ADR-0087 decision 4). A deployment asking for its Batch runs would otherwise buy a
series for every alarm, every instance and every function with them — and a function's
newest invocation is an event CloudWatch keeps, so a function that runs every minute
would append a record at every poll. The runs are what this check exists to show the
course of; the rest is a diagnosis read now. Granting a history later is additive: a
subject on a reading that already exists.

A job name `ignore_name_patterns` hides keeps a history too: its runs are still read,
since listing a queue answers with them (§2), and each names its subject and its
`jobId` like any other run — so with `series_keep` set, a hidden name's runs are kept
though no line shows them.

The strongest candidate left out is an **alarm**. CloudWatch documents
`StateTransitionedTimestamp`, on metric and composite alarms alike, as *the date and
time that the alarm's StateValue most recently changed* — the last-changed field
little-sister ADR-0087 decision 3 asks for — so an alarm's series would be one record
per spell. It is left out for the number, not for the object: the way to it is a
`series_keep` below the check, per aspect, the coarser form of the per-subject override
that record's decision 4 leaves open as additive — which the library would have to
offer first, since a type never sets the count itself (its decision 7).

### 4. A subject names an account by its configured name

The kind first, and `/` between the parts:

```
batch/<account>/<region>/<queue>/<job name>      a Batch job's run
codepipeline/<account>/<region>/<pipeline>       a pipeline
accounts/<name>/<name>/…                         the estate, the names sorted
```

`/` is the one character an account name cannot hold, since it is a node's path
segment, and AWS refuses it in a region, a queue, a job and a pipeline name — letters,
digits, hyphens and underscores, and a pipeline's `.` and `@` — so a subject splits
back into its parts, and the kind first keeps a job, a pipeline and the estate from
ever meeting. Past the 200 characters a subject may hold, or with a control character
in an account name, a subject is its kind, `/`, and `sha256:` with 32 hex digits of
the rest: still that kind's and still one object's, and never a refusal of a
configuration that loaded before.

**Not the account id.** It is AWS's identifier for the account, one a rename cannot
move and two checks reading one account would share — and it is the private string
[ADR-0001](0001-the-aws-check-type.md) keeps off every slug and every link, because
those end up in bookmarks and tickets. A subject is exactly where it would spread: the
envelope a client polls, the series file, a job name's line, and the address of a
subject's own page once the library draws one.

**Nor is the name the editorial label** little-sister ADR-0086 decision 4 keeps out of
subjects, although it is a path segment. It comes from the check's own configuration,
as a URL does for an `http` check, and this package already requires it to be stable,
because every maintenance pin under the account hangs off it (ADR-0001 §2); the
account's display text is `title`. Its costs are stated: a renamed account starts new
histories, as a renamed branch does in `little-sister-github`; a name pointed at
another account — its `role_arn` or `profile` edited — continues its histories, as a
pin on its node survives the same edit; and two checks may both call an account
`live`, in two organizations.

**This is the one place in the family where a subject is a name out of a
configuration rather than the provider's identifier**, and that binds any view that
joins subjects across checks: it keeps the check in its key, as the series key already
does (little-sister ADR-0087 decision 1).

### 5. The event each reading is of

**A Batch run names its `jobId`.** Batch keeps a finished job's state for at least
seven days, so a run is re-read poll after poll and must stay one record: seen
`RUNNABLE`, then `RUNNING`, then `SUCCEEDED`, it is one record that ends in its final
state. Several runs of one name in one poll are several readings of one subject, each
naming its own run — the case little-sister ADR-0086 decision 8, as little-sister
ADR-0087 decision 3 narrows it, was narrowed for. Its own time, `at`, is `stoppedAt`,
*when the job transitioned from the RUNNING state to a terminal state*: `null` while it
has not, so it stands where it was first observed until it finishes and then where it
finished.

**A kept run needs no line to be graded again.** A job name's line is written from all
of that name's runs, so by §7 it carries none of them, and a kept run is stored without
that line's code. That costs less than it looks: a finished run's verdict is its own
status — `SUCCEEDED` is OK and `FAILED` is ERROR, with no threshold in between — so a
window grades a kept run again exactly from its record. The two thresholds that could
have changed since, `max_run_time` and `max_wait_time`, grade only runs still running or
waiting, and a run's record is replaced by its final one once it has finished. The
exception is a run the check stops seeing before it ends — the check is removed, or
more than `max_jobs` newer runs finish between two polls — whose record stays in
flight.

**A pipeline names its newest execution's `pipelineExecutionId`**, so an execution read
in progress and again finished is one record, and its own time is the execution's
`startTime`, the instant its line reports. A pipeline with no dated execution names the
**state** `never-run` — no execution to name, and a pipeline that stays unrun is one
spell. An execution sent without an id names nothing and appends, which is not an
answer CodePipeline documents. The newest execution is read, not the page of a hundred
the check asks for to find it: the line is about the newest, and a pipeline run twice
between two polls is the rare case a page re-read on every poll would pay for.

No reading here names a source's own *last-changed* field, which the frozen-state rule
would have preferred: the two frozen states it keeps — a pipeline that has never run,
and the estate — have none, and a queue, which would have had to spell its state from
`state` and `status` since Batch documents no timestamp on it, keeps no history (§3).

### 6. The estate: the accounts, what became of each, and a root that grades nothing

**The object this check watches is the accounts it reads**, declared at construction
so a run that raises is still recorded against it (little-sister ADR-0086 decision 4):
`accounts/` and the configured names, sorted, so reordering the configuration does not
start a new history. The regions are left out, because what its history records —
whether each account opened — does not depend on them. Adding or removing an account
does start one, as renaming one does: the subject is the estate as its configuration
draws it (`little-sister-github` ADR-0014 §3).

**Its state is each account's outcome**, never one yes or no: `2 of 2` refused is a
credential problem and `1 of 3` one account's policy, which is why the check has always
counted them. It is spelled from the outcomes alone — sorted by name, as the subject is,
and each pair joined to the next by `/`, which a name cannot contain —

```
backup=expired/live=read
credentials=unusable            the credentials themselves did not open; no account was tried
```

— and the outcome after a pair's last `=` is one of `read`, `unreachable` and
`expired`, so a `;` or `=` inside a name cannot make two spellings meet, and a
spelling is a digest only past what a state may hold, or with a control character in a
name. **Never the error text**, so a reworded AWS message does not start a new spell.
The text stays in a record: the credentials' own failure in the estate's, and each
account's in that account's own reading, which its node is written from — one record for
all of them would grow by two clipped texts per refused account and pass 2 KB at the
second.

**The root declares `UNDEFINED` and keeps its sentence.** It declared `OK` beside the
accounts and regions in scope, and it grades nothing: an account that failed is red on
its own node and reaches the root by roll-up (ADR-0001 §2). Declared `OK`, the estate's
kept reading would have stood as `OK` on every run the credentials opened, every account
refused included; declared `UNDEFINED`, what stood there is what the run rolls up to,
which little-sister ADR-0087 decision 8 says of any root that declares `UNDEFINED`,
whatever it says. **So the estate's recorded code is the whole check's roll-up at its
latest poll, not a verdict on the credentials**: a spell's record keeps what stood at
its latest poll, which is the state rule's cost for every check, and an alarm that fires
in the middle of a spell recolors it. The state is what the estate's history is for.
The account nodes still declare `OK`: no reading is placed on them.

### 7. A line made from one reading carries it

`little-sister-github` ADR-0014 §7's rule: a line the grading writes out of **one**
reading carries that reading's record as its `data` and its subject as its own — an
alarm's, a function's, a pipeline's, a queue's own line, a name's line where one
instance carries the name, and a region that could not be read. A line written out of
several carries none: a name's line over several instances, every coverage line, and a
job name's line, which carries no record but names, as its `subject`, the one object
all of its runs are of. An account's refusal and the credentials' failure are prose on
their node, as they were, and carry nothing.

### 8. Free text is clipped once, and every field is bounded

An alarm's description, a queue's and a job's status reason, and an error AWS answered
with are clipped **once**, in the measuring half, to 300 characters and then to 600 of
the bytes the seam weighs a record in (little-sister ADR-0086 decision 7), and the line
is written from what was kept — the bounds `little-sister-github` and
`little-sister-wiz` keep. A name is bounded the same way: one AWS limits to ASCII is
never cut, and one written in an alphabet JSON escapes is cut past 600 bytes, and its
slug **can** move with it. `slug()` keeps only `[A-Za-z0-9._-]`, so the slug moves
where the cut takes one of those characters, or where the name keeps none and its slug
is a hash of the whole name: a name of `prod-` and 150 kanji keeps its slug when cut,
one of 150 kanji alone does not. A status or a state is held to 100 bytes; an
identifier is kept whole, or — past 100 bytes, or with a control character in it — as
`sha256:` and 32 hex digits of it, because a clipped identifier could meet another one
and a digest cannot, and one with a control character would not travel. AWS mints them
all short and plain, so these are bounds rather than rules anybody meets.

Measured against the default `record_limit` of 2048, every field at its bound in the
characters JSON escapes the most: the heaviest reading possible is an alarm with a
255-character name and a 1024-character description, at 1330 bytes; an account refused
with the longest error and renewal, 1280; a run with the longest queue name, job name
and reason, 1169.

**One record can still be refused**, and it is stated rather than engineered away: the
estate of so many accounts that their names alone pass `record_limit` — about a hundred,
with ordinary names. The record-size declaration this package has yet to make is what
will refuse that configuration at startup, by name, instead of at every run.

## Consequences

- **The package speaks check API epoch 3**, and beside an older library it refuses at
  startup, naming both epochs. Its floor rises to the release that speaks it.
- **The tree says what it said.** Measured rather than argued: the module as it was, on
  the library it was written for, and this one, on the library that speaks the epoch,
  run over one set of fixtures — a deployment's own configuration among them; every
  aspect; unreadable regions; refused, expired and renewed accounts; rules, sentences
  and shortening; aspects switched off; no credentials at all — agreed on every node,
  code, slug, line, report, card and log line, and differed in one place: the root's
  declared code (§6).
- **No configuration key changes, and only a long name's slug can move**: a name
  written in an alphabet JSON escapes that runs past 600 bytes — an alarm's, or an EC2
  `Name` tag — is cut, and its slug can move with it (§8), so a pin on that line can
  stop matching. Every other maintenance pin still matches.
- **At the top of its own page the check's node reads what its accounts roll up to** —
  red when an account is red — where it read OK whatever they said, because
  little-sister 0.3.18 heads the page of a node that declares nothing (§6) with what it
  rolls up to. Its card on the dashboard rolls up exactly as before.
- **With every account pinned, both read MAINTENANCE** where they read OK.
- **Lines carry what they read**, a few hundred bytes a line with ordinary names, in the
  tree and in every envelope a client polls; the field names in §1 are keys from now
  on, as a slug is, since a deployment's line template or grading will read them.
- **With `series_keep` set, a deployment keeps three histories** — each Batch job
  name's runs, each pipeline's executions and the estate's spells — and nothing else.
  Without it, the default, nothing is kept beyond the node.
- **Free text past 300 characters is shorter on its line than AWS wrote it**; an
  alarm's description, which may run to 1024, is the case that shows it.

## Alternatives considered

- **One reading per EC2 name.** Refused in §1: a fleet's launch times pass
  `record_limit`, and its line needs every one of them.
- **A subject on everything that can name an event or a state** — alarms by
  `StateTransitionedTimestamp`, queues by their state, functions by their newest
  invocation, accounts by their outcome. Refused in §3, for what `series_keep` being one
  number per check makes it cost.
- **Alarms alone as well.** Refused in §3 for the number, not the object.
- **AWS's account id in a subject.** Refused in §4: the private string ADR-0001 keeps
  off every slug and link, in exactly the places a subject goes.
- **`:` between a subject's parts**, as `little-sister-github`'s have it. An account
  name may hold one; nothing in a subject here may hold `/`.
- **One reading per job name**, carrying its newest finished run and what is in flight,
  named by the finished run — `little-sister-github`'s `actions` shape. Refused in §5:
  a run that started and finished between two polls would never be kept, and a run's
  flight would ride on another run's record.
- **A reading per execution in the page.** Refused in §5: a hundred re-read on every
  poll, for the pipeline run twice between two.
- **The estate as one yes or no**, or its state spelled from the error text. Refused in
  §6: the first cannot tell a credential problem from one account's policy, and the
  second starts a spell whenever AWS rewords a message.
- **Each account's error text in the estate's record.** Refused in §6: one record for
  every account passes 2 KB at the second refusal.
- **The regions in the estate's subject.** Refused in §6: what its history records does
  not depend on them.
- **Keeping the root's `OK`.** Refused in §6: the estate would stand as `OK` on every
  run the credentials opened.
- **Moving the scope sentence into the root's report**, so the root would be a silent
  container the library already rolled up. Refused: a visible change to the root's card,
  for a rule little-sister ADR-0087 decision 8 now states of any root that declares
  `UNDEFINED`.

