# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2026-10-04

**Paths move, and the library goes first.** This release needs little-sister 0.3.19 (see
*Requires*). **Every Lambda function's line becomes a node of its own** beneath
`lambda`, **every pipeline's beneath `codepipeline`, and every Batch job name's beneath
a node for its queue**, inside `batch`; and **a check that names one account loses the
account's level** — `/<path>/live/ec2` becomes `/<path>/ec2`. A maintenance pin, a
`nodes.yaml` entry and a path a client watches are keyed by a path and do not follow: a
pin set on a path that moved stays listed as one whose node is no longer reported, until
it expires, and is set again on the new path; a `nodes.yaml` entry left at an old path
keeps a node there that nothing reports. A node's own status history — when it changed,
and how long each status stood — is keyed by its path as well, and a node that moved
starts it again. A check that names several accounts keeps every path it had: there it
is lines that move, onto the new nodes. No `type:` name, no configuration key and no
slug changes, and every history of runs is found again: it is keyed by the account's
name and the region, never by a path. The first three entries under *Changed* name each
move and the fourth what a hidden job name no longer keeps; one under *Fixed* asks for
an edit where a `subnodes:` block names an account, and another says what a poll now
asks of CloudWatch in requests.

### Added

- **A Lambda function's runs are kept, where the check keeps a series.** With
  `series_keep:` set, every one-minute bucket of CloudWatch's metric in which a function
  was invoked is one run of that function, a record of its own: `name`, `at` — the
  minute's start — `invocations`, `errors`, and `duration_ms`, the slowest invocation of
  the minute in whole milliseconds. A run failed where it counted an error, and keeps
  that verdict at any age. little-sister draws a function's runs on the function's node
  at the times they ran, and every function's on one time axis in `lambda`'s Series view
  ([ADR-0006](docs/adr/0006-a-functions-runs-are-kept-and-a-function-has-a-node.md)).
  The function's own reading is what it was, and its line says what it said, from the
  function's node (see *Changed*). With `series_keep` unset — the default — nothing is
  kept and no metric more is asked.
- **What a function's runs ask of CloudWatch**, which bills `GetMetricData` by the
  metric requested. Every poll asks `Errors` of every function, as before; `Invocations`
  and `Duration` are asked only of a function that has a run to read — a minute its kept
  runs lack, or one no poll has read since it was an hour old, because its numbers may
  grow until then. That is every poll of the hour after a run, and the one after it. A
  function that did not run is asked nothing more; one that runs once a day costs about
  8% more at a poll every minute, and a sixth more at a poll every hour; and one that
  runs at least hourly three times as much. The first poll after a start reads again
  every run the series keeps, once. How much CloudWatch answers follows `series_keep`: a
  function whose kept runs fill its series is asked no further back than they reach —
  the last hour, the last day, or the fifteen days — and every other function the
  fifteen days, as it was. So at `series_keep: 30`, and a poll more often than every
  half hour, a function invoked every minute answers an hour's points where it answered
  fifteen days'. A series of sixty runs or more reaches past such a function's hour, and
  it then answers a day's; one of 1,440 or more, the fifteen days' again. That is
  `Errors`: `Invocations` and `Duration` are asked from the oldest minute a poll is to
  read, ordinarily the last hour or so of such a function, and less where the series
  keeps less. Every figure here counts a metric once for each call that asks it: whether
  CloudWatch bills it again for each page of an answer that takes several (see *Fixed*)
  was not measured. The role needs nothing new: `cloudwatch:GetMetricData` was already
  on its list.
- **A function's runs weigh on little-sister's `series_limit`.** A check that keeps a
  series keeps one more for every function it reads, and nothing is configured for it:
  some 340 bytes a kept run as the library weighs it, 10 KB a function at
  `series_keep: 30`. The library's default ceiling of 8 MiB therefore holds the runs of
  some eight hundred functions, less what else the instance keeps, and of some hundred
  and twenty at `series_keep: 200`. little-sister measures it: a line on
  `/little-sister/engine` warns as soon as the configuration would need more than the
  ceiling — the moment to lower `series_keep` or to raise `series_limit` in
  `settings.yaml`, since past the ceiling the series written to longest ago is let go.
- **A run's duration is declared as a measure**: `duration_ms`, in `ms`, labeled
  *Duration*. A deployment that keeps a series draws a function's runs as stems to their
  duration with no key of its own. little-sister's `measures:` block disagrees per
  field: `duration_ms: null` leaves a run a tick, and naming `invocations` or `errors`
  draws a count.
- **A Batch run says how long it waited and ran, and a pipeline's execution how long it
  took.** A run's record gains `wait_s`, from when the job was created to when it
  started, and `duration_s`, from then to when it stopped; a pipeline's record gains
  `duration_s`, from its execution's start to the last change CodePipeline recorded of
  it. Each is whole seconds and stands once it is known: a run that is still running has
  waited and has no duration yet, and an execution has one once it is over. Both are
  declared as measures, in `s`, labeled *Duration* and *Wait*, so **a check that keeps a
  series shows plots it did not**: little-sister draws a job name's *Wait* and
  *Duration* on the job name's node and a pipeline's *Duration* on the pipeline's, once
  a run has the number — and on the check's own node for a job name or a pipeline that
  has no node at the moment. `wait_s: null` or `duration_s: null` in the `measures:`
  block takes a plot away, `duration_s` a run's and an execution's alike. A record an
  earlier release kept carries neither number and draws no stem: a run gains its two
  while Batch still lists it, seven days at least, and of the finished executions a
  pipeline's history holds, the newest alone. Nothing more is asked of AWS, and a record
  gains fields and loses none
  ([ADR-0008](docs/adr/0008-a-run-and-an-execution-say-how-long-they-took.md)).
- **A kept Batch run and a kept execution say how they stood.** Where the check keeps a
  series, every run a poll reads is marked on its job name's node, and listed on its
  History page with a sentence — `SUCCEEDED, waited 10m, ran 50m`: one that succeeded
  passes and one that failed fails, and one that still runs or waits passes until it is
  past `max_run_time` or `max_wait_time`, warns from then on, and takes its last mark
  from the poll that reads it finished. A kept run carried no mark before. A pipeline's
  newest execution is marked as the pipeline's line stands, and every execution read
  behind it by what its status means in `state_map`; the one that was the newest is read
  once more for that, by the poll that first finds a newer one — so a success that had
  grown past `max_age_warn` is a success again. One that a newer execution overtook,
  `Superseded`, is marked as neither: it did not fail, and it did not deploy. The map
  itself is what it was, and still grades the line of a pipeline whose newest execution
  was superseded. A finished execution an earlier release kept is not read again, except
  the newest of them: it keeps the sentence and the mark its pipeline's line had while
  it was the newest, until it leaves the series
  ([ADR-0009](docs/adr/0009-a-job-name-and-a-pipeline-have-nodes.md)).
- **A pipeline's history is whole from its first poll.** Where the check keeps a series,
  a poll reads more than a pipeline's newest execution: out of the one page of
  executions the aspect already asked for, every execution the pipeline's history lacks
  or holds unfinished, as many as `series_keep` and no more than the hundred a page
  holds. An execution that a newer one overtook while it ran is read to its end, where
  it kept the record of its last read, and so gains its `duration_s`. Nothing more is
  asked of AWS, and with `series_keep` unset the newest is read and nothing else.

### Changed

- **Every Lambda function has a node of its own.** `lambda` wrote a line for each
  function; it now hands back a node for each, named by what AWS calls the function,
  with the function's line on it — the same sentence under the same slug. A `shorten`
  rule gives the node its title and never reaches its path, and what a `subnodes:` block
  says for an aspect is not said of a function that carries the aspect's name. Where an
  account reads several regions, a function hangs beneath its region's node,
  `…/lambda/<region>/<function>`, and its line no longer prints the region; where it
  reads one, directly beneath `lambda`. `lambda` itself keeps the count of functions in
  scope. The line that says a region could not be read stays on `lambda` where its
  regions have no nodes; where they have, it stands on the region's node, under the slug
  it had. A region's node is not folded away on a dense dashboard, as `lambda`'s is not,
  unless `nodes.yaml` says so for its path. A function that is deleted, or that a rule
  now ignores, leaves the tree with the next run that lists its region whole. **A pin on
  a function's line stops matching**: set it again on the function's node. So does a pin
  on the line of a region that could not be read, where the account reads several: set
  it again on the region's node.
- **Every pipeline, every job queue and every job name has a node of its own.**
  `codepipeline` and `batch` wrote a line for each; they now hand back nodes, each named
  by what AWS calls it: a pipeline beneath `codepipeline`, a queue beneath `batch`, and
  a job name beneath its queue — `…/batch/<queue>/<job name>`, also where an account
  holds one queue. A pipeline's line and a job name's stand on their nodes, under the
  slugs they had, and say what they said less the region and the queue that stood in
  front (below); a queue's node carries the line the queue had where it had one —
  `INVALID`, `DISABLED`, no jobs found, or read only as far as `max_jobs` — and is quiet
  otherwise. A `shorten` rule gives a pipeline's and a job name's node its title and
  never reaches its path, and what a `subnodes:` block says for an aspect is not said of
  a node that carries the aspect's name. Where an account reads several regions, a
  pipeline and a queue hang beneath their region's node, as a function does. **No line
  on such a node prints its region, and a job name's no longer prints its queue**: the
  levels above it say both. `codepipeline` and `batch` keep their counts and their
  rosters, and the line of a region that could not be read where their regions have no
  nodes. A queue's node and a region's are not folded away on a dense dashboard, unless
  `nodes.yaml` says so for the path. A pipeline or a queue that is deleted, or that the
  configuration now ignores, leaves the tree with the next run that lists its region; a
  job name leaves with the first run in which Batch lists no run of it, about a week
  after its last one — and, in a queue read at `max_jobs`, as soon as its runs are no
  longer among those read, until it runs again. A name whose only listed run is being
  started — past `RUNNABLE`, not yet `RUNNING` — is not read, as it was not, and is
  without its node for that poll. What was kept of a job name or a pipeline whose node
  has left is listed on the check's History page and drawn on the check's own node until
  the node returns. **A pin on a pipeline's line, a queue's or a job name's stops
  matching**: set it again on the node — a queue's on the line its node carries, since a
  pin on a queue's node silences its job names as well. So does a pin on the line of a
  region that could not be read, where the account reads several: set it again on the
  region's node ([ADR-0009](docs/adr/0009-a-job-name-and-a-pipeline-have-nodes.md)).
- **A check that names one account has no account level.** A level stands in the tree
  only where the configuration names several of it
  ([ADR-0007](docs/adr/0007-a-level-stands-only-where-the-configuration-names-several.md)):
  such a check hangs its aspects beneath its own node, and says there what refused the
  account — the reason and the command that renews an expired login — on a node that is
  then `ERROR`. A pin on that node is the pin on the account. **Edit what names the old
  paths**: a pin, a `nodes.yaml` entry or a watched path under `/<path>/<account>/…` is
  now under `/<path>/…`, and an entry left in `nodes.yaml` at the old path is not passed
  over: it keeps a node there that nothing reports. The account's `title` and `about`
  labeled the node it no longer has, so they are read and not shown — the log says so
  once when the check is loaded — and belong in the check's own `title:` and `about:`.
  The check's card says the regions the account is read in and where its credentials
  come from, as the account's card did. A check that names several accounts keeps its
  accounts' level. The day a configuration names a second account, or an account a
  second region, every path beneath the new level moves the same way.
- **A job name `ignore_name_patterns` hides is no longer kept.** Its runs were read and,
  with `series_keep` set, kept, though no line showed them. They are left out where the
  runs are read now, so a hidden name has no node, no plots and no history. What was
  kept of one before stays, listed and drawn on the check's own node as it was, until
  the library lets it go.
- **The README names the page that lists this package's schemes.** little-sister's
  System page is two views now, and what an installation registered — the schemes
  this package claims among it, and its keeper — is on the one called *Installed*,
  `/system/installed` (little-sister ADR-0100); the README says so where it said
  `/system`. Prose only: no code moved.

### Fixed

- **An answer CloudWatch hands back in pages is read to its end.** `GetMetricData`
  answers in pages, each with a token for the next, and `lambda` read the first alone. A
  page ends where its part of the window *could* hold 100,800 data points — the metrics
  asked times the minutes in it — whatever they hold, so in a region of five functions
  or more the first page did not reach back the fifteen days that were asked: fourteen
  days with five functions, seventeen hours with a hundred. A function that last ran
  before that read as one with no data in fifteen days, was asked again at a coarser
  period, billed again, and its line named a coarser last run — or none, where it had
  last run before the first page of every period: `no recent invocations`, which warns
  where a run is expected. The token is followed now, whatever the check keeps, for at
  most 200 pages; past that the region says that it could not be read, and why. **A poll
  makes more requests for it**: three for every fourteen functions asked their fifteen
  days — and for one that did not run in them, which is asked a coarser period as well,
  or both, up to half a request in all. A region of a hundred functions that ran is 22
  requests where it was one for each period asked, and a region of five hundred 108.
  Where this was measured a page took a third of a second with a hundred functions and
  2.8 s with five hundred: some seven seconds a poll for the one region, and some five
  minutes for the other, which a check that polls every minute does not have. A poll
  that outgrows its `frequency:` is reported late on `/little-sister/engine`, and it is
  `frequency:` that gives it time: `timeout:` bounds nothing in this type. Whether
  CloudWatch bills a metric again for each page was not measured.
- **A metric CloudWatch could not answer is a region that could not be read.**
  `GetMetricData` answers each query of a call on its own, and may say of one that it
  could not — `InternalError`, `Forbidden` — while the call succeeds. `lambda` took that
  result's empty list of points for a function with no data: it asked again at the
  coarser periods, was billed again, and showed an older last run, or a function never
  invoked. It is a read that failed now. The region's line says which metric of which
  function CloudWatch did not answer, and what CloudWatch said; the functions' nodes
  stay as they were; and the next poll asks again.
- **An account called like an aspect shows its own title and `about`.** Where a check
  names several accounts, one called `ec2`, `lambda`, `batch`, `cloudwatch` or
  `codepipeline` was shown under that aspect's title and `about`, and stayed in view on
  a dense dashboard where the aspect does: little-sister applies what is declared for a
  name to every node of that name. An account's node now says that the configuration
  names it (little-sister ADR-0118), and shows the `title` and `about` the account was
  given, or none. **A `subnodes:` entry written under an account's own name no longer
  labels the account**: say it in the account's `title:` and `about:`, and a
  `show_when_quiet` for it under the account's path in `nodes.yaml`.
- **The README's policy section names `s3:DeleteObject` for the keeper.** *The IAM
  policy* listed the keeper's actions without it, where the keeper's own section, its
  record and the annotated example name it. A role written from that list cannot delete
  a presence file: it stays in the bucket once its standby is gone, the log warns of it
  every interval, and of a standby that died the instance log never says when it stood
  by. Prose only.
- **An account read with configured keys says so on its card.** The line that says where
  an account's credentials come from named the ambient credential chain where the check
  reads with a `secrets:` block's static keys.
- **A date that says `-0000` is read as the time in UTC it names.** The S3 keeper read an
  HTTP date with Python's own reader, which answers one that says `-0000` without a
  zone. The lease's instant was then stored on the machine's clock, the age of a lease
  measured against such a date was unknown — so the lease read as alive — and noting the
  store's clock raised. S3 says `GMT`, so it took a proxy, or a lease edited by hand. A
  date that names no zone at all is no instant: a line shows it as the text it is.
  (little-sister ADR-0120)

### Requires

- **little-sister 0.3.19 or newer.** The floor rises from 0.3.18 because that release is
  the first that lets a check read what it kept (little-sister ADR-0113), write a line
  for the record alone (little-sister ADR-0111), say that a node's children are complete
  (little-sister ADR-0109) and say that a run names a node (little-sister ADR-0118) —
  what a function's runs and the nodes of a function, a pipeline and a job name are
  built on. Against an older library the check fails at its first run. Upgrade the
  library first.

## [0.1.4] - 2026-09-27

**Upgrade the library first:** this release speaks little-sister's check API epoch 3 and
needs little-sister 0.3.18 (see *Requires*). Beyond that, nothing you configure moves —
no `type:` name, no configuration key — and every line says what it said, with three
exceptions an upgrade can meet. Free text past 300 characters is clipped, and a name so
long in an alphabet JSON escapes that it is cut moves its slug, so a pin on that line
can stop matching. The check's own page heads with what its accounts roll up to, so red
where an account is red, rather than OK (both in *Changed*). And a keeper registered
with a `KeeperConfig` built in code, whose `prefix` lacks the trailing `/` or begins
with one, keeps its objects under that prefix rather than beside it (see *Fixed*); a
keeper configured by `config/aws-keeper.yaml` keeps them where it did.

### Added

- **The `aws` check runs as two halves, on the library's third check API epoch.** Each
  run first reads AWS and hands back what it read, then says what that means from those
  readings alone, so the same verdict can be reached again later over a reading this
  process did not take
  ([ADR-0005](docs/adr/0005-a-run-is-its-readings-and-the-runs-keep-a-history.md),
  little-sister ADR-0086). A run reads one thing per reading: whether the credentials
  opened and what became of each account, then every alarm, instance, function,
  pipeline, job queue and Batch job run, and every region an aspect could not read —
  each record naming the aspect it was read for, its kind, and the account and region
  it is about. An ignore list that saves no request — alarm names, instance states, job
  names — is applied to what was read, so what it hides is still neither listed nor
  counted.
- **Every line made from one reading carries it**: the reading's record as the line's
  `data` — an alarm's line, a function's, a pipeline's, a queue's, an instance name's
  where one instance carries that name, and a region's that could not be read. A job
  name's line is made from all of that name's runs and carries none of them, and names
  the job it is about as its `subject`. The record shows on the node's own page and in
  the JSON a client reads — a few hundred bytes a line with ordinary names — and its
  field names are keys from now on, like a slug (ADR-0005 §1), so a line template or a
  grading map may be written against them. Every time in a record is under `at`,
  `started` or `ended`, the names little-sister reads as an instant: an instance's
  launch as `started`, a function's newest invocation as `at`, a job's creation as
  `created.at`.
- **`series_keep:` keeps three histories on this check.** The setting is little-sister's
  — `series_keep: 200` keeps the newest 200 records of each history, the oldest dropped
  first — and this check says what its histories are. Each Batch job name's runs, one
  record per run named by its `jobId`, so a run seen waiting, running and finished is
  one record, in its final state once it has finished; each pipeline's executions, one
  record per execution named by its id, and one for as long as a pipeline has never run;
  and the accounts' own, one record each time an account opens or stops opening. Alarms,
  instances, functions and queues keep none. A history names an account by its
  configured `name`, so renaming an account starts its histories again. The accounts'
  own history is of the accounts the configuration lists, so adding or removing an
  account starts that one again too. With `series_keep` unset — the default — nothing is
  kept beyond the node.

### Changed

- **`aws sso login` starts through little-sister's process function**
  (little-sister ADR-0089). The renewal runs the CLI in a process group of its own,
  with nothing on its stdin and bounded by the same `timeout:` as before, and a login
  still waiting for its person when the instance stops is ended with the instance —
  its line then says the stop ended it. What a login needs is unchanged: the CLI opens
  the browser and prints its URL itself. Nothing to configure.
- **The install snippet names versions instead of placeholders.** `little-sister==<the
  version you pin>` could not go stale and could not be checked either; the library
  line now carries the floor this release was built against and the package line the
  version being released, and the release refuses either if it drifts.
- **The check's own node declares no code of its own.** It declared OK beside the
  accounts and regions in scope, and now declares nothing, as a container. Its card on
  the dashboard rolls up to its accounts exactly as before. At the top of its own page
  it read OK whatever its accounts said; with little-sister 0.3.18 it reads what they
  roll up to, so red when an account is red. With every account pinned, both read
  MAINTENANCE where they read OK.
- **Free text is clipped once, at 300 characters.** An alarm's description, a queue's
  status reason and the error AWS answered with are shorter on their line than AWS
  wrote them when they ran past that; a name written in an alphabet JSON escapes is
  cut past 600 bytes, and its slug can move with it, so a pin on that line can stop
  matching. The line says exactly the text the record keeps.

### Fixed

- **A Lambda function's line no longer flips to *no log event* between polls.** The
  log read took an empty page from CloudWatch Logs for the end of the stream, but
  GetLogEvents may answer one while the stream still has events. It now follows the
  page's backward token until an event comes back or the stream ends, for at most three
  more pages, one call each on top of the usual two; past that the line says
  `newest log event not reached in 4 pages` rather than that there is none.
- **A `KeeperConfig` built in code keeps its state under its prefix.** The prefix was
  normalized — a leading `/` dropped, a trailing one added — only when it was read from
  `config/aws-keeper.yaml`, so `register_s3_keeper(config=KeeperConfig(bucket=…,
  prefix="state"))` wrote every object beside the prefix instead of under it:
  `state.little-sister-owner.json`, `stateevents.json`, in the bucket's root. The class
  now normalizes its own `prefix`, so that config keeps them at
  `state/.little-sister-owner.json` and `state/events.json`, as the file always did.
  **Which keys move:** only those of a keeper registered with a hand-built
  `KeeperConfig` whose non-empty `prefix` lacked the trailing `/` (or began with one).
  Such an installation starts from an empty prefix after the upgrade — its state
  restores empty and it takes a fresh lease — unless its objects are moved first, each
  from the key the prefix made as written to the one it makes normalized
  (`stateevents.json` to `state/events.json`, `/state/events.json` to
  `state/events.json`), the lease and the other `.little-sister-` objects included. A
  prefix written as `state/`, an empty one, and every configuration read from the file
  are unchanged.

### Requires

- **little-sister 0.3.18 or newer.** The floor rises from 0.3.15 because that release is
  the first to speak check API epoch 3, where a check type measures and then grades
  (little-sister ADR-0086), and the first with the process function the SSO login
  starts through (little-sister ADR-0089); this package says `require_api(3)`, and
  against an older library it refuses at import, naming both epochs. Upgrade the
  library first; no configuration changes with it.

## [0.1.3] - 2026-09-05

### Added

- **The S3 keeper: this instance's state, in a bucket.** little-sister keeps what
  a restart needs as files under `var/state/` — the maintenance pins, the event log
  behind every node's history — and takes a **keeper** to carry that directory
  somewhere durable. This is one, and with it a deployment redeployed onto a fresh
  machine — one terminated without a stop, too — comes up as the instance that
  stopped on the old one. Turn it on with a `config/aws-keeper.yaml` naming a
  `bucket` (plus optional `prefix`, `identity` from `config/aws.yaml`, the bucket's
  `region`, and `lapse_after`) and a `little_sister_aws.keeper.register_s3_keeper()`
  call in the same import-before-app block as the secret provider — **the keeper
  registers nothing on import**, as the provider does not. No file means no keeper,
  which is what a second configuration root for a laptop wants; a file that cannot
  be read refuses the start.

  **One prefix, one instance, held by a lease.** One object under the prefix says
  who may write there; the holder re-writes it every `state_interval` — a heartbeat
  — and writes the state files behind it, unconditionally. A second instance on the
  same prefix restores the state like any other (reading needs no lease), then
  **stands by**: it monitors, keeps its state locally, sends nothing, reads the lease
  once per interval, and takes over when the lease lapses (`lapse_after` heartbeats
  missed, three by default) or is given up. A holder whose heartbeat is refused, or
  whose bucket does not answer for `lapse_after` intervals, demotes itself before it
  writes anything and takes the lease back when it is free. Nothing latches and
  nothing needs a restart. Liveness is measured inside one S3 answer — `Date`
  against `LastModified` against the `ttl_seconds` the holder wrote — so no
  machine's clock enters it; a graceful stop gives the lease up with a heartbeat of
  zero, so the next standby takes it at once rather than waiting.

  **What it says, by the library's loss principle**, on its child
  `/little-sister/aws-keeper`, each line under its own slug there and every line a
  claim: `standby`, `demoted` and `unreachable` are WARN, because nothing is
  lost while they stand — a standby's pins are local, and its line says so. Nothing
  this keeper reports is ERROR. What the keeper merely knows — who holds the lease
  and on what terms, whom it was taken from and how, the last transitions — is the
  child's **report**, on its page and never on a card. Every instant in a line is shown in the
  `timezone` and `time_format` of `settings.yaml`, and every instant in the lease is
  ISO 8601 UTC.

  **Versioning off**, and checked once at startup: with a heartbeat a minute,
  versioning is tens of thousands of versions a month of a file nobody reads, so the
  keeper asks `GetBucketVersioning` on its first call and carries
  `versioning` at WARN while it finds versioning enabled — suspended is
  fine. That needs `s3:GetBucketVersioning`; without it the report says it could
  not ask. The identity wants `s3:GetObject`, `s3:PutObject` and
  `s3:DeleteObject` under the prefix and `s3:ListBucket` on the bucket — the lease
  and the keeper's other objects live under the same prefix, so they need no policy
  of their own ([ADR-0004](docs/adr/0004-the-s3-keeper.md)).

  **Authority follows the lease.** Whoever holds it wrote the truth up to the moment
  it lapsed, so a standby that takes over continues with the *store's* state and not
  its own: the keeper remembers the ETag of every file it loaded or saved and answers
  little-sister's `changed_since_sync()` at the takeover from one listing; the
  library adopts those files before the first save and keeps what they replaced as
  `.bak` on `/little-sister/state`. The order is *take the lease, then adopt, then
  save*. A takeover that changed something is `takeover` at WARN for ten
  minutes and in the report after; the successor of a holder that died before anybody wrote
  again takes over silently, with its own state. (little-sister ADR-0077; ADR-0004
  decision 4.)

  **Two actions on `/little-sister/aws-keeper`**, admin-only, through the library's
  action seam: **Take over** writes the lease onto this instance regardless of who
  holds it — the holder demotes itself at its next heartbeat, within one interval,
  and both pages say it was an operator's (the lease carries `how`); the adoption
  and the first save follow in the same click, since the library flushes the state
  layer after every action, and on the holder itself the action is that flush —
  and **Release** gives it up now, as a clean stop
  would. A released instance does not take the lease back on its own — a coin toss
  against the standby the button was pressed for — and carries `released`
  at WARN until another instance takes the lease, since nothing of its state reaches
  the store meanwhile; *take over* takes it back, and once another instance has held
  the lease it is an ordinary standby again. The manual unlock from a shell is gone
  with the reason for it.

  **The holder sees who stands by, and the prefix keeps a log.** A standby writes
  `.little-sister-standby-<key>.json` beside the lease every interval — its mark
  percent-encoded in the key, the mark and since when in the body, with its own
  `ttl_seconds` — and the holder lists once per interval, carrying
  `standbys` at WARN while anybody is there. Whoever lists deletes a
  presence file older than its ttl and writes that instance's *stood by* into
  `.little-sister-instances.json`: one entry per transition — took the lease (from
  whom, how), released it, stood by from when to when — the last hundred, newest
  first, never restored, the one object a non-holder writes and so the one with a
  conditional `PUT`; the report shows the last three. Everything under
  the prefix that starts with `.little-sister-` is the keeper's and is never offered
  to the library as a state file.

  **Two clocks.** Every stamp written into the bucket is on S3's clock, and every
  line shows a store stamp in host time: the offset between the two is measured on
  every answer from its `Date` header and the reader converts with its own. Past 5 s
  the offset is `clock` at WARN, cleared under 3 s.

  The client is bounded in seconds (2 s connect, 5 s read, two attempts) because
  both the save and the tick run on the scheduler tick, and the session is re-opened
  once on a credential error, which is what an assumed role's hour-long credentials
  need from a process that runs for weeks.

- **`docs/architecture.md` ships with the package** — what is built, the three
  surfaces and the rules that bind them, with the record named beside each. It is
  written for somebody working on this package rather than installing it, and it is
  here because the records already ship and a description of the seams is less than
  their arguments.

### Requires

- **little-sister >= 0.3.15**, up from 0.3.13: the release that carries the keeper
  seam (`little_sister.keeper`) this version fills — with the `tick` and `close` the
  lease needs, which that release's seam grew for it, and the `changed_since_sync()`
  the takeover answers (its ADR-0077) — the action seam the two buttons go through
  (its ADR-0076), and `little_sister.spans.local_time`, which the keeper's lines
  render instants with.
  An *added* name is the mismatch a check API epoch cannot catch — an epoch says
  what was removed — so the floor is what keeps an older library from meeting
  `register_s3_keeper()` with an `ImportError`. The check API epoch itself did not
  move: a keeper is not a check.

## [0.1.2] - 2026-08-29

### Removed

- **The `ec2` aspect's `max_per_name` and `max_age` keys**, and the thresholds
  they defaulted to. Each was one number that could produce one severity — a
  count that could only warn, an age that could only burn — and each judged every
  instance name in every account by the same figure. Replace them with the pairs
  below; a configuration still using the old spellings is refused at startup, by
  name, like any unknown key.

  ```yaml
  ec2:
    max_per_name: 1      # was: warn at two boxes under one name
    max_age: 14d         # was: burn at a fortnight
  ```

  becomes

  ```yaml
  ec2:
    max_per_name_warn: 1
    max_age_error: 14d
  ```

- **The `ec2` aspect's `fleet_size` and `fleet_max_age`.** A group larger than
  `fleet_size` used to be read as a deliberate fleet and judged by a shorter
  clock — a rule that keyed on the *reading* rather than on the name, and could
  therefore only ever be one rule for every estate. A fleet is now a name a rule
  matches, and the clock is that rule's:

  ```yaml
  ec2:
    rules:
      - name: load tests
        prefixes: [loadtest-]
        max_per_name_warn: 15     # many is fine...
        max_age_error: 4h         # ...but not for hours
  ```

  A large group under a name no rule mentions is judged by the block's own
  levels, which is what they are for.

- **The `ec2` aspect's `ignore_name_patterns`.** Ignoring is a rule action now:

  ```yaml
  ec2:
    rules:
      - name: scratch
        prefixes: [tmp-, scratch-]
        ignore: true
  ```

  Three things come with the move: one matcher vocabulary for the whole aspect,
  ordering (a rule *above* an ignore rule excepts names from it — "ignore `tmp-`
  except `tmp-db`", which a flat list could not say), and the same non-listing,
  non-counting behavior as before. `cloudwatch` and `batch` keep their
  `ignore_name_patterns` for now; `codepipeline` and `lambda` lose theirs below.

- **The `codepipeline` aspect's `max_age`, its default month, and its
  `ignore_name_patterns`.** The staleness clock is a pair now
  (`max_age_warn` / `max_age_error`, with `max_age_reason`) and has no default,
  because how long a success stays evidence that a pipeline works depends on how
  often it is meant to run; ignoring is a rule action, as in `ec2`:

  ```yaml
  codepipeline:
    max_age_warn: 31d
    max_age_error: 90d
    rules:
      - name: nightly builds
        prefixes: [nightly-]
        max_age_warn: 36h        # it runs every night
      - name: release pipelines
        prefixes: [release-]
        max_age: null            # runs when we release; never stale
      - name: sandboxes
        prefixes: [sandbox-]
        ignore: true
  ```

- **The `lambda` aspect's `ignore:` list of whole function names.** Ignoring is a
  rule action here too, and a rule matches by exact `names:`, by `prefixes:` or by
  `regexes:` rather than by whole names being the only spelling:

  ```yaml
  lambda:
    rules:
      - name: retired handlers
        prefixes: [old-]
        ignore: true
  ```

- **The built-in EC2 thresholds.** This aspect now grades **nothing** until your
  configuration says what to grade: a level you do not write is not compared
  against, and there is no default fortnight and no default "one box per name".
  What a name may carry and how long a box may run are facts about your estate,
  and this package has never seen it. An `ec2:` block that sets no level is legal
  and gives you the inventory — every name, its count and the age of its oldest
  box, uncolored — and says so once in the log, so a silent aspect is never a
  silent surprise. **If you were relying on the old defaults, write them down.**

### Added

- **A named identity may say only which region its store is in.** `aws.yaml` used
  to refuse an entry with no `profile:` and no `role_arn:` as *the ambient chain
  under another name*; it is now legal, and it means *this store, in this region,
  read as whatever this host is already authorized as* — an instance role, a task
  role, keys in the environment. It is not the plain schemes wearing a name: those
  read the store the environment implies, and this one names the store whatever
  the environment implies (ADR-0002 §9 — a Parameter Store name in another region
  is another parameter).

  ```yaml
  # the developer's configuration root
  live:
    profile: primary-admin
    region: eu-central-1

  # the cloud root — same name, so every committed reference is identical
  live:
    region: eu-central-1
  ```

  This is what a deployment that runs on a laptop *and* in a cloud account needs:
  only the `aws.yaml` differs between the two, never a reference. An entry that
  names nothing at all — no profile, no role, no region — is still refused, and the
  refusal now says both ways out rather than only what is wrong (ADR-0002 §6).

- **Two levels on every EC2 threshold**, so both readings can warn *and* burn:
  `max_per_name_warn` / `max_per_name_error` and `max_age_warn` /
  `max_age_error`. The comparison is *more than*, so `max_per_name_warn: 1` warns
  at two — and `0` is how you ask to hear about any instance under a name at all,
  which is what an estate writes for the names it has not classified. An error
  level must be above its warn level, or the configuration is refused
  ([ADR-0003](docs/adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md)).

- **A sentence per judgment: `max_per_name_reason` and `max_age_reason`.** A
  number decides the color and never says what is wrong — two boxes under one
  name is "there should be only one of these" for one name and "a second one
  cannot have attached the block device" for another. The sentence rides on the
  line when that judgment fires, and a line that trips both carries both:
  `jenkins: 2 (20d) — Too many.; Too old.`

- **`rules:` on the `ec2` aspect — a set of names with its own limits.** A rule
  owns names by exact value (`names:`), by `prefixes:`, by `regexes:` (case
  insensitive, matched anywhere unless you anchor them), or `unnamed: true` for
  the instances with no `Name` tag. It carries the same level and reason keys as
  the block above it.

  The **first** rule that matches a name decides, and only that one — so an
  exception is a rule written above the rule it excepts, and there is no negation
  key. A judgment a rule does not mention is inherited from the block **whole**:
  write either level of a pair and the rule owns that pair, which is what lets a
  fleet rule raise a warning level in one line without restating an error level
  it does not want. A rule's limits are applied to **each** matching name on its
  own, never to their sum: two load tests carrying ten and twelve boxes are two
  lines against the rule's levels, not twenty-two.

  Two more things a rule can say. `ignore: true` drops the names it matches.
  `max_age: null` (or `max_per_name: null`) switches a whole judgment off for
  them and inherits nothing — which is how an instance you keep deliberately old
  is written: there is no infinity to compare against, only a comparison that
  does not happen, and the line still shows the age, uncolored.

- **`rules:` on the `codepipeline` aspect too**, the same vocabulary keyed on the
  pipeline name: `names:` / `prefixes:` / `regexes:`, first match wins, inherit by
  pair, `ignore: true`, and a `null` pair for a pipeline that is never stale. A
  pipeline's staleness can now reach **error** as well as warning, where it could
  only ever warn however long ago the last release was. Only a success is judged
  stale — a failure is already the finding. (`unnamed:` is EC2's alone: a pipeline
  is named by existing, so a rule asking for the unnamed group there would be one
  that can never match, and it is refused.)

- **`rules:` on the `lambda` aspect, and two sentences.** What a rule overrides
  there is not a graded pair: `error_max_age` is a **gate** — it decides whether
  the newest error is graded at all, since past it CloudWatch has condensed the
  count into a bucket with the successful runs around it — and "warn at seven
  days, error at fourteen" is not a sentence about a gate. So a rule sets
  `error_max_age`, `read_log_status` (two API calls per function, and the ones
  worth paying for are not always the whole account), and `expect_invocations`.

  That last one is new and answers a standing annoyance: a function nobody has
  invoked warns, which is right for a scheduled job and wrong for a handler that
  runs when somebody calls it. `expect_invocations: false`, on the block or on a
  rule, says silence is fine there. `error_reason` and `silent_reason` are the
  sentences those two judgments say when they fire.

  `error_max_age` **keeps its default** where the EC2 and CodePipeline clocks lost
  theirs: where the CloudWatch window ends is a fact about CloudWatch, not an
  opinion about your estate.

- **A rule's name is the fallback sentence.** A judgment that fires with no
  `_reason` of its own says the rule's name instead — `jenkins-agent-1: 4 (2h) —
  the build agents` — which at least says where in the config the decision was
  made. A rule therefore needs a `name:`, and it is also what refusals and the
  log line below call it.

### Changed

- **An EC2 line is colored by the worse of its two judgments**, rather than by
  age outranking count. The outcome is the same wherever the old rules applied —
  an age past its error level still beats a duplicate warning — and it is now
  what the two levels mean rather than a special case.

- **An EC2 line shows the ages of a group as a range**, where it showed only the
  oldest. The shape follows what the ages *print as* rather than how many boxes
  there are: boxes that all read the same are one value (`jenkins: 4 (16h)`),
  exactly two distinct readings are both shown (`jenkins: 2 (15h 3m, 15h 4m)` —
  two values are not an interval), and three or more become youngest to oldest
  (`web: 4 (1m - 16h)`). A name being rolled and a name started once and left now
  read differently, where before both said `(16h)`.

  Nothing to configure, and the grading is unchanged: the **oldest** member still
  decides the age judgment, because an instance is patched by being replaced. The
  roster in the node's report shows the same range as the line.

- **The configuration card shows what an installation actually grades on.** With
  no defaults left, a check's own configuration report is the only place to read
  that: each judgment is one entry carrying its levels and the sentence it says,
  and the rules are a nested list in the order they are consulted — each shown
  **effective**, so a rule that names one level and inherits the rest displays
  what it will really do.

- **An `ec2:` rule that matches no instance name is reported in the log**, at
  `INFO`, naming the rules — and only when that set changes, this run's first
  included. It is never reported on a node: a regex with a typo in it is a fact
  about your configuration, and coloring a card over it would send somebody
  hunting through an account where nothing is wrong.

## [0.1.1] - 2026-08-23

### Added

- **`little_sister_aws.identity`** — how a session is opened, as this package's
  second public surface. An `Identity` (profile, static keys, `role_arn`,
  `role_session_name`, `sts_region`) with `base_session()`, `assumed_session()` and
  `open_session()`, which proves the credentials before it returns; and beside them
  the SSO login that answers an expired one: `login_capability()`, `login_problem()`,
  `run_sso_login()`, `SsoLogins` and the one-per-process `SSO_LOGINS`. It reads no
  check configuration and needs no check, so a deployment can open a session before
  any check exists — resolving an AWS-backed secret reference, for instance
  ([ADR-0001](docs/adr/0001-the-aws-check-type.md)).

- **`parse_sso_block` and `SsoBlockError`, beside the `SsoConfig` they produce:
  the `sso:` block's one reader**, on the identity surface. The differences
  between its callers are arguments — `default=` carries the caller's own budget
  for an absent block or key, `allow_cooldown=False` refuses that key outright
  for a caller that reads its secrets once at startup — and a refusal leaves as
  **parts** (which key, what was wrong with it, what would have been accepted),
  never as a sentence: each caller words its own refusals and raises its own
  type ([ADR-0001](docs/adr/0001-the-aws-check-type.md) §6).

- **`parse_optional_text` and `OptionalTextError`** — the same bargain for the
  other thing every caller of the surface reads: one optional string field (a
  profile, a role, a session name, a region). Absent means the caller's default;
  a key written and left empty is refused as the typo it is, never read as
  "unset"; and a value that is not text is refused rather than stringified. The
  refusals leave as parts, worded and typed at the call sites.

- **The AWS secret provider** — this package now carries the `aws-sm://` and
  `aws-ssm://` secret references (`little_sister_aws.secrets`) and the named
  reading identities behind them (`little_sister_aws.identities`, the `aws`
  configuration aspect: `config/aws.yaml`, whose shape is this package's and
  whose contents are each deployment's). Secrets Manager must return a non-empty
  `SecretString`, Parameter Store a `SecureString`; either address may select one
  field of a JSON document with `#/<JSON Pointer>`; every identity declared
  becomes a scheme pair of its own (`aws-ssm-<name>://…`), and an identity may
  renew its own expired SSO login while the application starts, on the boot's
  budget. **Nothing registers on import**: a deployment installs the provider
  with one explicit call, `register_aws_secret_resolvers()`, in its
  import-before-app slot
  ([ADR-0002](docs/adr/0002-aws-secret-references.md), traveled here with the
  code and closed with the move).

### Changed

- **An account this check could not look at now says so in the log**, with the
  one fact a refusal does not always carry: **who we actually were**. A check
  that ran and graded badly is reporting, and reports on its node; a check that
  could not *look* is a different event, and until now it made no sound at all —
  the engine's own line says the check completed, because it did, so a run whose
  every account was refused reached a log file as `OK` with the refusal sitting
  only on a card somebody had to go and open. Each account that could not be
  opened logs one `ERROR` naming what was attempted (the role), which credentials
  were used, **the account and ARN those credentials proved to be**, and what AWS
  said in full; the run then says how many of how many — `2 of 2` is the shape of
  a credential problem, `1 of 3` the shape of one account's policy. The identity
  is proven with one `sts:GetCallerIdentity` **on the failure path only**, so a
  healthy run pays nothing for it. A check can say which profile it *meant* to
  use; what the ambient chain resolves to is decided by the machine, and being
  wrong about that is otherwise invisible — `role cannot be assumed` is the first
  anybody hears of it. `caller_identity()` joins this package's identity surface
  for callers that need the same answer.

- **The package summary names all three of its surfaces.** The `description` in
  `pyproject.toml` — the one line an index shows beside the name — said only
  "AWS check type", which was the whole package when it was extracted and has not
  been since it absorbed the secret provider and the identity seam. Somebody
  looking for either of those was being told to keep looking — by the index, by the
  README's own opening sentence, and by the docstring on the package they had just
  installed, all three of which now name all three surfaces. The README grew the
  two chapters that summary now promises: what the aspect leaves already say
  (their titles, their `about` text and which of them stay visible while quiet, all
  shipped by the type rather than configured), and the fact that little-sister
  attributes every scheme this package's registration claims **to this package**,
  visibly on `/system`, refusing a second package's claim on the same name
  (little-sister ADR-0064). Metadata only, plus prose: no code moved.

- **The four roster aspects now declare that their quiet lines are still worth
  reading**, so a deployment does not. `ec2`, `lambda`, `batch` and `codepipeline`
  name everything they found on every run, whether or not anything is wrong, which
  is a list read *because* nothing is — and a dense dashboard folds a quiet leaf
  into a chip. The type says so once now (`show_when_quiet` beside each aspect's
  label, little-sister ADR-0063), where it used to take an entry per aspect **per
  account** in every installation's `config/nodes.yaml`; an account added later
  inherits it instead of quietly missing it. **`cloudwatch` deliberately does not
  declare it**: `show_healthy: false` is the opposite claim about its own lines,
  made where it belongs. A deployment that disagrees writes
  `show_when_quiet: false` in its own `subnodes:` block, or per node path in
  `nodes.yaml`; both still win. Needs little-sister **0.3.13**, the release that
  reads the flag out of a type's declaration — which is the floor the entry below
  raises to anyway.

- **Breaking: this package speaks check API epoch 2 and needs `little-sister >=
  0.3.13`.** little-sister now reads the whole `subnodes:` block itself, for every check
  type, and a type only **declares** what it ships (little-sister ADR-0025). So this check no
  longer parses that block, no longer layers its own defaults, and no longer hands a
  `title` / `about` back on an aspect result: it declares `SUBNODES` and the
  `{pin_note}` token, and the library resolves and applies them. Nothing changes in
  **what a deployment writes** — the same `subnodes:` block, with the same `{default}`
  extension — and a deployment now gets that block for every installed branch type
  rather than for the ones that chose to read it. Installed beside an older library this
  package refuses at startup, naming both epochs.

- **The aspect text no longer names the account or its regions.** A label is
  resolved once per subnode *name*, and every account's `cloudwatch` leaf is named
  `cloudwatch` — one text, all accounts — so the five built-in `about`s now say
  *this account* instead of naming one. Nothing is lost: the leaf hangs from the
  account's own node, its `description` still reads *CloudWatch alarms in backup*,
  and that account node's card still lists the regions this check reads for it. A
  deployment that had written its own `subnodes:` text is unaffected.

- **The credentials line names the profile the ambient chain was given.** Where no
  `profile:` is configured, the check's card and each account's line now read
  `ambient credential chain (AWS_PROFILE=…)` when the environment names one. An
  `AWS_PROFILE` exported for something else entirely is otherwise deciding which
  identity assumes these roles, and `role cannot be assumed` is the first anybody
  hears of it.

- The `aws` check composes an `Identity` per account and delegates to that seam.
  Its configuration, its per-account layering of `profile:` and `role_arn:`, its
  one `sts:GetCallerIdentity` per profile-only account and its renew-once-and-retry
  policy are unchanged.

- The check's `sso:` refusals are rendered from the shared reader's parts, in
  sentences of the check's own. Two of them shifted slightly (`aws 'sso'.login …`
  where it said `aws 'sso.login' …`), and a malformed `sso.timeout`/`sso.cooldown`
  now names its key instead of surfacing `parse_duration`'s bare words.

- **A `profile:` that is not text is refused** instead of stringified, at the
  check and on an account: `profile: 123` used to be read as the profile name
  `"123"` and handed to boto3 and `aws sso login`. A line that lost its quoting
  is the same typo family as a key written and left empty, and it now draws a
  refusal naming the key (`… must be text, got int`).

### Fixed

- **A `profile:` key written and left empty is refused** instead of read as *no
  profile*, at the check and on an account. Silently, it meant falling back to
  whatever `AWS_PROFILE` happened to say and then failing to assume a role that was
  never trusted from there — with a card that said nothing was configured.

### Requires

- **`little-sister >= 0.3.13`** — the release that speaks check API epoch 2, which
  this package speaks since this version (the entry under *Changed* says what moved).

## [0.1.0] - 2026-08-16

### Added

- The **`aws`** check type: one node per account, one node per aspect beneath it.
- Five aspects: **`cloudwatch`** (metric and composite alarms), **`ec2`**
  (instances grouped by their `Name` tag, graded on count and age), **`lambda`**
  (the `Errors` metric and the newest log event's status word, on one line),
  **`codepipeline`** (each pipeline's most recent execution) and **`batch`** (job
  queues, and one line per job name carrying its finished, running and runnable
  readings).
- Per-aspect **`enabled:`** — a switched-off aspect emits no node and makes no API
  call; every aspect off is refused at startup.
- Assumed-role sessions per account, with an optional `~/.aws/config` `profile:`
  that composes with `role_arn`, and an `sso:` block that can renew an expired SSO
  login where doing so can work — bounded by a timeout and a per-profile cooldown.
