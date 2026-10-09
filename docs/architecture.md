# little-sister-aws — what is built

What this package **is**, in enough detail to work in it without opening a decision
record. The records say *why* each shape was chosen and what was rejected, and
[`decisions.md`](decisions.md) digests every one in [`adr/`](adr/); this file says what
is true now and what follows from it, and names the record beside each rule so you can
go and argue with it. The division is deliberate: you should not have to read the
records to write correct code here, and you should always read the governing one before
**changing** a shape rather than building within it.

Settings and their defaults are the [`README.md`](../README.md) — it ships, and it is
written for whoever installs this package. Nothing here repeats it.

How this package is *worked in* — the gate, the test rules, the docs discipline — is
the working rulebook at the repository root, which does not ship with it.

## 1. Three surfaces, and the line between them

This package publishes three things, and it is worth knowing which one you are in.
(The [`README.md`](../README.md) counts *four* parts because it splits the providers —
a consumer installs each with its own call. They are one surface here because they are
the same shape.)

1. **The `aws` check type** (`aws.py`, with `_rules.py` beneath it) — the product.
   Registered by importing `little_sister_aws`, whose `__init__` calls
   `require_api(3)` first, so a library that has moved past the check-authoring
   surface refuses at import rather than at the first run.
2. **The identity seam** (`identity.py`) — how a session is opened and an expired
   login renewed, usable with no check in the process.
3. **The application providers** (`secrets.py`, `keeper.py`, with `identities.py`
   reading the file both use) — the AWS secret resolvers, and the S3 keeper that
   carries little-sister's `var/state/`. **Neither registers on import**: a
   deployment calls `register_aws_secret_resolvers()` and `register_s3_keeper()` in
   its own import-before-app block, because which stores an installation reads its
   credentials from, and where it keeps its state, are decisions that should be
   readable at the place they are taken
   ([ADR-0002](adr/0002-aws-secret-references.md),
   [ADR-0004](adr/0004-the-s3-keeper.md)).

**The import that registers the type also declares what the SDK writes into a log** —
four noise caps on boto3's loggers (§6) — and that is all an import of this package
does: every surface passes `__init__`, and every one of them opens its sessions through
boto3 ([ADR-0010](adr/0010-the-package-declares-what-its-sdk-writes.md)).

The line that decides what may live here at all: **what is true of the extension
travels with the package; what names somebody's org, tenant, account, region or
threshold belongs in a deployment's YAML.** It is the test to apply to any new knob
([ADR-0001](adr/0001-the-aws-check-type.md) §4).

## 2. The modules

| | |
|---|---|
| `__init__.py` | the API epoch (`require_api(3)`), the noise caps declared for what boto3 writes (§6), and the import whose side effect registers the type |
| `aws.py` | the `aws` check type: configuration, the five aspects — each measured and then graded — and the tree it writes |
| `_rules.py` | the configuration vocabulary the aspects share — a graded threshold is a pair, a rule owns names ([ADR-0003](adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md)). Private on purpose: it is shared *between the aspects*, not with anybody outside |
| `identity.py` | the identity seam (§4) |
| `identities.py` | the `aws` configuration aspect — named identities, read from `config/aws.yaml`. It reads a **file**, which is exactly why it sits beside the seam and not in it |
| `secrets.py` | the `aws-sm://` and `aws-ssm://` resolvers, and one session per identity for the process |
| `keeper.py` | the S3 keeper, the `aws-keeper` aspect, and the one self-report contributor this package registers (§5) |

## 3. The check: account first, aspect second

One check type reads every service. Its tree is `<check path>` → one node per
**account**, where the check names several → one node per **aspect** beneath it:

```
/team/aws/live/cloudwatch      /team/aws/backup/cloudwatch
/team/aws/live/ec2             …
```

Account first because the account is what an operator acts on as a group — *staging
is down for the migration* is one maintenance pin against one node — and because an
account's node absorbs its own bad news: a role that cannot be assumed reddens that
account and leaves the others reporting
([ADR-0001](adr/0001-the-aws-check-type.md) §2).

**A level stands only where the configuration names several of it**
([ADR-0007](adr/0007-a-level-stands-only-where-the-configuration-names-several.md)).
Those reasons are reasons to tell accounts apart, so a check that names one account has
no account level: `grade()` hangs its aspects beneath the check's own node
(`_grade_alone`), which is then where the account's refusal is said, and which a pin on
the account is set on. What is counted is `len(self.accounts)` and
`len(self.regions_for(account))` — the configuration, never what AWS answered — so a
tree changes its shape when its configuration does and at no other time. Three things
follow in the code. An account's `title` and `about` label a node the one account does
not have, and the constructor says so once in the log. The check's `config_summary()`
says that account's regions and credentials, which its node's page would have. And the
sentence each aspect's `about` ends with names the node that silences the account — the
account's, or the check's own — so it is spelled at construction (`_pin_notes`).

**Three aspects hand back a node for every subject**, each named by what AWS calls it:
`lambda` for every function
([ADR-0006](adr/0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) §9),
`codepipeline` for every pipeline, and `batch` for every job queue and, beneath a
queue's, for every job name in it
([ADR-0009](adr/0009-a-job-name-and-a-pipeline-have-nodes.md)). A `shorten` rule's
result is the title of a function's node, a pipeline's and a job name's; a queue's has
none. An aspect whose subjects
are nodes has a **region's level** — a node for each region the account's configuration
names, where it names several (`_region_node`), and its subjects directly beneath it
where it names one; `_subjects_node` builds either shape for all three. A region's node
declines the density trade as its aspect does, and its flag rides the result where the
aspect's is declared (`show_when_quiet`, little-sister ADR-0063). **A queue is a level
in every Batch path**: AWS names it and no configuration does, so it does not come and
go, and its node declines the trade as a region's does. `cloudwatch` and `ec2` write a
line for each thing they read, have no levels beneath them, and print the region on a
line where the account reads several; a line on a subject's own node prints none.

```
/team/aws/lambda/collector                  one account, which reads one region
/team/aws/lambda/eu-west-1/collector        one account, which reads several
/team/aws/live/lambda/collector             several accounts; this one reads one region
/team/aws/live/lambda/eu-west-1/collector   several accounts; this one reads several
/team/aws/codepipeline/deploy               a pipeline, hung as a function is
/team/aws/batch/nightly/etl                 a job name, beneath its queue's node
/team/aws/batch/eu-west-1/nightly/etl       its queue beneath a region's, where several
```

- **The aspects** are `cloudwatch`, `ec2`, `lambda`, `codepipeline` and `batch`, run
  in that fixed order (`AwsCheck.ASPECTS`). A switched-off aspect emits **no node and
  makes no API call**, which is the half that matters to a role whose policy does not
  carry that service at all.
- **A slug is a stored key.** Every entry is slugged on values that must not drift,
  because a maintenance pin lives against `(path, slug)` — so changing a slug's shape
  is a breaking change even though nothing in the code says so. The region is in the
  slug whether or not it is printed, and a display-name rule never reaches it.
- **Grading is configured, never assumed.** A threshold is a `<name>_warn` /
  `<name>_error` pair with a `<name>_reason` beside it; `rules:` matches names and
  overrides the block's pairs for what it matches, first match wins, wholly; ignoring
  is a rule action. Nothing has a default: an installation that grades nothing gets an
  inventory, not an opinion. The comparison is **strictly above** —
  `max_per_name_warn: 1` warns at two. `_rules.py`'s docstring is the full vocabulary.
- **One console address, one coverage line.** Every link an entry carries is built
  by `_console_url(region, path, fragment)` — the six services differ by a path and a
  fragment and nothing else — and every aspect's *N in scope (regions)* line by
  `_scope_line`. The **wording is shared and the grading is not**: `cloudwatch` is the
  only aspect whose coverage line warns, because alarms going quiet is a symptom where
  an account may legitimately run no EC2, and it passes that verdict in rather than
  spelling the sentence again ([ADR-0003](adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md)
  is the same instinct applied to thresholds).
- **A link is the console's own address, or that address in what the deployment wraps
  it in** ([ADR-0013](adr/0013-a-console-link-opens-the-account-it-names.md)). The
  console's address names no account and opens in whichever one the browser is signed
  in to, so every link a line or a roster writes goes through
  `_link(account, address)`: the address as it is where neither the check nor the
  account sets `console_link`, and otherwise the account's template — its own, or the
  check's (`console_link_for`) — filled by `_wrapped`, `{url}` with the address and
  `{account_id}` with the account's id, each percent-encoded whole. **The id is the
  configuration's, and no call asks for it**: `Account.account_id` is the entry's
  `account_id` or the one its `role_arn` names, read where the accounts are parsed
  (`_parse_account_id`). What cannot be a link is refused when the check loads — a
  template that is not written as a URL is, or names a token but the two
  (`_parse_console_link`), and a template that names the id over an account that says
  none (`_hold_account_ids`). The id reaches the address of a link and nothing else: no
  path, slug, subject or record. Where an account's links open is a row of its card
  (`_links_summary`) — the account's, and the check's own where it names one account.
- **A rule that matches nothing goes to the log and never to a node.** It is a fact
  about the *configuration*, not about the estate, and coloring a card over a typo in
  a file sends somebody hunting through an account where nothing is wrong.
- **A check that could not look is not a check that graded badly.** An account's
  own reading says which of the two happened — `read`, `unreachable` or `expired` —
  rather than the grading inferring it from the shape of the result, and an account
  that could not be read is logged with the three facts that are useless apart: what
  was attempted, **who we actually were** (`caller_identity`), and what AWS said.
- **A node that holds subjects says when its children are complete** (little-sister
  ADR-0109): `lambda`, `codepipeline` or `batch`, or a region's node beneath one, where
  its listing was read whole — so a function, a pipeline or a queue that was deleted, or
  that the configuration now ignores, leaves with that run — and never where it could
  not be read, so the nodes stay. A queue's node says it of its job names in every run
  that lists it, read at its cap too: a name that fell behind `max_jobs` would otherwise
  stand stale beneath it (ADR-0009 §2). That is why `BATCH_STATUSES` is every status
  Batch has, each a `ListJobs` call: a name whose one job was in a status not asked for
  left the tree for that poll. A node whose children are configuration — the
  root's accounts or aspects, an aspect's regions — never says it: a run cannot find one
  of those gone.
- **A node this type does not name says so** (`dynamic=True`, little-sister ADR-0118): a
  function's, a pipeline's, a queue's and a job name's, named by AWS, and a region's and
  an account's, named by the configuration, read or not. `SUBNODES` and a deployment's
  `subnodes:` block are keyed by an aspect's name and reach every node of that name that
  does not say so: with it, a function called `batch` or an account called `ec2` is no
  aspect. Such a node's labels are the ones its own result carries — a `shorten` rule's
  title, an account's `title` and `about`, a region's and a queue's `show_when_quiet` —
  and a deployment labels it by path, in `nodes.yaml`. An aspect is this type's own
  name, and says nothing.

### A run is two halves

`measure()` reads and `grade(measurements, now)` builds the tree
([ADR-0005](adr/0005-a-run-is-its-readings-and-the-runs-keep-a-history.md),
little-sister ADR-0086); each aspect is a `_measure_<aspect>` beside a
`_grade_<aspect>`.

- **The grading reads the readings, the configuration and the `now` it is handed** —
  no session, no clock of its own, nothing the measuring half left on the check. A
  record is turned back into the values the lines were always written from
  (`_alarm_of`, `_instance_of`, …), so a line is written by the code that wrote it
  before the split.
- **One reading per thing a run read**: the estate first, each account's own, then each
  aspect's in the order it read them. A record names its `aspect`, its `kind`, and the
  `account` and `region` it is about; ADR-0005 §1 lists every kind's fields, and they
  are keys, like a slug. A field goes into `_reading` as a mapping of its own, so a
  record's `state` is never taken for the measurement's.
- **What a setting spares decides its half.** One that spares a request is read while
  measuring — `include_composite`, a `lambda` or `codepipeline` rule's `ignore`,
  `read_log_status`, `ignore_queue_patterns`, `max_jobs` — and one that only chooses
  what is said is the grading's, so an alarm an ignore list hides is still a reading.
  `batch`'s `ignore_name_patterns` spares the keeping: the measuring half leaves a
  hidden job name's runs out, so the name has no series (ADR-0009 §7), and the grading
  reads the list too, for a run that was read before the list named it. Which rules
  matched a name is noted while measuring: the log line about a rule that matched
  nothing is state kept between runs.
- **Four kinds keep a history, and no others**: a Batch job's run, named by its `jobId`;
  a pipeline's reading, by its execution's id or the state `never-run`; a Lambda
  function's run, by the start of its one-minute bucket; and the estate, by each
  account's outcome
  — `backup=expired/live=read`. A subject names an account by its configured `name`, the
  kind first and `/` between the parts — `batch/<account>/<region>/<queue>/<job name>`,
  `lambda/<account>/<region>/<function>` — so an account's name is a stored key twice
  over: every pin under it hangs off it, and so does every history. A subject keeps
  every part whatever shape the tree has, which is why a history survives a change of
  shape and a path does not.
- **A function's reading and its runs are two kinds of record**
  ([ADR-0006](adr/0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) §2). The
  `function` reading is the newest bucket of `Errors`, asked on every poll, and names no
  subject; a `run` is one bucket read in full — `invocations`, `errors`, `duration_ms` —
  and names the function. The function's line stands on the function's node, carries the
  function's reading and **names the function as its subject**, which is what makes the
  node stand for it (little-sister ADR-0106 decision 2); every run the poll read is said
  for the record alone, in `for_record` (`_run_entry`), `ERROR` where it counted an
  error.
- **A function's line holds an error it saw**
  ([ADR-0012](adr/0012-a-functions-line-holds-an-error-it-saw.md)). Beside the newest
  bucket, the `function` reading carries the newest **error** in the window the function
  was asked — `error.at`, the clean buckets since, and what the buckets inside the
  function's hold count together (`_errors_held`), from the same answer and at no
  request more — and the grading keeps the line at ERROR while that error is younger
  than `error_hold` (`_held`):
  *3 errors in the last 1h, the newest 23m ago · 2 clean runs since, the last 2m ago*.
  The hold is a duration, a key of the `lambda:` block and of its rules, an hour by
  default or the gate where that is shorter (`LambdaConfig.hold_for`); `0s` is no hold;
  written longer than the gate, or than the fifteen days of one-minute points, it is
  refused when the check loads (`_hold_within_gate`). The window a function is asked in
  reaches the hold as well as its series (`_window`). A run's own record and verdict are
  untouched.
- **A job name and a pipeline stand on nodes as a function does, and each run and each
  execution is said for the record**
  ([ADR-0009](adr/0009-a-job-name-and-a-pipeline-have-nodes.md)). A job name's line is
  written from every run of the name, carries none, names the job name as its subject
  and is marked `running` while a job of the name waits or runs,
  little-sister ADR-0042 decision 6 (`_job_node`); each run the poll read is said in
  `for_record` with a verdict of its own (`_job_run_entry`) — `OK` or `ERROR` once it
  has finished, and while it runs or waits `OK` until it is past `max_run_time` or
  `max_wait_time`, counted to the `now` the grading is handed. A pipeline's line carries
  the reading of the execution it is written from (`_pipeline_node`, `_line_index`): its
  newest, the one that started last, unless that one is in flight on a first run, and
  then the newest behind it with a verdict to keep — one neither in flight nor
  superseded, or one on a retry
  ([ADR-0014](adr/0014-a-pipelines-line-keeps-its-verdict-while-an-execution-is-in-flight.md)).
  Where `series_keep` is set, the measuring half reads behind the newest, out of the one
  page it asks for, every execution `self.kept(subject)` lacks or holds in a status
  outside `_EXECUTION_ENDED`, as many as the series keeps (`_lacking`) — and, once, the
  execution the history holds as the line's, or each of several that started at one
  instant (`_carried`), where the line is now written from another: what stood for it
  was the pipeline's line. The grading says of each what its status means in
  `state_map`, raised past `max_run_time` while it is in flight (`_execution_entry`),
  and of one that was `Superseded`, nothing.
- **A pipeline's line keeps its verdict while an execution is in flight**
  ([ADR-0014](adr/0014-a-pipelines-line-keeps-its-verdict-while-an-execution-is-in-flight.md)).
  `InProgress` passes (`DEFAULT_PIPELINE_STATE_MAP`), and an execution is in flight
  while its status is in `_EXECUTION_IN_FLIGHT`, `InProgress` or `Stopping`. Beside the
  newest, the measuring half hands the grading the execution the line is written from
  and every one in flight, out of the page it already reads (`_read_pipelines`). The
  line says that execution's verdict (`_verdict_of`) and what is in flight, a phrase for
  each status (`_in_flight_phrase`, `_by_status`), is the worse of them, and is marked
  `running` while anything is in flight (`_pipeline_entry`). `max_run_time` is a pair on
  `codepipeline` whose default, `DEFAULT_PIPELINE_RUN_TIME`, warns above thirty minutes
  — the one pair of the type with a default — held on the line against the oldest
  execution in flight in each status, and for the record against each. A retry is an
  execution in flight that the history holds `Failed` or `Stopped`
  (`_EXECUTION_RETRIED_FROM`) or holds on a retry already: where `series_keep` is set,
  the measuring half asks for one page of its action executions at every poll while it
  runs (`_retried`, `_actions`, `_ACTIONS_PAGE`), what the check kept deciding what it
  asks (little-sister ADR-0113 decision 3). The answer rides on the reading as a `Retry`
  — how many action executions failed and how many were abandoned, when the retry began,
  a refusal's words — and is kept in the record's `retry` block (`_pipeline_reading`,
  `_retry_of`). What it says the execution had ended in (`_ended_in`) is the verdict the
  line keeps (`_gives_verdict`, `_line_index`), the bound counts from the retry's start
  (`_begun`), and a refusal leaves the line as for a first run, warning with its words
  (`_in_flight_phrase`).
- **What a poll asks of CloudWatch is decided by what the check kept**
  (`_read_functions`, little-sister ADR-0113). `self.kept(subject)` is read before
  anything is asked, and only where `series_keep` is set: each function is asked
  `Errors` in the smallest of `_RUN_WINDOWS` that reaches its oldest kept run, and in
  the largest while its kept runs do not fill the series (`_window`), so how far back a
  busy function is asked follows how deep its series is; a second call asks
  `Invocations` and the `Maximum` of `Duration` of the functions that have a bucket to
  read in full and of no others, from the oldest of those buckets (`_read_runs`) — one
  their kept runs lack, or one whose kept run was observed before the bucket was as old
  as `_RUN_OVERLAP` (`_kept_runs`), and never one older than the series would keep — and
  a region's first poll in a process reads again what the series keeps. Every
  `get_metric_data` answer is followed by its token to its end, and a query CloudWatch
  says it did not answer — any status but `Complete` and `PartialData` — fails the
  region's read there (`_metric_data`, `_ANSWERED`), so that no empty result is taken
  for a function that never ran. With no series kept none of the history is asked, and
  the aspect reads the fifteen days as it did.
- **`duration_ms` is declared as a measure** (`MEASURES`, passed as `measure_defaults`;
  little-sister ADR-0092), so a function's runs are drawn to their duration with no key
  in a deployment's file. A record's number carries its unit in its name (ADR-0006 §6).
- **A Batch run and a pipeline's execution carry how long they took**
  ([ADR-0008](adr/0008-a-run-and-an-execution-say-how-long-they-took.md)): `wait_s` and
  `duration_s` on a `job` record, `duration_s` on a `pipeline` record, both declared in
  `MEASURES`. The measuring half computes them (`_seconds`, in `_run_reading` and
  `_pipeline_reading`): whole seconds, a null until both instants are known and where
  the second lies before the first, and an execution's only in the statuses of
  `_EXECUTION_ENDED`, counted to the `lastUpdateTime` its listing answers. The grading
  reads neither, and counts a job's ages to the instant it is handed. little-sister
  draws the plots on the node that stands for the subject (little-sister ADR-0106
  decisions 2 and 4): a job name's own node and a pipeline's own, and the check's own
  node for a subject whose node a run removed, until it returns.
- **The root grades nothing**: it declares `UNDEFINED` beside the sentence that says
  what is watched, so the estate's kept reading stands at what the run rolls up to — and
  where the check names one account it takes that account's refusal, and is then
  `ERROR`. A line made from one reading carries it as its `data` and its subject; one
  made from several carries none — a job name's line names its subject instead. Free
  text is clipped once, in the measuring half, by `_kept`.

## 4. The identity seam — `identity.py`

An `Identity` is one reading identity (profile, static keys, a role, where to assume
it); `open_session()` turns one into a boto3 session whose credentials have been
**proven** — assuming the role is that proof where there is a role, one
`sts:GetCallerIdentity` where there is only a profile. Two rules bind everything here
([ADR-0001](adr/0001-the-aws-check-type.md) §5):

- **No check, no file, no run.** Nothing in this module reads a configuration file,
  knows a check type's schema, or needs a check to exist. What a caller has to say it
  says in arguments — and where several packages read the same block, the *reader* is
  here and the words are the caller's: `parse_sso_block` and `parse_optional_text`
  answer with a value or with the **parts** of a refusal (`SsoBlockError`,
  `OptionalTextError`), so a check can pin itself where an identity file refuses a
  whole start. **This is the test to apply to anything proposed for this module.**
- **The login budget belongs to the caller.** `open_session()` **renews nothing**: a
  stale credential raises from here, and whether to answer that with `aws sso login`
  — and what the attempt may cost — is decided one call further out, because a check
  waiting on an engine worker and an application waiting inside its own import can
  afford very different numbers. `SsoLogins.renew()` therefore takes its timeout and
  cooldown as arguments and reads no configuration.

`SSO_LOGINS` is **one instance per process**, keyed by profile, with a per-profile
lock and a cooldown, and it is exported rather than reimplemented: two instances would
each hold half of the machine's history and open two browsers for one expiry.

**Every session is built on the process's one loader of service models**
([ADR-0011](adr/0011-one-loader-of-service-models-for-every-session.md)).
`new_session()` builds the botocore core session itself, registers `SERVICE_MODELS`'s
loader as its `data_loader` component and hands it to boto3, so a service's model —
its JSON and the endpoint ruleset beside it — is parsed for the first client of that
service in the process and never again, where a session of boto3's own parses it for
itself: three accounts, thirty runs, 424 MiB at the highest against 95. Every surface
reaches that builder: the check through its `_new_session` seam, the keeper and the
secret provider through `open_session`'s default factory, and a deployment's own
code through either. `SERVICE_MODELS` is process-wide for the reason `SSO_LOGINS` is —
two checks in one process must not parse twice — and holds one loader for each search
path a session resolves, built by botocore's own `create_loader`, so `AWS_DATA_PATH`
and a profile's `data_path` keep their meaning. Its search path takes a directory
once, because boto3 appends its own to the loader of every session it builds. **A
session is still a run's**: nothing of a run's sessions outlives it, the credentials
are proven at the top of each run, and the record says what would change that.

`is_credential_error()` is the reading every caller shares — *stale credentials* as
against *AWS said no* — and its docstring carries what it answers in each of the four
SSO states, measured. The three callers act on it differently on purpose: the check
renews on its own generous budget, the secret provider on the boot's short one, and
the keeper does not renew at all.

**The surface is released and frozen**: `Identity`, `base_session`, `assumed_session`,
`open_session`, `login_capability`, `login_problem`, `run_sso_login`, `SsoLogins`,
`SSO_LOGINS`, `parse_sso_block`, `parse_optional_text` and their error parts went out
with 0.1.1, `new_session` unlisted among them; `ServiceModels` and `SERVICE_MODELS`
with 0.1.6. A change to any of them is a version, not an edit.

Three changes to it have been asked for and answered, all by the S3 keeper having
been written against the released shape — a `region` on the identity, a refreshing
assumed session, and merging `login_problem()` with `SsoLogins.renew()`. The first
two are rejected in [ADR-0004](adr/0004-the-s3-keeper.md)'s alternatives, with the
trigger that would reopen each.

## 5. The providers

Both are registered by the deployment, never by an import, and both read
`config/aws.yaml` through `identities.py` for their named identities — a name becomes
a scheme (`aws-ssm-live://…`) so a reference never carries a credential, a region or a
role ([ADR-0002](adr/0002-aws-secret-references.md)).

- **Secrets** — `aws-sm://` reads Secrets Manager, `aws-ssm://` an SSM
  `SecureString`, either with `#/<JSON Pointer>` to select one string from a JSON
  secret. Clients are built when a secret is resolved, never at registration; one
  session per identity is opened and shared. A resolution happens once, at startup.
- **The keeper** — `register_s3_keeper()` fills little-sister's keeper seam with an
  S3 store for `var/state/`, configured by the `aws-keeper` aspect
  (`config/aws-keeper.yaml`: `bucket`, and optionally `prefix`, `identity`,
  `region`). No file means no keeper, which is what a second configuration root for a
  laptop wants. The client is bounded in seconds because the save runs on
  little-sister's scheduler tick, and the session is re-opened once on a credential
  error, because this is the one caller that holds a session for the life of the
  process ([ADR-0004](adr/0004-the-s3-keeper.md)).

  **One prefix, one instance, held by a lease** — one object under the prefix,
  `.little-sister-owner.json` (dropped from the listing, so the library never
  restores it as state). The holder re-writes it in `tick`, every interval, with
  `If-Match` on the version it last wrote — the heartbeat — and writes the state
  files behind it **unconditionally**: the heartbeat that landed is the condition,
  and a second guard on the same guarantee would only add a failure mode. An
  instance that does not hold it restores at startup (reading needs no lease),
  reads the lease in `tick`, sends nothing — `tick` answers `False` and the layer
  sends nothing — and takes it with S3's compare-and-swap the moment it is absent,
  lapsed or given up. Liveness is `Date` of the answer against `LastModified` of the
  object against the `ttl_seconds` in it (`lapse_after × interval`, written by the
  holder), every term S3's. A refused heartbeat, or `lapse_after` unanswered ones,
  demotes the holder before it writes; `close` gives the lease up with a `ttl` of
  zero. Nothing latches, and nothing needs a restart.

  **Authority follows the lease** (little-sister ADR-0077): the keeper remembers
  the ETag of every state file it loaded or saved and answers the seam's
  `changed_since_sync()` from one listing — the files whose ETag differs, and any it
  never saw — at the moment a tick makes this instance the holder; the library
  adopts them before the first save and keeps what they replaced as `.bak`. So a
  standby that takes over continues with the store's state, not its own, and the
  order is *take the lease, then let the layer adopt, then save*. Beside the lease
  live two more objects of the keeper's, never restored — everything under the
  prefix that starts with `.little-sister-` is dropped from the listing by one rule
  — a **presence file** per standby (`.little-sister-standby-<key>.json`, the mark
  percent-encoded, written every interval with the writer's own `ttl_seconds`; the
  holder lists once per interval, fetches a body once per new ETag, and deletes a
  file older than its ttl, writing the dead standby's *stood by* into the log) and
  the **instance log** (`.little-sister-instances.json`, one entry per transition,
  newest first, a hundred kept, the one object a non-holder writes and so the one
  with a conditional `PUT`; a standby re-reads it when the lease names a holder it
  did not know). **Two clocks**: every stamp in the store is the store's
  — S3's `Date`, or the host's clock moved by the offset measured on every answer —
  and a reader converts with its own offset before a store stamp meets a local one
  on a page; past 5 s the offset is a line, cleared under 3 s. **Two actions** on the
  keeper's child, through little-sister's ADR-0076 seam: *take over* (the lease
  written onto this instance regardless, with `how: operator` in it, so both pages
  read it as an operator's within one interval; the adoption follows at the next
  tick) and
  *release* (a heartbeat of zero; not taken back on this instance's own tick until
  another instance has held the lease). The actions run on a web thread, so the
  keeper's lease state is under a lock; a tick can wait behind a click for the
  client's bound, about fourteen seconds.

  The lines, by the library's loss principle, every one a claim with a code:
  `takeover` WARN for ten minutes after a takeover that adopted something,
  `standbys`, `standby`, `demoted`, `released`, `unreachable` and `clock` at WARN,
  `versioning` at WARN where the bucket versions (asked once, at the first call).
  What the keeper merely knows is the child's **report** (`S3Keeper.report()`,
  registered beside the lines; little-sister ADR-0076 decision 1): who holds the
  lease and on what terms, whom it was taken from and how, a takeover once its ten
  minutes are over, the instance log's last three, a versioning check that could
  not be made. Instants are stored ISO 8601 UTC and shown through `settings.yaml`
  (`little_sister.spans.local_time`). The mark is **little-sister's**
  (`little_sister.instance`, its ADR-0074): no two processes share one, one
  process's does not change while it runs, and it is compared for equality and
  never parsed here.

## 6. What binds this package from outside

- **little-sister is a floor, never a pin** — two plugins that each pinned an exact
  version could not be installed together. The floor names the release that promised
  the surface this package imports; `require_api()` catches the other direction.
- **Only the promised surface is imported** — little-sister `architecture.md` §11.
- **boto3 is the one dependency beyond the library**, argued in
  [ADR-0001](adr/0001-the-aws-check-type.md) §3: signing SigV4 by hand would be a
  signing implementation and its test suite, bought for one dependency saved.
- **What boto3 writes into a deployment's log is declared, and no level is set**
  ([ADR-0010](adr/0010-the-package-declares-what-its-sdk-writes.md)). `__init__.py`
  declares four rows through `little_sister.noise.cap` (little-sister `architecture.md`
  §11): `botocore` and `urllib3` at `INFO`, which takes the SDK's `DEBUG` lines — a
  session's token and what a call answered among them — and `botocore.credentials` and
  `botocore.tokens` at `WARNING`, which takes the sentence a new session says of
  itself. little-sister sets the rows where the application is imported; a level the
  deployment's startup file set stands against them, `LOG_LEVEL` has a logger back by
  name, and nothing the SDK says as a warning is taken out. No row reaches what a
  startup file reads from AWS before that import. A row names a logger that is
  botocore's to rename, so `tests/test_noise.py` has the SDK itself write each kind of
  line — in an interpreter of its own, which sends nothing to AWS — and holds the rows
  and the two tables that print them against it. A new use of the SDK that writes under
  another logger, a resource or a managed transfer, is measured and declared with it.
- **Every session stands on botocore's component seam**
  ([ADR-0011](adr/0011-one-loader-of-service-models-for-every-session.md)):
  `register_component('data_loader', …)` on the core session, which every client
  creation reads back with `get_component`. Public by name and held apart from
  botocore's internal components, and the seam boto3 itself stands on through its
  `botocore_session` argument — but not a page of botocore's published reference,
  which documents the loader and not the session. So `tests/test_service_models.py`
  holds it, with the SDK itself in the process: two sessions the check builds share
  one loader object, and a client from each is built on the one model that loader's
  cache holds. The day a botocore release stops reading the component, the second is
  the test that goes red, where the weight would otherwise come back without a word.
