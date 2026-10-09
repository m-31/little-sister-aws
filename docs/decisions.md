# little-sister-aws — Decisions

> One digest per decision: the heading, the answer in a few lines, and a link to the
> Architecture Decision Record in [`adr/`](adr/) for the context, the alternatives and
> the date. The digest says **what** was decided; the record says why, and holds the
> history. A bare number here is this repository's; a reference to one of
> little-sister's is always written `little-sister ADR-00NN`, because the two numbering
> spaces overlap. What the decisions add up to, as one description of what is built, is
> [`architecture.md`](architecture.md).
>
> Every decision here is in force: a record that is superseded or withdrawn leaves, and
> its digest with it.

---

### ADR-0001 — The `aws` check type: account nodes, aspect leaves, and boto3

One type, `aws`, reads every service as an aspect, beneath a node per account where a
check names several: the account is what an operator pins, and what absorbs its own
refusal. boto3 rather than signing by hand, and a package rather than a deployment's
code. `profile:` composes with `role_arn` and is layered on an account as `regions:` is;
an expired SSO login is renewed on the check's own bounded budget. The identity seam,
`little_sister_aws.identity`, is a public surface that reads no file and knows no check
type, and the secret provider lives in this package too.
→ [record](adr/0001-the-aws-check-type.md)

### ADR-0002 — AWS secret references: strict stores, JSON Pointer selection, identity schemes

`aws-sm://` reads a non-empty `SecretString` and `aws-ssm://` a `SecureString`, and
either may select one string from a JSON document with `#/<JSON Pointer>`. A reference
names a secret and never how it is read: a named identity of `config/aws.yaml` becomes a
scheme of its own, `aws-sm-<name>://`, because no separator survives both stores, and an
identity nobody declared is a scheme nobody registered. A deployment registers the
resolvers by an explicit call — nothing registers on import — and a failure discloses
an address, never a value. → [record](adr/0002-aws-secret-references.md)

### ADR-0003 — A graded threshold is a pair, and a rule owns names

A graded threshold is a `<name>_warn` / `<name>_error` pair with a `<name>_reason`
beside it, compared strictly above; a level not written is not graded, no pair has a
default but `codepipeline`'s `max_run_time` (ADR-0014), and the package ships no
sentences of its own. `rules:` matches names — `names:`, `prefixes:`, `regexes:` — and
the first that matches decides, a pair it does not write inherited whole; ignoring is a
rule action. A rule that matches nothing is a line in the log, never a node, and a
group's ages are a range whose oldest grades.
→ [record](adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md)

### ADR-0004 — The S3 keeper: one prefix, one lease, a heartbeat at S3's clock

`register_s3_keeper()` keeps the instance's `var/state/` in a bucket, configured by an
aspect of its own, `config/aws-keeper.yaml`; no file means no keeper. One prefix has one
holder: a lease rewritten every interval with `If-Match`, and taken by a conditional
write once it is absent, lapsed or given up — liveness measured inside one S3 answer,
every stamp the store's. An instance that does not hold it stands by, says so, and
takes over with the store's state; nothing latches. The client is bounded in seconds,
and the bucket is a mirror of bounded memory, never a history.
→ [record](adr/0004-the-s3-keeper.md)

### ADR-0005 — A run is its readings, and only the runs and the estate keep a history

`measure()` hands back one reading per thing a run read — the estate first, each
account's own, then each aspect's — and `grade()` builds the tree from those readings,
the configuration and the clock it is handed; a setting is read in the half whose work
it spares. A history is kept of four kinds only: a Batch job's runs, a pipeline's
executions, a function's runs, and the estate, by each account's outcome. A subject
names an account by its configured name, never by AWS's id, and the root grades nothing.
→ [record](adr/0005-a-run-is-its-readings-and-the-runs-keep-a-history.md)

### ADR-0006 — A function's runs are kept, and a function has a node

A function's run is a one-minute bucket of CloudWatch's metric in which it was invoked,
kept under the function: `invocations`, `errors` and `duration_ms`, declared as a
measure. The function's reading stays one reading, and its line holds an error it saw
for `error_hold` (ADR-0012). A function is asked in the smallest of three windows — an
hour, a day, fifteen days — that reaches its kept runs and its hold, a run is read in
full by a second call once it exists, and a bucket is read again until a poll has read
it an hour old. Every function has a node, and its line names it.
→ [record](adr/0006-a-functions-runs-are-kept-and-a-function-has-a-node.md)

### ADR-0007 — A level stands in the tree only where the configuration names several

An account's level stands where a check names several accounts, and a region's beneath
`lambda`, `codepipeline` and `batch` where an account reads several regions; the aspect
is always a level. What is counted is the configuration, never what AWS answers. A check
that names one account stands for it: the aspects hang beneath the check's own node,
which says the account's refusal and its configuration. A subject and a slug keep every
part, so a history survives a change of shape and a path does not.
→ [record](adr/0007-a-level-stands-only-where-the-configuration-names-several.md)

### ADR-0008 — A run and an execution say how long they took

A Batch run's record carries `wait_s` and `duration_s`, and a pipeline execution's
`duration_s`, counted between the instants AWS records: whole seconds, each once both
its instants are known and an execution's once it is over, none counted to a poll's
clock, and none where the second instant lies before the first. The type declares both
as measures in `s`, so a kept series draws them with no key of a deployment's.
→ [record](adr/0008-a-run-and-an-execution-say-how-long-they-took.md)

### ADR-0009 — A job name and a pipeline have nodes

A pipeline has a node beneath `codepipeline`, and a job name one beneath its queue's,
which stands in every Batch path and says its job names are complete in every run that
lists it: all seven of Batch's statuses are asked, `STARTING` running and `SUBMITTED`
and `PENDING` waiting. A job name's line is written from its runs, carries none and is
marked running while one is in flight; each run is said for the record. A poll reads, of
one page, what a pipeline's history lacks or holds unfinished; a superseded execution is
said nothing of, and a job name the list hides is not kept.
→ [record](adr/0009-a-job-name-and-a-pipeline-have-nodes.md)

### ADR-0010 — The package declares what its SDK writes into a log

Importing the package declares four noise caps through little-sister's `noise.cap`:
`botocore` and `urllib3` at `INFO`, `botocore.credentials` and `botocore.tokens` at
`WARNING`. little-sister sets them where the application is imported, a level a
deployment's startup file set stands against them, and `LOG_LEVEL` has a logger back by
name. No level is set here, nothing the SDK says as a warning is taken out, and what a
startup file reads before the application is imported is under no cap.
→ [record](adr/0010-the-package-declares-what-its-sdk-writes.md)

### ADR-0011 — One loader of service models for every session

`new_session` builds every session on a botocore core session that carries the
process's one loader of service models, `SERVICE_MODELS`, one for each search path — so
a service's model is parsed once in a process, and three accounts over thirty runs that
stood at 424 MiB at the highest stand at 95. The seam is botocore's `data_loader`
component, which boto3 itself stands on; two threads parse a model twice at worst and
read it after. A session is still a run's.
→ [record](adr/0011-one-loader-of-service-models-for-every-session.md)

### ADR-0012 — A function's line holds an error it saw

Beside the newest bucket, a function's reading carries the newest error in the window it
was asked, from the answer it already has, and its line stays ERROR while that error is
younger than `error_hold`, saying how many the hold holds, when the newest was and what
ran clean since. The hold is a duration on the `lambda:` block and its rules, an hour by
default or the gate where that is shorter; `0s` is none, and one written longer than the
gate or than fifteen days is refused. A run's record and verdict are its own, and the
gate keeps its meaning.
→ [record](adr/0012-a-functions-line-holds-an-error-it-saw.md)

### ADR-0013 — A console link opens the account it names

`console_link`, a template on the check that an account's own replaces, wraps every link
of an account in the address its people sign in through: `{url}` and `{account_id}`,
each percent-encoded, any other token refused. The id is the configuration's — out of
the account's `role_arn`, or its `account_id` — and is in a link's address where a
template names it, and in no path, slug or subject, nor in a field of a reading. With no
template a link is what it was, and the account's card says where its links open.
→ [record](adr/0013-a-console-link-opens-the-account-it-names.md)

### ADR-0014 — A pipeline's line keeps its verdict while an execution is in flight

`InProgress` passes. While a pipeline's newest execution is in flight — `InProgress` or
`Stopping` — its line is written from the newest with a verdict to keep, says what is in
flight beside it and is marked running; what is in flight makes it worse and never
better, and warns past `max_run_time`, thirty minutes by default. Where a series is
kept, an execution the history holds failed or stopped that runs again is a retry, asked
about, and keeps its failure until it succeeds. The line carries the execution it is
written from, and the history's line is read once more when it moves.
→ [record](adr/0014-a-pipelines-line-keeps-its-verdict-while-an-execution-is-in-flight.md)
