# little-sister-aws

**AWS for [little-sister](https://github.com/m-31/little-sister)**, in four parts:
the **`aws` check type** — one or more AWS accounts on the status tree, with a node
per account and a node per aspect beneath it — the **secret provider** behind
`aws-sm://` and `aws-ssm://` references, the **S3 keeper** that carries this
instance's `var/state/` into a bucket, and the **identity seam** all three open their
sessions through, which a deployment may also use on its own.

- **Needs little-sister ≥ 0.3.18** (a floor, never a pin), and **boto3**.
- **Registers one check type: `aws`.**
- **Ships the AWS secret provider** — `aws-sm://` and `aws-ssm://` secret
  references, with named reading identities — which a deployment installs by an
  explicit call, never by import (see *Resolving secrets from AWS*).
- **Ships an S3 keeper** — `little_sister_aws.keeper`: little-sister's `var/state/`
  in a bucket, so an instance redeployed onto a fresh machine comes up as the one
  that stopped on the old one; one lease per prefix, so a second instance on the
  same prefix stands by, says so, and takes over when the first is gone. Installed
  by an explicit call, like the provider (see *Keeping the state in a bucket*).
- **Ships the identity seam** — `little_sister_aws.identity`: a session opened from
  a profile, static keys or an assumed role, with the SSO login beside it — for code
  that needs one where no check exists (see *Opening a session without a check*).
- **Ships the leaves' display text**, so no deployment writes it: a title and an
  `about` per aspect, and which of them stay visible on a quiet dashboard.

```
/<path>                     what is watched
  /<path>/live              one node per account, its own assumed session
    /<path>/live/cloudwatch   alarms
    /<path>/live/ec2          instances, grouped by their Name tag
    /<path>/live/lambda       functions
    /<path>/live/codepipeline pipelines
    /<path>/live/batch        job queues and the jobs in them
  /<path>/backup
    …
```

Account first, aspect second, because the account is what an operator acts on as a
group: "staging is down for the migration" is one maintenance pin on one node, where
a flat list of alarms would be one pin per alarm. Each account's node also absorbs
its own bad news — a role that cannot be assumed reddens that account and leaves the
others reporting.

## Install

```toml
dependencies = [
    # Pin them: an upgrade is then a deliberate edit rather than drift. The library
    # number is the floor this release was built against.
    "little-sister==0.3.18",
    "little-sister-aws==0.1.4",
]
```

and one import in the deployment's `wsgi.py`, **before** `little_sister.app`:

```python
import little_sister_aws  # noqa: F401  (registers the `aws` type)
```

## Configure

One check config, one `accounts:` list.
[`examples/checks/aws.yaml`](examples/checks/aws.yaml) is the whole shape with a
comment per knob; the short version:

```yaml
type: aws
path: /team/aws
frequency: 60s
timeout: 120s

regions: [eu-central-1]          # the default every account inherits

accounts:
  - name: live
    role_arn: arn:aws:iam::000000000000:role/application/monitoring-role
  - name: backup
    regions: [eu-west-1]         # replaces the default, does not add to it

cloudwatch: {}                   # every aspect has an `enabled:` and its own knobs
batch:
  enabled: false                 # off: no node, and no API call
```

**Credentials.** By default the ambient AWS credential chain — an instance profile,
a task role, an SSO session, the `AWS_*` variables — and each account's `role_arn`
is assumed from it. `profile:` names an `~/.aws/config` profile to assume *from*
and composes with `role_arn`; static keys are an optional `secrets:` block of
little-sister secret references, and are mutually exclusive with `profile`.

**Switching an aspect off.** Each aspect block opens with `enabled:`. Off, the
aspect emits no node and makes no API call, which is what a role whose policy does
not carry that service needs. An aspect that says nothing is on; every aspect off is
refused at startup; and the check's card names what is off, because an absent node
otherwise reads exactly like a broken check.

## What the leaves already say

The aspect leaves arrive with their own display text, so a deployment writes none
of it: each ships a **title** and an **about** — what that aspect reads, what it
grades, and what it deliberately does not count — and each `about` ends with the
same note that a single line can be put into maintenance on its own while the rest
keeps reporting.

The text is **declared, not applied**. little-sister resolves it per field against
whatever the check's own `subnodes:` block says, so replacing one sentence keeps
the rest:

```yaml
subnodes:
  ec2:
    title: Instances        # replaces the shipped title; the shipped `about` stays
```

and a `nodes.yaml` entry keyed by path still beats both.

**Four of the five stay visible while they are quiet.** `ec2`, `lambda`, `batch`
and `codepipeline` report a *roster* — they name everything they found, every run,
whether or not anything is wrong — so the list is read precisely **because**
nothing is, and a dense dashboard that folds a quiet leaf into a chip takes away
the thing worth looking at. That is a fact about the aspect and true in every
installation, so the type declares it once (`show_when_quiet`) rather than each
deployment declaring it per aspect per account. `cloudwatch` is deliberately not
among them: its own `show_healthy: false` makes the opposite claim about its own
lines, and drops the alarms that are fine.

A deployment that disagrees says `show_when_quiet: false` for that name in the
check's `subnodes:` block, or per path in `nodes.yaml`. Both still win.

## What a run records

Each run records what it read, one reading per thing: whether the credentials opened
and what became of each account, then every alarm, instance, function, pipeline, job
queue and Batch job run it read, and every region an aspect could not read. Every line
made from one reading carries that reading's record as its `data` — an alarm's, a
function's, a pipeline's, a queue's, a name's where one instance carries it — so a line
template or a client can read what the line read; a job name's line is made from all of
its runs, and carries none of them. Free text is clipped once, at 300 characters, and
the line says exactly what the record keeps.

`series_keep:` — little-sister's setting, **0 by default** — keeps three histories on
this check: each **Batch job**'s runs, one record per run however many polls saw it,
in its final state once it has finished; each **pipeline**'s executions, one record per
execution; and the accounts' own — one record each time an account opens or stops
opening. Alarms, instances, functions and queues keep none. A history is keyed by the
account's configured `name`, so renaming an account starts it again. The accounts' own
history is of the accounts the configuration lists, so adding or removing an account
starts that one again too. Why it is shaped this way is
[ADR-0005](docs/adr/0005-a-run-is-its-readings-and-the-runs-keep-a-history.md).

## The IAM policy

One role per account, and it has to cover every aspect that is switched on, in every
region the account is watched in:

| Aspect | Actions |
|---|---|
| `cloudwatch` | `cloudwatch:DescribeAlarms` |
| `ec2` | `ec2:DescribeInstances` |
| `lambda` | `lambda:ListFunctions`, `cloudwatch:GetMetricData`, `logs:DescribeLogStreams`, `logs:GetLogEvents` |
| `codepipeline` | `codepipeline:ListPipelines`, `codepipeline:ListPipelineExecutions` |
| `batch` | `batch:DescribeJobQueues`, `batch:ListJobs` |

The deployment's own identity needs `sts:AssumeRole` on each role, and
`sts:GetCallerIdentity` is spent once per profile-only account. The **keeper**, if
one is configured, needs its own: `s3:GetObject` and `s3:PutObject` on the keys
under its prefix, `s3:ListBucket` on the bucket, and — optionally, for the check
that says whether versioning is on — `s3:GetBucketVersioning`.

## Resolving secrets from AWS

This package also carries the AWS secret provider: little-sister secret
references that read AWS Secrets Manager and SSM Parameter Store, resolved once
at startup, before any check exists. A deployment installs it with one call in
its import-before-app slot — **the provider registers nothing on import**, because
which stores an installation reads its credentials from is a decision, and a
decision should be readable at the place it is taken:

```python
from little_sister_aws.secrets import register_aws_secret_resolvers

register_aws_secret_resolvers()          # before `little_sister.app` is imported
```

Because the registration is made from here, little-sister records **this package**
as the one that answers for every scheme the call claims: `/system` lists
`aws-sm://`, `aws-ssm://` and each identity's pair with this installation's
version beside them, and a second package claiming one of those names refuses at
startup naming both — a scheme is where a credential is read from, and import
order may not decide it.

A check config may then say, in any `secrets:` block:

```yaml
secrets:
  token: aws-ssm:///team/github/token              # an SSM SecureString
  client_secret: aws-sm://team/wiz#/oauth/client_secret   # one field of a JSON secret
```

The schemes are **additive** — `env://` and any other registered scheme keep
working beside them, and one `secrets:` block may mix stores per credential;
installing this provider changes nothing about references that name another
scheme.

Both stores are read **strictly**: Secrets Manager must return a non-empty
`SecretString` (binary secrets are refused), and Parameter Store must report the
parameter's type as exactly `SecureString` — decryption being requested does not
prove the value was stored encrypted. Either address may end in
`#/<JSON Pointer>` to select one non-empty string out of a JSON document;
malformed JSON, a missing path or a non-string selection fails the reference
rather than falling back to the whole document, and no error ever contains a
fetched value.

**Named identities.** Secrets in several accounts are read through identities a
deployment declares in its own `config/aws.yaml` — this package owns the file's
*shape* ([`examples/aws.yaml`](examples/aws.yaml) is the whole of it), the
deployment owns its contents. Each name becomes a scheme pair of its own —
`aws-sm-live://…` reads through the `live` entry, with its profile and assumed
role — so a reference stays a name for a secret and never carries a credential,
and an identity nobody declared is an unregistered scheme, refused at load
naming the reference. An identity may also renew its own expired SSO login
while the application starts, bounded by the boot rather than by a check's
budget; its `sso:` block says whether and for how long.

The stores need `secretsmanager:GetSecretValue` and `ssm:GetParameter` on
whatever identity reads them, beside the `sts:AssumeRole` a role-bearing
identity spends. The design record is
[`docs/adr/0002-aws-secret-references.md`](docs/adr/0002-aws-secret-references.md).

## Keeping the state in a bucket

little-sister keeps what a restart needs as files under `var/state/` — the
maintenance pins somebody set, the event log behind every node's history — and takes
a **keeper** to carry that directory somewhere durable. This package has one, so a
deployment redeployed onto a fresh machine comes up as the instance that stopped on
the old one.

Two things turn it on. A `config/aws-keeper.yaml`:

```yaml
bucket: example-monitoring-state   # required; nothing else is
prefix: instances/prod             # default: the bucket's root. One instance per prefix.
identity: live                     # default: none — read as whatever the host already is
region: eu-central-1               # default: what the profile or the environment implies
lapse_after: 3                     # default: 3 — missed heartbeats before the lease is dead
```

and a call in the same import-before-app block as the secret provider, because
**the keeper registers nothing on import** either:

```python
from little_sister_aws.keeper import register_s3_keeper

register_s3_keeper()               # returns None where no aws-keeper.yaml declares one
```

The file is one of two routes. `register_s3_keeper(config=KeeperConfig(bucket=…,
prefix=…))` — `KeeperConfig` from the same module, with the file's keys and defaults —
takes a configuration built in the deployment's own startup code and reads no file,
which is the route for a bucket name that is not a constant, such as one carrying the
account id.

`identity:` names an entry in `config/aws.yaml` (above); one that was never declared
refuses the start, as does an unknown key, a key left empty, a missing `bucket:`, or
a `lapse_after` that is not a positive integer. **No file at all means no keeper** —
which is what a second configuration root for a laptop wants — and the session is
opened lazily, at the first call, so an unreachable bucket is a line on
`/little-sister` rather than a start that fails.

**One prefix, one instance, held by a lease.** One object under the prefix says
who may write here, and the instance that holds it re-writes it every
`state_interval` — a heartbeat — and writes the state files behind it. A second
instance started on the same prefix restores the state like any other (reading
needs no lease), then **stands by**: it monitors, keeps its state on its own disk,
sends nothing to the bucket, reads the lease once per interval, and says so on its
child `/little-sister/aws-keeper` at WARN. When the lease lapses — `lapse_after` heartbeats missed,
three by default — or is given up, it takes over and writes on. A holder whose
heartbeat is refused, or whose bucket does not answer for `lapse_after` intervals,
demotes itself to standby *before* it writes anything, and takes the lease back
when it is free. Nothing here needs a restart, and nothing here is red. The
keeper's lines are the entries of `/little-sister/aws-keeper`, each under its own
slug there (a pin holds against that path and slug), and every line is a claim:

```
standby       the lease on s3://…/instances/prod is held by
              web-2:1:20260904T173000Z:9f3ac180, last heartbeat 40 s ago and
              lapsing in 2m 20s; this instance keeps its state locally only, and
              a pin set here does not survive it
```

`standby`, `demoted` and `unreachable` are WARN, by the library's own rule that
what *would* be lost at a restart is WARN and only what *is* lost is ERROR — and a
standby loses nothing while it stands. What it costs, said plainly: **a pin set on a
standby is local**. What the keeper merely *knows* is the child's **report**, on its
page and never on a card: who holds the lease and on what terms, whom it was taken
from and how, the last transitions. A quiet holder's card therefore says nothing —
the report does:

```
This instance (web-1:1:20260905T081500Z:2b7de044) holds the lease on
s3://…/instances/prod: a heartbeat every 1m, lapsing after 3 missed.

Took over s3://…/instances/prod from web-2:1:…, lapsed 12 s before (1 earlier
claim, the most recent at …).
```

**Authority follows the lease.** Whoever holds it wrote the truth up to the moment
it lapsed, so when a standby takes over it continues with the *store's* state and
not its own: the keeper remembers the ETag of every file it loaded or saved, and at
the takeover names the files the store changed since; little-sister adopts them
before the first save and keeps what they replaced beside each file as `.bak`, listed
on `/little-sister/state`, where **take the backups** swaps them back. A takeover
that changed something says so on the keeper's child for ten minutes at WARN, then
in its report; the successor of a holder that died before anybody wrote again takes
over silently, with its own state.

```
takeover      took over s3://…/instances/prod: the store had changed for 2 files
              (events.json, maintenance.json) since this instance last synced
              with it at 09:12; what they replaced is on /little-sister/state
standbys      1 instance is standing by on s3://…/instances/prod: web-2:1:…
              since 09:14. In a rollout this clears within minutes; a second
              instance that stays is a misconfiguration
```

and, in the report, the instance log's last transitions: *web-1:1:… took the lease
from web-2:1:… (lapsed) at 09:20; web-2 stood by from 09:14 to 09:17; …*

**The holder sees who stands by.** A standby writes a small presence file beside
the lease every interval, with its own `ttl_seconds`; the holder lists the prefix
once per interval — about the price of its heartbeat — and carries `standbys` at WARN
while anybody is there. Whoever lists deletes a presence file older than its ttl, so
a killed standby is gone from the page within one ttl of its death, and writes that
instance's *stood by from … to …* into the **instance log**, `.little-sister-
instances.json` beside the lease: one entry per transition — who took the lease from
whom and how, who released it, who stood by from when to when — the last hundred,
never restored, the last three shown in the keeper's report. It is the one record of the
deployment that outlives every instance in it.

**Two actions, for an operator who knows what they are doing**, on
`/little-sister/aws-keeper`, admin-only: **Take over** writes the lease onto this
instance regardless of who holds it — the holder demotes itself at its next
heartbeat, within one interval, and until then both pages say *holds*, which is safe
because no save runs behind a refused heartbeat; the taker's `predecessor` says it
was an operator's and how fresh the holder's last heartbeat was, the holder's
`demoted` says the same, and this instance adopts what the store changed and saves
in the same click, since every action is followed by a flush; pressed on the holder
itself it is that flush, the state written now — and **Release** gives the lease up
now, as a clean stop would. A released instance
does *not* take the lease back on its own — that would be a coin toss against the
standby the button was pressed for — and says so at WARN (`released`: nothing of its
state reaches the store until an instance takes the lease); *take over* takes it
back, and once another instance has held the lease it is an ordinary standby again.

**Two clocks.** Every stamp in the bucket is S3's clock, and every page shows a store
stamp in the host's time — the offset is measured on every answer from the `Date`
header — so a standby's *since* and the log's intervals line up with the local
times beside them. A host more than 5 s off shows `clock` at WARN (cleared under
3 s); past fifteen minutes S3 refuses every request, and that already shows as a
lost lease.

**Liveness is S3's clock, not anybody's.** Whether a lease is alive is the answer's
`Date` against the object's `LastModified`, compared with the `ttl_seconds` the
holder wrote — every term from S3, so two instances on two machines read the same
thing. A **graceful stop** (`stop.sh`, SIGTERM) gives the lease up with a heartbeat
of zero, so the next standby takes it on its next read instead of waiting; an
instance terminated without a stop — an auto-scaling group's — is the case the
lease is designed for, and the wait is `lapse_after × state_interval`.

The mark is little-sister's — one per process, `<name>:<pid>:<started>:<tag>`, where
the name is yours from `instance:` in `settings.yaml` and the hostname otherwise —
and `/system` shows you the same mark for the instance you are looking at. Every
instant in the lease is ISO 8601 UTC, and every instant in a line is shown in the
`timezone` and `time_format` of `settings.yaml`, like the rest of the page.

**What the bucket wants: versioning off.** The heartbeat is a `PUT` a minute, so
versioning would be about 43,000 versions a month of a 463-byte object for a history
nobody reads; a lifecycle rule bounds that and does not prevent it. The keeper asks
`GetBucketVersioning` **once at startup** and carries a WARN line while it finds
versioning enabled (suspended is fine; a bucket that once had it on can do no
better). That needs `s3:GetBucketVersioning`; without it the keeper says in its
report that it could not ask. The prefix holds the current state of one instance — a mirror of a
bounded memory — and there is nothing in it worth a version.

**What one instance costs**, eu-central-1, at the default interval: about **$0.50 a
month** for the holder — 43,200 heartbeats and as many listings at the `PUT` price,
the state files only when they change, the instance log only on transitions — and
about **$0.25** for a standby, its presence heartbeats plus its reads. A shorter
`state_interval` buys a shorter failover at the same rate per heartbeat.

The identity needs `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject` on the keys
under the prefix, `s3:ListBucket` on the bucket, and optionally
`s3:GetBucketVersioning`.
The design record is
[`docs/adr/0004-the-s3-keeper.md`](docs/adr/0004-the-s3-keeper.md); the annotated
file is [`examples/aws-keeper.yaml`](examples/aws-keeper.yaml).

## Opening a session without a check

`little_sister_aws.identity` is this package's second public surface, for code in a
deployment that has to reach AWS **before** any check exists — resolving an AWS-backed
secret reference at startup, typically. It needs no check, no check configuration and
no run:

```python
from little_sister_aws.identity import Identity, open_session

session = open_session(Identity(
    profile="corp-sso",                                   # from ~/.aws/config
    role_arn="arn:aws:iam::000000000000:role/monitoring-role",
))
```

`open_session` proves the credentials before it returns: assuming the role is that
proof where there is a role, and one `sts:GetCallerIdentity` is spent where there is
only a profile — so an expired login is one failure, at the moment the session is
opened, rather than the same news in the words of whatever was read first.

Renewing an expired login is a **separate call**, because what a login may cost
belongs to whoever is waiting for it:

```python
from little_sister_aws.identity import SSO_LOGINS, SsoConfig, login_problem

problem = login_problem("corp-sso", SsoConfig())     # "" when a login could work here
if not problem:
    problem = SSO_LOGINS.renew("corp-sso", timeout=30, cooldown=600)
```

`SSO_LOGINS` is **one instance per process**, keyed by profile, with a per-profile
lock and a cooldown — so a check and a deployment that notice the same expiry open one
browser between them. A second implementation of it anywhere in the process would
defeat exactly that, which is why this is exported rather than left to be rewritten.

`timeout` is an argument rather than a setting: a check spends its own timeout on an
engine worker thread, while an application resolving secrets during its import is
holding a worker that has not finished booting, and wants a much smaller number.

## Develop

The gate, and the hook that runs it before every commit. The hook is **opt-in**:
`core.hooksPath` is local git configuration, so no checkout can carry it for you and
a fresh clone commits with nothing checking it.

```bash
uv sync --frozen                     # the environment, from uv.lock

# What the hook runs, in this order:
uv run ruff check
uv run shellcheck $(git ls-files -- '*.sh' 'hooks/pre-commit')
uv run mypy
uv run mypy --python-version 3.11    # against the floor, not the interpreter you have
uv run pytest -q

# Enable it:
git config core.hooksPath hooks
```

[`hooks/pre-commit`](hooks/pre-commit) runs exactly the five commands under that
comment and is **byte-identical in every Python project of the family**, so a fix to the gate is a fix everywhere. The tests
never call AWS: every boto3 client is built behind one seam per service, and the
suite replaces it.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — what is built: the surfaces above
  and the rules that bind them, with the record named beside each. Written for
  somebody working **in** this package rather than installing it.
- [`docs/adr/0001-the-aws-check-type.md`](docs/adr/0001-the-aws-check-type.md) — why
  one type with aspects rather than one type per service, why the tree is account
  first, and why this package uses boto3 where the rest of the family uses stdlib
  `urllib`.
- [`docs/adr/0002-aws-secret-references.md`](docs/adr/0002-aws-secret-references.md) —
  the secret-reference grammar: the strict stores, JSON Pointer selection, and why
  a reading identity is a scheme rather than part of the address.
- [`docs/adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md`](docs/adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md)
  — how this type grades: a threshold is a warn/error pair with a sentence, a rule
  owns a set of names and overrides the block's limits for them, and the package
  ships no thresholds of its own.
- [`docs/adr/0004-the-s3-keeper.md`](docs/adr/0004-the-s3-keeper.md) — the keeper: its
  own configuration aspect, why every write is conditional and a refused one is
  reported rather than merged away, and why the session is re-opened at call time
  instead of the frozen identity seam growing a refresh.
- [`docs/adr/0005-a-run-is-its-readings-and-the-runs-keep-a-history.md`](docs/adr/0005-a-run-is-its-readings-and-the-runs-keep-a-history.md)
  — how a run measures and then grades: one reading per thing it read, which of them
  keep a history (a Batch job's runs, a pipeline's executions, the accounts' own), and
  why a history names an account by its configured name.

## License

MIT — see [LICENSE](LICENSE).
