# little-sister-aws

**AWS for [little-sister](https://github.com/m-31/little-sister)**, in three parts:
the **`aws` check type** — one or more AWS accounts on the status tree, with a node
per account and a node per aspect beneath it — the **secret provider** behind
`aws-sm://` and `aws-ssm://` references, and the **identity seam** both of them open
their sessions through, which a deployment may also use on its own.

- **Needs little-sister ≥ 0.3.13** (a floor, never a pin), and **boto3**.
- **Registers one check type: `aws`.**
- **Ships the AWS secret provider** — `aws-sm://` and `aws-ssm://` secret
  references, with named reading identities — which a deployment installs by an
  explicit call, never by import (see *Resolving secrets from AWS*).
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
    "little-sister==<the version you pin>",
    "little-sister-aws==<this version>",
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
`sts:GetCallerIdentity` is spent once per profile-only account.

## Resolving secrets from AWS

This package also carries the AWS secret provider: little-sister secret
references that read AWS Secrets Manager and SSM Parameter Store, resolved once
at startup, before any check exists. A deployment installs it with one call in
its import-before-app slot — **nothing registers on import**, because which
stores an installation reads its credentials from is a decision, and a decision
should be readable at the place it is taken:

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
comment and is **byte-identical in every project of the family**, so a fix to the gate is a fix everywhere. The tests
never call AWS: every boto3 client is built behind one seam per service, and the
suite replaces it.

## Documentation

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

## License

MIT — see [LICENSE](LICENSE).
