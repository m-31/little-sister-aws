# ADR-0001 — The `aws` check type: account nodes, aspect leaves, and boto3

- **Status:** Accepted
- **Date:** 2026-10-10 (the type was accepted 2026-08-09)
- **Related:** [ADR-0002](0002-aws-secret-references.md) (the secret references the
  identities on this package's seam are read with),
  [ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) (where
  the account's level stands),
  [ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) and
  [ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md) (the aspects that hand back
  nodes), [ADR-0013](0013-a-console-link-opens-the-account-it-names.md) (an account's
  links, and the id they may carry), little-sister **ADR-0042** (coded entries),
  little-sister **ADR-0043** / little-sister **ADR-0044** (the coverage reading and the
  roster), little-sister **ADR-0025** (subnode text); the lift-out this record promised
  has happened, and this package is the result

> This record was written in the deployment whose AWS checks this type replaced and
> traveled here with the code: *that codebase* in the Context below is that
> deployment's, and the checks it names are the ones this type absorbed.

## Context

Watching several AWS accounts raises four questions before any of them is about
CloudWatch. Whether one check type reads every service or one reads each; whether
the tree branches on the account or on the service; what a single alarm is, as a
thing an operator acts on; and how to reach AWS at all.

The obvious arrangement — a check type per service, each building its own session,
each returning a flat list tagged with the environment it came from — answers all
four badly at once, and answers them again for every service added.

A fifth question arrived later, and is answered here rather than in a record of its
own because the answer turned out to be machinery this type already had: **who else
in the process opens a session.** For a while, nobody. Then AWS-backed secret
references had to resolve once at check *construction* — before any check exists,
out of no check's configuration, on the thread importing the application.

What follows is the arrangement this package uses instead, and why.

## Decision

### 1. One type, `aws`, with aspects — not one type per service

The other checks in that codebase (`infrastructure.py`: long-running batch EC2
instances, SageMaker kernel gateways, duplicate autoscaling groups) read the *same
accounts through the same assumed session*. A type per service would assume every
role once per service, carry the account list three times, and give the dashboard
three unrelated nodes for one provider. `github` already answers this shape:
one check, one credential, one frequency, one child per aspect.

### 2. Account first, aspect second

Where a check names several accounts the tree is `/<path>/<account>/<aspect>`, not
`/<path>/<aspect>` with the account in each line. Three reasons, in the order they
mattered:

- **A pin needs a node.** "Staging is down for the migration" is one maintenance
  pin on one node. Flat, it is one pin per alarm, and the next deploy invents new
  alarms that nobody pinned.
- **A failure needs an owner.** An account whose role cannot be assumed reddens
  *its* node and the others keep reporting. Flat, that failure has nowhere to live
  except the root, where it either colors everything or is lost among the lines.
- **A tag on every line is a tree that was not available.** Labeling each result
  with the environment it came from is what a flat list does when it cannot branch.
  This one can, so the label becomes the node.

**Those are reasons to tell accounts apart, so the account's level stands where a check
names several.** A check that names one account hangs its aspects beneath its own node,
`/<path>/<aspect>`, and says there what refuses the account
([ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) §2).

The aspect leaf itself stays **flat** for `cloudwatch` and `ec2`: an alarm carries its
own verdict, so the finding is what an operator acts on, and each line is a coded
`Entry` (little-sister ADR-0042). Where an estate sorts alarms by a name prefix, that
becomes one word on the line (`tag_prefix`) rather than a second node — the account is
what such a split is usually carrying, and the tree carries the account.

**Three aspects hand back nodes** for what they read: `lambda` a node for each function
([ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) §9),
`codepipeline` one for each pipeline, and `batch` one for each job queue with a node for
each job name beneath it ([ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md)). An
alarm's line and an instance name's stay on their aspect's node, and the region stays in
their slugs.

**An account's entry takes two keys for its links**, beside those that say where it is
read from ([ADR-0013](0013-a-console-link-opens-the-account-it-names.md)):
`console_link`, a template the type fills for every link it writes for the account,
readable at the check and on an account exactly like `regions:` and `profile:` below;
and `account_id`, for an account that names no role to read its id from.

**The credential half of the same decision: from where, into what.** An account has its
own session, and its own node where a check names several; where the session the role is
assumed *from* comes from is the other half of that, and the ambient chain — one for all
accounts — is right on a server and wrong on the machine this is developed on, where one
config's roles and another's can live in **different organizations**, reachable only as
two different `~/.aws/config` profiles.

- **`profile:` is readable at the check and on an account**, exactly like
  `regions:`, and it **composes** with `role_arn` rather than replacing it —
  `profile` says from where, `role_arn` says into what. Unset it changes
  nothing: boto3 reads the ambient chain, `AWS_PROFILE` included. It is
  **mutually exclusive with a `secrets:` block**, because a profile *is* a set
  of credentials and a config naming both has said two things about which
  estate it watches.
- An account with a profile and **no** role spends one `sts:GetCallerIdentity`
  before its aspects run. Assuming a role was already the proof that the
  credentials work; without one there was nothing to fail until three aspects
  failed separately, each in its own words.
- **An expired SSO login is renewable, and the check decides whether renewing
  is even a sensible thing to attempt here.** `sso.login: auto` — the default —
  runs `aws sso login` only where it can work: an SSO profile, the `aws` CLI on
  `PATH`, no platform-supplied credentials (`AWS_EXECUTION_ENV`,
  `ECS_CONTAINER_METADATA_URI`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
  `KUBERNETES_SERVICE_HOST`, …), not a container, and a machine where a browser
  opens. `always` skips the question, `never` never shells out. **The decision
  and its reason are printed on the check's card**, because "auto" without a
  word on whether auto works here is the reassuring version of saying nothing.
- The renewal is bounded twice: a **timeout** (default 2m), because a login
  holds an engine worker thread while it waits for a human, and a **cooldown**
  (default 10m) **per profile, in process-wide state**, because the browser and
  the token cache belong to the machine — two checks on one profile must not
  both open a login, and at `frequency: 60s` a login nobody completes would
  otherwise be a browser window a minute for as long as you are away from the
  desk.
- The login is started through **little-sister's process function**
  (little-sister ADR-0089), never by a `subprocess` of this package's own: in a process
  group of its own, with `/dev/null` for stdin and the timeout above as its bound, and
  ended with the instance — a login still waiting for its person when the instance
  stops is ended, and the account's line says the stop ended it. What a login needs is
  the CLI's own business: it opens the browser and prints its URL itself.
- Either way the account carries **two lines**: what expired, and the exact
  `aws sso login --profile …` that fixes it — except where no profile is
  configured, since telling a server to open a browser is advice for a machine
  that is not this one.

### 3. boto3, not stdlib `urllib`

Every other check type in this family reaches its provider over stdlib `urllib`,
and each ships with little-sister as its only dependency. This one does not.
Signing SigV4 for `sts:AssumeRole` and the CloudWatch API by hand is a signing
implementation plus the test suite that keeps it honest, bought to save a
dependency that AWS itself maintains, that is already in this deployment's
transitive world the moment anything talks to AWS, and that the `aws-ssm://`
secret resolver — now this package's own — wants anyway.

The cost is named rather than waved away: `little-sister-aws` is the first
package in the family with a dependency beyond little-sister, and it declares it
as a **floor**, like its little-sister floor. `boto3-stubs` with one extra per
service this package calls goes in the dev group — without the per-service extras
every client types as
`BaseClient` and strict mypy checks nothing at all on the one call path that
matters. Payloads are narrowed into this module's own frozen `Alarm` at the read
seam, so nothing downstream touches a boto3 response and the tests need no
AWS-shaped fixtures.

### 4. It is a package, not a deployment's private code

AWS is a *product*: a second installation can adopt this type knowing nothing but
its README and its example config. That is what earns a check type a distribution
of its own rather than a home inside whichever estate first needed it — and it sets
the line every later decision here is measured against. What is true of the *type*
is in this package: the aspects, the grading, the subnode prose, the defaults. What
is true of one installation is in that installation's YAML: which accounts, which
regions, which roles, which thresholds, which naming.

Concretely, that means the module imports only little-sister's published
check-authoring surface, its tests use no fixture belonging to any installation,
and it is written to the **library's** Python floor (3.11) rather than to whichever
interpreter it happens to be developed on.

### 5. `little_sister_aws.identity` is a second public surface

Everything the fifth question needs already lived here, and lived inside
`AwsCheck`: `_new_session`, the `AssumeRole` with its session name and STS region,
the `GetCallerIdentity` that proves a profile-only identity, and the `aws sso login`
renewal with its capability test, timeout and cooldown. It is a surface of its own
now rather than a check's private half.

1. **What it publishes.** An `Identity` — profile, static keys, role, session name,
   STS region — plus `base_session()`, `assumed_session()` and `open_session()`,
   and beside them `login_capability()`, `login_problem()`, `run_sso_login()`,
   `SsoLogins` and `SSO_LOGINS`. `AwsCheck` composes an `Identity` per account and
   delegates; its configuration, its per-account layering and its retry-once policy
   are unchanged, and the tests that pin them did not move.

2. **The rule for that surface: it reads no file, knows no check type's schema, and
   takes the mapping as an argument from whoever read the file.** Nothing here opens
   a configuration directory and nothing needs a check to have been built. That is
   what makes it usable by the callers it was extracted for, and it is the test to
   apply to anything proposed for it later. `identity.py`'s own docstring says the
   same, so the two cannot drift apart.

3. **`SSO_LOGINS` is exported rather than reimplemented, and that is the reason the
   code moved rather than being copied.** One instance per process, keyed by profile,
   with a per-profile lock and a cooldown: two implementations in one process would
   each hold half of the machine's history and open two browsers for one expiry. A
   deployment writing its own would not be a duplication, it would be a defect.

4. **A login's budget belongs to its caller.** `SsoLogins.renew()` takes its timeout
   and cooldown as arguments and reads no configuration, because a check waiting on an
   engine worker thread and an application waiting inside its own import can afford
   very different numbers — the second is a worker that has not finished booting, and
   a generous timeout there is a failed start rather than a slow one. `open_session()`
   therefore does not renew anything: whether to try, and at what price, is one call
   further out.

### 6. The seam carries the readers its callers were each writing privately

The `sso:` block — whether, and how hard, an expired login may be renewed — was
written in three packages: this check's own configuration, a deployment's identity
file, and a deployment-resident check type of that deployment's own. Each had grown
a private parser. The copies' *deliberate* differences — what a bad block costs, and
what a login may spend — were carried by every copy again, while their wordings
drifted apart by accident and their suites then pinned the drift. So the reader is
one function on this surface, `parse_sso_block`, beside the `SsoConfig` it produces
and the modes and defaults it validates against, with the differences as arguments:

1. **`default=` is the budget, and it is the caller's.** An absent block and
   absent keys mean the *caller's* numbers — exactly what point 4 above states for
   `SsoLogins.renew()`. This check passes nothing and keeps its generous window; a
   boot passes its own short one.
2. **`allow_cooldown=False` refuses the key rather than ignoring it.** A
   cooldown answers "how often may an unattended machine re-open a browser",
   which a caller that reads its secrets once at startup must not be asked.
3. **A refusal is parts, not a sentence.** `SsoBlockError` carries which key,
   what was wrong with it and what would have been accepted, and every caller
   renders its own words and translates to its own type — a check pins itself,
   an identity file refuses a whole start. The suites on both sides of the seam
   pin sentences that disagree on purpose, so a wording that lived in the
   reader would be one of them broken the day anybody harmonized it.

A *parser of configuration* on this surface is exactly what point 2's width is for:
the block arrives already read, by whoever owns the file it came from.

The `sso:` block was not alone. *An optional string, and a key written and left
empty is a typo, not a value* — the rule this check learned the hard way about
`profile:` — had also been written once per package, and two of the three
copies quietly **stringified** a value that was not text on top: `profile: 123`
read as the profile name `"123"`, handed to boto3 and to `aws sso login`, and
no suite anywhere pinned the coercion. So the seam carries a second reader in
the same shape — `parse_optional_text`, with `OptionalTextError` as its parts —
and the refusal won: absent means the caller's default, written-and-left-empty
refuses, and a non-text value refuses as the same typo family. This check's
`_parse_profile` is that reader plus the one thing that stays the check's own:
the backtick-and-newline ban on a name that is printed back inside a Markdown
code span and handed to a subprocess.

### 7. The AWS secret provider lives here too — and what still bounds the package

Decision 4's line is *what is true of the type lives here, what is true of an
installation lives in its YAML*, and for a while this package registered one check
type and published one seam beside it. It now also carries the AWS **secret
resolvers** and the named identities they read secrets with —
`little_sister_aws.secrets` and `little_sister_aws.identities`, with the `aws`
configuration aspect declared here and `config/aws.yaml`'s shape owned here.
[ADR-0002](0002-aws-secret-references.md) is their design record; it traveled with
them, and registration stays the deployment's own explicit call.

That makes three surfaces rather than one, which is a boundary worth stating so it
does not keep moving: this package is the home of what is true of **AWS**, and the
one AWS check type whose subject is a particular organization's own system stays in
that organization's deployment, by that deployment's own record, forever. The rule
for `identity.py` is untouched by the arrival — `identities.py` reads a **file**,
which is exactly why it sits *beside* the seam and never in it.

## Consequences

- `boto3` is this package's dependency, declared as a **floor** beside the library's
  own — the first in the family to have one beyond little-sister.
- A maintenance pin is keyed `(path, slug)`. The path carries the account, or is the
  check's own where the check names one, so the slug does not; it carries the
  **region**, always, even where the line does not print it — otherwise every pin on an
  aspect's own line re-points the day a second region is configured. A pin on a
  function's, a pipeline's, a queue's or a job name's node is keyed by a path that gains
  the region's level that day, and moves with it
  ([ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) §6).
  Neither the path nor the slug carries the alarm ARN, because that carries the account
  id and a private string in a `?reason=` value is a private string in somebody's
  bookmark. Nor does a link the type builds by itself: the console address names no
  account, and the id is in a link only where a deployment's `console_link` names it
  (§2).
- Two gradings are deliberate and worth knowing on the first run, because the
  cheaper reading of each is the one people expect: `INSUFFICIENT_DATA` is a
  **WARN**, not an OK, since an alarm with no data is usually an alarm whose metric
  stopped arriving; and **composite alarms are read**, because `describe_alarms`
  returns only metric alarms unless asked and a blind spot is easy to inherit
  without deciding to. Both are one `state_map` / `include_composite` line away from
  the other answer, which is the point of them being configuration.
- Every account gets every aspect (`cloudwatch`, `ec2`, `lambda`, `codepipeline`,
  `batch`); an aspect is switched off per check with `enabled: false`. The day one
  account differs from the rest, that becomes a per-account `aspects:` list; it is
  not one today because a list with one member in it teaches nobody anything.
- A process gets one `SSO_LOGINS`, and every caller that may renew a login shares
  its history — so a check's browser window and a boot's are the same window, and
  the cooldown that suppresses a second one is machine-wide by construction.
