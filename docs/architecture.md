# little-sister-aws — what is built

What this package **is**, in enough detail to work in it without opening a decision
record. The records say *why* each shape was chosen and what was rejected; this file
says what is true now and what follows from it, and names the record beside each rule
so you can go and argue with it. The division is deliberate: you should not have to
read the records to write correct code here, and you should always read the governing
one before **changing** a shape rather than building within it.

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

The line that decides what may live here at all: **what is true of the extension
travels with the package; what names somebody's org, tenant, account, region or
threshold belongs in a deployment's YAML.** It is the test to apply to any new knob
([ADR-0001](adr/0001-the-aws-check-type.md) §4).

## 2. The modules

| | |
|---|---|
| `__init__.py` | the API epoch (`require_api(3)`) and the import whose side effect registers the type |
| `aws.py` | the `aws` check type: configuration, the five aspects — each measured and then graded — and the tree it writes |
| `_rules.py` | the configuration vocabulary the aspects share — a graded threshold is a pair, a rule owns names ([ADR-0003](adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md)). Private on purpose: it is shared *between the aspects*, not with anybody outside |
| `identity.py` | the identity seam (§4) |
| `identities.py` | the `aws` configuration aspect — named identities, read from `config/aws.yaml`. It reads a **file**, which is exactly why it sits beside the seam and not in it |
| `secrets.py` | the `aws-sm://` and `aws-ssm://` resolvers, and one session per identity for the process |
| `keeper.py` | the S3 keeper, the `aws-keeper` aspect, and the one self-report contributor this package registers (§5) |

## 3. The check: account first, aspect second

One check type reads every service. Its tree is `<check path>` → one node per
**account** → one node per **aspect** beneath it:

```
/team/aws/live/cloudwatch      /team/aws/backup/cloudwatch
/team/aws/live/ec2             …
```

Account first because the account is what an operator acts on as a group — *staging
is down for the migration* is one maintenance pin against one node — and because an
account's node absorbs its own bad news: a role that cannot be assumed reddens that
account and leaves the others reporting
([ADR-0001](adr/0001-the-aws-check-type.md) §2).

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
- **A rule that matches nothing goes to the log and never to a node.** It is a fact
  about the *configuration*, not about the estate, and colouring a card over a typo in
  a file sends somebody hunting through an account where nothing is wrong.
- **A check that could not look is not a check that graded badly.** An account's
  own reading says which of the two happened — `read`, `unreachable` or `expired` —
  rather than the grading inferring it from the shape of the result, and an account
  that could not be read is logged with the three facts that are useless apart: what
  was attempted, **who we actually were** (`caller_identity`), and what AWS said.

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
  what is said is the grading's, so what an ignore list hides is still a reading. Which
  rules matched a name is noted while measuring: the log line about a rule that matched
  nothing is state kept between runs.
- **Three kinds keep a history, and no others**: a Batch job's run, named by its
  `jobId`; a pipeline, by its newest execution's id or the state `never-run`; and the
  estate, by each account's outcome — `backup=expired/live=read`. A subject names an
  account by its configured `name`, the kind first and `/` between the parts —
  `batch/<account>/<region>/<queue>/<job name>` — so an account's name is a stored key
  twice over: every pin under it hangs off it, and so does every history.
- **The root grades nothing**: it declares `UNDEFINED` beside the sentence that says
  what is watched, so the estate's kept reading stands at what the run rolls up to. A
  line made from one reading carries it as its `data` and its subject; one made from
  several carries none — a job name's line names its subject instead. Free text is
  clipped once, in the measuring half, by `_kept`.

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

`is_credential_error()` is the reading every caller shares — *stale credentials* as
against *AWS said no* — and its docstring carries what it answers in each of the four
SSO states, measured. The three callers act on it differently on purpose: the check
renews on its own generous budget, the secret provider on the boot's short one, and
the keeper does not renew at all.

**The surface is released and frozen**: `Identity`, `base_session`, `assumed_session`,
`open_session`, `login_capability`, `login_problem`, `run_sso_login`, `SsoLogins`,
`SSO_LOGINS`, `parse_sso_block`, `parse_optional_text` and their error parts went out
with 0.1.1. A change to any of them is a version, not an edit.

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

## 7. The records that bind this package

Each is digested in one or two lines here; the record carries the argument and what
was rejected. Read one before changing what it decided.

- **[ADR-0001](adr/0001-the-aws-check-type.md) — the `aws` check type.** One type with
  aspects rather than one type per service; account first, aspect second; boto3 over
  stdlib; a package rather than a deployment's private code; **§5** the identity seam
  and its two rules; **§6** the readers the seam carries for its callers; **§7** the
  secret provider living here too.
- **[ADR-0002](adr/0002-aws-secret-references.md) — AWS secret references.** What
  `aws-sm://` and `aws-ssm://` address, why a named identity is a **scheme** rather
  than part of the address, and why registration is the deployment's call.
- **[ADR-0003](adr/0003-a-graded-threshold-is-a-pair-and-a-rule-owns-names.md) — a
  graded threshold is a pair, and a rule owns names.** The configuration vocabulary
  `_rules.py` implements, and why one number that produced one severity had to go.
- **[ADR-0004](adr/0004-the-s3-keeper.md) — the S3 keeper.** Its own aspect; one
  lease per prefix, held by a heartbeat every interval and taken by a conditional
  write, with the state files written unconditionally behind it; standby instead of a
  latch; the bounded client, and the session re-opened once at call time. **§8**
  liveness measured inside one S3 answer and release as a heartbeat of zero; **§9**
  reporting by the library's loss principle, WARN for a standby, and the two actions
  the web app owes; **§10** versioning off and checked once; **§12** the bucket as a
  mirror of bounded memory, never a history.
- **[ADR-0005](adr/0005-a-run-is-its-readings-and-the-runs-keep-a-history.md) — a
  run is its readings, and only the runs and the estate keep a history.** The
  conversion to little-sister's measure/grade split: one reading per thing a run read,
  the configuration split by what it spares, a history only for a Batch job's runs, a
  pipeline's executions and the estate, a subject that names an account by its
  configured name, and a root that grades nothing.
