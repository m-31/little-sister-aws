# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  ([ADR-0002](docs/adr/0002-aws-secret-references.md), travelled here with the
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

- **Breaking: this package speaks check API epoch 2 and needs
  `little-sister >= 0.3.13`.** little-sister now reads the whole `subnodes:` block
  itself, for every check type, and a type only **declares** what it ships (its
  ADR-0025, 2026-08-19 update). So this check no longer parses that block, no
  longer layers its own defaults, and no longer hands a `title` / `about` back on
  an aspect result: it declares `SUBNODES` and the `{pin_note}` token, and the
  library resolves and applies them. Nothing changes in **what a deployment
  writes** — the same `subnodes:` block, with the same `{default}` extension — and
  a deployment now gets that block for every installed branch type rather than for
  the ones that chose to read it. Installed beside an older library this package
  refuses at startup, naming both epochs.

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
