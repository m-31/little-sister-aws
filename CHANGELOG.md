# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  non-counting behavior as before. The other four aspects keep their
  `ignore_name_patterns` for now.

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
  refusal now says both ways out rather than only what is wrong. See ADR-0002 §6's
  update note.

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
  about your configuration, and colouring a card over it would send somebody
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

- **Breaking: this package speaks check API epoch 2 and needs `little-sister >=
  0.3.13`.** little-sister now reads the whole `subnodes:` block itself, for every check
  type, and a type only **declares** what it ships (its ADR-0025). So this check no
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
