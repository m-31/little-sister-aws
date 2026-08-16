# ADR-0001 — The `aws` check type: account nodes, aspect leaves, and boto3

- **Status:** Accepted
- **Date:** 2026-08-10
- **Related:** little-sister **ADR-0042** (coded entries), little-sister
  **ADR-0043** / **ADR-0044** (the coverage reading and the roster), little-sister
  **ADR-0025** (subnode text),
  **plugin-repository.md** (the lift-out this ADR promised, and which has happened)

> **Update (2026-08-12) — the account's *login*, not just its role.** Decision 2
> below gave each account a node and its own session; what it did not say was
> where the session the role is assumed **from** comes from. It came from the
> ambient chain, one for all accounts, which is right on a server and wrong on the
> machine this is developed on: one config's roles and another's can live in
> **different organizations**, reachable only as two different `~/.aws/config`
> profiles. So:
>
> - **`profile:` is readable at the check and on an account**, exactly like
>   `regions:`, and it **composes** with `role_arn` rather than replacing it —
>   `profile` says from where, `role_arn` says into what. Unset it changes
>   nothing: boto3 reads the ambient chain, `AWS_PROFILE` included. It is
>   **mutually exclusive with a `secrets:` block**, because a profile *is* a set
>   of credentials and a config naming both has said two things about which
>   estate it watches.
> - An account with a profile and **no** role spends one `sts:GetCallerIdentity`
>   before its aspects run. Assuming a role was already the proof that the
>   credentials work; without one there was nothing to fail until three aspects
>   failed separately, each in its own words.
> - **An expired SSO login is renewable, and the check decides whether renewing
>   is even a sensible thing to attempt here.** `sso.login: auto` — the default —
>   runs `aws sso login` only where it can work: an SSO profile, the `aws` CLI on
>   `PATH`, no platform-supplied credentials (`AWS_EXECUTION_ENV`,
>   `ECS_CONTAINER_METADATA_URI`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
>   `KUBERNETES_SERVICE_HOST`, …), not a container, and a machine where a browser
>   opens. `always` skips the question, `never` never shells out. **The decision
>   and its reason are printed on the check's card**, because "auto" without a
>   word on whether auto works here is the reassuring version of saying nothing.
> - The renewal is bounded twice: a **timeout** (default 2m), because a login
>   holds an engine worker thread while it waits for a human, and a **cooldown**
>   (default 10m) **per profile, in process-wide state**, because the browser and
>   the token cache belong to the machine — two checks on one profile must not
>   both open a login, and at `frequency: 60s` a login nobody completes would
>   otherwise be a browser window a minute for as long as you are away from the
>   desk.
> - Either way the account carries **two lines**: what expired, and the exact
>   `aws sso login --profile …` that fixes it — except where no profile is
>   configured, since telling a server to open a browser is advice for a machine
>   that is not this one.
>
> Nothing here is a departure from the decisions below; it is the credential half
> of decision 2 written down. It travels to `little-sister-aws` with the rest —
> `subprocess` and `shutil` are stdlib, and the capability test is a pure function
> of what it is handed.

## Context

Watching several AWS accounts raises four questions before any of them is about
CloudWatch. Whether one check type reads every service or one reads each; whether
the tree branches on the account or on the service; what a single alarm is, as a
thing an operator acts on; and how to reach AWS at all.

The obvious arrangement — a check type per service, each building its own session,
each returning a flat list tagged with the environment it came from — answers all
four badly at once, and answers them again for every service added. What follows is
the arrangement this type uses instead, and why.

## Decision

### 1. One type, `aws`, with aspects — not one type per service

The other checks in that codebase (`infrastructure.py`: long-running batch EC2
instances, SageMaker kernel gateways, duplicate autoscaling groups) read the *same
accounts through the same assumed session*. A type per service would assume every
role once per service, carry the account list three times, and give the dashboard
three unrelated nodes for one provider. `github` already answers this shape:
one check, one credential, one frequency, one child per aspect.

### 2. Account first, aspect second

The tree is `/<path>/<account>/<aspect>`, not `/<path>/<aspect>` with the account
in each line. Three reasons, in the order they mattered:

- **A pin needs a node.** "Staging is down for the migration" is one maintenance
  pin on one node. Flat, it is one pin per alarm, and the next deploy invents new
  alarms that nobody pinned.
- **A failure needs an owner.** An account whose role cannot be assumed reddens
  *its* node and the others keep reporting. Flat, that failure has nowhere to live
  except the root, where it either colours everything or is lost among the lines.
- **A tag on every line is a tree that was not available.** Labelling each result
  with the environment it came from is what a flat list does when it cannot branch.
  This one can, so the label becomes the node.

The aspect leaf itself stays **flat**: an alarm carries its own verdict, so the
finding is what an operator acts on, and each line is a coded `Entry`
(little-sister ADR-0042). Where an estate sorts alarms by a name prefix, that
becomes one word on the line (`tag_prefix`) rather than a second node — the account
is what such a split is usually carrying, and the tree carries the account.

### 3. boto3, not stdlib `urllib`

Every other check type in this family reaches its provider over stdlib `urllib`,
and each ships with little-sister as its only dependency. This one does not.
Signing SigV4 for `sts:AssumeRole` and the CloudWatch API by hand is a signing
implementation plus the test suite that keeps it honest, bought to save a
dependency that AWS itself maintains, that is already in this deployment's
transitive world the moment anything talks to AWS, and that the eventual
`aws-ssm://` secret resolver will want anyway.

The cost is named rather than waved away: `little-sister-aws` will be the first
package in the family with a dependency beyond little-sister, and it declares it
as a **floor**, like its little-sister floor. `boto3-stubs[cloudwatch,sts]` goes
in the dev group — without the per-service extras every client types as
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

## Consequences

- `boto3` is this package's dependency, declared as a **floor** beside the library's
  own — the first in the family to have one beyond little-sister.
- A maintenance pin is keyed `(path, slug)`. The path carries the account, so the
  slug does not; it carries the **region**, always, even where the line does not
  print it — otherwise every pin re-points the day a second region is configured.
  Neither carries the alarm ARN, because that carries the account id and a private
  string in a `?reason=` value is a private string in somebody's bookmark.
- Two gradings are deliberate and worth knowing on the first run, because the
  cheaper reading of each is the one people expect: `INSUFFICIENT_DATA` is a
  **WARN**, not an OK, since an alarm with no data is usually an alarm whose metric
  stopped arriving; and **composite alarms are read**, because `describe_alarms`
  returns only metric alarms unless asked and a blind spot is easy to inherit
  without deciding to. Both are one `state_map` / `include_composite` line away from
  the other answer, which is the point of them being configuration.
- Every account gets every aspect. The day an account runs no SageMaker, that
  becomes a per-account `aspects:` list; it is not one today because a list with
  one member in it teaches nobody anything.
