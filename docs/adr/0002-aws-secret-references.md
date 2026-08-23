# ADR-0002 — AWS secret references: strict stores, JSON Pointer selection, identity schemes

- **Status:** Accepted
- **Date:** 2026-08-23 (the reference grammar was accepted 2026-08-16)
- **Related:** [ADR-0001](0001-the-aws-check-type.md) (the identity seam these
  resolvers open sessions through), little-sister **ADR-0023** (the
  secret-reference seam and its failure semantics), little-sister **ADR-0035**
  (registering a configuration aspect), little-sister **ADR-0064** (a scheme is
  claimed by exactly one package)

> The reference grammar below was written in the deployment that first needed the
> resolvers and travelled here with the code, renumbered into this repository's
> sequence — the same road this package's check type took. Every committed
> reference and every refusal wording survived that move verbatim, and the suites
> that pin them moved with it.

## Context

The first deployment's GitHub and WIZ checks already named credentials as
little-sister secret references. They used `env://`, while the dashboard this
family replaced read the same values from SSM Parameter Store, and some AWS
secrets are JSON documents containing several credentials.

Little-sister deliberately owns only the `scheme://address` resolver registry. An
application registers a resolver before importing `little_sister.app`, and owns
the cloud SDK it needs; the library ships no AWS client. So the resolvers belong
to a package that already carries boto3 — and they belong beside the sessions
they open, because they cannot borrow a check's: a check's session belongs to a
check run, and constructor secrets resolve before any check exists.

Nor is one identity enough to read them. The secrets sit in **several accounts**,
each reachable only through its own profile and assumed role, and the first
machine that ran this renews its login with `aws sso login` by hand. That is a
requirement about who reads a secret, arriving against a grammar that deliberately
says nothing about identity.

The address becomes committed configuration. Its scheme and selector grammar
therefore have to survive both of those pressures — a move between repositories,
and the arrival of identity — without an edit to a single reference in a single
check file. They did.

## Decision

1. **This package carries the resolvers; the deployment registers them.** The
   implementations are `little_sister_aws.secrets` and the named identities are
   `little_sister_aws.identities`; a deployment turns them on with an explicit
   `register_aws_secret_resolvers()` call in its own import-before-app slot.
   **Nothing registers on import.** Which stores an installation reads its
   credentials from is a decision, and a decision should be readable at the place
   it is taken. Installing the code that implements the schemes changes nothing by
   itself.

   Import order used to be the second reason, and is no longer: little-sister
   ADR-0064 attributes every scheme to the package that claimed it and refuses a
   second claim from another one, so an import-time registration could no longer
   let import order decide where a credential comes from. What that closed is the
   hazard, not the question of where the sentence belongs. The call stays in the
   deployment's own code because that is where somebody reads it.

2. **Secrets Manager accepts only a non-empty `SecretString`.** A missing or empty
   string and a binary-only secret fail resolution. Little-sister's resolver
   contract returns text, so silently decoding an unspecified binary format would
   be a second contract hidden inside the first.

3. **Parameter Store accepts only `SecureString`.** The call always sets
   `WithDecryption=True`, then checks the returned parameter's `Type` is exactly
   `SecureString`. `String`, `StringList`, a missing type and an unknown future
   type all fail even when AWS returned a value: asking for decryption does not
   prove the value was stored encrypted.

4. **Either address may select one string from a JSON document.** Its grammar is
   `<store-id>[#<JSON Pointer>]`, for example
   `aws-ssm:///team/wiz#/oauth/client_secret`. When present, the pointer
   starts with `/`; `~1` means `/` and `~0` means `~`. The resolver removes it
   before calling AWS, parses the fetched text as JSON and returns only a selected
   non-empty string. Invalid pointer syntax, malformed JSON, a missing path or a
   selected object, array, number, boolean, null or empty string fails resolution.
   Without a selector the fetched text is returned unchanged; its contents are
   never guessed from whether it happens to look like JSON.

5. **A reference identifies a secret, not the identity used to read it.** No
   profile, region or role syntax enters the address — ever. The plain `aws-sm://`
   and `aws-ssm://` schemes read through boto3's ordinary credential, profile and
   region chain, which is what an installation with one identity wants and what
   every address committed before identities existed still means.

6. **A deployment may declare named identities, and each one is a scheme pair.**
   In an `aws` configuration aspect — `profile`, `role_arn`, `region`, `sts_region`,
   `role_session_name` per name — registration then registers `aws-sm-<identity>://`
   and `aws-ssm-<identity>://` beside the plain pair. A reference still carries no
   credential, no region and no role: only a **name** for one, which now has
   somewhere to point. How that identity authenticates stays installation
   configuration, outside the reference grammar.

7. **The identity goes in the scheme because no separator survives both stores.** A
   cross-account Secrets Manager read requires a full **ARN** as the secret id, and an
   ARN carries `:`; Parameter Store accepts only a bare name (`a-zA-Z0-9_.-` and `/`)
   and refuses an ARN outright. Any in-address prefix would therefore be a rule with
   an exception inside it, and the exception would be the cross-account case — the one
   the identities exist for. A scheme is committed configuration exactly like the
   address, so nothing is lost by putting the name there.

8. **An unconfigured identity is a configuration error, not a check error.** It is an
   unregistered scheme, so little-sister raises `UnknownSchemeError` and the load
   fails loudly, which is the split little-sister ADR-0023 asked for and is better
   than what an in-address identity could have given: a resolution failure pinning
   one check.

9. **The sessions are the identity seam's** ([ADR-0001](0001-the-aws-check-type.md)):
   the profile/`AssumeRole`/SSO machinery, including the process-wide `SSO_LOGINS`
   with its per-profile lock and cooldown — a second implementation in the same
   process would race it for the same profile's browser. `region` belongs to the
   identity rather than to the session: a Parameter Store name in another region is
   another parameter.

10. **A login at secret-resolution time is bounded by the boot, not by a run.**
    Secrets resolve during the app import inside a gunicorn worker, so an `aws sso
    login` there competes with the worker timeout and the start script's readiness
    wait. It gets one attempt per profile per process and a timeout chosen against
    those, rather than the check's per-run cooldown, which answers a different
    question. In configuration that is an `sso:` block per identity — `login` and
    `timeout`, no `cooldown` — defaulting to 45 seconds against the check's 120; in
    the launcher it is a worker timeout and a readiness wait that a deployment
    raises together, because neither of them alone keeps a boot alive.

11. **Failures disclose addresses, never values.** AWS denial/missing errors,
    wrong store types and JSON-selection errors use little-sister's existing
    `SecretError` path, pinning only the check that needs the secret. A message may
    name the store id and pointer because both are committed configuration; it never
    includes the fetched document or selected value.

## Consequences

- The schemes are **additive**: `env://` and every other registered scheme keep
  working beside them, one `secrets:` block may mix stores per credential, and a
  future provider (another cloud, a vault) arrives as more schemes rather than as
  a replacement. Where a credential does move from `.env` to AWS, that is one
  reference edit and a restart; secret resolution remains once at construction,
  as little-sister ADR-0023 requires.
- A plain-text SSM parameter cannot be accepted by mistake merely because its value
  looks like a credential.
- JSON documents can group related credentials without teaching each check how its
  store represents them. JSON Pointer, including its escaping and array rules, is
  part of the provider contract rather than check code.
- Resolver registration is inert for `env://` references. AWS clients are built
  only when configuration actually selects one of the AWS schemes, so installing
  the provider does not make local startup contact AWS by itself.
- `config/aws.yaml`'s **shape** is this package's while its contents stay each
  deployment's — the same split every aspect-owning package in this family makes.
- A failed or unanswered login at startup leaves the affected checks in `ERROR`
  until a restart, because a secret resolves once at construction (little-sister
  ADR-0023). That is accepted rather than solved here; re-resolution belongs to
  little-sister's reload work.
- This package is now three surfaces rather than one — the `aws` check type, this
  provider, and the identity seam beneath both. That is deliberate and bounded:
  the one AWS check type whose subject is a particular organization's own system
  stays in that deployment, by that deployment's own record, forever.

## Alternatives considered

- **Put the resolvers in little-sister.** Rejected: it would make the core choose
  and ship a cloud SDK despite deliberately exposing an application-owned seam.
- **Leave them in the deployment that first needed them.** That was the right first
  home — check sessions have a different lifecycle, and a package named for checks
  should not quietly become a provider bundle before that surface is designed. It
  stopped being right once the surface *was* designed and a second installation
  wanted the same stores: two deployments would have carried two copies of one
  grammar, and the copies would have disagreed.
- **Use this package's transitive boto3 dependency from the deployment.**
  Rejected: a check package is free to change its implementation without
  preserving a deployment's undeclared import.
- **Accept every SSM parameter type.** Rejected: `WithDecryption=True` is harmless
  for `String` and `StringList`, so it cannot enforce that a credential was stored
  as encrypted secret material.
- **Use dotted JSON paths.** Rejected: a dot may be part of an object key and needs
  a new escaping language. JSON Pointer already defines nested lookup and escaping.
- **Return an entire JSON document when selection fails.** Rejected: a typo would
  pass a credential consumer the wrong value and conceal the configuration error.
- **Carry S3-backed runtime storage here too, while the provider is being built.**
  Rejected: a place to keep state at runtime is a different interface from a place
  to read a secret at construction, and deciding both at once would have settled the
  second one by accident.
