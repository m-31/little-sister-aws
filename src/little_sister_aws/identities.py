"""The named AWS identities a deployment reads its **secrets** with.

A secret reference names *what* to read (ADR-0002). This module is *who reads
it*: the ``aws`` configuration aspect — ``config/aws.yaml`` — declares named
identities, a profile, a role to assume, the region the store lives in, and
each name becomes a **scheme** of its own, so a reference stays a name for a
secret and never carries a credential:

.. code-block:: yaml

    live:
      profile: primary-admin
      role_arn: arn:aws:iam::000000000000:role/monitoring-role
      region: eu-central-1

.. code-block:: yaml

    token: aws-ssm-live:///team/github/token

The identity goes in the scheme rather than in the address because no separator
survives both stores: a cross-account Secrets Manager id is an **ARN**, which
carries ``:``, while Parameter Store takes a bare name and refuses an ARN
outright. A scheme has room, is committed configuration exactly like the
address, is claimed once, and gives the error split for free — an identity
nobody declared is an unregistered scheme, which little-sister refuses at load
rather than pinning one check to a puzzle.

This package owns the file's **shape**; a deployment owns its contents, and
whether the file is read at all — registration is a call the deployment makes
(:func:`little_sister_aws.secrets.register_aws_secret_resolvers`), never a
side effect of installing this package. The sessions come from
:mod:`little_sister_aws.identity` beside this module: one implementation of
profile, ``AssumeRole`` and the SSO login bookkeeping per process.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from little_sister.config_dir import register_aspect, sole_aspect_file

from little_sister_aws.identity import (
    DEFAULT_ROLE_SESSION_NAME,
    DEFAULT_STS_REGION,
    Identity,
    OptionalTextError,
    SsoBlockError,
    SsoConfig,
    parse_optional_text,
    parse_sso_block,
)

logger = logging.getLogger(__name__)

#: The configuration aspect this package's provider half adds: ``config/aws.yaml``.
ASPECT = "aws"

#: What one identity entry may carry. Anything else is a typo worth naming: a
#: misspelled ``role_arn`` would otherwise leave the identity reading the store
#: with the profile's own rights, which is a different account's answer to the
#: same question and looks like nothing went wrong.
_KEYS = frozenset({"profile", "role_arn", "region", "sts_region",
                   "role_session_name", "sso"})

#: How long an ``aws sso login`` may hold the **boot** — a much smaller number than
#: the check's, and for a different reason: a check spends its own timeout on an
#: engine worker thread, while this one is holding a worker that has not finished
#: importing the application. Both of a launcher's waits have to be longer than
#: this times the number of distinct profiles that could need a login; the
#: deployment's start script is where that arithmetic is written.
DEFAULT_STARTUP_LOGIN_TIMEOUT_SECONDS = 45

#: What an identity may be called. It becomes the tail of a **scheme**
#: (``aws-ssm-<name>``), and little-sister lower-cases and strips a scheme before
#: it looks it up, so a name that is not already in this shape would be registered
#: under one spelling and looked up under another.
_NAME = re.compile(r"[a-z][a-z0-9-]*")


class IdentityConfigError(Exception):
    """``config/aws.yaml`` cannot be read as identities.

    Raised, not logged. Every other failure on the AWS secret path is
    deliberately narrow — one check pinned, everything else reporting — but
    this file decides *which account a credential is read from*, and a
    deployment that started with half of its identities missing would resolve
    secrets through whatever the ambient chain happens to be. That is the
    failure named identities exist to prevent, so it is a refusal to start, at
    the place that can still say why.
    """


def startup_sso() -> SsoConfig:
    """The login policy an identity gets when it says nothing: ask the machine
    first, and hold the boot for no longer than
    :data:`DEFAULT_STARTUP_LOGIN_TIMEOUT_SECONDS`."""
    return SsoConfig(timeout_seconds=DEFAULT_STARTUP_LOGIN_TIMEOUT_SECONDS)


@dataclass(frozen=True)
class NamedIdentity:
    """One declared identity: how to become it, and where its stores are.

    ``region`` is not part of :class:`~little_sister_aws.identity.Identity`
    because a *session* has no one region — a check reads several. A **store**
    does: a Parameter Store name exists in one region, and a Secrets Manager
    secret in another is a different secret. Empty means the region the profile
    or the environment already implies, which is the case a single-region
    installation never has to think about.
    """

    name: str
    identity: Identity
    region: str = ""
    sso: SsoConfig = field(default_factory=lambda: startup_sso())


def _text(entry: Mapping[str, Any], key: str, *, where: str) -> str:
    """One optional string. A key written and left empty is a typo, not a value —
    the same rule the `aws` check learned the hard way about ``profile:``, read
    by the identity seam's one reader (``parse_optional_text``) and refused
    here in this file's words, as the ``IdentityConfigError`` that stops the
    start."""
    try:
        return parse_optional_text(entry, key, where=f"{where}: {key!r}")
    except OptionalTextError as error:
        if error.kind == "left-empty":
            raise IdentityConfigError(
                f"{where}: {key!r} was written and left empty") from error
        raise IdentityConfigError(
            f"{where}: {key!r} must be a non-empty string") from error


def _sso_message(where: str, error: SsoBlockError) -> str:
    """This file's own sentence for one refused ``sso:`` block.

    The reader hands back parts; the words are this file's and stay here —
    they quote ``'sso.timeout'`` whole and say "more than zero" where the two
    check suites close the quote early and say "greater", and this suite pins
    the difference. A wording that lived in the shared reader would be one of
    those three suites broken the day anybody harmonized it.
    """
    if error.kind == "not-a-mapping":
        return f"{where}: 'sso' must be a mapping"
    if error.kind == "unknown-keys":
        return (f"{where}: unknown key(s) in 'sso' "
                f"{', '.join(repr(key) for key in error.unknown)} "
                f"— known: {', '.join(error.accepted)}")
    if error.kind == "not-a-mode":
        return (f"{where}: 'sso.login' must be one of "
                f"{', '.join(error.accepted)} (got {error.got!r})")
    if error.kind == "not-a-duration":
        return f"{where}: 'sso.{error.key}': {error.problem}"
    if error.kind == "not-positive":
        # Zero would not mean "no timeout" — it would mean "kill it before it
        # starts", and an unbounded login holds a booting worker forever.
        return f"{where}: 'sso.timeout' must be more than zero"
    return str(error)  # a kind this file has no sentence for yet


def _sso(value: object, *, where: str) -> SsoConfig:
    """The ``sso:`` block — whether this identity may renew its own login, and
    what that may cost the boot.

    The reading is ``parse_sso_block``'s, beside the :class:`SsoConfig` it
    produces (ADR-0001 §6). What stays here is everything
    that makes the block an *identity's*: the boot's budget as the default
    (:func:`startup_sso`, 45 seconds against the check's 120), **no**
    ``cooldown`` key — a cooldown answers "how often may an unattended machine
    re-open a browser", and a startup reads its secrets once — and the
    sentences above, raised as the :class:`IdentityConfigError` that refuses
    the start, file and identity named, where a check's same block would only
    pin that check.
    """
    try:
        return parse_sso_block(value, where=f"{where}: 'sso'",
                               default=startup_sso(), allow_cooldown=False)
    except SsoBlockError as error:
        raise IdentityConfigError(_sso_message(where, error)) from error


def _identity(name: str, entry: object, *, path: Path) -> NamedIdentity:
    """One ``name: {…}`` block, refused rather than guessed at."""
    where = f"{path}: identity {name!r}"
    if not _NAME.fullmatch(name):
        raise IdentityConfigError(
            f"{path}: {name!r} is not a usable identity name — it becomes the tail "
            "of a scheme, so it must start with a lower-case letter and carry only "
            "lower-case letters, digits and hyphens")
    if not isinstance(entry, Mapping):
        raise IdentityConfigError(
            f"{where} must be a mapping of settings, got "
            f"{type(entry).__name__}")
    unknown = sorted(set(entry) - _KEYS)
    if unknown:
        raise IdentityConfigError(
            f"{where}: unknown key(s) {', '.join(repr(key) for key in unknown)} "
            f"— known: {', '.join(sorted(_KEYS))}")
    identity = Identity(
        profile=_text(entry, "profile", where=where),
        role_arn=_text(entry, "role_arn", where=where),
        role_session_name=(_text(entry, "role_session_name", where=where)
                           or DEFAULT_ROLE_SESSION_NAME),
        sts_region=(_text(entry, "sts_region", where=where)
                    or DEFAULT_STS_REGION))
    if not identity.profile and not identity.role_arn:
        raise IdentityConfigError(
            f"{where} names neither a profile nor a role, so it is the ambient "
            "chain under another name — use the plain 'aws-sm://' and "
            "'aws-ssm://' schemes for that")
    return NamedIdentity(name=name, identity=identity,
                         region=_text(entry, "region", where=where),
                         sso=_sso(entry.get("sso"), where=where))


def load_identities(spec: str | Path | None = None) -> dict[str, NamedIdentity]:
    """Every identity ``config/aws.yaml`` declares, or none where there is no file.

    No file and an empty file both mean *no named identities*, which is exactly
    what a deployment ran with before they existed: the plain schemes on the
    ambient chain. Anything else that cannot be read is a refusal.
    """
    path = sole_aspect_file(ASPECT, spec)
    if path is None:
        logger.info("aws: no %s.yaml in the configuration — the plain 'aws-sm://' "
                    "and 'aws-ssm://' schemes only", ASPECT)
        return {}
    try:
        body = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise IdentityConfigError(f"{path} could not be read: {error}") from error
    if body is None:
        return {}
    if not isinstance(body, Mapping):
        raise IdentityConfigError(
            f"{path} must be a mapping of identity names, got "
            f"{type(body).__name__}")
    identities = {str(name): _identity(str(name), entry, path=path)
                  for name, entry in body.items()}
    logger.info("aws: %d identit(y/ies) declared in %s: %s", len(identities),
                path, ", ".join(sorted(identities)) or "none")
    return identities


def declare_aspect() -> None:
    """Claim ``config/aws.yaml`` before the first configuration scan."""
    register_aspect(ASPECT)


__all__ = ["ASPECT", "DEFAULT_STARTUP_LOGIN_TIMEOUT_SECONDS",
           "IdentityConfigError", "NamedIdentity", "declare_aspect",
           "load_identities"]
