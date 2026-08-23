"""AWS-backed secret resolvers, registered by the deployment that wants them.

``aws-sm://`` reads a text secret from AWS Secrets Manager;
``aws-ssm://`` reads only an SSM Parameter Store ``SecureString``. Either address
may end in ``#/<JSON Pointer>`` to select one non-empty string from a JSON secret.

Either scheme may also carry a **named identity** — ``aws-ssm-live://…`` reads
through the ``live`` entry of ``config/aws.yaml`` (see
:mod:`little_sister_aws.identities`), with its profile and its assumed role.
The plain schemes are the ambient credential chain, which is what a deployment
had before identities existed and what it keeps when it declares none.

**Nothing here registers on import.** A deployment calls
:func:`register_aws_secret_resolvers` in its own import-before-app slot — which
stores it reads its credentials from is a decision, and a decision should be
readable at the place it is taken. Installing this package changes nothing by
itself.

Clients are built only when a secret is resolved — never at registration — and
through one seam per service so the tests do not contact AWS. One session per
identity is opened and shared: two references reading through the same identity
assume its role once, at startup, and both wait for that once.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, TypeAlias, cast

from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError
from little_sister.secrets import Resolver, SecretError, register_resolver

from little_sister_aws.identities import (
    NamedIdentity,
    declare_aspect,
    load_identities,
)
from little_sister_aws.identity import (
    SSO_LOGINS,
    Identity,
    is_credential_error,
    login_command,
    login_problem,
    open_session,
    run_sso_login,
)

if TYPE_CHECKING:
    # Per-service boto3 stubs are development dependencies, not runtime imports.
    from mypy_boto3_secretsmanager.client import SecretsManagerClient
    from mypy_boto3_ssm.client import SSMClient

logger = logging.getLogger(__name__)

JsonValue: TypeAlias = (bool | int | float | str | list["JsonValue"]
                        | dict[str, "JsonValue"] | None)


#: The ambient chain under a name, so that "no identity" and "this identity" take
#: one code path. An :class:`Identity` with neither a profile nor a role is exactly
#: what ``boto3.client(...)`` was doing before this existed.
AMBIENT = NamedIdentity(name="", identity=Identity())

#: Long enough that a boot never opens two browsers for one profile, short enough
#: to be meaningless afterwards — a process that lives for days resolves its
#: secrets in the first second of the first one.
STARTUP_LOGIN_COOLDOWN_SECONDS = 600

#: One session per identity, opened on first use and shared by every reference
#: that names it — so an assumed role is assumed once. Secrets resolve at startup
#: and never again, so these live no longer than the boot that filled them.
_SESSIONS: dict[str, Session] = {}


def _new_session(identity: NamedIdentity) -> Session:
    """Open *identity*'s session — the one seam a test replaces.

    ``open_session`` proves the credentials before it returns: assuming the role
    is that proof where there is a role, and one ``sts:GetCallerIdentity`` where
    there is only a profile. So a stale login fails here, once, naming the
    identity, rather than in the words of whichever store was read first.
    """
    return open_session(identity.identity)


def _sso_login(profile: str, timeout: int) -> str:
    """The one place a subprocess is started — and so the one seam a test
    replaces, the same bargain :func:`_new_session` makes for boto3."""
    return run_sso_login(profile, timeout)


def _renew(identity: NamedIdentity) -> str:
    """Renew this identity's login. ``""`` when AWS is worth asking again.

    The budget is the **boot's**, not a check's: `sso.timeout` here defaults to
    45 seconds rather than the check's 120, because what is waiting is a gunicorn
    worker that has not finished importing the application.

    The cooldown exists only to make *one attempt per profile per process* true —
    a boot lasts seconds, so any non-zero value does that, and two identities
    behind one profile get one browser between them. The bookkeeping is the
    process-wide :data:`~little_sister_aws.identity.SSO_LOGINS`, which is also
    what keeps this login and a *check's* login from opening two windows for one
    expiry.
    """
    profile = identity.identity.profile
    problem = login_problem(profile, identity.sso)
    if problem:
        return problem
    return SSO_LOGINS.renew(profile, timeout=identity.sso.timeout_seconds,
                            cooldown=STARTUP_LOGIN_COOLDOWN_SECONDS,
                            login=_sso_login)


def _refused(identity: NamedIdentity, error: BaseException, problem: str
             ) -> SecretError:
    """Two sentences: what AWS refused, and what a human could do about it.

    The identity is named because it is committed configuration and because
    "which of them" is the first question; the profile's login command is printed
    where there is one, for the same reason the check prints it on a node. No
    fetched value can be here — nothing has been read yet.
    """
    who = (f"AWS identity {identity.name!r}" if identity.name
           else "the ambient AWS chain")
    profile = identity.identity.profile
    advice = (f"renew it with `{login_command(profile)}` — {problem}"
              if profile else problem)
    return SecretError(f"{who} has no usable credentials: {error}. {advice}")


def _session_for(identity: NamedIdentity) -> Session:
    """This identity's session, opening it once and renewing a stale login once.

    The retry is the whole point, and it is the same bargain the `aws` check
    makes during a run: an SSO login expires about once a working day, and on
    the machine where that happens the fix is a command this process can run. The
    difference is *when* — here it is the import, so a login that cannot happen
    fails the secret rather than reddening a node, and every check that named
    this identity is pinned until a restart.
    """
    cached = _SESSIONS.get(identity.name)
    if cached is not None:
        return cached
    try:
        session = _new_session(identity)
    except (BotoCoreError, ClientError) as error:
        if not is_credential_error(error):
            raise
        problem = _renew(identity)
        if problem:
            raise _refused(identity, error, problem) from error
        try:
            session = _new_session(identity)
        except (BotoCoreError, ClientError) as again:
            raise _refused(
                identity, again,
                "the login was renewed and the credentials are still refused"
            ) from again
        logger.info("aws: %s opened after renewing its login",
                    identity.name or "the ambient chain")
    _SESSIONS[identity.name] = session
    return session


def _new_secrets_manager_client(
        identity: NamedIdentity = AMBIENT) -> SecretsManagerClient:
    """A Secrets Manager client for *identity*, in the region it names."""
    return _session_for(identity).client(
        "secretsmanager", region_name=identity.region or None)


def _new_ssm_client(identity: NamedIdentity = AMBIENT) -> SSMClient:
    """A Parameter Store client for *identity*, in the region it names."""
    return _session_for(identity).client(
        "ssm", region_name=identity.region or None)


def forget_sessions() -> None:
    """Drop every opened session. For tests, and for a registration that runs
    twice in one process."""
    _SESSIONS.clear()


def _address_parts(address: str) -> tuple[str, str | None]:
    """Split ``store-id#/pointer`` without sending the selector to AWS."""
    store_id, marker, pointer = address.partition("#")
    if not store_id:
        raise SecretError("AWS secret address has no store id before its JSON Pointer")
    if not marker:
        return store_id, None
    if not pointer.startswith("/"):
        raise SecretError(
            f"AWS secret address {store_id!r} has an invalid JSON Pointer: "
            "the selector after '#' must start with '/'")
    return store_id, pointer


def _pointer_token(encoded: str, *, store_id: str, pointer: str) -> str:
    """Decode one RFC 6901 token, refusing every escape except ``~0``/``~1``."""
    decoded: list[str] = []
    index = 0
    while index < len(encoded):
        character = encoded[index]
        if character != "~":
            decoded.append(character)
            index += 1
            continue
        if index + 1 >= len(encoded) or encoded[index + 1] not in {"0", "1"}:
            raise SecretError(
                f"JSON Pointer {pointer!r} for AWS secret {store_id!r} "
                "contains an invalid '~' escape")
        decoded.append("~" if encoded[index + 1] == "0" else "/")
        index += 2
    return "".join(decoded)


def _array_index(token: str, *, store_id: str, pointer: str) -> int:
    """Read the canonical JSON Pointer spelling of an array index."""
    digits = bool(token) and all("0" <= character <= "9" for character in token)
    if not digits or (len(token) > 1 and token.startswith("0")):
        raise SecretError(
            f"JSON Pointer {pointer!r} for AWS secret {store_id!r} "
            f"has invalid array index {token!r}")
    return int(token)


def _select_json(raw: str, *, store_id: str, pointer: str | None) -> str:
    """Return raw text, or the non-empty string selected from its JSON value."""
    if pointer is None:
        return raw
    invalid_json = False
    try:
        current = cast(JsonValue, json.loads(raw))
    except json.JSONDecodeError:
        # Raise after leaving the handler: JSONDecodeError retains its input as
        # ``.doc``, so chaining it would attach the fetched secret to our error.
        current = None
        invalid_json = True
    if invalid_json:
        raise SecretError(
            f"AWS secret {store_id!r} is not valid JSON for Pointer {pointer!r}")

    for encoded in pointer[1:].split("/"):
        token = _pointer_token(encoded, store_id=store_id, pointer=pointer)
        if isinstance(current, dict):
            if token not in current:
                raise SecretError(
                    f"JSON Pointer {pointer!r} does not exist in AWS secret "
                    f"{store_id!r}")
            current = current[token]
            continue
        if isinstance(current, list):
            index = _array_index(token, store_id=store_id, pointer=pointer)
            if index >= len(current):
                raise SecretError(
                    f"JSON Pointer {pointer!r} does not exist in AWS secret "
                    f"{store_id!r}")
            current = current[index]
            continue
        raise SecretError(
            f"JSON Pointer {pointer!r} cannot be traversed in AWS secret "
            f"{store_id!r}")

    if not isinstance(current, str) or current == "":
        raise SecretError(
            f"JSON Pointer {pointer!r} in AWS secret {store_id!r} "
            "does not select a non-empty string")
    return current


def resolve_secrets_manager(address: str,
                            identity: NamedIdentity = AMBIENT) -> str:
    """Resolve one ``aws-sm`` address to a non-empty ``SecretString`` value."""
    secret_id, pointer = _address_parts(address)
    response = _new_secrets_manager_client(identity).get_secret_value(
        SecretId=secret_id)
    value = response.get("SecretString")
    if not isinstance(value, str) or value == "":
        raise SecretError(
            f"AWS Secrets Manager secret {secret_id!r} has no non-empty "
            "SecretString (binary secrets are not supported)")
    return _select_json(value, store_id=secret_id, pointer=pointer)


def resolve_parameter_store(address: str,
                            identity: NamedIdentity = AMBIENT) -> str:
    """Resolve one ``aws-ssm`` address, accepting only ``SecureString``."""
    parameter_name, pointer = _address_parts(address)
    response = _new_ssm_client(identity).get_parameter(
        Name=parameter_name, WithDecryption=True)
    parameter = response.get("Parameter")
    if not isinstance(parameter, dict):
        raise SecretError(
            f"AWS Parameter Store returned no parameter for {parameter_name!r}")
    parameter_type = parameter.get("Type")
    if parameter_type != "SecureString":
        shown_type = repr(parameter_type) if parameter_type is not None else "missing"
        raise SecretError(
            f"AWS Parameter Store parameter {parameter_name!r} has type "
            f"{shown_type}; expected SecureString")
    value = parameter.get("Value")
    if not isinstance(value, str) or value == "":
        raise SecretError(
            f"AWS Parameter Store SecureString {parameter_name!r} has no "
            "non-empty value")
    return _select_json(value, store_id=parameter_name, pointer=pointer)


def _bind(resolve: Callable[[str, NamedIdentity], str],
          identity: NamedIdentity) -> Resolver:
    """One resolver, for one identity. The registry hands a resolver the address
    and nothing else, so *which identity* has to be closed over here."""
    def resolver(address: str) -> str:
        return resolve(address, identity)
    return resolver


def register_aws_secret_resolvers(
        identities: Mapping[str, NamedIdentity] | None = None) -> None:
    """Install the AWS schemes before ``little_sister.app`` is imported.

    ``aws-sm`` and ``aws-ssm`` are the ambient chain, exactly as they were. Every
    identity in ``config/aws.yaml`` adds a pair of its own —
    ``aws-sm-<name>`` and ``aws-ssm-<name>`` — so a reference names an identity
    without carrying a credential, a region or a role (ADR-0002).

    An identity nobody declared is therefore a scheme nobody registered, which
    little-sister refuses at load naming the reference: a configuration error,
    loudly, rather than one check pinned to a puzzle.
    """
    if identities is None:
        # The aspect has to be declared before anything asks for its file, and
        # this call *is* the import-before-app slot little-sister ADR-0035 means
        # by "before the first configuration scan".
        declare_aspect()
        identities = load_identities()
    declared = identities
    register_resolver("aws-sm", _bind(resolve_secrets_manager, AMBIENT))
    register_resolver("aws-ssm", _bind(resolve_parameter_store, AMBIENT))
    for name, identity in declared.items():
        register_resolver(f"aws-sm-{name}",
                          _bind(resolve_secrets_manager, identity))
        register_resolver(f"aws-ssm-{name}",
                          _bind(resolve_parameter_store, identity))


__all__ = ["forget_sessions", "register_aws_secret_resolvers"]
