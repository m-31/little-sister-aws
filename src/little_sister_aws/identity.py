"""How this process becomes somebody who may read an AWS account.

An :class:`Identity` is one reading identity — a profile, static keys, a role to
assume, and where to assume it — and :func:`open_session` turns one into a boto3
session whose credentials have been **proven**. Beside it lives everything that
answers an *expired* login: :func:`login_capability` (whether ``aws sso login``
could work on this machine at all), :func:`run_sso_login` (the one place a
subprocess starts) and :data:`SSO_LOGINS` (one instance per process, so two
callers behind one profile cannot both open a browser).

This is the package's second public surface, and it exists because the ``aws``
check is no longer the only thing in a process that has to open a session: a
deployment resolving an AWS-backed **secret reference** needs the same profile,
the same role and the same login, at a time when no check exists yet
(:doc:`../docs/adr/0001-the-aws-check-type`). Two rules follow from
that second caller, and both are why this module is not simply the check's private
helpers under a new name:

* **No check, no file, no run.** Nothing here reads a configuration file, knows
  a check type's schema, or needs a check to have been built. What a caller has
  to say, it says in arguments — and where three packages write the same thing,
  the argument may be the mapping itself: :func:`parse_sso_block` takes one
  ``sso:`` block from whoever read the file, :func:`parse_optional_text` one
  optional string field (a profile, a role, a region), and each answers with
  its value or with the **parts** of a refusal (:class:`SsoBlockError`,
  :class:`OptionalTextError`) for the caller to word and type itself.
* **The login budget belongs to the caller.** A renewal during a check *run* may
  spend that check's timeout; a renewal during an application's *import* may not,
  because something is booting behind it. So :meth:`SsoLogins.renew` takes its
  timeout and cooldown as arguments and reads no configuration of its own.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

import boto3
import botocore.session
from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError
from little_sister.checks import CheckError, parse_duration, plain
from little_sister.spans import format_span

#: This module's own logger, under this module's name — little-sister configures
#: the root handlers, so the records land where every other line does.
logger = logging.getLogger(__name__)

#: What the assumed session is called — the string CloudTrail shows beside every
#: call made through it. It names *the reader*, which is the useful thing for
#: somebody reading an audit log, so the default names this package. An
#: installation that wants its own history in CloudTrail sets
#: ``role_session_name`` and gets it.
DEFAULT_ROLE_SESSION_NAME = "little-sister"

#: Where the ``AssumeRole`` call itself is made. STS has a global endpoint, but a
#: regional endpoint is the faster and more available of the two.
DEFAULT_STS_REGION = "eu-central-1"

#: ``sso.login`` — when a caller may run ``aws sso login`` itself.
#: :data:`SSO_LOGIN_AUTO` is the default and asks :func:`login_capability`
#: first; :data:`SSO_LOGIN_ALWAYS` skips that question (a machine that knows
#: better than the guess); :data:`SSO_LOGIN_NEVER` never shells out and only
#: prints the command.
SSO_LOGIN_AUTO = "auto"
SSO_LOGIN_ALWAYS = "always"
SSO_LOGIN_NEVER = "never"
SSO_LOGIN_MODES = (SSO_LOGIN_AUTO, SSO_LOGIN_ALWAYS, SSO_LOGIN_NEVER)

#: How long ``aws sso login`` may take before it is killed. It is waiting for a
#: human at a browser, so it is generous — but it is bounded, because it holds
#: whatever thread called it for as long as it runs. A caller whose thread is a
#: worker booting an application wants a much smaller number, which is why this
#: is a default rather than a rule.
DEFAULT_SSO_LOGIN_TIMEOUT_SECONDS = 120

#: How long after an attempt the next one may be made, per profile. This is the
#: knob that keeps an unattended machine sane: without it a login that nobody
#: completes is retried on every run, and at ``frequency: 60s`` that is a browser
#: window a minute for as long as you are away from the desk.
DEFAULT_SSO_LOGIN_COOLDOWN_SECONDS = 600

#: Environment variables that mean *the platform supplies these credentials* —
#: a task role, an instance profile, a pod identity, a Lambda. Any of them set
#: is a machine where no browser will ever open and where credentials renew
#: themselves anyway, so ``login: auto`` stays out of the way.
CLOUD_MARKERS = (
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_NAME",
    "ECS_CONTAINER_METADATA_URI",
    "ECS_CONTAINER_METADATA_URI_V4",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "KUBERNETES_SERVICE_HOST",
)

#: Files that say "inside a container". Docker writes the first, Podman the
#: second. A container is not automatically a *cloud* instance, but it is a
#: place where ``aws sso login`` opens a browser that nobody can see.
CONTAINER_MARKERS = ("/.dockerenv", "/run/.containerenv")

#: Error codes and exception types that mean *the credentials went stale* rather
#: than *the answer is no*. Taken from ``var/account/s3_copy.py``, which learned
#: them the long way on cross-account copies that outlive one credential window.
CREDENTIAL_ERROR_CODES = frozenset({
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidToken",
    "TokenRefreshRequired",
    "RequestExpired",
    "RequestTimeTooSkewed",
})
CREDENTIAL_ERROR_TYPES = frozenset({
    "CredentialRetrievalError",
    "NoCredentialsError",
    "PartialCredentialsError",
    "TokenRetrievalError",
    "UnauthorizedSSOTokenError",
    "SSOTokenLoadError",
    "SSOError",
})


#: The environment variables botocore reads for the ambient profile name, in its
#: own order of precedence. They are read here for **reporting** only — what the
#: ambient chain resolves to is boto3's business, and this is how a card can say
#: which profile that turned out to be instead of leaving an operator to guess.
AMBIENT_PROFILE_VARS = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE")


def ambient_profile(environ: Mapping[str, str]) -> tuple[str, str]:
    """The variable and profile name the ambient chain would take from *environ*,
    or ``("", "")`` where it names none.

    A pure function of what it is handed, for the reason :func:`login_capability`
    is one: the answer is a sentence somebody reads off a card.
    """
    for variable in AMBIENT_PROFILE_VARS:
        value = environ.get(variable, "").strip()
        if value:
            return variable, value
    return "", ""


@dataclass(frozen=True)
class SsoConfig:
    """The ``sso:`` block: whether, and how hard, to renew a login."""

    login: str = SSO_LOGIN_AUTO
    timeout_seconds: int = DEFAULT_SSO_LOGIN_TIMEOUT_SECONDS
    cooldown_seconds: int = DEFAULT_SSO_LOGIN_COOLDOWN_SECONDS


# --- reading an ``sso:`` block -----------------------------------------------


#: What :class:`SsoBlockError` reports was wrong: the block was not a mapping;
#: it carried a key nobody knows; ``login`` named no mode in
#: :data:`SSO_LOGIN_MODES`; a duration could not be read at all; ``timeout``
#: was zero or less; ``cooldown`` was below zero.
SsoBlockKind = Literal["not-a-mapping", "unknown-keys", "not-a-mode",
                       "not-a-duration", "not-positive", "negative"]


class SsoBlockError(Exception):
    """One refused ``sso:`` block, as **parts rather than a sentence**.

    Three packages write this block, and their suites pin refusal sentences
    that disagree on purpose — quote placement, "greater" against "more", a
    grammar per site — and refusal *types* that disagree for better reason: a
    check's bad block pins that check, an identity file's refuses a whole
    start. No shared sentence can satisfy them, so this error carries what a
    sentence would have to say — *which key* (:attr:`key`), *what was wrong
    with it* (:attr:`kind`, with :attr:`got`, :attr:`unknown` or
    :attr:`problem` as the kind requires), *what would have been accepted*
    (:attr:`accepted`) — and every caller translates the type and renders its
    own words from the parts.

    ``str()`` of one is a plain factual line for logs and tracebacks, so that
    even a refusal nobody translated still names its block. It is not operator
    prose and no caller should show it as any; the sentences belong to the
    call sites.
    """

    def __init__(self, kind: SsoBlockKind, *, where: str, key: str = "",
                 got: object = None, unknown: tuple[str, ...] = (),
                 accepted: tuple[str, ...] = (), problem: str = "") -> None:
        bits: list[str] = [kind]
        if key:
            bits.append(f"key {key!r}")
        if unknown:
            bits.append("unknown " + ", ".join(unknown))
        if got is not None:
            bits.append(f"got {got!r}")
        if accepted:
            bits.append("accepted " + ", ".join(accepted))
        if problem:
            bits.append(problem)
        super().__init__(f"{where}: " + "; ".join(bits))
        self.kind: SsoBlockKind = kind
        self.where = where
        self.key = key
        self.got = got
        self.unknown = unknown
        self.accepted = accepted
        self.problem = problem


#: What a caller that passes no ``default=`` gets: the module's own numbers
#: above, i.e. a *check's* budget. Module state rather than a call in the
#: signature; frozen, so shared is safe.
_DEFAULT_SSO = SsoConfig()


def parse_sso_block(value: object, *, where: str,
                    default: SsoConfig = _DEFAULT_SSO,
                    allow_cooldown: bool = True) -> SsoConfig:
    """One ``sso:`` block — whether, and how hard, to renew a login.

    The one reader of the block, with the differences between its callers as
    arguments rather than smoothed away. *default* is where the budget lives:
    absent keys — and an absent block — mean *default*'s numbers, so a check
    keeps its generous window and a boot passes its short one, and this
    function knows neither (the same rule :meth:`SsoLogins.renew` follows for
    the same reason). *allow_cooldown* is whether ``cooldown`` is a key at
    all: it answers "how often may an unattended machine re-open a browser",
    which a caller that reads its secrets once at startup must refuse rather
    than ignore. *where* names the block in the error's own factual line —
    the callers' rendered sentences carry their own subject.

    A block that cannot be read raises :class:`SsoBlockError`, never a
    sentence of this module's: which sentence a refusal earns, and what type
    carries it, are the caller's decisions and stay at the call sites.
    """
    if value is None:
        return default
    if not isinstance(value, Mapping):
        raise SsoBlockError("not-a-mapping", where=where, got=value)
    known = (("cooldown", "login", "timeout") if allow_cooldown
             else ("login", "timeout"))
    unknown = tuple(sorted(str(key) for key in value if str(key) not in known))
    if unknown:
        raise SsoBlockError("unknown-keys", where=where, unknown=unknown,
                            accepted=known)
    login = str(value.get("login", default.login)).strip().lower()
    if login not in SSO_LOGIN_MODES:
        raise SsoBlockError("not-a-mode", where=where, key="login", got=login,
                            accepted=SSO_LOGIN_MODES)
    timeout = _sso_duration(value.get("timeout"), default.timeout_seconds,
                            where=where, key="timeout")
    if timeout <= 0:
        # Zero would not mean "no timeout" here — it would mean "kill it before
        # it starts", and an unbounded login holds whatever thread called it
        # for as long as a human ignores a browser.
        raise SsoBlockError("not-positive", where=where, key="timeout",
                            got=timeout)
    cooldown = default.cooldown_seconds
    if allow_cooldown:
        cooldown = _sso_duration(value.get("cooldown"),
                                 default.cooldown_seconds,
                                 where=where, key="cooldown")
        if cooldown < 0:
            raise SsoBlockError("negative", where=where, key="cooldown",
                                got=cooldown)
    return SsoConfig(login=login, timeout_seconds=timeout,
                     cooldown_seconds=cooldown)


def _sso_duration(value: object, fallback: int, *, where: str,
                  key: str) -> int:
    """``parse_duration``, its ``CheckError`` caught at the source.

    Not every caller of the reader speaks that exception — and one of them
    once let it escape an application boot naming no file, no identity and no
    key. The catch is here so that a malformed duration is the same kind of
    part as every other refusal.
    """
    try:
        return parse_duration(value, fallback)
    except CheckError as error:
        raise SsoBlockError("not-a-duration", where=where, key=key,
                            problem=str(error)) from error


# --- reading one optional string ---------------------------------------------


#: What :class:`OptionalTextError` reports was wrong: the key was written and
#: left empty (``key:`` with nothing after it), the value was not text at all,
#: or it was text with nothing in it.
OptionalTextKind = Literal["left-empty", "not-text", "blank"]


class OptionalTextError(Exception):
    """One refused optional string, as **parts rather than a sentence** —
    :class:`SsoBlockError`'s bargain, for the other block every caller of this
    module reads: a profile, a role, a session name, a region.

    The rule being enforced is one sentence long — *a key written and left
    empty is a typo, not a value* — and its refusals are worded differently,
    and typed differently, at every site that pins them. So the error carries
    which key (:attr:`key`), what was wrong with it (:attr:`kind`, with
    :attr:`got` where there was a value), and every caller translates the
    type and renders its own words. ``str()`` of one is a plain factual line
    for logs and tracebacks only.
    """

    def __init__(self, kind: OptionalTextKind, *, where: str, key: str,
                 got: object = None) -> None:
        bits: list[str] = [kind, f"key {key!r}"]
        if got is not None:
            bits.append(f"got {got!r}")
        super().__init__(f"{where}: " + "; ".join(bits))
        self.kind: OptionalTextKind = kind
        self.where = where
        self.key = key
        self.got = got


def parse_optional_text(entry: Mapping[str, Any], key: str, *, where: str,
                        default: str = "") -> str:
    """One optional string field: absent means *default*, present means a
    non-empty text, stripped.

    The one reader of the rule that has been learned separately at three
    sites: ``key in entry`` rather than a ``None`` test, because a key that
    was **written and left empty is a typo, not a value** — reading it as
    "unset" is how a credential path silently becomes the ambient one, the
    one failure that looks like nothing at all. A value that is not text is
    the same typo family and is refused rather than coerced: ``profile: 123``
    is not somebody's profile name, it is a line that lost its quoting or its
    meaning, and a stringified surprise would be handed to boto3 and to
    ``aws sso login``.

    A field that cannot be read raises :class:`OptionalTextError`, never a
    sentence of this module's: which words a refusal earns, and what type
    carries it, are the caller's decisions and stay at the call sites.
    """
    if key not in entry:
        return default
    value = entry[key]
    if value is None:
        raise OptionalTextError("left-empty", where=where, key=key)
    if not isinstance(value, str):
        raise OptionalTextError("not-text", where=where, key=key, got=value)
    text = value.strip()
    if not text:
        raise OptionalTextError("blank", where=where, key=key, got=value)
    return text


# --- one reading identity ----------------------------------------------------


@dataclass(frozen=True)
class Identity:
    """Who this process becomes to read one account.

    Every field is *what was configured*, not what boto3 will end up doing:
    empty is the absence of a value, and the absence of all of them is the
    ambient credential chain — an instance profile, a task role, an SSO session,
    ``AWS_PROFILE`` — exactly as it was before any of these keys existed.

    ``profile`` and static keys are alternatives rather than a pair, and the
    profile wins: it is the one written down here, while keys are the exception.
    ``role_arn`` composes with either, and with neither, because *from where*
    and *into what* are two different questions.
    """

    profile: str = ""
    access_key: str = ""
    secret_key: str = ""
    role_arn: str = ""
    role_session_name: str = DEFAULT_ROLE_SESSION_NAME
    sts_region: str = DEFAULT_STS_REGION


class SessionFactory(Protocol):
    """How a session is built — the one seam a test replaces.

    A protocol rather than ``Callable[..., Session]`` so that strict typing
    survives the substitution: a fake that forgets a keyword is a type error
    here rather than a puzzle at run time.
    """

    def __call__(self, *, aws_access_key_id: str = "",
                 aws_secret_access_key: str = "",
                 aws_session_token: str = "",
                 profile_name: str = "") -> Session: ...


def new_session(*, aws_access_key_id: str = "", aws_secret_access_key: str = "",
                aws_session_token: str = "", profile_name: str = "") -> Session:
    """Build one boto3 session. Empty credentials mean the ambient chain; an
    empty profile means whichever one that chain would pick for itself."""
    return boto3.Session(
        aws_access_key_id=aws_access_key_id or None,
        aws_secret_access_key=aws_secret_access_key or None,
        aws_session_token=aws_session_token or None,
        profile_name=profile_name or None)


def base_session(identity: Identity, *,
                 factory: SessionFactory = new_session) -> Session:
    """The session a role is assumed *from* — or the session itself, where there
    is no role.

    Three sources, ordered by how specific they are. A profile wins because it is
    the one that was written down; static keys are next; the ambient chain is
    what is left, and is still the normal case on a server.
    """
    if identity.profile:
        return factory(profile_name=identity.profile)
    if identity.access_key and identity.secret_key:
        return factory(aws_access_key_id=identity.access_key,
                       aws_secret_access_key=identity.secret_key)
    return factory()


def assumed_session(identity: Identity, base: Session, *,
                    factory: SessionFactory = new_session) -> Session:
    """*base*, or the session that assuming this identity's role produces."""
    if not identity.role_arn:
        return base
    sts = base.client("sts", region_name=identity.sts_region)
    credentials = sts.assume_role(
        RoleArn=identity.role_arn,
        RoleSessionName=identity.role_session_name)["Credentials"]
    return factory(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"])

def caller_identity(session: Session, *, sts_region: str = "") -> str:
    """Who *session* actually is — ``"<account>, <arn>"`` — or ``""``.

    The one question a refused call leaves open and **no configuration can
    answer**. A check can say which profile it *meant* to use; it cannot say what
    the ambient credential chain resolved to on this machine, and that is exactly
    the case where being wrong is invisible: an ``AWS_PROFILE`` exported for
    something else decides which identity assumes these roles, and *role cannot
    be assumed* is the first anybody hears of it.

    ``var/account/s3_copy.py`` prints this before it copies anything — profile,
    and the account id it proved — and that line is the difference between a
    puzzle and a sentence. Here it is spent on the **failure path only**, so a
    healthy run costs nothing.

    **Never raises, and never returns a half-answer.** It runs while explaining
    somebody else's error, and a diagnostic that replaces the thing it explains
    is worse than no diagnostic at all.
    """
    try:
        answer = session.client("sts", region_name=sts_region).get_caller_identity()
    except Exception:
        return ""
    account, arn = str(answer.get("Account", "")), str(answer.get("Arn", ""))
    if account and arn:
        return f"{account}, {arn}"
    return account or arn


def open_session(identity: Identity, *, base: Session | None = None,
                 factory: SessionFactory = new_session) -> Session:
    """One identity's session, with its credentials **proven**.

    Assuming the role is itself the proof where there is a role: it is a call,
    and stale credentials fail it. A profile-only identity touches AWS nowhere
    until somebody reads something, so one ``sts:GetCallerIdentity`` is spent
    here to force the question — which is what makes an expired login *one*
    failure, at the moment the session is opened, instead of the same news in
    the words of whatever happened to be read first. Nothing is spent where no
    profile is configured: that path is exactly what the ambient chain always
    was.

    Pass *base* to reuse a session already built for this identity's profile —
    a caller opening several roles from one profile builds it once and says so.

    **It renews nothing.** A credential that has gone stale raises from here, and
    whether to answer that with ``aws sso login`` — and what the attempt may cost —
    is the caller's, one call further out, because a check waiting on an engine
    worker and an application waiting inside its own import can afford very
    different numbers (ADR-0001 §5, its fourth point; the module docstring's second
    rule). The three callers in this family answer it differently on purpose, and
    :func:`is_credential_error` is the reading they share.
    """
    source = base if base is not None else base_session(identity, factory=factory)
    session = assumed_session(identity, source, factory=factory)
    if not identity.role_arn and identity.profile:
        session.client("sts", region_name=identity.sts_region).get_caller_identity()
    return session


# --- renewing an expired SSO login -------------------------------------------
#
# A named profile is normally an SSO profile, and an SSO login expires — eight
# hours by default, i.e. once a working day. Everything *inside* that window
# botocore already handles: the short-lived role credentials behind the profile
# are refreshed silently, and a fresh session picks them up for free. What is
# left is the outer window, where the only fix is a human at a browser — and on a
# developer's machine that is a command this process can run itself.
# `var/account/s3_copy.py` does exactly this for a long copy; the difference here
# is that this runs unattended, possibly on a server, so the same idea needs
# three guards it does not: a capability test (:func:`login_capability`), a
# timeout, and a cooldown.


def is_credential_error(error: BaseException) -> bool:
    """True when *error* means the credentials went stale rather than that AWS
    said no. The two need opposite answers: a stale credential is worth renewing
    and retrying, an ``AccessDenied`` is worth reporting.

    **What this answers for an SSO profile**, measured on 2026-09-03 against
    botocore 1.43 with a fabricated ``~/.aws`` and an endpoint nothing was
    listening on, because *"it tried to log in when I had no connection"* is the
    reading somebody will otherwise reach for:

    * a **valid** cached token and an unreachable endpoint —
      ``EndpointConnectionError``, **false**: the transport failure travels as itself.
    * an **expired** token with refresh material, endpoint unreachable — the refresh
      is attempted and its ``EndpointConnectionError`` propagates, **false**.
    * an **expired** token with nothing to refresh with — no ``refreshToken``, or a
      registration that has itself expired — ``TokenRetrievalError``, **true**, and
      decided from the token cache alone without a single call. This is the one that
      renews on a machine with no connection, and the reading is *right*: the
      credential is stale and a login is the fix. It is simply the same answer online
      and off.
    * a valid token an endpoint **refuses** — ``UnauthorizedSSOTokenError``, **true**.

    So being offline does not by itself make this say yes, and what it costs when it
    does is one login attempt per profile per process, bounded by the caller's timeout
    and the cooldown. **Whether to spend that is not decided here**: this function
    reports a state, and ``open_session`` renews nothing — whether to try, and at what
    price, belongs one call further out (ADR-0001 §5, its fourth point). The three
    callers in this family answer it differently on purpose.
    """
    if type(error).__name__ in CREDENTIAL_ERROR_TYPES:
        return True
    if isinstance(error, ClientError):
        code_value = error.response.get("Error", {}).get("Code", "")
        return code_value in CREDENTIAL_ERROR_CODES
    return False


def login_capability(*, profile: str, profile_config: Mapping[str, Any],
                     aws_cli: str | None, environ: Mapping[str, str],
                     platform: str, container: bool) -> str:
    """Why ``aws sso login`` could not work here — or ``""`` when it could.

    This is what ``login: auto`` asks before it shells out, and it is a **pure
    function of what it looks at** on purpose: the answer is a sentence somebody
    reads, so it is a sentence worth testing directly, and each reason below is
    somebody's actual machine rather than a hypothetical.

    The order is most-informative first. A missing profile is asked about before
    anything else, because without one there is no login to renew and no way to
    tell whether the ambient credentials even come from SSO.
    """
    if not profile:
        return "no profile is configured, so there is no named login to renew"
    if not (profile_config.get("sso_session") or profile_config.get("sso_start_url")):
        return f"profile {profile} is not an SSO profile"
    if not aws_cli:
        return "the aws CLI is not on PATH"
    for marker in CLOUD_MARKERS:
        if environ.get(marker):
            return (f"{marker} is set, so these credentials come from the "
                    f"platform and renew themselves")
    if container:
        return "this is a container, where nobody would see the browser"
    if platform not in ("darwin", "win32") and not (
            environ.get("DISPLAY") or environ.get("WAYLAND_DISPLAY")):
        return "there is no display here to open a browser on"
    return ""


def in_container() -> bool:
    """True inside Docker or Podman. Its own function because it is the one
    machine fact :func:`login_capability` cannot be handed as a string."""
    return any(Path(marker).exists() for marker in CONTAINER_MARKERS)


def read_profile_config(profile: str) -> Mapping[str, Any]:
    """What ``~/.aws/config`` says about *profile*, or nothing if it says
    nothing. Its own function, so a test can answer for a machine it is not
    running on."""
    try:
        scoped = botocore.session.Session(profile=profile).get_scoped_config()
    except BotoCoreError:      # ProfileNotFound, an unreadable config file
        return {}
    return dict(scoped)


def login_problem(profile: str, sso: SsoConfig, *,
                  profile_config: Callable[[str], Mapping[str, Any]]
                  = read_profile_config) -> str:
    """Why an automatic login could not happen for *profile* — ``""`` when it
    could. The whole environment is read here and nowhere else, which is what
    keeps :func:`login_capability` a pure function of its arguments.

    ``never`` and ``always`` answer before the machine is looked at, so a caller
    that has said either never pays for reading ``~/.aws/config``.
    """
    if sso.login == SSO_LOGIN_NEVER:
        return "automatic login is off (`sso: login: never`)"
    if sso.login == SSO_LOGIN_ALWAYS:
        return ""
    return login_capability(
        profile=profile,
        profile_config=profile_config(profile),
        aws_cli=shutil.which("aws"),
        environ=os.environ,
        platform=sys.platform,
        container=in_container())


def login_command(profile: str) -> str:
    """The command a human would run — printed wherever we cannot run it."""
    return f"aws sso login --profile {profile}" if profile else "aws sso login"


def run_sso_login(profile: str, timeout: int) -> str:
    """Run one ``aws sso login``. ``""`` when it succeeded, else why it did not.

    Never ``shell=True`` and never a composed string: *profile* comes from a
    config file, and a config file is not a thing to interpolate into a shell.
    """
    command = ["aws", "sso", "login"] + (["--profile", profile] if profile else [])
    logger.info("aws: renewing the SSO login (%s)", login_command(profile))
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, check=False)
    except FileNotFoundError:
        return "the aws CLI is not on PATH"
    except OSError as error:
        return f"`{login_command(profile)}` could not be started: {plain(error)}"
    except subprocess.TimeoutExpired:
        return (f"`{login_command(profile)}` was still waiting after "
                f"{format_span(timeout)} and was stopped")
    if completed.returncode != 0:
        lines = (completed.stderr or completed.stdout or "").strip().splitlines()
        detail = lines[-1].strip() if lines else f"exit {completed.returncode}"
        # The CLI's own words, folded into a reason that is rendered as Markdown
        # (little-sister ADR-0018) — escaped like any other captured output.
        return f"`{login_command(profile)}` failed: {plain(detail[:200])}"
    logger.info("aws: the SSO login for %s was renewed",
                profile or "the default profile")
    return ""


@dataclass(frozen=True)
class _Attempt:
    """When a login was last tried for a profile, and how it went."""

    at: float
    problem: str


class SsoLogins:
    """``aws sso login`` bookkeeping, shared by everything in the process.

    The browser and the SSO token cache belong to the **machine**, not to a
    caller. Two callers pointed at one profile must not both open a login, and
    the cooldown that stops a browser re-opening every minute has to be the same
    one for both — a per-caller attribute would give each of them their own. So
    this is deliberately module state, one instance (:data:`SSO_LOGINS`) keyed by
    profile name, and the per-profile lock is what serialises the two readers of
    one profile that go stale at the same moment.

    That single instance is also why this class is public and why a second
    implementation of it, in a deployment or another package, would be a bug
    rather than a duplication: two of them in one process would each hold half
    the machine's history and open two browsers for one expiry.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._last: dict[str, _Attempt] = {}

    def _profile_lock(self, profile: str) -> threading.Lock:
        with self._lock:
            return self._locks.setdefault(profile, threading.Lock())

    def forget(self) -> None:
        """Drop every recorded attempt, so the next call may log in again."""
        with self._lock:
            self._last.clear()

    def renew(self, profile: str, *, timeout: int, cooldown: int,
              login: Callable[[str, int], str] = run_sso_login,
              clock: Callable[[], float] = time.monotonic) -> str:
        """Renew *profile*'s login. ``""`` when it is worth retrying AWS now.

        *timeout* and *cooldown* are arguments and not settings read from
        anywhere: what a login may cost depends on what the caller is holding
        while it waits — an engine worker thread, or a process that has not
        finished starting.

        Inside *cooldown* seconds of the previous attempt the previous verdict is
        returned **without running anything**. That covers both directions: a
        login that nobody completed is not re-opened a minute later, and a login
        that just succeeded is not run twice because a second reader noticed the
        same expiry.
        """
        with self._profile_lock(profile):
            previous = self._last.get(profile)
            if previous is not None and clock() - previous.at < cooldown:
                if previous.problem:
                    return (f"{previous.problem} (not tried again within "
                            f"{format_span(cooldown)})")
                return ""
            problem = login(profile, timeout)
            self._last[profile] = _Attempt(clock(), problem)
            return problem


#: The one instance. Module state, for the reason :class:`SsoLogins` gives.
SSO_LOGINS = SsoLogins()
