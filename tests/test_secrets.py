"""AWS-backed secret references: store validation and JSON selection."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from botocore.exceptions import ClientError
from little_sister import config_dir, secrets
from little_sister.secrets import SecretError, UnknownSchemeError

from little_sister_aws import secrets as aws_secrets
from little_sister_aws.identities import NamedIdentity, startup_sso
from little_sister_aws.identity import SSO_LOGINS, Identity

#: Two roles, so that "each identity opens its own" is visible.
ROLE = "arn:aws:iam::000000000000:role/monitoring-role"
OTHER_ROLE = "arn:aws:iam::000000000001:role/monitoring-role"

#: The profile an identity names when the test is about its login.
PROFILE = "corp-sso"


@pytest.fixture(autouse=True)
def _restore_secret_resolvers():
    """A registration in one test must not become another test's premise."""
    with mock.patch.dict(secrets._resolvers):
        yield


@pytest.fixture
def config_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A configuration root of this test's own, with no `aws.yaml` in it.

    A bare registration reads the aspect file from wherever little-sister's
    configuration lives; this package has no deployment `config/` beside it,
    and borrowing one from the working directory would be a test that passes
    only where it happens to run. No file means no named identities — the
    plain schemes on the ambient chain, exactly the case these tests are
    about.
    """
    root = tmp_path / "config"
    root.mkdir()
    monkeypatch.setenv("LITTLE_SISTER_CONFIG_DIR", str(root))
    return root


def _secrets_manager(monkeypatch: pytest.MonkeyPatch,
                     response: dict[str, object]) -> mock.Mock:
    client = mock.Mock()
    client.get_secret_value.return_value = response
    monkeypatch.setattr(aws_secrets, "_new_secrets_manager_client",
                        lambda identity=aws_secrets.AMBIENT: client)
    return client


def _parameter_store(monkeypatch: pytest.MonkeyPatch,
                     response: dict[str, object]) -> mock.Mock:
    client = mock.Mock()
    client.get_parameter.return_value = response
    monkeypatch.setattr(aws_secrets, "_new_ssm_client",
                        lambda identity=aws_secrets.AMBIENT: client)
    return client


def test_registers_both_aws_schemes(
        monkeypatch: pytest.MonkeyPatch, config_root: Path) -> None:
    _secrets_manager(monkeypatch, {"SecretString": "from-sm"})
    _parameter_store(monkeypatch, {
        "Parameter": {"Type": "SecureString", "Value": "from-ssm"},
    })

    aws_secrets.register_aws_secret_resolvers()

    assert secrets.resolve("aws-sm://team/token") == "from-sm"
    assert secrets.resolve("aws-ssm:///team/token") == "from-ssm"


def test_aws_registration_leaves_the_environment_fallback_available(
        monkeypatch: pytest.MonkeyPatch, config_root: Path) -> None:
    monkeypatch.setenv("LOCAL_SECRET", "from-env")

    aws_secrets.register_aws_secret_resolvers()

    assert secrets.resolve("env://LOCAL_SECRET") == "from-env"


def test_secrets_manager_returns_secret_string_unchanged(
        monkeypatch: pytest.MonkeyPatch) -> None:
    client = _secrets_manager(monkeypatch, {"SecretString": "  exact value  "})

    value = aws_secrets.resolve_secrets_manager("team/token")

    assert value == "  exact value  "
    client.get_secret_value.assert_called_once_with(SecretId="team/token")


@pytest.mark.parametrize("response", [
    {"SecretBinary": b"binary"},
    {"SecretString": ""},
    {},
])
def test_secrets_manager_refuses_anything_but_nonempty_text(
        monkeypatch: pytest.MonkeyPatch, response: dict[str, object]) -> None:
    _secrets_manager(monkeypatch, response)

    with pytest.raises(SecretError, match="non-empty SecretString"):
        aws_secrets.resolve_secrets_manager("team/token")


def test_parameter_store_requires_and_decrypts_secure_string(
        monkeypatch: pytest.MonkeyPatch) -> None:
    client = _parameter_store(monkeypatch, {
        "Parameter": {"Type": "SecureString", "Value": "secret"},
    })

    value = aws_secrets.resolve_parameter_store("/team/token")

    assert value == "secret"
    client.get_parameter.assert_called_once_with(
        Name="/team/token", WithDecryption=True)


@pytest.mark.parametrize("parameter_type", ["String", "StringList", None,
                                             "FutureType"])
def test_parameter_store_refuses_every_non_secure_string_type(
        monkeypatch: pytest.MonkeyPatch,
        parameter_type: str | None) -> None:
    parameter: dict[str, object] = {"Value": "looks-secret"}
    if parameter_type is not None:
        parameter["Type"] = parameter_type
    _parameter_store(monkeypatch, {"Parameter": parameter})

    with pytest.raises(SecretError, match="expected SecureString"):
        aws_secrets.resolve_parameter_store("/team/token")


@pytest.mark.parametrize("response", [
    {},
    {"Parameter": {"Type": "SecureString"}},
    {"Parameter": {"Type": "SecureString", "Value": ""}},
])
def test_parameter_store_refuses_a_missing_or_empty_value(
        monkeypatch: pytest.MonkeyPatch, response: dict[str, object]) -> None:
    _parameter_store(monkeypatch, response)

    with pytest.raises(SecretError):
        aws_secrets.resolve_parameter_store("/team/token")


def test_json_pointer_selects_nested_and_escaped_object_keys(
        monkeypatch: pytest.MonkeyPatch) -> None:
    client = _secrets_manager(monkeypatch, {
        "SecretString": '{"oauth":{"client/secret":{"~key":"chosen"}}}',
    })

    value = aws_secrets.resolve_secrets_manager(
        "team/wiz#/oauth/client~1secret/~0key")

    assert value == "chosen"
    client.get_secret_value.assert_called_once_with(SecretId="team/wiz")


def test_json_pointer_can_traverse_an_array(
        monkeypatch: pytest.MonkeyPatch) -> None:
    client = _parameter_store(monkeypatch, {
        "Parameter": {
            "Type": "SecureString",
            "Value": '{"tokens":[{"value":"first"}]}',
        },
    })

    assert aws_secrets.resolve_parameter_store(
        "/team/tokens#/tokens/0/value") == "first"
    client.get_parameter.assert_called_once_with(
        Name="/team/tokens", WithDecryption=True)


def test_json_pointer_refuses_to_traverse_through_a_scalar(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _secrets_manager(monkeypatch, {
        "SecretString": '{"oauth":{"secret":"abc"}}',
    })

    with pytest.raises(SecretError, match="cannot be traversed"):
        aws_secrets.resolve_secrets_manager(
            "team/token#/oauth/secret/typo")


@pytest.mark.parametrize("address", ["team/token#", "team/token#not/a/pointer"])
def test_refuses_a_malformed_json_selector_before_calling_aws(
        monkeypatch: pytest.MonkeyPatch, address: str) -> None:
    new_client = mock.Mock(side_effect=AssertionError("AWS must not be called"))
    monkeypatch.setattr(aws_secrets, "_new_secrets_manager_client", new_client)

    with pytest.raises(SecretError, match="JSON Pointer"):
        aws_secrets.resolve_secrets_manager(address)

    new_client.assert_not_called()


def test_a_json_parse_error_does_not_disclose_the_fetched_document(
        monkeypatch: pytest.MonkeyPatch) -> None:
    document = "TOP-SECRET-DOCUMENT-is-not-json"
    _secrets_manager(monkeypatch, {"SecretString": document})

    with pytest.raises(SecretError) as caught:
        aws_secrets.resolve_secrets_manager("team/token#/password")

    assert document not in str(caught.value)
    assert str(caught.value) == (
        "AWS secret 'team/token' is not valid JSON for Pointer '/password'")
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("document,pointer", [
    ('{"oauth": {}}', "/oauth/missing"),
    ('{"oauth": {"secret": {}}}', "/oauth/secret"),
    ('{"oauth": {"secret": []}}', "/oauth/secret"),
    ('{"oauth": {"secret": 42}}', "/oauth/secret"),
    ('{"oauth": {"secret": true}}', "/oauth/secret"),
    ('{"oauth": {"secret": null}}', "/oauth/secret"),
    ('{"oauth": {"secret": ""}}', "/oauth/secret"),
])
def test_json_selection_requires_an_existing_nonempty_string(
        monkeypatch: pytest.MonkeyPatch, document: str, pointer: str) -> None:
    _secrets_manager(monkeypatch, {"SecretString": document})

    with pytest.raises(SecretError):
        aws_secrets.resolve_secrets_manager(f"team/token#{pointer}")


@pytest.mark.parametrize("pointer", ["/~", "/~2"])
def test_json_pointer_refuses_invalid_escapes(
        monkeypatch: pytest.MonkeyPatch, pointer: str) -> None:
    _secrets_manager(monkeypatch, {
        "SecretString": '{"tokens":["first"],"~":"tilde"}',
    })

    with pytest.raises(SecretError, match="JSON Pointer"):
        aws_secrets.resolve_secrets_manager(f"team/token#{pointer}")


@pytest.mark.parametrize(("pointer", "token"), [
    ("/tokens/01", "01"),
    ("/tokens/-", "-"),
])
def test_json_pointer_refuses_noncanonical_array_indexes(
        monkeypatch: pytest.MonkeyPatch, pointer: str, token: str) -> None:
    _secrets_manager(monkeypatch, {
        "SecretString": '{"tokens":["first"]}',
    })

    with pytest.raises(SecretError) as caught:
        aws_secrets.resolve_secrets_manager(f"team/token#{pointer}")

    assert str(caught.value) == (
        f"JSON Pointer {pointer!r} for AWS secret 'team/token' "
        f"has invalid array index {token!r}")


def test_json_pointer_refuses_an_array_index_past_the_end(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _secrets_manager(monkeypatch, {
        "SecretString": '{"tokens":["first"]}',
    })

    with pytest.raises(SecretError, match="does not exist"):
        aws_secrets.resolve_secrets_manager("team/token#/tokens/1")


def test_refuses_an_empty_store_id_before_calling_aws(
        monkeypatch: pytest.MonkeyPatch) -> None:
    new_client = mock.Mock(side_effect=AssertionError("AWS must not be called"))
    monkeypatch.setattr(aws_secrets, "_new_secrets_manager_client", new_client)

    with pytest.raises(SecretError) as caught:
        aws_secrets.resolve_secrets_manager("#/token")

    assert str(caught.value) == (
        "AWS secret address has no store id before its JSON Pointer")
    new_client.assert_not_called()


def test_aws_client_failure_uses_little_sisters_secret_error_path(
        monkeypatch: pytest.MonkeyPatch, config_root: Path) -> None:
    client = _secrets_manager(monkeypatch, {})
    client.get_secret_value.side_effect = RuntimeError("access denied")
    aws_secrets.register_aws_secret_resolvers()

    with pytest.raises(SecretError) as caught:
        secrets.resolve("aws-sm://team/token")

    assert "aws-sm://team/token" in str(caught.value)
    assert "access denied" in str(caught.value)


# --- one scheme per identity ------------------------------------------------
#
# The identity is in the scheme because no separator survives both stores: a
# cross-account Secrets Manager id is an ARN and carries ':', while Parameter
# Store takes a bare name and refuses an ARN outright. So `aws-ssm-live://…`
# reads through the `live` entry of `config/aws.yaml`, and the address stays a
# name for a secret.

class _FakeSession:
    """A session that records which client each identity asked for."""

    def __init__(self, identity: Any) -> None:
        self.identity = identity
        self.clients: list[tuple[str, str | None]] = []

    def client(self, service: str, region_name: str | None = None) -> Any:
        self.clients.append((service, region_name))
        client = mock.Mock()
        client.get_parameter.return_value = {
            "Parameter": {"Type": "SecureString",
                          "Value": f"from-{self.identity.name or 'ambient'}"}}
        client.get_secret_value.return_value = {
            "SecretString": f"from-{self.identity.name or 'ambient'}"}
        return client


def _sessions(monkeypatch: pytest.MonkeyPatch) -> list[_FakeSession]:
    """Replace the one seam that opens a session, and record every open."""
    opened: list[_FakeSession] = []

    def open_one(identity: Any) -> Any:
        session = _FakeSession(identity)
        opened.append(session)
        return session

    monkeypatch.setattr(aws_secrets, "_new_session", open_one)
    aws_secrets.forget_sessions()
    return opened


def _identity(name: str, **fields: str) -> Any:
    return NamedIdentity(name=name,
                         identity=Identity(role_arn=fields.pop("role_arn", ROLE),
                                           profile=fields.pop("profile", "")),
                         region=fields.pop("region", ""),
                         sso=startup_sso())


def test_each_declared_identity_gets_a_scheme_pair(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _sessions(monkeypatch)

    aws_secrets.register_aws_secret_resolvers({"live": _identity("live")})

    assert secrets.resolve("aws-ssm-live:///team/token") == "from-live"
    assert secrets.resolve("aws-sm-live://team/token") == "from-live"


def test_the_plain_schemes_stay_the_ambient_chain(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Every reference committed before identities existed keeps its meaning."""
    opened = _sessions(monkeypatch)

    aws_secrets.register_aws_secret_resolvers({"live": _identity("live")})

    assert secrets.resolve("aws-ssm:///team/token") == "from-ambient"
    assert [session.identity.identity for session in opened] == [Identity()]


def test_an_identity_nobody_declared_is_a_configuration_error(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Not a resolution failure pinning one check — a scheme nothing registered,
    which little-sister refuses at load naming the reference."""
    _sessions(monkeypatch)
    aws_secrets.register_aws_secret_resolvers({"live": _identity("live")})

    with pytest.raises(UnknownSchemeError, match="aws-ssm-develop"):
        secrets.resolve("aws-ssm-develop:///team/token")


def test_two_references_through_one_identity_open_one_session(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A role assumed twice at startup is two `AssumeRole` calls for one answer,
    and the second is the one that trips a rate limit nobody was expecting."""
    opened = _sessions(monkeypatch)
    aws_secrets.register_aws_secret_resolvers({"live": _identity("live")})

    secrets.resolve("aws-ssm-live:///team/token")
    secrets.resolve("aws-sm-live://team/other")

    assert len(opened) == 1


def test_each_identity_opens_its_own_session(
        monkeypatch: pytest.MonkeyPatch) -> None:
    opened = _sessions(monkeypatch)
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", role_arn=ROLE),
         "backup": _identity("backup", role_arn=OTHER_ROLE)})

    assert secrets.resolve("aws-ssm-live:///team/token") == "from-live"
    assert secrets.resolve("aws-ssm-backup:///team/token") == "from-backup"
    assert [session.identity.identity.role_arn for session in opened] == [
        ROLE, OTHER_ROLE]


def test_a_store_in_another_region_is_read_there(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A Parameter Store name exists in one region, and the same name in another
    is a different parameter — so the region belongs to the identity, not to the
    process that happens to start the deployment."""
    opened = _sessions(monkeypatch)
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", region="eu-west-1")})

    secrets.resolve("aws-ssm-live:///team/token")

    assert opened[0].clients == [("ssm", "eu-west-1")]


def test_without_a_region_the_session_decides(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`None`, not `""`: an empty string is a region name to boto3, and there is
    no region called nothing. Both stores, because both are asked separately."""
    opened = _sessions(monkeypatch)
    aws_secrets.register_aws_secret_resolvers({"live": _identity("live")})

    secrets.resolve("aws-sm-live://team/token")
    secrets.resolve("aws-ssm-live:///team/token")

    assert opened[0].clients == [("secretsmanager", None), ("ssm", None)]


def test_registration_declares_the_aspect_it_is_about_to_read(
        monkeypatch: pytest.MonkeyPatch, config_root: Path) -> None:
    """`config/aws.yaml` cannot be looked for until the aspect is declared, and
    the declaration has to happen in this slot — before anything reads it, which
    here is the very next line (little-sister ADR-0035). Undeclared, the lookup
    does not come back empty: little-sister resolves an aspect through its own
    table, so the name missing from it raises `KeyError`. A registration that read
    the file without declaring it would work only because something else had
    already claimed the name."""
    monkeypatch.setattr(config_dir, "ASPECTS", dict(config_dir.BUILTIN_ASPECTS))
    monkeypatch.setattr(config_dir, "_ASPECT_OWNERS", {})
    _sessions(monkeypatch)

    aws_secrets.register_aws_secret_resolvers()

    assert "aws" in config_dir.registered_aspects()


# --- an expired login, at the one moment nobody is watching -----------------
#
# Secrets resolve during the app import, so a login that has gone stale
# overnight fails a *boot* rather than reddening a node — and the fix is a
# command this process can run. It runs it once, with the boot's budget rather
# than a check's, and asks AWS again.

class _Expired(ClientError):
    def __init__(self) -> None:
        super().__init__(
            {"Error": {"Code": "ExpiredToken", "Message": "the token expired"}},
            "GetCallerIdentity")


def _stale(monkeypatch: pytest.MonkeyPatch, *,
           always: bool = False) -> dict[str, Any]:
    """A seam where each identity's **first** open finds a stale credential and
    the next one works — one machine, one expired login, several readers. With
    *always*, no renewal ever convinces it."""
    state: dict[str, Any] = {"logins": [], "sessions": [], "refused": set(),
                             "problem": ""}

    def open_one(identity: Any) -> Any:
        if always or identity.name not in state["refused"]:
            state["refused"].add(identity.name)
            raise _Expired()
        session = _FakeSession(identity)
        state["sessions"].append(session)
        return session

    def login(profile: str, timeout: int) -> str:
        state["logins"].append((profile, timeout))
        return str(state["problem"])

    monkeypatch.setattr(aws_secrets, "_new_session", open_one)
    monkeypatch.setattr(aws_secrets, "_sso_login", login)
    monkeypatch.setattr(aws_secrets, "login_problem", lambda profile, sso: "")
    SSO_LOGINS.forget()
    aws_secrets.forget_sessions()
    return state


def test_a_stale_login_is_renewed_once_and_the_secret_then_read(
        monkeypatch: pytest.MonkeyPatch) -> None:
    state = _stale(monkeypatch)
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", profile=PROFILE)})

    assert secrets.resolve("aws-ssm-live:///team/token") == "from-live"
    assert state["logins"] == [(PROFILE, 45)]


def test_the_budget_is_the_boots_and_not_a_checks(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A check may spend 120 seconds on an engine worker thread; here a gunicorn
    worker has not finished importing the application, and `start.sh` is already
    counting."""
    state = _stale(monkeypatch)
    identity = _identity("live", profile=PROFILE)
    aws_secrets.register_aws_secret_resolvers({"live": identity})

    secrets.resolve("aws-ssm-live:///team/token")

    assert identity.sso.timeout_seconds == 45
    assert state["logins"] == [(PROFILE, 45)]


def test_two_identities_behind_one_profile_open_one_browser(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The login belongs to the machine, not to an identity — and the process-wide
    bookkeeping that says so is `little_sister_aws`'s, which is also what keeps a
    *check's* renewal from opening a second window for the same expiry."""
    state = _stale(monkeypatch)
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", profile=PROFILE),
         "other": _identity("other", profile=PROFILE, role_arn=OTHER_ROLE)})

    secrets.resolve("aws-ssm-live:///team/token")
    secrets.resolve("aws-ssm-other:///team/token")

    assert state["logins"] == [(PROFILE, 45)]


def test_a_login_that_cannot_help_names_the_command(
        monkeypatch: pytest.MonkeyPatch) -> None:
    state = _stale(monkeypatch)
    state["problem"] = "the browser was never answered"
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", profile=PROFILE)})

    with pytest.raises(SecretError) as caught:
        secrets.resolve("aws-ssm-live:///team/token")

    assert "'live'" in str(caught.value)
    assert f"aws sso login --profile {PROFILE}" in str(caught.value)
    assert "the browser was never answered" in str(caught.value)


def test_a_machine_that_could_not_log_in_says_why_instead(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`login: auto` asks the machine first, and where the answer is no, that
    sentence is the useful half — not a subprocess nobody could have seen."""
    state = _stale(monkeypatch)
    monkeypatch.setattr(aws_secrets, "login_problem",
                        lambda profile, sso: "this is a container")
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", profile=PROFILE)})

    with pytest.raises(SecretError, match="this is a container"):
        secrets.resolve("aws-ssm-live:///team/token")

    assert state["logins"] == []


def test_a_refusal_is_reported_rather_than_renewed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`AccessDenied` means AWS said no, not that the credentials went stale. A
    browser would not help, and opening one for every denied role is how an
    afternoon disappears."""
    state = _stale(monkeypatch)

    def refuse(identity: Any) -> Any:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
            "AssumeRole")

    monkeypatch.setattr(aws_secrets, "_new_session", refuse)
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", profile=PROFILE)})

    with pytest.raises(SecretError, match="AccessDenied"):
        secrets.resolve("aws-ssm-live:///team/token")

    assert state["logins"] == []


def test_a_renewal_that_does_not_convince_aws_says_so(
        monkeypatch: pytest.MonkeyPatch) -> None:
    state = _stale(monkeypatch, always=True)
    aws_secrets.register_aws_secret_resolvers(
        {"live": _identity("live", profile=PROFILE)})

    with pytest.raises(SecretError, match="still refused"):
        secrets.resolve("aws-ssm-live:///team/token")

    assert state["logins"] == [(PROFILE, 45)]
