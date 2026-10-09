"""One reading identity: the session it opens, and the SSO login behind it.

No live AWS anywhere: sessions are built through the ``factory`` seam, and the CLI
through little-sister's process function, which the tests of :func:`run_sso_login`
replace — all but two, which run a stand-in ``aws`` script for real. The check's own
use of all this — what a node says when a login expired, what the card promises —
stays in ``test_aws.py``, because that is the check's behavior rather than this seam's.
"""
from __future__ import annotations

import os
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from little_sister import process

from little_sister_aws import identity as identity_module
from little_sister_aws.identity import (
    DEFAULT_ROLE_SESSION_NAME,
    DEFAULT_STS_REGION,
    SSO_LOGIN_MODES,
    Identity,
    OptionalTextError,
    SsoBlockError,
    SsoConfig,
    assumed_session,
    base_session,
    login_problem,
    open_session,
    parse_optional_text,
    parse_sso_block,
)

#: The two profiles these tests name — the same spellings ``test_aws.py`` uses,
#: because a login is keyed by profile and the two files describe one machine.
PRIMARY = "primary-admin"
SECONDARY = "secondary-admin"


# --- one identity, one session --------------------------------------------
#
# The claim these are written from is that an identity says *what was
# configured* and the seam decides what that means: which of the three sources
# is used, whether a role is assumed, and what is spent proving that any of it
# still works. A deployment resolving a secret reference calls exactly these
# three functions with no check anywhere, which is why they are tested without
# one.

class _Sts:
    """Just enough STS to assume a role and to answer who we are."""

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []
        self.identity_calls = 0

    def assume_role(self, *, RoleArn: str,
                    RoleSessionName: str) -> dict[str, Any]:
        self.calls.append({"RoleArn": RoleArn,
                           "RoleSessionName": RoleSessionName})
        return {"Credentials": {"AccessKeyId": "temporary-key",
                                "SecretAccessKey": "temporary-secret",
                                "SessionToken": "temporary-token"}}

    def get_caller_identity(self) -> dict[str, str]:
        self.identity_calls += 1
        return {"Account": "111"}


class _Session:
    """A session that remembers what it was built with and what it opened."""

    def __init__(self, sts: _Sts, **built: str) -> None:
        self.sts = sts
        self.built = built
        self.clients: list[tuple[str, str]] = []

    def client(self, name: str, region_name: str = "") -> Any:
        self.clients.append((name, region_name))
        return self.sts


def _factory() -> Any:
    """The session seam, recording every session it is asked to build."""
    sts = _Sts()
    built: list[_Session] = []

    def factory(*, aws_access_key_id: str = "", aws_secret_access_key: str = "",
                aws_session_token: str = "", profile_name: str = "") -> Any:
        session = _Session(sts, aws_access_key_id=aws_access_key_id,
                           aws_secret_access_key=aws_secret_access_key,
                           aws_session_token=aws_session_token,
                           profile_name=profile_name)
        built.append(session)
        return session

    factory.built = built                       # type: ignore[attr-defined]
    factory.sts = sts                           # type: ignore[attr-defined]
    return factory


def test_an_identity_that_names_nothing_is_the_ambient_chain() -> None:
    factory = _factory()

    base_session(Identity(), factory=factory)

    assert factory.built[0].built == {"aws_access_key_id": "",
                                      "aws_secret_access_key": "",
                                      "aws_session_token": "",
                                      "profile_name": ""}


def test_a_profile_wins_over_static_keys() -> None:
    factory = _factory()

    base_session(Identity(profile=PRIMARY, access_key="written-down",
                          secret_key="also-written-down"), factory=factory)

    assert factory.built[0].built["profile_name"] == PRIMARY
    assert factory.built[0].built["aws_access_key_id"] == ""


def test_static_keys_are_used_where_no_profile_is_named() -> None:
    factory = _factory()

    base_session(Identity(access_key="the-key", secret_key="the-secret"),
                 factory=factory)

    assert factory.built[0].built["aws_access_key_id"] == "the-key"
    assert factory.built[0].built["aws_secret_access_key"] == "the-secret"


def test_half_a_key_pair_is_not_a_credential() -> None:
    """A key without its secret is a half-written config, and reading it as one
    source would send boto3 looking for a password it was never given. The
    ambient chain is the honest answer, and it is what the caller had before."""
    factory = _factory()

    base_session(Identity(access_key="the-key"), factory=factory)

    assert factory.built[0].built["aws_access_key_id"] == ""


def test_an_identity_with_no_role_is_read_through_the_session_it_was_given(
        ) -> None:
    factory = _factory()
    base = factory()

    assert assumed_session(Identity(), base, factory=factory) is base
    assert base.clients == []


def test_a_role_is_assumed_in_its_own_region_under_its_own_name() -> None:
    factory = _factory()
    base = factory()

    session = assumed_session(
        Identity(role_arn="arn:aws:iam::111:role/monitoring",
                 role_session_name="the-reader", sts_region="eu-west-1"),
        base, factory=factory)

    assert base.clients == [("sts", "eu-west-1")]
    assert factory.sts.calls == [{"RoleArn": "arn:aws:iam::111:role/monitoring",
                                 "RoleSessionName": "the-reader"}]
    assert session.built == {"aws_access_key_id": "temporary-key",
                             "aws_secret_access_key": "temporary-secret",
                             "aws_session_token": "temporary-token",
                             "profile_name": ""}


def test_open_session_builds_its_own_base_when_it_is_given_none() -> None:
    factory = _factory()

    open_session(Identity(profile=PRIMARY,
                          role_arn="arn:aws:iam::111:role/monitoring"),
                 factory=factory)

    assert factory.built[0].built["profile_name"] == PRIMARY
    assert factory.sts.calls[0]["RoleArn"] == "arn:aws:iam::111:role/monitoring"


def test_open_session_assumes_from_a_base_it_is_given() -> None:
    """The caller that opens several roles from one profile builds that profile
    once and says so — the reason *base* is a parameter at all."""
    factory = _factory()
    base = factory()

    open_session(Identity(role_arn="arn:aws:iam::111:role/monitoring"),
                 base=base, factory=factory)

    assert base.clients == [("sts", DEFAULT_STS_REGION)]
    assert len(factory.built) == 2          # the base, and the assumed session


def test_a_profile_only_identity_is_proven_with_one_call_in_its_own_region(
        ) -> None:
    """The region is the identity's, here as much as on the `AssumeRole` — an
    estate that moved its STS calls off the default moved all of them."""
    factory = _factory()

    session = open_session(Identity(profile=PRIMARY, sts_region="eu-west-1"),
                           factory=factory)

    assert factory.sts.identity_calls == 1
    assert session.clients == [("sts", "eu-west-1")]


def test_assuming_the_role_is_the_proof_where_there_is_one() -> None:
    factory = _factory()

    open_session(Identity(profile=PRIMARY,
                          role_arn="arn:aws:iam::111:role/monitoring"),
                 factory=factory)

    assert factory.sts.calls != []
    assert factory.sts.identity_calls == 0


def test_the_ambient_chain_spends_nothing_proving_itself() -> None:
    """The path that existed before any of these keys did stays exactly as it
    was: no profile, no role, no call until somebody reads something."""
    factory = _factory()

    session = open_session(Identity(), factory=factory)

    assert session.clients == []
    assert factory.sts.identity_calls == 0


def test_the_defaults_name_this_package_and_a_regional_endpoint() -> None:
    assert Identity().role_session_name == DEFAULT_ROLE_SESSION_NAME
    assert Identity().sts_region == DEFAULT_STS_REGION


def test_the_boto3_seam_turns_an_empty_string_into_no_argument_at_all(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """boto3 reads ``None`` as *look it up* and an empty string as *this is the
    value*, so the difference is the whole ambient chain. The core session the seam
    builds for boto3 resolves the profile before boto3 sees it, and refuses one the
    machine lacks as boto3 would — so this machine has the one the test names."""
    (tmp_path / "config").write_text(f"[profile {PRIMARY}]\nregion = eu-central-1\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_DATA_PATH"):
        monkeypatch.delenv(name, raising=False)
    built: list[dict[str, Any]] = []
    monkeypatch.setattr(identity_module.boto3, "Session",
                        lambda **kwargs: built.append(kwargs))

    identity_module.new_session()
    identity_module.new_session(profile_name=PRIMARY)

    for name in ("aws_access_key_id", "aws_secret_access_key",
                 "aws_session_token", "profile_name"):
        assert built[0][name] is None
    assert built[1]["profile_name"] == PRIMARY
    assert built[1]["botocore_session"].profile == PRIMARY
    for kwargs in built:          # both on the process's one loader of service models
        assert (kwargs["botocore_session"].get_component("data_loader")
                is identity_module.SERVICE_MODELS.loader(None))


# --- what the ambient chain turns out to be --------------------------------

def test_the_environment_names_no_profile_by_default() -> None:
    assert identity_module.ambient_profile({}) == ("", "")


def test_aws_profile_is_read_first() -> None:
    assert identity_module.ambient_profile(
        {"AWS_PROFILE": PRIMARY, "AWS_DEFAULT_PROFILE": SECONDARY}) == (
            "AWS_PROFILE", PRIMARY)


def test_the_older_variable_still_counts() -> None:
    assert identity_module.ambient_profile(
        {"AWS_DEFAULT_PROFILE": SECONDARY}) == ("AWS_DEFAULT_PROFILE", SECONDARY)


def test_a_variable_set_to_nothing_names_nothing() -> None:
    """Exported and empty is how a shell says *unset* by accident, and it must
    not be reported as a profile nobody configured."""
    assert identity_module.ambient_profile({"AWS_PROFILE": "   "}) == ("", "")


# --- whether an automatic login may be tried at all ------------------------

def _refuse_to_be_read(profile: str) -> dict[str, Any]:
    raise AssertionError("~/.aws/config was read")


def test_never_answers_without_looking_at_the_machine() -> None:
    problem = login_problem(PRIMARY, SsoConfig(login="never"),
                            profile_config=_refuse_to_be_read)

    assert problem == "automatic login is off (`sso: login: never`)"


def test_always_skips_the_capability_question_entirely() -> None:
    """A machine that knows better than the guess — and a guess that is never
    made costs nothing, which is what the fake config file here proves."""
    assert login_problem(PRIMARY, SsoConfig(login="always"),
                         profile_config=_refuse_to_be_read) == ""


def test_auto_asks_the_machine_and_repeats_its_sentence() -> None:
    problem = login_problem(PRIMARY, SsoConfig(),
                            profile_config=lambda profile: {})

    assert problem == f"profile {PRIMARY} is not an SSO profile"


# --- can an `aws sso login` work on this machine at all? ------------------
#
# `login_capability` answers in a sentence that ends up on the dashboard, so the
# tests below are written from the sentence: each one is somebody's machine, and
# the assertion is what that operator would be told.

def _machine(**overrides: Any) -> dict[str, Any]:
    """A developer's Mac, logged into an SSO profile, with the CLI installed."""
    return {"profile": PRIMARY,
            "profile_config": {"sso_session": "corp"},
            "aws_cli": "/opt/homebrew/bin/aws",
            "environ": {},
            "platform": "darwin",
            "container": False, **overrides}


def test_a_developer_machine_can_log_in() -> None:
    assert identity_module.login_capability(**_machine()) == ""


def test_without_a_profile_there_is_no_named_login_to_renew() -> None:
    assert "no profile is configured" in identity_module.login_capability(
        **_machine(profile=""))


def test_a_profile_that_is_not_an_sso_profile_is_named_as_such() -> None:
    problem = identity_module.login_capability(
        **_machine(profile_config={"region": "eu-central-1"}))
    assert problem == f"profile {PRIMARY} is not an SSO profile"


def test_an_sso_session_and_a_legacy_sso_start_url_both_count() -> None:
    legacy = {"sso_start_url": "https://example.awsapps.com/start"}
    assert identity_module.login_capability(**_machine(profile_config=legacy)) == ""


def test_without_the_cli_there_is_nothing_to_run() -> None:
    assert identity_module.login_capability(**_machine(aws_cli=None)) == (
        "the aws CLI is not on PATH")


@pytest.mark.parametrize("marker", identity_module.CLOUD_MARKERS)
def test_platform_supplied_credentials_are_left_alone(marker: str) -> None:
    """A task role, an instance profile, a pod identity, a Lambda: no browser
    will open there, and those credentials renew themselves anyway."""
    problem = identity_module.login_capability(**_machine(environ={marker: "set"}))
    assert marker in problem and "platform" in problem


def test_a_container_is_not_a_place_a_browser_opens() -> None:
    assert "container" in identity_module.login_capability(**_machine(container=True))


def test_a_headless_linux_box_is_refused_and_a_desktop_one_is_not() -> None:
    headless = _machine(platform="linux", environ={})
    assert "no display" in identity_module.login_capability(**headless)
    assert identity_module.login_capability(
        **_machine(platform="linux", environ={"DISPLAY": ":0"})) == ""
    assert identity_module.login_capability(
        **_machine(platform="linux", environ={"WAYLAND_DISPLAY": "wayland-0"})) == ""


def test_macos_and_windows_need_no_display_variable() -> None:
    assert identity_module.login_capability(**_machine(platform="win32")) == ""


# --- which failures are worth renewing over -------------------------------

@pytest.mark.parametrize("code_value", sorted(identity_module.CREDENTIAL_ERROR_CODES))
def test_a_stale_credential_code_is_a_credential_error(code_value: str) -> None:
    assert identity_module.is_credential_error(
        ClientError({"Error": {"Code": code_value, "Message": "x"}}, "Op"))


def test_a_refusal_is_not_a_stale_credential() -> None:
    """The two need opposite answers: renew the one, report the other."""
    assert not identity_module.is_credential_error(
        ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Op"))


def test_a_missing_credential_is_a_credential_error_by_its_type() -> None:
    assert identity_module.is_credential_error(NoCredentialsError())
    assert not identity_module.is_credential_error(ValueError("unrelated"))


# --- the login is the machine's, not the check's --------------------------

@pytest.fixture(autouse=True)
def _forget_logins() -> None:
    """Module state is the point (one browser per machine), so each test starts
    from a machine nobody has logged into yet."""
    identity_module.SSO_LOGINS.forget()


class _Clock:
    """A hand-wound monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _recorder(problem: str = "") -> Any:
    calls: list[tuple[str, int]] = []

    def login(profile: str, timeout: int) -> str:
        calls.append((profile, timeout))
        return problem

    login.calls = calls                 # type: ignore[attr-defined]
    return login


def test_a_failed_login_is_not_retried_inside_the_cooldown() -> None:
    """At `frequency: 60s` an unattended failure would otherwise be a browser
    window a minute for as long as you are away from the desk."""
    logins = identity_module.SsoLogins()
    clock = _Clock()
    login = _recorder("nobody finished it")
    first = logins.renew(PRIMARY, timeout=120, cooldown=600,
                         login=login, clock=clock)
    clock.now += 599
    second = logins.renew(PRIMARY, timeout=120, cooldown=600,
                          login=login, clock=clock)
    assert first == "nobody finished it"
    assert "not tried again within 10m" in second
    assert len(login.calls) == 1


def test_past_the_cooldown_it_tries_again() -> None:
    logins = identity_module.SsoLogins()
    clock = _Clock()
    login = _recorder("nobody finished it")
    logins.renew(PRIMARY, timeout=120, cooldown=600, login=login, clock=clock)
    clock.now += 601
    logins.renew(PRIMARY, timeout=120, cooldown=600, login=login, clock=clock)
    assert len(login.calls) == 2


def test_a_second_account_on_one_profile_reuses_the_login_just_made() -> None:
    """Two accounts of one profile go stale in the same run; the first one's
    login fixed both, so the second must not open a browser to find that out."""
    logins = identity_module.SsoLogins()
    clock = _Clock()
    login = _recorder()
    assert logins.renew(PRIMARY, timeout=120, cooldown=600,
                        login=login, clock=clock) == ""
    clock.now += 1
    assert logins.renew(PRIMARY, timeout=120, cooldown=600,
                        login=login, clock=clock) == ""
    assert len(login.calls) == 1


def test_two_profiles_are_two_logins() -> None:
    logins = identity_module.SsoLogins()
    clock = _Clock()
    login = _recorder()
    logins.renew(PRIMARY, timeout=120, cooldown=600, login=login, clock=clock)
    logins.renew(SECONDARY, timeout=120, cooldown=600, login=login, clock=clock)
    assert [profile for profile, _ in login.calls] == [PRIMARY, SECONDARY]


def test_concurrent_renewals_of_one_profile_run_one_login() -> None:
    """The lock is per profile and the cooldown is read inside it, so the
    thread that queued behind a login sees the fresh stamp rather than a
    second browser."""
    logins = identity_module.SsoLogins()
    started = threading.Event()
    calls: list[str] = []

    def slow_login(profile: str, timeout: int) -> str:
        calls.append(profile)
        started.set()
        time.sleep(0.05)
        return ""

    def renew() -> None:
        logins.renew(PRIMARY, timeout=120, cooldown=600, login=slow_login)

    threads = [threading.Thread(target=renew) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert calls == [PRIMARY]


# --- running the CLI ------------------------------------------------------
#
# The CLI starts through little-sister's process function (little-sister ADR-0089):
# what a login came to is a `Finished`, and a CLI that could not start is
# `NotStarted`. Most of these replace that one call; the last two run a stand-in
# `aws` for real, from a directory put first on PATH.

def _finished(status: int = 0, *, stderr: str = "", stdout: str = "",
              ended: process.Ended = process.Ended.EXITED) -> process.Finished:
    return process.Finished(status=status, stdout=stdout.encode(),
                            stderr=stderr.encode(), ended=ended, stdout_cut=False,
                            stderr_cut=False, seconds=0.0)


def _not_started(cause: OSError | None) -> process.NotStarted:
    """What the process function raises: with the ``OSError`` that said so, or none
    while the instance is stopping."""
    try:
        if cause is None:
            raise process.NotStarted("aws was not started: the instance is stopping")
        raise process.NotStarted(f"aws could not be started: {cause}") from cause
    except process.NotStarted as error:
        return error


def _ran(monkeypatch: pytest.MonkeyPatch,
         result: Any) -> list[tuple[list[str], dict[str, Any]]]:
    """Replace the process function and record what it was asked to run."""
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv: Sequence[str], **kwargs: Any) -> process.Finished:
        calls.append((list(argv), kwargs))
        if isinstance(result, BaseException):
            raise result
        assert isinstance(result, process.Finished)
        return result

    monkeypatch.setattr(identity_module.process, "run", fake_run)
    return calls


def test_the_login_command_names_the_profile(
        monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _ran(monkeypatch, _finished(0))
    assert identity_module.run_sso_login(PRIMARY, 120) == ""
    assert [argv for argv, _ in calls] == [
        ["aws", "sso", "login", "--profile", PRIMARY]]


def test_without_a_profile_the_cli_is_left_to_pick_one(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`login: always` with no profile is still meaningful — AWS_PROFILE in the
    environment is a profile the CLI will find and this check never saw."""
    calls = _ran(monkeypatch, _finished(0))
    identity_module.run_sso_login("", 120)
    assert [argv for argv, _ in calls] == [["aws", "sso", "login"]]


def test_the_login_is_bounded_by_the_timeout_it_was_given(
        monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _ran(monkeypatch, _finished(0))
    identity_module.run_sso_login(PRIMARY, 120)
    assert calls[0][1]["timeout"] == 120


def test_a_failed_login_reports_the_cli_s_last_word(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _ran(monkeypatch, _finished(
        255, stderr="Attempting to automatically open the SSO page\n"
                    "Error loading SSO Token: Token has expired"))
    problem = identity_module.run_sso_login(PRIMARY, 120)
    assert "Token has expired" in problem
    assert "Attempting to automatically" not in problem


def test_a_login_nobody_completes_is_stopped_and_says_so(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """It holds an engine worker thread while it waits, so the bound is the
    point of the sentence, not decoration."""
    _ran(monkeypatch, _finished(-15, ended=process.Ended.BOUND))
    assert "still waiting after 2m" in identity_module.run_sso_login(PRIMARY, 120)


def test_a_login_the_instance_s_stop_ended_says_so(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A stop ends a login still waiting for its person (little-sister ADR-0088)."""
    _ran(monkeypatch, _finished(-15, ended=process.Ended.STOP))
    problem = identity_module.run_sso_login(PRIMARY, 120)
    assert "ended by the instance's stop" in problem
    assert "still waiting" not in problem


def test_a_missing_cli_is_a_reason_not_a_crash(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _ran(monkeypatch, _not_started(FileNotFoundError(2, "No such file", "aws")))
    assert identity_module.run_sso_login(PRIMARY, 120) == "the aws CLI is not on PATH"


def test_a_cli_that_cannot_start_says_why(monkeypatch: pytest.MonkeyPatch) -> None:
    _ran(monkeypatch, _not_started(PermissionError(13, "Permission denied", "aws")))
    problem = identity_module.run_sso_login(PRIMARY, 120)
    assert "could not be started" in problem
    assert "Permission denied" in problem


def test_a_login_asked_for_while_the_instance_stops_is_not_started(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _ran(monkeypatch, _not_started(None))
    problem = identity_module.run_sso_login(PRIMARY, 120)
    assert "the instance is stopping" in problem


def test_the_cli_s_words_are_escaped_before_they_reach_a_card(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """A reason renders as Markdown (little-sister ADR-0018), and the CLI's
    stderr is captured output like any other."""
    _ran(monkeypatch, _finished(1, stderr="see *this* [link](http://x)"))
    problem = identity_module.run_sso_login(PRIMARY, 120)
    assert r"\*this\*" in problem and r"\[link\]" in problem


def _stand_in(directory: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    """A stand-in `aws`, first on PATH, that the process function runs for real."""
    aws = directory / "aws"
    aws.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    aws.chmod(0o755)
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ.get('PATH', '')}")


def test_a_stand_in_cli_gets_its_arguments_and_nothing_on_stdin(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """What a login needs arrives, and nothing it does not: the CLI opens the browser
    itself and reads nothing from stdin, which is ``/dev/null``."""
    _stand_in(tmp_path, monkeypatch,
              'printf "%s\\n" "$@" > "$0.args"\n'
              'cat > "$0.stdin"\n'
              'echo "https://device.sso.example/?user_code=ABCD-EFGH"\n')
    assert identity_module.run_sso_login(PRIMARY, 30) == ""
    assert (tmp_path / "aws.args").read_text().split() == [
        "sso", "login", "--profile", PRIMARY]
    assert (tmp_path / "aws.stdin").read_text() == ""


def test_a_stand_in_cli_that_never_returns_is_ended_at_the_bound(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stand_in(tmp_path, monkeypatch, "sleep 60\n")
    started = time.monotonic()
    problem = identity_module.run_sso_login(PRIMARY, 1)
    assert "still waiting after" in problem
    assert time.monotonic() - started < 10


# --- the ``sso:`` block, read once for three packages ------------------------
#
# The claim these are written from is the reader's docstring: the differences
# between its callers arrive as arguments (`default`, `allow_cooldown`), and a
# refusal leaves as **parts** for the caller to word and type — never as a
# sentence of this module's. The sentences themselves are pinned where they are
# decided: `test_aws.py` for the check, each deployment's suite for its own.


def test_an_absent_block_is_the_callers_default() -> None:
    boot = SsoConfig(login="never", timeout_seconds=45, cooldown_seconds=1)
    assert parse_sso_block(None, where="w") == SsoConfig()
    assert parse_sso_block(None, where="w", default=boot) == boot


def test_the_block_is_read_in_the_configs_units() -> None:
    settings = parse_sso_block({"login": " NEVER ", "timeout": "3m",
                                "cooldown": "1h"}, where="w")
    assert (settings.login, settings.timeout_seconds,
            settings.cooldown_seconds) == ("never", 180, 3600)


def test_absent_keys_take_the_defaults_numbers_not_the_modules() -> None:
    """The budget belongs to the caller: a boot that passes 45 seconds must
    get 45 for a block that says nothing about time — never this module's
    generous check-shaped numbers."""
    boot = SsoConfig(timeout_seconds=45, cooldown_seconds=7)
    settings = parse_sso_block({"login": "never"}, where="w", default=boot)
    assert settings.timeout_seconds == 45
    assert settings.cooldown_seconds == 7


def test_without_cooldown_the_key_is_unknown_not_ignored() -> None:
    """`allow_cooldown=False` is a refusal, not a shrug: a caller that reads
    its secrets once at startup must not carry a knob that answers how often
    an unattended machine may re-open a browser."""
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block({"cooldown": "10m"}, where="w", allow_cooldown=False)
    assert caught.value.kind == "unknown-keys"
    assert caught.value.unknown == ("cooldown",)
    assert caught.value.accepted == ("login", "timeout")


def test_without_cooldown_the_defaults_cooldown_survives_untouched() -> None:
    boot = SsoConfig(cooldown_seconds=5)
    settings = parse_sso_block({"timeout": "10s"}, where="w", default=boot,
                               allow_cooldown=False)
    assert settings.cooldown_seconds == 5


def test_a_non_mapping_is_parts_whose_factual_line_names_the_block() -> None:
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block(["never"], where="quality 'sso'")
    assert caught.value.kind == "not-a-mapping"
    assert str(caught.value).startswith("quality 'sso': ")


def test_unknown_keys_arrive_sorted_beside_what_was_accepted() -> None:
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block({"cooldwn": "5m", "Timeout": 3}, where="w")
    assert caught.value.kind == "unknown-keys"
    assert caught.value.unknown == ("Timeout", "cooldwn")
    assert caught.value.accepted == ("cooldown", "login", "timeout")


def test_a_login_outside_the_modes_reports_what_it_compared() -> None:
    """`got` is the coerced word — stripped and lowered — because that is the
    thing that was looked up, and the modes come in declaration order, which
    is the order every caller prints them in today."""
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block({"login": " Sometimes "}, where="w")
    assert caught.value.kind == "not-a-mode"
    assert caught.value.key == "login"
    assert caught.value.got == "sometimes"
    assert caught.value.accepted == SSO_LOGIN_MODES


def test_a_login_written_and_left_empty_is_not_a_mode_either() -> None:
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block({"login": None}, where="w")
    assert caught.value.kind == "not-a-mode"
    assert caught.value.got == "none"


@pytest.mark.parametrize("key", ["timeout", "cooldown"])
def test_a_malformed_duration_is_a_part_not_an_escaped_checkerror(
        key: str) -> None:
    """The one refusal that has escaped a caller untyped: `parse_duration`
    speaks `CheckError`, which not every caller of this reader does. The catch
    sits inside the reader, so a malformed duration is the same kind of part
    as every other refusal — and names its key."""
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block({key: "a while"}, where="w")
    assert caught.value.kind == "not-a-duration"
    assert caught.value.key == key
    assert "invalid duration" in caught.value.problem


@pytest.mark.parametrize("value", [0, "0s", "-1m"])
def test_a_timeout_of_zero_or_less_is_refused_with_its_key(
        value: object) -> None:
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block({"timeout": value}, where="w")
    assert caught.value.kind == "not-positive"
    assert caught.value.key == "timeout"


def test_a_negative_cooldown_is_refused_and_zero_is_not() -> None:
    """Zero cooldown is a real setting — try again every time — where a zero
    timeout would kill a login before it starts. The two bounds differ on
    purpose, so they are pinned apart."""
    with pytest.raises(SsoBlockError) as caught:
        parse_sso_block({"cooldown": "-1m"}, where="w")
    assert caught.value.kind == "negative"
    assert caught.value.key == "cooldown"
    assert parse_sso_block({"cooldown": 0}, where="w").cooldown_seconds == 0


# --- one optional string, read once for three packages -----------------------
#
# The rule is one sentence — a key written and left empty is a typo, not a
# value — and, like the ``sso:`` block's, its refusals are worded and typed at
# the call sites. These tests pin the parts and the two behaviors the callers
# lean on: the caller's own default for an absent key, and the refusal (never
# a coercion) of a value that is not text.


def test_an_absent_key_is_the_callers_default() -> None:
    assert parse_optional_text({}, "profile", where="w") == ""
    assert parse_optional_text({}, "role_session_name", where="w",
                               default="little-sister") == "little-sister"


def test_a_present_value_arrives_stripped() -> None:
    assert parse_optional_text({"profile": "  corp  "}, "profile",
                               where="w") == "corp"


def test_a_key_written_and_left_empty_is_a_typo_not_the_default() -> None:
    """The rule the reader exists for: ``key in entry`` rather than a ``None``
    test, because reading ``profile:`` with nothing after it as *unset* is how
    a credential path silently becomes the ambient one — the one failure that
    looks like nothing at all."""
    with pytest.raises(OptionalTextError) as caught:
        parse_optional_text({"profile": None}, "profile", where="w",
                            default="fallback")
    assert caught.value.kind == "left-empty"
    assert caught.value.key == "profile"


@pytest.mark.parametrize("value", ["", "   "])
def test_text_with_nothing_in_it_is_refused_with_what_was_read(
        value: str) -> None:
    with pytest.raises(OptionalTextError) as caught:
        parse_optional_text({"region": value}, "region", where="w")
    assert caught.value.kind == "blank"
    assert caught.value.key == "region"
    assert caught.value.got == value


@pytest.mark.parametrize("value", [123, True, ["a"]])
def test_a_value_that_is_not_text_is_refused_not_stringified(
        value: object) -> None:
    """``profile: 123`` is not somebody's profile name; it is a line that lost
    its quoting or its meaning. Two callers used to stringify here, no suite
    anywhere pinned the coercion, and the surprise would have been handed to
    boto3 and to ``aws sso login`` — so the refusal wins, the same typo family
    as a key written and left empty."""
    with pytest.raises(OptionalTextError) as caught:
        parse_optional_text({"profile": value}, "profile", where="w")
    assert caught.value.kind == "not-text"
    assert caught.value.got == value


def test_the_factual_line_names_the_field_and_the_key() -> None:
    with pytest.raises(OptionalTextError) as caught:
        parse_optional_text({"profile": None}, "profile",
                            where="quality 'profile'")
    assert str(caught.value).startswith("quality 'profile': ")
    assert "'profile'" in str(caught.value)
