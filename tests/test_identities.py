"""Named AWS identities: what `config/aws.yaml` may say, and what it may not."""
from __future__ import annotations

from pathlib import Path

import pytest
from little_sister import config_dir
from little_sister.checks import CheckError

from little_sister_aws import identities as aws_identities
from little_sister_aws.identities import (
    DEFAULT_STARTUP_LOGIN_TIMEOUT_SECONDS,
    IdentityConfigError,
    declare_aspect,
    load_identities,
)
from little_sister_aws.identity import (
    DEFAULT_ROLE_SESSION_NAME,
    DEFAULT_STS_REGION,
)

ROLE = "arn:aws:iam::000000000000:role/monitoring-role"


@pytest.fixture(autouse=True)
def _declared() -> None:
    """The aspect is claimed before anything asks for its file — the order
    `register_extensions()` keeps, and the order these tests run in."""
    declare_aspect()


def _root(tmp_path: Path, body: str | None) -> Path:
    """A configuration root, with or without an `aws.yaml` in it."""
    root = tmp_path / "config"
    root.mkdir()
    if body is not None:
        (root / "aws.yaml").write_text(body, encoding="utf-8")
    return root


def test_no_file_at_all_is_the_ambient_chain(tmp_path: Path) -> None:
    """What this deployment ran with before identities existed, and what it keeps
    where it declares none."""
    assert load_identities(_root(tmp_path, None)) == {}


def test_an_empty_file_declares_nothing(tmp_path: Path) -> None:
    assert load_identities(_root(tmp_path, "# nothing yet\n")) == {}


def test_an_identity_carries_its_profile_role_and_region(tmp_path: Path) -> None:
    root = _root(tmp_path, f"""
live:
  profile: primary-admin
  role_arn: {ROLE}
  region: eu-west-1
""")

    live = load_identities(root)["live"]

    assert live.name == "live"
    assert live.identity.profile == "primary-admin"
    assert live.identity.role_arn == ROLE
    assert live.region == "eu-west-1"


def test_the_session_defaults_are_the_packages_own(tmp_path: Path) -> None:
    """`role_session_name` and `sts_region` are what CloudTrail and the
    `AssumeRole` call get, and an installation that says nothing gets what the
    `aws` check gets — one answer for the family, not two."""
    identity = load_identities(_root(tmp_path, f"live:\n  role_arn: {ROLE}\n"))

    assert identity["live"].identity.role_session_name == DEFAULT_ROLE_SESSION_NAME
    assert identity["live"].identity.sts_region == DEFAULT_STS_REGION
    assert identity["live"].region == ""


def test_a_profile_alone_is_an_identity(tmp_path: Path) -> None:
    """No role: the profile *is* the reader. That is the single-account case and
    the one a laptop uses."""
    identity = load_identities(_root(tmp_path, "local:\n  profile: corp-sso\n"))

    assert identity["local"].identity.profile == "corp-sso"
    assert identity["local"].identity.role_arn == ""


def test_an_identity_that_names_nothing_is_refused(tmp_path: Path) -> None:
    """Neither a profile nor a role is the ambient chain wearing a name, and a
    reference through it would read whatever the process happens to be — the
    exact confusion these identities exist to end."""
    with pytest.raises(IdentityConfigError, match="ambient chain under another"):
        load_identities(_root(tmp_path, "live:\n  region: eu-west-1\n"))


@pytest.mark.parametrize("name", ["Live", "live_one", "1live", "aws sm", ""])
def test_a_name_that_could_not_be_a_scheme_is_refused(
        tmp_path: Path, name: str) -> None:
    """The name becomes the tail of `aws-ssm-<name>`, and little-sister lower-cases
    a scheme before it looks it up — so a name that is not already in that shape
    would register under one spelling and resolve under another."""
    with pytest.raises(IdentityConfigError, match="not a usable identity name"):
        load_identities(_root(tmp_path, f"{name!r}:\n  role_arn: {ROLE}\n"))


def test_an_unknown_key_is_named_rather_than_ignored(tmp_path: Path) -> None:
    """A misspelled `role_arn` would otherwise leave the identity reading with the
    profile's own rights: a different account's answer to the same question, and
    nothing on the card to say so."""
    root = _root(tmp_path, f"live:\n  role: {ROLE}\n  profile: corp-sso\n")

    with pytest.raises(IdentityConfigError, match="unknown key\\(s\\) 'role'"):
        load_identities(root)


def test_a_key_written_and_left_empty_is_refused(tmp_path: Path) -> None:
    """The `aws` check learned this one the hard way about `profile:` — a key with
    nothing after it is a typo, and reading it as "unset" is how a credential path
    silently becomes the ambient one."""
    with pytest.raises(IdentityConfigError, match="written and left empty"):
        load_identities(_root(tmp_path, f"live:\n  profile:\n  role_arn: {ROLE}\n"))


def test_an_identity_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    with pytest.raises(IdentityConfigError, match="must be a mapping"):
        load_identities(_root(tmp_path, "live: primary-admin\n"))


def test_a_file_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    with pytest.raises(IdentityConfigError, match="must be a mapping"):
        load_identities(_root(tmp_path, "- live\n- develop\n"))


def test_a_file_that_is_not_yaml_is_refused(tmp_path: Path) -> None:
    with pytest.raises(IdentityConfigError, match="could not be read"):
        load_identities(_root(tmp_path, "live: [unclosed\n"))


def test_the_aspect_is_declared_under_this_packages_name() -> None:
    """`/system` says whose `config/aws.yaml` an operator is looking at, and the
    answer is the package that owns the file's **shape** — a deployment owns its
    contents, and a deployment's own suite is what watches that file still parse
    against us."""
    declare_aspect()

    assert aws_identities.ASPECT in config_dir.registered_aspects()
    assert config_dir.aspect_owner(aws_identities.ASPECT).startswith(
        "little_sister_aws")


# --- the login this identity may renew while the app is starting ------------

def test_an_identity_says_nothing_and_gets_the_boots_budget(
        tmp_path: Path) -> None:
    """45 seconds rather than the check's 120: a check spends its own timeout on
    an engine worker thread, and this one holds a worker that has not finished
    importing the application."""
    identity = load_identities(_root(tmp_path, f"live:\n  role_arn: {ROLE}\n"))["live"]

    assert identity.sso.login == "auto"
    assert identity.sso.timeout_seconds == DEFAULT_STARTUP_LOGIN_TIMEOUT_SECONDS


def test_an_identity_may_say_never_and_how_long(tmp_path: Path) -> None:
    root = _root(tmp_path, f"""
live:
  role_arn: {ROLE}
  sso:
    login: never
    timeout: 10s
""")

    identity = load_identities(root)["live"]

    assert identity.sso.login == "never"
    assert identity.sso.timeout_seconds == 10


@pytest.mark.parametrize("block,expected", [
    ("  sso:\n    cooldown: 10m\n", "unknown key\\(s\\) in 'sso' 'cooldown'"),
    ("  sso:\n    login: sometimes\n", "'sso.login' must be one of"),
    ("  sso:\n    timeout: 0\n", "'sso.timeout' must be more than zero"),
    ("  sso: never\n", "'sso' must be a mapping"),
])
def test_a_login_block_that_could_not_work_is_refused(
        tmp_path: Path, block: str, expected: str) -> None:
    """`cooldown` is the interesting refusal: the check has one, and copying it
    here would answer a question a startup never asks — how often may an
    unattended machine re-open a browser."""
    with pytest.raises(IdentityConfigError, match=expected):
        load_identities(_root(tmp_path, f"live:\n  role_arn: {ROLE}\n{block}"))


def test_a_malformed_timeout_refuses_the_start_naming_all_three(
        tmp_path: Path) -> None:
    """File, identity and key — the naming every other refusal in this file
    already carries. A malformed duration used to escape the boot as a bare
    `CheckError` naming none of them, because `parse_duration` speaks that
    type; the shared reader catches it at the source, and this file's
    translation is what turns it into the refusal-to-start it always should
    have been."""
    root = _root(tmp_path,
                 f"live:\n  role_arn: {ROLE}\n  sso:\n    timeout: a while\n")

    with pytest.raises(IdentityConfigError,
                       match=r"aws\.yaml.*identity 'live'.*'sso\.timeout'"
                             r".*invalid duration") as caught:
        load_identities(root)

    assert not isinstance(caught.value, CheckError)


def test_a_block_that_says_only_never_still_gets_the_boots_budget(
        tmp_path: Path) -> None:
    """The 45 seconds must survive a block that is present but silent about
    time: the default travels into the shared reader as an argument, and a
    reader that fell back to its own check-shaped numbers would hand this
    boot the check's 120."""
    root = _root(tmp_path, f"""
live:
  role_arn: {ROLE}
  sso:
    login: never
""")

    identity = load_identities(root)["live"]

    assert identity.sso.timeout_seconds == DEFAULT_STARTUP_LOGIN_TIMEOUT_SECONDS


@pytest.mark.parametrize("value", ["'   '", "123"])
def test_a_blank_or_non_text_value_draws_this_files_own_sentence(
        tmp_path: Path, value: str) -> None:
    """The optional-string reading is the identity seam's; the sentence —
    quoting the key, "must be a non-empty string" — is this file's own. A
    non-text value draws the same one: `profile: 123` is a line that lost its
    quoting, the same typo family as a key written and left empty, and this
    file has always refused it rather than stringifying."""
    body = f"live:\n  role_arn: {ROLE}\n  profile: {value}\n"

    with pytest.raises(IdentityConfigError,
                       match="'profile' must be a non-empty string"):
        load_identities(_root(tmp_path, body))
