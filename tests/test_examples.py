"""The three shipped examples, read by the code that will read an operator's copy.

`examples/checks/aws.yaml`, `examples/aws.yaml` and `examples/aws-keeper.yaml` are what
somebody copies to start from, and the first two were the one pair of artifacts no test
read. That is the wrong file to leave unparsed: this release replaced the whole
threshold vocabulary — `max_per_name` and `max_age` became pairs,
`ignore_name_patterns` and `ignore:` became a rule action — and an example still naming
a retired key would have shipped past a green suite to fail in somebody's first start,
on the aspect parser's unknown-key refusal.

So all three are read here through the entry points the application itself uses:
`AwsCheck.from_config`, `load_identities` and `load_keeper_config`. Nothing is mocked
and nothing reaches AWS — the check example declares no `secrets:` block, so no
reference is resolved, and a check is only *constructed*, never run.

The assertions past "it parses" are deliberately about **shape**, not about numbers.
An example is meant to be edited — a level raised, a rule renamed — and a test that
pinned those values would fail on every improvement to it. What is pinned is that the
file still demonstrates the vocabulary it exists to demonstrate: that it grades, that
it carries rules, and that at least one of them ignores.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from little_sister_aws.aws import AwsCheck
from little_sister_aws.identities import declare_aspect, load_identities
from little_sister_aws.keeper import KeeperConfig, load_keeper_config
from little_sister_aws.keeper import declare_aspect as declare_keeper_aspect

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(autouse=True)
def _declared() -> None:
    """The aspects are claimed before anything asks for their files — the order
    `register_extensions()` keeps."""
    declare_aspect()
    declare_keeper_aspect()


def _check_config() -> dict[str, Any]:
    body = yaml.safe_load(
        (EXAMPLES / "checks" / "aws.yaml").read_text(encoding="utf-8"))
    assert isinstance(body, dict), "the check example must be a mapping"
    return body


def _example_check() -> AwsCheck:
    check = AwsCheck.from_config(_check_config(), EXAMPLES / "checks")
    assert isinstance(check, AwsCheck)
    return check


def test_the_check_example_parses() -> None:
    """Every key in it is one this version still takes.

    The aspect parsers refuse an unknown key rather than ignoring it, so this one
    assertion is the whole guard: a retired key left in the example fails here with
    the message an operator would have got.
    """
    assert _example_check().accounts


def test_the_check_example_is_still_the_documented_type() -> None:
    assert _check_config()["type"] == "aws"


def test_the_ec2_example_grades_and_carries_rules() -> None:
    """It is the aspect the release rewrote, and the example is where the new
    vocabulary is shown: pairs on the block, and rules that override them."""
    ec2 = _example_check().ec2

    assert ec2.enabled
    assert ec2.grades, "the ec2 example must show thresholds — it grades nothing"
    assert ec2.rules, "the ec2 example must show `rules:`"
    assert any(rule.ignore for rule in ec2.rules), (
        "ignoring is a rule action now, and the example is where that is shown")
    assert any(rule.overrides for rule in ec2.rules), (
        "a rule that overrides no level demonstrates nothing about rules")


def test_the_codepipeline_and_lambda_examples_carry_rules_too() -> None:
    """Both aspects lost a key to the same move, so both examples have to show
    where it went."""
    check = _example_check()

    assert check.codepipeline.rules, "the codepipeline example must show `rules:`"
    assert any(rule.ignore for rule in check.codepipeline.rules)
    assert check.lambda_.rules, "the lambda example must show `rules:`"
    assert any(rule.ignore for rule in check.lambda_.rules)


def test_the_keeper_example_parses() -> None:
    """`examples/aws-keeper.yaml` is read by the loader an operator's copy meets,
    which refuses an unknown key rather than ignoring it — so a key retired from
    this file would fail here with the message the operator would have got."""
    config = load_keeper_config(EXAMPLES)

    assert isinstance(config, KeeperConfig)
    assert config.bucket, "the example must show a bucket — it is the one required key"


def test_the_keeper_example_shows_every_key_it_takes() -> None:
    """PL5: the example is the annotated *shape*, so a key it stops demonstrating
    is a key nobody copying this file will know exists."""
    config = load_keeper_config(EXAMPLES)

    assert config is not None
    assert config.prefix, "the example must show `prefix:`"
    assert config.identity, "the example must show `identity:`"
    assert config.region, "the example must show `region:`"
    assert config.prefix.endswith("/"), (
        "a prefix is normalized to end in one separator, and the example is read "
        "through the loader that does it")


def test_the_identities_example_parses() -> None:
    """`examples/aws.yaml` is another file an operator copies, and it is read by a
    different loader — through a configuration root, exactly as a deployment's is."""
    identities = load_identities(EXAMPLES)

    assert identities, "the identities example must declare at least one identity"
    for name, declared in identities.items():
        assert name == name.lower()
        assert (declared.identity.profile or declared.identity.role_arn
                or declared.region), (
            f"identity {name!r} names nothing — the loader refuses that")


# `console_link` and `account_id` are shown commented, as `profile:` is: unset, nothing
# moves. So no parser reads them where they stand, and a template that had stopped
# loading would ship in the one file an operator copies it from. They are read here the
# way an operator who takes the `#` away has them read.

def _shown(key: str) -> list[Any]:
    """Every value the check example shows for *key* on a commented line."""
    text = (EXAMPLES / "checks" / "aws.yaml").read_text(encoding="utf-8")
    return [yaml.safe_load(found) for found in re.findall(
        rf'^ *# {key}: ("[^"]*")', text, re.MULTILINE)]


def test_the_check_example_shows_a_console_link_on_the_check_and_on_an_account(
        ) -> None:
    """Both templates load, each names the two tokens, and the account's own is the
    one its links are wrapped in."""
    shown = _shown("console_link")
    assert len(shown) == 2, (
        "the example must show `console_link:` on the check and on an account")
    on_the_check, on_the_account = shown
    assert on_the_check != on_the_account, (
        "an account's own template that is the check's demonstrates no replacing")
    config = _check_config()
    config["console_link"] = on_the_check
    config["accounts"][1]["console_link"] = on_the_account
    check = AwsCheck.from_config(config, EXAMPLES / "checks")
    assert isinstance(check, AwsCheck)

    live, backup = check.accounts
    assert check.console_link_for(live) == on_the_check
    assert check.console_link_for(backup) == on_the_account
    for template in shown:
        assert "{url}" in template and "{account_id}" in template
    # Neither account says `account_id`: each id is read out of the role's ARN.
    assert (live.account_id, backup.account_id) == ("000000000000", "000000000001")


def test_the_check_example_shows_an_account_id_that_loads() -> None:
    """In quotes, as the comment beside it asks — and on the account whose role says
    the same, since one beside a role in another account is refused."""
    (shown,) = _shown("account_id")
    config = _check_config()
    config["accounts"][1]["account_id"] = shown
    check = AwsCheck.from_config(config, EXAMPLES / "checks")
    assert isinstance(check, AwsCheck)
    assert check.accounts[1].account_id == shown == "000000000001"


def test_the_readme_s_console_link_example_loads_as_it_is_written() -> None:
    """The README shows the template on a check and on an account that names no role.
    That block is read here beside the two keys every check file has, and says what
    the paragraph around it says: one id read out of a role, one said, and the
    account's own template in place of the check's."""
    readme = (EXAMPLES.parent / "README.md").read_text(encoding="utf-8")
    blocks = [block for block in re.findall(r"```yaml\n(.*?)```", readme, re.DOTALL)
              if "console_link:" in block]
    assert len(blocks) == 1, "the README shows `console_link:` in one block"
    config = {"type": "aws", "path": "/team/aws", **yaml.safe_load(blocks[0])}
    check = AwsCheck.from_config(config, EXAMPLES)
    assert isinstance(check, AwsCheck)

    live, sandbox = check.accounts
    assert (live.role_arn != "", sandbox.role_arn) == (True, "")
    assert (live.account_id, sandbox.account_id) == ("000000000000", "000000000001")
    assert check.console_link_for(live) == check.console_link != ""
    assert check.console_link_for(sandbox) == sandbox.console_link
    assert sandbox.console_link not in ("", check.console_link)
