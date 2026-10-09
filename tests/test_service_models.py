"""One loader of service models for every session this package builds (ADR-0011).

The one file beside ``test_noise.py`` that runs the SDK itself, and the one that does
it in this process: real sessions and real clients, built on keys made up here, with
nothing sent. Every client's endpoint is this machine, where nothing listens, and the
one call the check's own path makes — ``sts:AssumeRole`` — is answered by a
``before-send`` handler on the session that would make it, botocore's documented seam
for a response that stands in for the wire. The fakes the other suites inject at the
session seams never reach botocore, which is why the loader is tested here and not
there.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from botocore.loaders import Loader

from little_sister_aws import keeper, secrets
from little_sister_aws.aws import AwsCheck
from little_sister_aws.identities import NamedIdentity
from little_sister_aws.identity import SERVICE_MODELS, Identity, new_session
from little_sister_aws.keeper import KeeperConfig

REGION = "eu-central-1"
KEY, SECRET = "AKIAEXAMPLEEXAMPLE00", "not-a-key"

#: The directory boto3 appends to the loader of every session it builds, in boto3's
#: own words (``Session._setup_loader``).
BOTO3_DATA = os.path.join(os.path.dirname(boto3.__file__), "data")

#: What ``sts:AssumeRole`` answers, as the wire would carry it: the one call the
#: check's own path makes before it has a session for an account.
ASSUMED = b"""<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLEEXAMPLE00</AccessKeyId>
      <SecretAccessKey>not-a-key-either</SecretAccessKey>
      <SessionToken>not-a-token</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata>
</AssumeRoleResponse>"""


@pytest.fixture(autouse=True)
def _nowhere_to_send(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Nothing here reaches AWS: the credentials are the ones given, no profile and no
    instance is asked, and every endpoint is this machine, where nothing listens."""
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_DATA_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")


class _Wire:
    """Just enough of a raw HTTP body for botocore to read a response from."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def stream(self) -> list[bytes]:
        return [self._body]


def _answer_assume_role(session: boto3.Session) -> list[str]:
    """Have *session* answer ``sts:AssumeRole`` itself, and say what it was asked."""
    asked: list[str] = []

    def handler(request: Any, **_: Any) -> AWSResponse:
        asked.append(request.url)
        return AWSResponse(request.url, 200, {}, _Wire(ASSUMED))

    session.events.register("before-send.sts.AssumeRole", handler)
    return asked


def _loader_of(session: boto3.Session) -> Loader:
    """The loader *session*'s clients are built on: the component of the core session
    boto3 keeps under its one private name for it."""
    loader = session._session.get_component("data_loader")
    assert isinstance(loader, Loader)
    return loader


def _model(name: str) -> dict[str, Any]:
    """The model of service *name* as the process's loader holds it."""
    model = SERVICE_MODELS.loader(None).load_service_model(name, "service-2")
    assert isinstance(model, dict)
    return model


# --- two sessions the check builds -------------------------------------------


@pytest.fixture
def the_checks_two_sessions(monkeypatch: pytest.MonkeyPatch
                            ) -> tuple[boto3.Session, boto3.Session]:
    """The base session a check's run assumes from, and the session of one account
    with a role, built the way the run builds them — through the check's own seam."""
    monkeypatch.setenv("AWS_KEY", KEY)
    monkeypatch.setenv("AWS_SECRET", SECRET)
    check = AwsCheck.from_config({
        "type": "aws", "path": "/team/aws",
        "secrets": {"access_key_id": "env://AWS_KEY",
                    "secret_access_key": "env://AWS_SECRET"},
        "accounts": [{"name": "live",
                      "role_arn": "arn:aws:iam::000000000000:role/reader"}],
    }, Path("."))
    assert isinstance(check, AwsCheck)
    base = check._base_session()
    asked = _answer_assume_role(base)
    account = check._opened(base, check.accounts[0])
    assert len(asked) == 1 and asked[0].startswith("http://127.0.0.1:1/")
    return base, account


def test_two_sessions_the_check_builds_share_one_loader_object(
        the_checks_two_sessions: tuple[boto3.Session, boto3.Session]) -> None:
    base, account = the_checks_two_sessions
    assert base is not account
    assert _loader_of(base) is _loader_of(account) is SERVICE_MODELS.loader(None)


def test_a_client_from_each_is_built_on_the_one_model_the_loader_holds(
        the_checks_two_sessions: tuple[boto3.Session, boto3.Session]) -> None:
    """A client's ``meta.service_model`` is built on the loaded JSON as the loader
    cached it — its ``metadata`` is that JSON's own mapping, not a copy — so two
    clients on one cache show one object there, and two parses would show two."""
    base, account = the_checks_two_sessions
    for session in (base, account):
        client = session.client("ec2", region_name=REGION)
        assert client.meta.service_model.metadata is _model("ec2")["metadata"]


# --- the keeper's and the secret provider's sessions --------------------------


def test_the_keepers_client_is_built_on_the_same_loader() -> None:
    identity = NamedIdentity(name="keeper",
                             identity=Identity(access_key=KEY, secret_key=SECRET))
    client = keeper._new_client(
        identity, KeeperConfig(bucket="example-state", region=REGION))
    assert client.meta.service_model.metadata is _model("s3")["metadata"]


def test_the_secret_providers_session_is_built_on_the_same_loader(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "_SESSIONS", {})
    identity = NamedIdentity(name="reader", region=REGION,
                             identity=Identity(access_key=KEY, secret_key=SECRET))
    session = secrets._session_for(identity)
    assert _loader_of(session) is SERVICE_MODELS.loader(None)
    client = secrets._new_secrets_manager_client(identity)
    assert (client.meta.service_model.metadata
            is _model("secretsmanager")["metadata"])


# --- what the one loader is ----------------------------------------------------


def test_the_search_path_takes_boto3s_directory_once() -> None:
    """boto3 appends its ``data`` directory to the loader of every session it builds;
    the loader every session shares has it once, however many sessions are built."""
    new_session(aws_access_key_id=KEY, aws_secret_access_key=SECRET)
    loader = SERVICE_MODELS.loader(None)
    before = list(loader.search_paths)
    for _ in range(2):
        new_session(aws_access_key_id=KEY, aws_secret_access_key=SECRET)
    assert loader.search_paths == before
    assert loader.search_paths.count(BOTO3_DATA) == 1


def test_a_search_path_of_its_own_is_a_loader_of_its_own(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``AWS_DATA_PATH`` keeps its meaning: a session that names one is built on a
    loader that searches it first, as botocore's own would — one loader for that
    path, shared by every session that names it, beside the process's other one."""
    models = tmp_path / "models"
    monkeypatch.setenv("AWS_DATA_PATH", str(models))
    first = new_session(aws_access_key_id=KEY, aws_secret_access_key=SECRET)
    second = new_session(aws_access_key_id=KEY, aws_secret_access_key=SECRET)
    loader = _loader_of(first)
    assert loader is _loader_of(second) is SERVICE_MODELS.loader(str(models))
    assert loader is not SERVICE_MODELS.loader(None)
    assert loader.search_paths[0] == str(models)
    assert Loader.BUILTIN_DATA_PATH in loader.search_paths
    first.client("sts", region_name=REGION)        # the shipped models are still found
