"""The ``aws`` check type: the session seam, the account tree, and every aspect.

No live AWS anywhere: every session is built through the check's own
``_new_session`` seam, replaced here. They were written to depend on nothing
outside the module while it was still incubating in a deployment, which is why the
move into this package changed two import lines and nothing else.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from little_sister.checks import CHECK_TYPES, CheckError, CheckResult
from little_sister.status import StatusCode

from little_sister_aws import aws as aws_module
from little_sister_aws import identity as identity_module
from little_sister_aws.aws import (
    BATCH,
    CLOUDWATCH,
    CODEPIPELINE,
    DEFAULT_ROLE_SESSION_NAME,
    EC2,
    LAMBDA,
    NO_NAME_TAG,
    Account,
    Alarm,
    AwsCheck,
    CloudwatchConfig,
    Ec2Config,
    FunctionReading,
    Instance,
    LambdaConfig,
)

#: The clock every test runs against — held still, because an age is the one
#: reading here that would otherwise change between the fixture and the assertion.
NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aws_module, "_utcnow", lambda: NOW)

BASE_CONFIG: dict[str, Any] = {
    "type": "aws",
    "path": "/team/aws",
    "accounts": [
        {"name": "live", "role_arn": "arn:aws:iam::111:role/monitoring"},
        {"name": "backup", "role_arn": "arn:aws:iam::222:role/monitoring",
         "regions": ["eu-west-1"]},
    ],
}


#: What an installation has to write now that the package ships no thresholds of
#: its own: the two levels the old defaults used to supply. Every test *about*
#: grading names them, which is the point — a test that relied on a default would
#: be testing an opinion this package no longer holds.
GRADED_EC2: dict[str, Any] = {"max_per_name_warn": 1, "max_age_error": "14d"}


def _config(**overrides: Any) -> dict[str, Any]:
    return {**BASE_CONFIG, **overrides}


def _graded(**block: Any) -> AwsCheck:
    """A check whose `ec2:` block grades, with *block* layered over the levels."""
    return _build(ec2={**GRADED_EC2, **block})


def _build(**overrides: Any) -> AwsCheck:
    check = AwsCheck.from_config(_config(**overrides), Path("."))
    assert isinstance(check, AwsCheck)
    return check


def _alarm(name: str, state: str = "ALARM", *, description: str = "why",
           composite: bool = False) -> dict[str, Any]:
    return {"AlarmName": name, "StateValue": state,
            "AlarmDescription": description, "_composite": composite}


def _instance(name: str | None, state: str = "running", *,
              instance_id: str = "i-0",
              up: timedelta | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"InstanceId": instance_id, "State": {"Name": state}}
    if name is not None:
        row["Tags"] = [{"Key": "environment", "Value": "live"},
                       {"Key": "Name", "Value": name}]
    if up is not None:
        row["LaunchTime"] = NOW - up
    return row


def _fleet(name: str, size: int, up: timedelta) -> list[dict[str, Any]]:
    return [_instance(name, instance_id=f"i-{n}", up=up) for n in range(size)]


class _FakeSts:
    """Just enough STS to assume a role, or refuse to.

    ``expire`` is how many of the next calls (of either kind) fail the way an
    expired SSO token fails — the trigger for a renewal — as against ``refuse``,
    which is AWS saying no and means something else entirely.
    """

    def __init__(self, refuse: set[str] | None = None, expire: int = 0,
                 expire_roles: set[str] | None = None,
                 deny_identity: bool = False) -> None:
        self.refuse = refuse or set()
        self.expire = expire
        self.expire_roles = set(expire_roles or ())
        self.deny_identity = deny_identity
        self.calls: list[dict[str, str]] = []
        self.identity_calls = 0

    def _expired(self, operation: str) -> None:
        if self.expire > 0:
            self.expire -= 1
            raise ClientError(
                {"Error": {"Code": "ExpiredToken",
                           "Message": "The security token included in the "
                                      "request is expired"}},
                operation)

    def assume_role(self, *, RoleArn: str, RoleSessionName: str) -> dict[str, Any]:
        self.calls.append({"RoleArn": RoleArn, "RoleSessionName": RoleSessionName})
        if RoleArn in self.expire_roles:
            # Once each: the account is readable again after a renewal.
            self.expire_roles.discard(RoleArn)
            raise ClientError(
                {"Error": {"Code": "ExpiredToken", "Message": "expired"}},
                "AssumeRole")
        self._expired("AssumeRole")
        if RoleArn in self.refuse:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not allowed"}},
                "AssumeRole")
        return {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK",
                                "SessionToken": f"TOK-{RoleArn}"}}

    def get_caller_identity(self) -> dict[str, str]:
        self.identity_calls += 1
        self._expired("GetCallerIdentity")
        if self.deny_identity:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not allowed"}},
                "GetCallerIdentity")
        return {"Account": "111", "Arn": "arn:aws:iam::111:user/fake"}


class _FakePaginator:
    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        self.pages = pages
        self.alarm_types: list[list[str]] = []

    def paginate(self, *, AlarmTypes: list[str]) -> list[dict[str, Any]]:
        self.alarm_types.append(list(AlarmTypes))
        composite_wanted = "CompositeAlarm" in AlarmTypes
        out = []
        for page in self.pages:
            out.append({
                "MetricAlarms": [a for a in page if not a["_composite"]],
                "CompositeAlarms": [a for a in page
                                    if a["_composite"] and composite_wanted],
            })
        return out


class _FakeCloudwatch:
    def __init__(self, paginator: _FakePaginator, metrics: dict[str, Any],
                 calls: list[list[dict[str, Any]]]) -> None:
        self._paginator = paginator
        self._metrics = metrics
        self._calls = calls

    def get_paginator(self, name: str) -> _FakePaginator:
        assert name == "describe_alarms"
        return self._paginator

    def get_metric_data(self, *, StartTime: datetime, EndTime: datetime,
                        MetricDataQueries: list[dict[str, Any]]) -> dict[str, Any]:
        """A data point comes back only at a period at least as coarse as the one
        the fixture says the function has data at — which is what makes the
        60 → 300 → 3600 fallback testable."""
        self._calls.append(MetricDataQueries)
        results = []
        for query in MetricDataQueries:
            stat = query["MetricStat"]
            name = stat["Metric"]["Dimensions"][0]["Value"]
            point = self._metrics.get(name)
            if point is not None and stat["Period"] >= point.get("period", 60):
                results.append({"Id": query["Id"],
                                "Values": [point["errors"]],
                                "Timestamps": [NOW - point["age"]]})
            else:
                results.append({"Id": query["Id"], "Values": [], "Timestamps": []})
        return {"MetricDataResults": results}


class _FakeLambdaPaginator:
    def __init__(self, pages: list[list[str]]) -> None:
        self.pages = pages

    def paginate(self) -> list[dict[str, Any]]:
        return [{"Functions": [{"FunctionName": name} for name in page]}
                for page in self.pages]


class _FakeLambda:
    def __init__(self, pages: list[list[str]]) -> None:
        self._paginator = _FakeLambdaPaginator(pages)

    def get_paginator(self, name: str) -> _FakeLambdaPaginator:
        assert name == "list_functions"
        return self._paginator


class _FakeLogs:
    """The newest log event per function. A function absent from ``messages`` has
    no stream at all, which is what a never-invoked function looks like."""

    def __init__(self, messages: dict[str, str | None],
                 calls: list[str]) -> None:
        self._messages = messages
        self._calls = calls

    @staticmethod
    def _name(group: str) -> str:
        return group.removeprefix("/aws/lambda/")

    def describe_log_streams(self, *, logGroupName: str, orderBy: str,
                             descending: bool, limit: int) -> dict[str, Any]:
        self._calls.append(logGroupName)
        assert (orderBy, descending, limit) == ("LastEventTime", True, 1)
        if self._name(logGroupName) not in self._messages:
            return {"logStreams": []}
        return {"logStreams": [{"logStreamName": "2026/08/10/[$LATEST]abc"}]}

    def get_log_events(self, *, logGroupName: str, logStreamName: str,
                       limit: int, startFromHead: bool) -> dict[str, Any]:
        assert (limit, startFromHead) == (1, False)
        message = self._messages.get(self._name(logGroupName))
        if message is None:
            return {"events": []}
        return {"events": [{"message": message}]}


class _FakeEc2Paginator:
    """`describe_instances` pages, each a list of reservations."""

    def __init__(self, pages: list[list[list[dict[str, Any]]]]) -> None:
        self.pages = pages

    def paginate(self) -> list[dict[str, Any]]:
        return [{"Reservations": [{"Instances": r} for r in page]}
                for page in self.pages]


class _FakeEc2:
    def __init__(self, paginator: _FakeEc2Paginator) -> None:
        self._paginator = paginator

    def get_paginator(self, name: str) -> _FakeEc2Paginator:
        assert name == "describe_instances"
        return self._paginator


class _FakePipelinePaginator:
    def __init__(self, pages: list[list[str]]) -> None:
        self.pages = pages

    def paginate(self) -> list[dict[str, Any]]:
        return [{"pipelines": [{"name": name} for name in page]}
                for page in self.pages]


class _FakeCodePipeline:
    """Pipeline names by page, and each pipeline's execution summaries.

    A pipeline absent from ``executions`` has never been executed, which is the
    case the original could not report at all.
    """

    def __init__(self, pages: list[list[str]],
                 executions: dict[str, list[dict[str, Any]]],
                 calls: list[tuple[str, int]]) -> None:
        self._pages = pages
        self._executions = executions
        self._calls = calls

    def get_paginator(self, name: str) -> _FakePipelinePaginator:
        assert name == "list_pipelines"
        return _FakePipelinePaginator(self._pages)

    def list_pipeline_executions(self, *, pipelineName: str,
                                 maxResults: int) -> dict[str, Any]:
        self._calls.append((pipelineName, maxResults))
        return {"pipelineExecutionSummaries":
                list(self._executions.get(pipelineName, []))}


class _FakeQueuePaginator:
    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        self.pages = pages

    def paginate(self) -> list[dict[str, Any]]:
        return [{"jobQueues": page} for page in self.pages]


class _FakeJobPaginator:
    """Jobs keyed by (queue, status), each a list of pages."""

    def __init__(self, jobs: dict[tuple[str, str], list[list[dict[str, Any]]]],
                 calls: list[tuple[str, str]]) -> None:
        self.jobs = jobs
        self.calls = calls

    def paginate(self, *, jobQueue: str,
                 jobStatus: str) -> list[dict[str, Any]]:
        self.calls.append((jobQueue, jobStatus))
        return [{"jobSummaryList": page}
                for page in self.jobs.get((jobQueue, jobStatus), [])]


class _FakeBatch:
    def __init__(self, queues: list[list[dict[str, Any]]],
                 jobs: dict[tuple[str, str], list[list[dict[str, Any]]]],
                 calls: list[tuple[str, str]]) -> None:
        self._queues = queues
        self._jobs = jobs
        self._calls = calls

    def get_paginator(self, name: str) -> Any:
        if name == "describe_job_queues":
            return _FakeQueuePaginator(self._queues)
        assert name == "list_jobs"
        return _FakeJobPaginator(self._jobs, self._calls)


class _FakeSession:
    """One account's session. ``alarms`` is keyed by region."""

    def __init__(self, sts: _FakeSts, credentials: dict[str, str],
                 alarms: dict[str, list[list[dict[str, Any]]]],
                 unreadable: set[str],
                 instances: dict[str, list[list[dict[str, Any]]]],
                 ec2_unreadable: set[str],
                 functions: dict[str, list[list[str]]],
                 metrics: dict[str, dict[str, Any]],
                 messages: dict[str, str | None],
                 lambda_unreadable: set[str],
                 *,
                 pipelines: dict[str, list[list[str]]] | None = None,
                 executions: dict[str, list[dict[str, Any]]] | None = None,
                 pipelines_unreadable: set[str] | None = None,
                 queues: dict[str, list[list[dict[str, Any]]]] | None = None,
                 jobs: dict[tuple[str, str],
                            list[list[dict[str, Any]]]] | None = None,
                 batch_unreadable: set[str] | None = None) -> None:
        self.sts = sts
        self.credentials = credentials
        self.alarms = alarms
        self.unreadable = unreadable
        self.instances = instances
        self.ec2_unreadable = ec2_unreadable
        self.functions = functions
        self.metrics = metrics
        self.messages = messages
        self.lambda_unreadable = lambda_unreadable
        self.pipelines = pipelines or {}
        self.executions = executions or {}
        self.pipelines_unreadable = pipelines_unreadable or set()
        self.queues = queues or {}
        self.jobs = jobs or {}
        self.batch_unreadable = batch_unreadable or set()
        self.clients: list[tuple[str, str]] = []
        self.paginators: dict[str, _FakePaginator] = {}
        self.metric_calls: list[list[dict[str, Any]]] = []
        self.log_calls: list[str] = []
        self.execution_calls: list[tuple[str, int]] = []
        self.job_calls: list[tuple[str, str]] = []

    def client(self, name: str, region_name: str = "") -> Any:
        self.clients.append((name, region_name))
        if name == "sts":
            return self.sts
        if name == "codepipeline":
            if region_name in self.pipelines_unreadable:
                raise ClientError(
                    {"Error": {"Code": "AccessDenied",
                               "Message": "no pipelines"}},
                    "ListPipelines")
            return _FakeCodePipeline(self.pipelines.get(region_name, []),
                                     self.executions, self.execution_calls)
        if name == "batch":
            if region_name in self.batch_unreadable:
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no batch"}},
                    "DescribeJobQueues")
            return _FakeBatch(self.queues.get(region_name, []), self.jobs,
                              self.job_calls)
        if name == "ec2":
            if region_name in self.ec2_unreadable:
                raise ClientError(
                    {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
                    "DescribeInstances")
            return _FakeEc2(_FakeEc2Paginator(
                [[reservation] for reservation
                 in self.instances.get(region_name, [])]))
        if name == "lambda":
            if region_name in self.lambda_unreadable:
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no lambda"}},
                    "ListFunctions")
            return _FakeLambda(self.functions.get(region_name, []))
        if name == "logs":
            return _FakeLogs(self.messages, self.log_calls)
        if region_name in self.unreadable:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no cloudwatch"}},
                "DescribeAlarms")
        paginator = _FakePaginator(self.alarms.get(region_name, []))
        self.paginators[region_name] = paginator
        return _FakeCloudwatch(paginator, self.metrics, self.metric_calls)


def _stub(check: AwsCheck, sts: _FakeSts | None = None, *,
          alarms: dict[str, list[list[dict[str, Any]]]] | None = None,
          unreadable: set[str] | None = None,
          instances: dict[str, list[list[dict[str, Any]]]] | None = None,
          ec2_unreadable: set[str] | None = None,
          functions: dict[str, list[list[str]]] | None = None,
          metrics: dict[str, dict[str, Any]] | None = None,
          messages: dict[str, str | None] | None = None,
          lambda_unreadable: set[str] | None = None,
          pipelines: dict[str, list[list[str]]] | None = None,
          executions: dict[str, list[dict[str, Any]]] | None = None,
          pipelines_unreadable: set[str] | None = None,
          queues: dict[str, list[list[dict[str, Any]]]] | None = None,
          jobs: dict[tuple[str, str],
                     list[list[dict[str, Any]]]] | None = None,
          batch_unreadable: set[str] | None = None) -> list[_FakeSession]:
    """Replace the one place boto3 is constructed; record what was built."""
    shared_sts = sts if sts is not None else _FakeSts()
    built: list[_FakeSession] = []

    def factory(**credentials: str) -> Any:
        session = _FakeSession(shared_sts, credentials, alarms or {},
                               unreadable or set(), instances or {},
                               ec2_unreadable or set(), functions or {},
                               metrics or {}, messages or {},
                               lambda_unreadable or set(),
                               pipelines=pipelines, executions=executions,
                               pipelines_unreadable=pipelines_unreadable,
                               queues=queues, jobs=jobs,
                               batch_unreadable=batch_unreadable)
        built.append(session)
        return session

    check._new_session = factory        # type: ignore[method-assign]
    return built


def _child(result: CheckResult, name: str) -> CheckResult:
    for child in result.children:
        if child.name == name:
            return child
    raise AssertionError(f"no child {name!r} in {[c.name for c in result.children]}")


def _texts(result: CheckResult) -> list[str]:
    return list(result.reason_texts)


# --- configuration --------------------------------------------------------

def test_the_type_is_registered_under_its_bare_name() -> None:
    assert CHECK_TYPES["aws"] is AwsCheck


def test_defaults() -> None:
    check = _build()
    settings = check.cloudwatch
    assert check.regions == ("eu-central-1",)
    assert check.role_session_name == DEFAULT_ROLE_SESSION_NAME == "little-sister"
    assert settings.ignore_name_patterns == ("targettracking",)
    assert settings.include_composite is True
    assert settings.show_healthy is False


def test_an_organizations_naming_is_not_a_default_of_the_type() -> None:
    """The two knobs whose original values named the estate this was ported from.
    A prefix that tags alarms and a session name in somebody's CloudTrail are
    configuration; shipping them as defaults would publish one organization's
    conventions to every installation."""
    check = _build()
    assert check.cloudwatch.tag_prefix == ""
    assert check.role_session_name == "little-sister"
    tagged = _build(cloudwatch={"tag_prefix": "team-"})
    assert tagged.cloudwatch.tag_prefix == "team-"


def test_insufficient_data_departs_from_the_original_and_warns() -> None:
    settings = _build().cloudwatch
    assert settings.code_for("ALARM") is StatusCode.ERROR
    assert settings.code_for("INSUFFICIENT_DATA") is StatusCode.WARN
    assert settings.code_for("OK") is StatusCode.OK


def test_an_unknown_state_is_not_a_quiet_ok() -> None:
    assert _build().cloudwatch.code_for("PENDING") is StatusCode.WARN


def test_the_state_map_can_be_overridden_one_state_at_a_time() -> None:
    settings = _build(cloudwatch={"state_map": {"INSUFFICIENT_DATA": "OK"}}
                      ).cloudwatch
    assert settings.code_for("INSUFFICIENT_DATA") is StatusCode.OK
    assert settings.code_for("ALARM") is StatusCode.ERROR      # untouched


def test_an_account_inherits_the_default_regions_or_overrides_them() -> None:
    check = _build(regions=["eu-central-1", "us-east-1"])
    live, backup = check.accounts
    assert check.regions_for(live) == ("eu-central-1", "us-east-1")
    assert check.regions_for(backup) == ("eu-west-1",)      # replaced, not added


@pytest.mark.parametrize("accounts", [None, [], "live", [{"role_arn": "arn:x"}]])
def test_accounts_must_be_a_non_empty_list_of_named_entries(
        accounts: object) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(accounts=accounts), Path("."))


def test_a_duplicate_account_name_is_refused() -> None:
    with pytest.raises(CheckError, match="duplicate account name 'live'"):
        AwsCheck.from_config(
            _config(accounts=[{"name": "live"}, {"name": "live"}]), Path("."))


def test_a_misspelled_account_key_is_refused_by_name() -> None:
    with pytest.raises(CheckError, match="role-arn"):
        AwsCheck.from_config(
            _config(accounts=[{"name": "live", "role-arn": "arn:x"}]), Path("."))


def test_a_misspelled_cloudwatch_key_is_refused_by_name() -> None:
    with pytest.raises(CheckError, match="show_healty"):
        AwsCheck.from_config(
            _config(cloudwatch={"show_healty": True}), Path("."))


@pytest.mark.parametrize("regions", [[], ["eu-central-1", "eu-central-1"], [" "]])
def test_bad_region_lists_are_refused(regions: object) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(regions=regions), Path("."))


def test_a_bad_per_account_region_list_names_the_account() -> None:
    with pytest.raises(CheckError, match="account 'live'"):
        AwsCheck.from_config(
            _config(accounts=[{"name": "live", "regions": []}]), Path("."))


@pytest.mark.parametrize("minimum", [0, -1, True, "many"])
def test_expect_min_alarms_cannot_switch_the_backstop_off(minimum: object) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(
            _config(cloudwatch={"expect_min_alarms": minimum}), Path("."))


def test_the_common_fields_still_bind() -> None:
    """The `**kwargs` contract: a common field the type never heard of must
    still reach `Check.__init__`, and the list of them grows with the library
    (little-sister ADR-0049)."""
    check = _build(frequency="60s", timeout="120s", title="AWS")
    assert (check.frequency_seconds, check.timeout_seconds, check.title) == (
        60, 120.0, "AWS")


# --- credentials ----------------------------------------------------------

def test_without_a_secrets_block_the_ambient_chain_is_used() -> None:
    check = _build()
    built = _stub(check)
    check.run()
    assert built[0].credentials == {}


def test_a_secrets_block_resolves_static_keys(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_KEY", "AKIA-configured")
    monkeypatch.setenv("AWS_SECRET", "s3cret")
    check = _build(secrets={"access_key_id": "env://AWS_KEY",
                            "secret_access_key": "env://AWS_SECRET"})
    assert (check.access_key, check.secret_key) == ("AKIA-configured", "s3cret")
    built = _stub(check)
    check.run()
    assert built[0].credentials["aws_access_key_id"] == "AKIA-configured"


def test_half_a_key_pair_is_refused() -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(
            _config(secrets={"access_key_id": "env://AWS_KEY"}), Path("."))


def test_an_unresolvable_reference_pins_the_check_instead_of_running_it() -> None:
    check = _build(secrets={"access_key_id": "env://ABSENT_KEY",
                            "secret_access_key": "env://ABSENT_SECRET"})
    assert check.secret_errors      # the engine pins on this and never calls run()


def test_config_summary_names_the_accounts_and_never_a_secret(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_KEY", "AKIA-configured")
    monkeypatch.setenv("AWS_SECRET", "s3cret")
    summary = _build(secrets={"access_key_id": "env://AWS_KEY",
                              "secret_access_key": "env://AWS_SECRET"}
                     ).config_summary()
    assert "live" in summary and "eu-central-1" in summary
    assert "AKIA-configured" not in summary and "s3cret" not in summary


# --- the session seam -----------------------------------------------------

def test_each_account_is_assumed_with_the_configured_session_name() -> None:
    check = _build(role_session_name="little-sister")
    sts = _FakeSts()
    _stub(check, sts)
    check.run()
    assert sts.calls == [
        {"RoleArn": "arn:aws:iam::111:role/monitoring",
         "RoleSessionName": "little-sister"},
        {"RoleArn": "arn:aws:iam::222:role/monitoring",
         "RoleSessionName": "little-sister"},
    ]


def test_the_assumed_session_carries_that_account_s_credentials() -> None:
    check = _build()
    built = _stub(check)
    check.run()
    tokens = [session.credentials.get("aws_session_token") for session in built]
    assert tokens[1:] == ["TOK-arn:aws:iam::111:role/monitoring",
                          "TOK-arn:aws:iam::222:role/monitoring"]


def test_sts_is_reached_in_the_configured_region() -> None:
    check = _build(sts_region="us-east-1")
    built = _stub(check)
    check.run()
    assert ("sts", "us-east-1") in built[0].clients


def test_an_account_without_a_role_arn_is_not_assumed() -> None:
    check = _build(accounts=[{"name": "here"}])
    sts = _FakeSts()
    built = _stub(check, sts)
    check.run()
    assert sts.calls == []
    assert len(built) == 1          # the base session, and no second one


def test_no_credentials_at_all_is_one_error_line_and_no_children() -> None:
    check = _build()

    def refuse(**credentials: str) -> Any:
        raise NoCredentialsError()

    check._new_session = refuse         # type: ignore[method-assign]
    result = check.run()
    assert result.code is StatusCode.ERROR
    assert result.children == ()
    assert "no usable AWS credentials" in _texts(result)[0]


# --- the tree -------------------------------------------------------------

def test_the_root_carries_one_child_per_account_in_config_order() -> None:
    check = _build()
    _stub(check)
    result = check.run()
    assert [child.name for child in result.children] == ["live", "backup"]


def test_each_account_carries_one_child_per_aspect() -> None:
    check = _build()
    _stub(check)
    live = _child(check.run(), "live")
    assert [child.name for child in live.children] == [
        CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH]
    assert AwsCheck.ASPECTS == (CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH)


def test_the_root_stays_ok_and_says_only_what_is_watched() -> None:
    """An account that failed is red on its own node and reaches the container
    by roll-up; repeating it here would report one fact twice."""
    check = _build()
    _stub(check, _FakeSts(refuse={"arn:aws:iam::222:role/monitoring"}))
    result = check.run()
    assert result.code is StatusCode.OK
    assert _texts(result) == ["2 accounts, 2 account/region pairs in scope"]


def test_the_scope_counts_each_account_s_own_regions() -> None:
    check = _build(regions=["eu-central-1", "us-east-1"])
    _stub(check)
    # live inherits two regions, backup overrides to one: three pairs, not four.
    assert _texts(check.run()) == ["2 accounts, 3 account/region pairs in scope"]


def test_an_unassumable_account_reddens_its_own_node_only() -> None:
    check = _build()
    _stub(check, _FakeSts(refuse={"arn:aws:iam::222:role/monitoring"}))
    result = check.run()
    backup = _child(result, "backup")
    assert backup.code is StatusCode.ERROR
    assert backup.children == ()
    assert "role cannot be assumed" in _texts(backup)[0]
    assert _child(result, "live").code is StatusCode.OK
    assert _child(_child(result, "live"), CLOUDWATCH).reason


def test_an_account_publishes_its_own_title_about_and_config() -> None:
    check = _build(accounts=[{"name": "backup", "title": "Backup (Ireland)",
                              "about": "Off-site copies.",
                              "regions": ["eu-west-1"]}])
    _stub(check)
    backup = _child(check.run(), "backup")
    assert backup.title == "Backup (Ireland)"
    assert backup.about == "Off-site copies."
    assert "eu-west-1" in backup.config


def test_the_root_report_is_the_configured_scope_not_the_reachable_one() -> None:
    """`report` is presence, never a status claim (little-sister ADR-0044)."""
    check = _build()
    _stub(check, _FakeSts(refuse={"arn:aws:iam::222:role/monitoring"}))
    assert check.run().report == ("- **live** — eu-central-1\n"
                                  "- **backup** — eu-west-1")


# --- the cloudwatch aspect ------------------------------------------------

def _cloudwatch(check: AwsCheck, **stub: Any) -> CheckResult:
    _stub(check, **stub)
    return _child(_child(check.run(), "live"), CLOUDWATCH)


def test_an_alarm_becomes_one_coded_line_with_its_console_link() -> None:
    check = _build()
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[
        _alarm("api-5xx", description="Too many 5xx")]]})
    assert leaf.code is None            # the lines carry the verdict, not the node
    entry = leaf.reason[0]          # worst first: the alarm outranks the scope line
    assert entry.code is StatusCode.ERROR
    assert entry.text == (
        "[api-5xx](https://eu-central-1.console.aws.amazon.com/cloudwatch/home"
        "?region=eu-central-1#s=Alarms&alarm=api-5xx): in ALARM — Too many 5xx")


def test_an_alarm_without_a_description_says_what_the_original_said() -> None:
    check = _build()
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[
        _alarm("api-5xx", description="")]]})
    assert leaf.reason[0].text.endswith("Alarm has no description!")


def test_a_prefixed_alarm_is_tagged_and_a_composite_one_too() -> None:
    """The prefix is configured, not built in — an alarm naming convention belongs
    to the estate being watched."""
    check = _build(cloudwatch={"tag_prefix": "team-"})
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[
        _alarm("team-api-5xx"), _alarm("rollup", composite=True)]]})
    tagged = {entry.text.split("): ")[-1] for entry in leaf.reason[:2]}
    assert any("(team)" in text for text in tagged)
    assert any("(composite)" in text for text in tagged)


def test_the_tag_word_is_the_prefix_without_its_separator() -> None:
    """Derived rather than configured a second time: `tag_prefix: "sre-"` means
    the word is `sre`, and a second knob to say so again is a second thing to get
    wrong. It is also what keeps a deployment's lines reading as they did before
    the key was renamed."""
    for prefix, word in (("sre-", "sre"), ("team_", "team"), ("SRE.", "sre"),
                         ("plain", "plain")):
        settings = _build(cloudwatch={"tag_prefix": prefix}).cloudwatch
        assert settings.tag_word == word


def test_no_alarm_is_tagged_when_no_prefix_is_configured() -> None:
    leaf = _cloudwatch(_build(), alarms={"eu-central-1": [[
        _alarm("team-api-5xx")]]})
    assert "(" not in leaf.reason[0].text.split("): ")[-1]


def test_composite_alarms_can_be_switched_off() -> None:
    check = _build(cloudwatch={"include_composite": False})
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[
        _alarm("metric-one"), _alarm("rollup", composite=True)]]})
    assert "rollup" not in " ".join(_texts(leaf))
    assert "1 alarm in scope" in _texts(leaf)[-1]


def test_every_page_is_read() -> None:
    check = _build()
    leaf = _cloudwatch(check, alarms={"eu-central-1": [
        [_alarm("page-one")], [_alarm("page-two")]]})
    assert "2 alarms in scope" in " ".join(_texts(leaf))


def test_ignored_names_are_neither_listed_nor_counted() -> None:
    """Out of the lines *and* out of the count: an ignored alarm is out of scope,
    not a silent zero. Both patterns here — the shipped default and a configured
    one — have to leave together."""
    check = _build(cloudwatch={"ignore_name_patterns": ["noisy", "targettracking"]})
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[
        _alarm("api-Noisy-1"), _alarm("TargetTracking-svc"),
        _alarm("api-5xx")]]})
    assert [entry.slug for entry in leaf.reason] == [
        "eu-central-1-api-5xx", "scope"]
    assert "1 alarm in scope" in _texts(leaf)[-1]


def test_healthy_alarms_are_off_by_default_and_can_be_switched_on() -> None:
    alarms = {"eu-central-1": [[_alarm("quiet", "OK"), _alarm("loud")]]}
    quiet = _cloudwatch(_build(), alarms=alarms)
    assert "quiet" not in " ".join(_texts(quiet))
    assert "2 alarms in scope" in _texts(quiet)[-1]     # counted, just not listed

    loud = _cloudwatch(_build(cloudwatch={"show_healthy": True}), alarms=alarms)
    assert "quiet" in " ".join(_texts(loud))


def test_the_worst_line_comes_first_and_the_healthy_one_last() -> None:
    check = _build(cloudwatch={"show_healthy": True})
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[
        _alarm("fine", "OK"), _alarm("stale", "INSUFFICIENT_DATA"),
        _alarm("burning", "ALARM")]]})
    assert [entry.code for entry in leaf.reason] == [
        StatusCode.ERROR, StatusCode.WARN, StatusCode.OK, StatusCode.OK]
    assert "burning" in leaf.reason[0].text
    assert "fine" in leaf.reason[2].text
    # the scope line ends the list rather than sitting between the two groups
    assert leaf.reason[-1].slug == "scope"


def test_the_scope_line_warns_when_nothing_is_seen() -> None:
    leaf = _cloudwatch(_build(), alarms={"eu-central-1": [[]]})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text == "no alarms in scope (eu-central-1)"


def test_the_scope_line_warns_below_the_expected_minimum() -> None:
    check = _build(cloudwatch={"expect_min_alarms": 5})
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[_alarm("only", "OK")]]})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text == (
        "1 alarm in scope (eu-central-1), expected at least 5")


def test_a_region_that_cannot_be_read_is_its_own_warn_line() -> None:
    check = _build(accounts=[{"name": "live", "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _cloudwatch(check, alarms={"eu-central-1": [[_alarm("api-5xx")]]},
                       unreadable={"eu-west-1"})
    warns = [entry for entry in leaf.reason if entry.code is StatusCode.WARN]
    assert len(warns) == 1
    assert warns[0].text.startswith("eu-west-1: alarms cannot be read")
    assert "api-5xx" in leaf.reason[0].text      # the readable region still reported


def test_the_region_shows_in_the_line_only_when_there_is_more_than_one() -> None:
    one = _cloudwatch(_build(), alarms={"eu-central-1": [[_alarm("api-5xx")]]})
    assert one.reason[0].text.startswith("[api-5xx]")

    check = _build(accounts=[{"name": "live", "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    two = _cloudwatch(check, alarms={"eu-central-1": [[_alarm("api-5xx")]]})
    assert two.reason[0].text.startswith("eu-central-1 / [api-5xx]")


def test_the_slug_carries_the_region_even_when_the_text_does_not() -> None:
    """A pin must not re-point the day a second region is configured."""
    leaf = _cloudwatch(_build(), alarms={"eu-central-1": [[_alarm("api-5xx")]]})
    assert leaf.reason[0].slug == "eu-central-1-api-5xx"


def test_the_same_alarm_name_in_two_accounts_stays_two_pins() -> None:
    check = _build()
    _stub(check, alarms={"eu-central-1": [[_alarm("api-5xx")]],
                         "eu-west-1": [[_alarm("api-5xx")]]})
    result = check.run()
    live = _child(_child(result, "live"), CLOUDWATCH)
    backup = _child(_child(result, "backup"), CLOUDWATCH)
    # Same slug, different node — a pin is keyed on (path, slug), and the path
    # is what the account node buys.
    assert live.reason[0].slug == "eu-central-1-api-5xx"
    assert backup.reason[0].slug == "eu-west-1-api-5xx"


def test_the_leaf_report_lists_what_was_found_without_a_verdict() -> None:
    leaf = _cloudwatch(_build(), alarms={"eu-central-1": [[
        _alarm("api-5xx"), _alarm("quiet", "OK")]]})
    assert leaf.report.splitlines() == [
        "- [api-5xx](https://eu-central-1.console.aws.amazon.com/cloudwatch/home"
        "?region=eu-central-1#s=Alarms&alarm=api-5xx)",
        "- [quiet](https://eu-central-1.console.aws.amazon.com/cloudwatch/home"
        "?region=eu-central-1#s=Alarms&alarm=quiet)"]


def test_an_alarm_name_with_markdown_in_it_is_folded_but_the_link_is_not() -> None:
    leaf = _cloudwatch(_build(), alarms={"eu-central-1": [[_alarm("a*b c")]]})
    assert r"[a\*b c](" in leaf.reason[0].text
    assert "alarm=a%2Ab%20c" in leaf.reason[0].text


def test_the_aspect_leaf_declares_its_built_in_display_text() -> None:
    # Declared, not stamped (little-sister ADR-0025): the text
    # is resolved by the library and written by the engine per subnode name, so
    # it is read off the check rather than off the result. The `{pin_note}` token
    # this package declares beside it has expanded by the time it lands here.
    labels = _build().subnode_labels[CLOUDWATCH]
    assert labels["title"] == "CloudWatch alarms"
    assert "composite alike" in labels["about"]
    assert "pin the line you are working on" in labels["about"]


def test_the_aspect_leaves_hand_over_no_label_of_their_own() -> None:
    # The other half of the same claim, where it can fail: a result carrying a
    # label would be reaching past the declaration to a channel that is only for
    # a child the run *named* — an account, not an aspect.
    leaf = _cloudwatch(_build(), alarms={"eu-central-1": [[_alarm("x")]]})
    assert (leaf.title, leaf.about) == ("", "")


def test_a_deployment_can_extend_that_text_rather_than_replace_it() -> None:
    check = _build(subnodes={CLOUDWATCH: {"about": "{default}\n\nAsk #ops first."}})
    about = check.subnode_labels[CLOUDWATCH]["about"]
    assert "Ask #ops first." in about
    assert "composite alike" in about


def test_one_declaration_serves_every_account_s_leaf_of_that_name() -> None:
    """The claim the reworded prose rests on.

    little-sister resolves a label once per subnode *name* and writes it wherever
    that name appears, at any depth — so this check's two accounts emit the same
    five names and share one declaration each. That is why the text can no longer
    name an account, and why nothing here hands a label back on a result. (The
    at-any-depth write itself is the library's own claim and is tested there; an
    engine cannot be started from this package, which has no configuration
    directory of its own.)
    """
    check = _build()
    _stub(check, alarms={})
    accounts = [_child(check.run(), name) for name in ("live", "backup")]
    names = [tuple(leaf.name for leaf in account.children) for account in accounts]
    assert names[0] == names[1] == AwsCheck.ASPECTS
    for account in accounts:
        for leaf in account.children:
            assert (leaf.title, leaf.about) == ("", "")
            assert check.subnode_labels[leaf.name]["about"]


def test_the_four_roster_aspects_decline_the_density_trade() -> None:
    """The claim `nodes.yaml` used to make seventeen times, made once here.

    `show_when_quiet` rides the same declaration as the labels (little-sister
    ADR-0063), so the library merges it into one per-name map and the engine
    applies it at any depth — which is what makes one line in this package cover
    every aspect of every account of every installation. `cloudwatch` is the
    deliberate absence: `show_healthy: false` is the opposite claim about its own
    lines, made where it belongs.
    """
    check = _build()
    assert check.subnode_show_when_quiet == {
        EC2: True, LAMBDA: True, CODEPIPELINE: True, BATCH: True}
    assert CLOUDWATCH not in check.subnode_show_when_quiet


def test_a_deployment_can_still_decline_what_this_package_declares() -> None:
    """A declaration is a default, not a verdict: the deployment's own
    `subnodes:` block beats it per name, and `nodes.yaml` beats that per path."""
    check = _build(subnodes={EC2: {"show_when_quiet": False}})
    assert check.subnode_show_when_quiet[EC2] is False
    assert check.subnode_show_when_quiet[BATCH] is True     # untouched


def test_no_aspect_result_stamps_the_flag() -> None:
    """Every name this check emits is one it declared, so nothing rides a result.
    A stamped value would be a static fact re-shipped on every run, invisible
    beside the declarations it contradicts."""
    check = _build()
    _stub(check, alarms={})
    for account in (_child(check.run(), name) for name in ("live", "backup")):
        for leaf in account.children:
            assert leaf.show_when_quiet is None


def test_the_built_in_text_names_no_account_and_the_description_does() -> None:
    # One label per subnode *name* covers every account's leaf of that name, so
    # the prose cannot name one. The account is still on the leaf — in the
    # description, which is written per run and per account — and above it, in
    # the node the leaf hangs from.
    check = _build()
    assert "backup" not in check.subnode_labels[CLOUDWATCH]["about"]
    _stub(check, alarms={})
    result = check.run()
    leaf = _child(_child(result, "backup"), CLOUDWATCH)
    assert leaf.description == "CloudWatch alarms in backup"


# --- the narrowed value objects -------------------------------------------

def test_an_account_defaults_to_the_ambient_chain_and_the_shared_regions() -> None:
    account = Account(name="here")
    assert (account.role_arn, account.regions) == ("", ())


def test_an_alarm_is_a_metric_alarm_unless_it_says_otherwise() -> None:
    assert Alarm(name="a", region="r", state="OK", description="d").composite is False


def test_the_ignore_match_is_a_substring_and_case_insensitive() -> None:
    settings = CloudwatchConfig(ignore_name_patterns=("noisy",))
    assert settings.ignored("svc-Noisy-42")
    assert not settings.ignored("cpu-usage")


# --- the ec2 aspect -------------------------------------------------------

def _ec2(check: AwsCheck, **stub: Any) -> CheckResult:
    _stub(check, **stub)
    return _child(_child(check.run(), "live"), EC2)


def test_one_line_per_name_with_the_count() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [
        [_instance("prometheus")], [_instance("jenkins"), _instance("jenkins")]]})
    assert [entry.text.split("): ")[-1] for entry in leaf.reason[:2]] == ["2", "1"]
    assert "jenkins" in leaf.reason[0].text
    assert "prometheus" in leaf.reason[1].text


def test_one_instance_is_ok_and_two_of_a_name_warn() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [
        [_instance("prometheus")], [_instance("jenkins"), _instance("jenkins")]]})
    codes = {entry.text.split("[")[-1].split("]")[0]: entry.code
             for entry in leaf.reason if entry.slug != "scope"}
    assert codes == {"jenkins": StatusCode.WARN, "prometheus": StatusCode.OK}


def test_max_per_name_warn_moves_the_line_between_ok_and_warn() -> None:
    instances = {"eu-central-1": [[_instance("jenkins"), _instance("jenkins")]]}
    assert _ec2(_graded(), instances=instances).reason[0].code is StatusCode.WARN
    relaxed = _ec2(_graded(max_per_name_warn=2), instances=instances)
    assert relaxed.reason[0].code is StatusCode.OK


def test_a_terminated_instance_is_not_counted() -> None:
    """It lingers in the API for about an hour; counting it would report a
    duplicate that no longer exists."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("prometheus"), _instance("prometheus", "terminated"),
        _instance("prometheus", "shutting-down")]]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 1")


def test_a_stopped_instance_is_counted() -> None:
    """A stopped box under a name that should be unique is exactly the leftover
    this aspect is looking for; `ignore_states` is how you disagree."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("prometheus"), _instance("prometheus", "stopped")]]})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text.endswith(": 2")


def test_ignore_states_is_configurable() -> None:
    leaf = _ec2(_build(ec2={"ignore_states": ["stopped"]}),
                instances={"eu-central-1": [[
                    _instance("prometheus"), _instance("prometheus", "stopped")]]})
    assert leaf.reason[0].text.endswith(": 1")


def test_instances_without_a_name_tag_become_one_line() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance(None), _instance(None), _instance("prometheus")]]})
    unnamed = [entry for entry in leaf.reason if NO_NAME_TAG in entry.text]
    assert len(unnamed) == 1
    assert unnamed[0].text == f"{NO_NAME_TAG}: 2"
    # The stored key, unchanged by the group being keyed on `None` internally:
    # a slug is what a maintenance pin is held against, so it must not move.
    assert unnamed[0].slug == "eu-central-1-no-Name-tag"
    assert unnamed[0].code is StatusCode.WARN     # two of them, like any name
    assert "](" not in unnamed[0].text            # not a console search


def test_an_ignored_name_is_neither_listed_nor_counted() -> None:
    leaf = _ec2(_build(ec2={"rules": [{"name": "spot", "prefixes": ["spot-"],
                                       "ignore": True}]}),
                instances={"eu-central-1": [[
                    _instance("spot-worker-1"), _instance("prometheus")]]})
    assert "spot-worker-1" not in " ".join(_texts(leaf))
    assert leaf.reason[-1].text == "1 instance in scope (eu-central-1)"


def test_the_scope_line_counts_instances_not_names() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [
        [_instance("jenkins"), _instance("jenkins")], [_instance("prometheus")]]})
    assert leaf.reason[-1].text == "3 instances in scope (eu-central-1)"


def test_an_empty_account_is_ok_here_unlike_the_alarm_aspect() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": []})
    assert leaf.reason == [leaf.reason[0]]
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text == "no instances in scope (eu-central-1)"


def test_the_same_name_in_two_regions_is_two_lines_not_a_duplicate() -> None:
    check = _build(accounts=[{"name": "live", "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _ec2(check, instances={"eu-central-1": [[_instance("prometheus")]],
                                  "eu-west-1": [[_instance("prometheus")]]})
    lines = [entry.text for entry in leaf.reason if entry.slug != "scope"]
    assert lines == [
        "eu-central-1 / [prometheus](https://eu-central-1.console.aws.amazon.com"
        "/ec2/home?region=eu-central-1#Instances:search=prometheus): 1",
        "eu-west-1 / [prometheus](https://eu-west-1.console.aws.amazon.com"
        "/ec2/home?region=eu-west-1#Instances:search=prometheus): 1"]
    assert [entry.slug for entry in leaf.reason[:2]] == [
        "eu-central-1-prometheus", "eu-west-1-prometheus"]


def test_a_region_whose_instances_cannot_be_read_is_its_own_warn_line() -> None:
    check = _build(accounts=[{"name": "live", "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _ec2(check, instances={"eu-central-1": [[_instance("prometheus")]]},
                ec2_unreadable={"eu-west-1"})
    assert leaf.reason[0].text.startswith("eu-west-1: instances cannot be read")
    assert leaf.reason[0].code is StatusCode.WARN
    assert "prometheus" in leaf.reason[1].text      # the readable region reports


def test_the_worst_line_comes_first_here_too() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("alpha"), _instance("zulu"), _instance("zulu")]]})
    assert leaf.reason[0].code is StatusCode.WARN and "zulu" in leaf.reason[0].text
    assert [entry.slug for entry in leaf.reason] == [
        "eu-central-1-zulu", "eu-central-1-alpha", "scope"]


def test_the_ec2_report_is_the_roster_of_names_and_counts() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("jenkins"), _instance("jenkins"), _instance("prometheus")]]})
    assert leaf.report.splitlines() == ["- jenkins: 2", "- prometheus: 1"]


def test_the_ec2_leaf_declares_its_own_display_text() -> None:
    labels = _build().subnode_labels[EC2]
    assert labels["title"] == "EC2 instances"
    assert "`Name` tag" in labels["about"]


def test_a_misspelled_ec2_key_is_refused_by_name() -> None:
    with pytest.raises(CheckError, match="max_per_names"):
        AwsCheck.from_config(_config(ec2={"max_per_names": 2}), Path("."))


@pytest.mark.parametrize("level", [-1, True, "two"])
def test_a_count_level_must_be_an_integer_of_zero_or_more(level: object) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(ec2={"max_per_name_warn": level}), Path("."))


@pytest.mark.parametrize("key", ["max_per_name", "max_age"])
def test_the_keys_this_replaced_are_refused_like_any_other_typo(key: str) -> None:
    """Nothing is owed to a config written against them: they are unknown keys
    now, and the message names them beside the keys that do exist."""
    with pytest.raises(CheckError, match=key):
        AwsCheck.from_config(_config(ec2={key: 1}), Path("."))


def test_ec2_keeps_the_defaults_that_are_facts_about_aws_and_no_others() -> None:
    """The line this package draws: a terminated instance lingering in the API
    for about an hour is a fact about AWS, so not counting it is a default. What
    a name may carry and how long a box may run are facts about an estate, so
    they are not — and the aspect grades nothing until an installation says."""
    settings = _build().ec2
    assert settings.ignore_states == ("terminated", "shutting-down")
    assert settings.rules == ()
    assert (settings.per_name.warn, settings.per_name.error) == (None, None)
    assert (settings.age.warn, settings.age.error) == (None, None)
    assert not settings.grades


def test_an_instance_narrows_to_the_fields_the_aspect_uses() -> None:
    instance = Instance(instance_id="i-1", name="a", region="r", state="running")
    assert (instance.name, instance.state) == ("a", "running")


def test_the_ec2_state_match_is_case_insensitive() -> None:
    assert Ec2Config().ignored_state("Terminated")


# --- the ec2 aspect: age --------------------------------------------------

def test_the_age_rides_on_every_line() -> None:
    """Including the healthy ones: it is the reading, not an exception report."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("prometheus", up=timedelta(days=12)),
        _instance("jenkins", up=timedelta(hours=5)),
        _instance("jenkins", up=timedelta(days=3))]]})
    lines = {entry.text.split("](")[0].lstrip("["): entry.text
             for entry in leaf.reason if entry.slug != "scope"}
    assert lines["jenkins"].endswith(": 2 (5h, 3d)")   # two of them, two ages
    assert lines["prometheus"].endswith(": 1 (12d)")


def test_an_instance_past_max_age_turns_the_line_red() -> None:
    """An instance is patched by being replaced, so age is a security reading —
    true of a single, perfectly tidy instance."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("prometheus", up=timedelta(days=15))]]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert leaf.reason[0].text.endswith(": 1 (15d)")


def test_just_under_two_weeks_is_still_ok() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("prometheus", up=timedelta(days=13, hours=23))]]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 1 (13d 23h)")


def test_max_age_error_is_configurable() -> None:
    instances = {"eu-central-1": [[_instance("prometheus", up=timedelta(days=3))]]}
    assert _ec2(_graded(), instances=instances).reason[0].code is StatusCode.OK
    strict = _ec2(_graded(max_age_error="2d"), instances=instances)
    assert strict.reason[0].code is StatusCode.ERROR


def test_age_outranks_the_duplicate_warning() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", up=timedelta(days=20)),
        _instance("jenkins", up=timedelta(hours=1))]]})
    assert leaf.reason[0].code is StatusCode.ERROR      # not the WARN of a count
    assert leaf.reason[0].text.endswith(": 2 (1h, 20d)")


def test_an_instance_without_a_launch_time_is_graded_by_count_alone() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[_instance("prometheus")]]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 1")          # no age invented


# --- the ec2 aspect: the age range -----------------------------------------

def test_boxes_that_read_the_same_age_are_shown_once() -> None:
    """Forty minutes apart inside one hour, both print as `1d 1h` — so they *are*
    the same age as far as a card that says `1d 1h` is concerned. `1d 1h - 1d 1h`
    would be noise manufactured out of precision the reader was never shown, and
    it is exactly what a dedupe on the raw seconds would print."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", instance_id="i-1",
                  up=timedelta(hours=25, minutes=10)),
        _instance("jenkins", instance_id="i-2",
                  up=timedelta(hours=25, minutes=50))]]})
    assert leaf.reason[0].text.endswith(": 2 (1d 1h)")


def test_two_distinct_ages_are_shown_as_both_of_them() -> None:
    """Not as an interval: an interval says there is a spread with members
    inside it, and two adjacent values are just two values."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", instance_id="i-1",
                  up=timedelta(hours=15, minutes=3)),
        _instance("jenkins", instance_id="i-2",
                  up=timedelta(hours=15, minutes=4))]]})
    assert leaf.reason[0].text.endswith(": 2 (15h 3m, 15h 4m)")


def test_three_or_more_distinct_ages_become_youngest_to_oldest() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", instance_id="i-1", up=timedelta(minutes=10)),
        _instance("jenkins", instance_id="i-2",
                  up=timedelta(hours=15, minutes=3)),
        _instance("jenkins", instance_id="i-3",
                  up=timedelta(hours=16, minutes=10))]]})
    assert leaf.reason[0].text.endswith(": 3 (10m - 16h 10m)")


def test_a_rolled_name_and_a_forgotten_one_no_longer_read_alike() -> None:
    """The reading this whole change exists for."""
    rolling = [_instance("web", instance_id=f"i-{n}", up=timedelta(minutes=n))
               for n in range(1, 4)]
    rolling.append(_instance("web", instance_id="i-old", up=timedelta(hours=16)))
    forgotten = [_instance("db", instance_id=f"i-db{n}", up=timedelta(hours=16))
                 for n in range(4)]
    leaf = _ec2(_graded(), instances={"eu-central-1": [rolling, forgotten]})
    lines = {entry.text.split("](")[0].lstrip("["): entry.text
             for entry in leaf.reason if entry.slug != "scope"}
    assert lines["web"].endswith(": 4 (1m - 16h)")
    assert lines["db"].endswith(": 4 (16h)")


def test_the_oldest_member_still_decides_the_grade() -> None:
    """The range is a reading; the oldest is the verdict. An instance is patched
    by being replaced, so the box that has run longest is the security fact."""
    leaf = _ec2(_graded(max_age_error="10d"), instances={"eu-central-1": [[
        _instance("jenkins", instance_id="i-young", up=timedelta(minutes=5)),
        _instance("jenkins", instance_id="i-old", up=timedelta(days=20))]]})
    assert leaf.reason[0].code is StatusCode.ERROR


def test_the_roster_shows_the_same_range_as_the_line() -> None:
    """One renderer: a group whose card and report disagreed about its age would
    be worse than either."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", instance_id="i-1", up=timedelta(minutes=10)),
        _instance("jenkins", instance_id="i-2", up=timedelta(hours=15)),
        _instance("jenkins", instance_id="i-3", up=timedelta(hours=16))]]})
    assert leaf.report.splitlines() == ["- jenkins: 3 (10m - 16h)"]
    assert leaf.reason[0].text.endswith(": 3 (10m - 16h)")


def test_a_group_with_no_launch_times_still_shows_no_age() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", instance_id="i-1"),
        _instance("jenkins", instance_id="i-2")]]})
    assert leaf.reason[0].text.endswith(": 2")


def test_a_group_reports_the_ages_it_has() -> None:
    """Some members without a launch time do not blank the reading: the count
    beside the name already says how many boxes there are."""
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", instance_id="i-1"),
        _instance("jenkins", instance_id="i-2", up=timedelta(hours=3))]]})
    assert leaf.reason[0].text.endswith(": 2 (3h)")


# --- the ec2 aspect: levels, and what a line says -------------------------

def test_the_aspect_grades_nothing_until_the_config_says_what_to_grade() -> None:
    """This package ships no thresholds. Five boxes under one name, a month old,
    are an inventory line and not a finding, because nobody has said otherwise."""
    leaf = _ec2(_build(), instances={"eu-central-1": [
        _fleet("jenkins", 5, timedelta(days=30))]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 5 (30d)")


def test_an_aspect_that_grades_nothing_says_so_once_in_the_log(
        caplog: pytest.LogCaptureFixture) -> None:
    """An omission logs; a contradiction refuses. Grading nothing is legal, and
    it is more often somebody who has not noticed that there are no defaults."""
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        _build(ec2={"enabled": True})
    assert "grades nothing" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        _build(ec2=GRADED_EC2)
    assert "grades nothing" not in caplog.text


def test_a_switched_off_aspect_is_not_told_that_it_grades_nothing(
        caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        _build(ec2={"enabled": False})
    assert "grades nothing" not in caplog.text


def test_a_count_has_a_warning_level_and_an_error_level() -> None:
    """The whole point of the pair: a count could only ever warn before."""
    block = {"max_per_name_warn": 1, "max_per_name_error": 8}
    instances = {"eu-central-1": [_fleet("jenkins", 2, timedelta(hours=1))]}
    assert _ec2(_build(ec2=block), instances=instances).reason[0].code \
        is StatusCode.WARN
    many = {"eu-central-1": [_fleet("jenkins", 9, timedelta(hours=1))]}
    assert _ec2(_build(ec2=block), instances=many).reason[0].code \
        is StatusCode.ERROR


def test_an_age_has_a_warning_level_and_an_error_level() -> None:
    """And the mirror of the above: an age could only ever burn."""
    block = {"max_age_warn": "7d", "max_age_error": "14d"}
    week = {"eu-central-1": [[_instance("prometheus", up=timedelta(days=8))]]}
    assert _ec2(_build(ec2=block), instances=week).reason[0].code \
        is StatusCode.WARN
    month = {"eu-central-1": [[_instance("prometheus", up=timedelta(days=20))]]}
    assert _ec2(_build(ec2=block), instances=month).reason[0].code \
        is StatusCode.ERROR


def test_a_level_is_more_than_never_at_least() -> None:
    """`max_per_name_warn: 1` is *one is fine, two is not* — the key is named for
    the largest value that is still fine. At-or-above would turn every single
    instance in the estate yellow."""
    one = {"eu-central-1": [[_instance("prometheus")]]}
    assert _ec2(_graded(), instances=one).reason[0].code is StatusCode.OK
    two = {"eu-central-1": [_fleet("prometheus", 2, timedelta(hours=1))]}
    assert _ec2(_graded(), instances=two).reason[0].code is StatusCode.WARN


def test_zero_is_how_a_block_asks_about_a_name_it_has_not_classified() -> None:
    """It follows from *more than*: the largest count that is still fine is
    none, so any instance under any name is worth a line."""
    leaf = _ec2(_build(ec2={"max_per_name_warn": 0}),
                instances={"eu-central-1": [[_instance("something-new")]]})
    assert leaf.reason[0].code is StatusCode.WARN


@pytest.mark.parametrize("block", [
    {"max_per_name_warn": 8, "max_per_name_error": 2},
    {"max_per_name_warn": 2, "max_per_name_error": 2},
    {"max_age_warn": "14d", "max_age_error": "7d"},
    {"max_age_warn": "7d", "max_age_error": "7d"},
])
def test_an_error_level_must_be_above_its_warn_level(block: dict[str, Any]) -> None:
    """Equal is refused with the rest: the comparison is *more than*, so a warn
    level that is not below the error one can never be reported."""
    with pytest.raises(CheckError, match="above"):
        AwsCheck.from_config(_config(ec2=block), Path("."))


def test_a_level_written_as_null_is_not_graded() -> None:
    """A level with no number is a comparison that does not happen — there is no
    infinity to write. (Three, not eleven: the fleet clock is still live in this
    aspect and judges a group above `fleet_size` on its own.)"""
    instances = {"eu-central-1": [_fleet("jenkins", 3, timedelta(days=90))]}
    leaf = _ec2(_build(ec2={"max_per_name_warn": None, "max_age_error": None}),
                instances=instances)
    assert leaf.reason[0].code is StatusCode.OK


def test_the_sentence_of_the_judgment_that_fired_rides_on_the_line() -> None:
    leaf = _ec2(_graded(max_per_name_reason="Only one of these should exist."),
                instances={"eu-central-1": [
                    _fleet("jenkins", 2, timedelta(hours=1))]})
    assert leaf.reason[0].text.endswith(
        ": 2 (1h) — Only one of these should exist.")


def test_a_healthy_line_carries_no_sentence() -> None:
    """A reason explains a color. A line that is not colored has nothing to
    explain, and an inventory read while everything is fine stays readable."""
    leaf = _ec2(_graded(max_per_name_reason="Only one of these should exist."),
                instances={"eu-central-1": [[_instance("prometheus")]]})
    assert "—" not in leaf.reason[0].text


def test_a_line_that_trips_both_judgments_carries_both_sentences() -> None:
    """Count first, then age: two independent judgments meet on one line, and a
    reader who is told only the worse of them has to work out the other."""
    leaf = _ec2(_graded(max_per_name_reason="Too many.", max_age_reason="Too old."),
                instances={"eu-central-1": [
                    _fleet("jenkins", 2, timedelta(days=20))]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert leaf.reason[0].text.endswith(": 2 (20d) — Too many.; Too old.")


def test_only_the_judgment_that_fired_speaks() -> None:
    leaf = _ec2(_graded(max_per_name_reason="Too many.", max_age_reason="Too old."),
                instances={"eu-central-1": [
                    _fleet("jenkins", 2, timedelta(hours=1))]})
    assert leaf.reason[0].text.endswith("— Too many.")


def test_a_sentence_is_escaped_like_any_other_configured_text() -> None:
    """It is authored in YAML and lands in a Markdown line beside a link."""
    leaf = _ec2(_graded(max_per_name_reason="See [the runbook](x) *now*"),
                instances={"eu-central-1": [
                    _fleet("jenkins", 2, timedelta(hours=1))]})
    assert r"\[the runbook\]" in leaf.reason[0].text
    assert r"\*now\*" in leaf.reason[0].text


def test_a_sentence_with_no_level_to_explain_is_refused() -> None:
    """Dead configuration: somebody wrote a sentence expecting to see it."""
    with pytest.raises(CheckError, match="could never be shown"):
        AwsCheck.from_config(
            _config(ec2={"max_age_reason": "Too old."}), Path("."))


@pytest.mark.parametrize("reason", ["", "   ", 7])
def test_a_sentence_must_be_a_non_empty_string(reason: object) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(
            _config(ec2={"max_per_name_warn": 1,
                         "max_per_name_reason": reason}), Path("."))


# --- the ec2 aspect: rules -------------------------------------------------

LOADTEST_RULE: dict[str, Any] = {
    "name": "load tests", "prefixes": ["loadtest-"],
    "max_per_name_warn": 15, "max_age_error": "4h",
}


def test_a_fleet_is_a_name_a_rule_matches() -> None:
    """What `fleet_size` used to do, said as what it always meant: these names
    may carry many boxes, and only for hours. The count is *loosened* and the
    clock *shortened* by the same rule — which is why an override has to be able
    to relax a limit and not only tighten one."""
    check = _build(ec2={**GRADED_EC2, "rules": [LOADTEST_RULE]})
    young = _ec2(check, instances={"eu-central-1": [
        _fleet("loadtest-2026-08-09", 11, timedelta(hours=3))]})
    assert young.reason[0].code is StatusCode.OK
    old = _ec2(_build(ec2={**GRADED_EC2, "rules": [LOADTEST_RULE]}),
               instances={"eu-central-1": [
                   _fleet("loadtest-2026-08-09", 11, timedelta(hours=5))]})
    assert old.reason[0].code is StatusCode.ERROR


def test_a_rule_judges_each_matching_name_on_its_own_never_their_sum() -> None:
    """Two load tests carrying 10 and 12 boxes are two lines against a warn
    level of 15 — not 22 against it. The reading is *this name carries too
    many*, and neither name does."""
    leaf = _ec2(_build(ec2={**GRADED_EC2, "rules": [LOADTEST_RULE]}),
                instances={"eu-central-1": [
                    _fleet("loadtest-a", 10, timedelta(minutes=30)),
                    _fleet("loadtest-b", 12, timedelta(minutes=30))]})
    assert [entry.code for entry in leaf.reason[:2]] == [
        StatusCode.OK, StatusCode.OK]


def test_the_oldest_member_decides_a_rule_not_the_newest() -> None:
    """A rolling fleet cannot reset its own clock by replacing members."""
    rolling = _fleet("loadtest-2026-08-09", 10, timedelta(minutes=5))
    rolling.append(_instance("loadtest-2026-08-09", instance_id="i-old",
                             up=timedelta(hours=6)))
    leaf = _ec2(_build(ec2={**GRADED_EC2, "rules": [LOADTEST_RULE]}),
                instances={"eu-central-1": [rolling]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert leaf.reason[0].text.startswith("[loadtest-2026-08-09]")


def test_the_first_matching_rule_decides_and_only_that_one() -> None:
    rules = [{"name": "first", "prefixes": ["web-"], "max_per_name_warn": 10},
             {"name": "second", "prefixes": ["web-"], "max_per_name_warn": 0}]
    leaf = _ec2(_build(ec2={"rules": rules}),
                instances={"eu-central-1": [_fleet("web-1", 3, timedelta(hours=1))]})
    assert leaf.reason[0].code is StatusCode.OK


def test_an_exception_is_a_rule_above_the_rule_it_excepts() -> None:
    """There is no negation key, because order already says it."""
    rules = [{"name": "the legacy box", "names": ["web-legacy"],
              "max_per_name_error": 4},
             {"name": "web", "prefixes": ["web-"], "max_per_name_warn": 0}]
    leaf = _ec2(_build(ec2={"rules": rules}), instances={"eu-central-1": [
        _fleet("web-legacy", 2, timedelta(hours=1)),
        _fleet("web-api", 2, timedelta(hours=1))]})
    codes = {entry.text.split("]")[0].lstrip("["): entry.code
             for entry in leaf.reason if entry.slug != "scope"}
    assert codes == {"web-legacy": StatusCode.OK, "web-api": StatusCode.WARN}


def test_a_rule_inherits_by_pair_not_by_key() -> None:
    """`max_per_name_warn: 15` takes the *whole* count pair, so the block's
    error level of 8 does not come with it — which is what lets a rule loosen a
    limit in one line instead of three. The age pair, untouched, is inherited."""
    block = {"max_per_name_warn": 1, "max_per_name_error": 8,
             "max_age_error": "14d", "rules": [LOADTEST_RULE]}
    leaf = _ec2(_build(ec2=block), instances={"eu-central-1": [
        _fleet("loadtest-x", 12, timedelta(hours=1))]})
    assert leaf.reason[0].code is StatusCode.OK       # not the block's error at 8
    aged = _ec2(_build(ec2={**block, "rules": [
        {"name": "web", "prefixes": ["web-"], "max_per_name_warn": 3}]}),
        instances={"eu-central-1": [[_instance("web-1", up=timedelta(days=20))]]})
    assert aged.reason[0].code is StatusCode.ERROR    # the block's age pair, whole


def test_a_pair_written_as_null_is_ungraded_and_inherits_nothing() -> None:
    """A box kept deliberately old: there is no infinity to compare against,
    only a comparison that does not happen — and the line keeps showing the age,
    so the instance does not quietly leave the inventory."""
    rule = {"name": "the licence server", "names": ["licence"],
            "max_age": None}
    leaf = _ec2(_build(ec2={**GRADED_EC2, "rules": [rule]}),
                instances={"eu-central-1": [[
                    _instance("licence", up=timedelta(days=312))]]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 1 (312d)")


@pytest.mark.parametrize("matcher,name", [
    ({"names": ["Prometheus"]}, "prometheus"),          # exact, case-insensitive
    ({"prefixes": ["Web-"]}, "web-1"),
    ({"regexes": ["^db[0-9]{2}$"]}, "db07"),
    ({"regexes": ["mid"]}, "a-middle-name"),            # `search`, not fullmatch
])
def test_every_matcher_form_finds_its_name(matcher: dict[str, Any],
                                           name: str) -> None:
    rule = {"name": "matched", "max_per_name_warn": 0, **matcher}
    leaf = _ec2(_build(ec2={"rules": [rule]}),
                instances={"eu-central-1": [[_instance(name)]]})
    assert leaf.reason[0].code is StatusCode.WARN


def test_one_rule_may_own_several_names_and_several_forms() -> None:
    """A set of names sharing one set of limits is the ordinary case; a rule per
    name would copy every level and every sentence once per member."""
    rule = {"name": "the reporters", "names": ["billing-reporter"],
            "prefixes": ["rp-"], "regexes": ["-reporter$"],
            "max_per_name_warn": 0}
    leaf = _ec2(_build(ec2={"rules": [rule]}), instances={"eu-central-1": [
        [_instance("billing-reporter")], [_instance("rp-usage")],
        [_instance("usage-reporter")], [_instance("prometheus")]]})
    codes = {entry.text.split("]")[0].lstrip("["): entry.code
             for entry in leaf.reason if entry.slug != "scope"}
    assert codes == {"billing-reporter": StatusCode.WARN,
                     "rp-usage": StatusCode.WARN,
                     "usage-reporter": StatusCode.WARN,
                     "prometheus": StatusCode.OK}


def test_the_group_nobody_named_is_addressed_as_unnamed() -> None:
    """Not by the placeholder the card prints for it, which is display text this
    package may reword — and which an instance could be named."""
    rule = {"name": "unnamed instances", "unnamed": True,
            "max_per_name_error": 0}
    leaf = _ec2(_build(ec2={"rules": [rule]}), instances={"eu-central-1": [[
        _instance(None), _instance("prometheus")]]})
    unnamed = [entry for entry in leaf.reason if entry.text.startswith(NO_NAME_TAG)]
    named = [entry for entry in leaf.reason
             if entry.slug != "scope" and entry not in unnamed]
    assert [entry.code for entry in unnamed] == [StatusCode.ERROR]
    assert [entry.code for entry in named] == [StatusCode.OK]


def test_an_ignore_rule_is_ordered_like_any_other() -> None:
    """"Ignore everything under `tmp-` except `tmp-db`" is two rules in the
    obvious order — which a flat list of substrings could not say at all."""
    rules = [{"name": "the temp database", "names": ["tmp-db"],
              "max_per_name_warn": 0},
             {"name": "scratch", "prefixes": ["tmp-"], "ignore": True}]
    leaf = _ec2(_build(ec2={"rules": rules}), instances={"eu-central-1": [
        [_instance("tmp-db")], [_instance("tmp-scratch")]]})
    texts = " ".join(_texts(leaf))
    assert "tmp-db" in texts and "tmp-scratch" not in texts
    assert leaf.reason[-1].text == "1 instance in scope (eu-central-1)"


def test_a_judgment_with_no_sentence_of_its_own_says_the_rules_name() -> None:
    """A worse sentence than one somebody wrote, and much better than a bare
    color: it says which rule made the decision."""
    rule = {"name": "the build agents", "prefixes": ["jenkins-agent"],
            "max_per_name_error": 2}
    leaf = _ec2(_build(ec2={"rules": [rule]}), instances={"eu-central-1": [
        _fleet("jenkins-agent-1", 4, timedelta(hours=2))]})
    assert leaf.reason[0].text.endswith(": 4 (2h) — the build agents")


def test_a_written_sentence_beats_the_rules_name() -> None:
    rule = {"name": "the build agents", "prefixes": ["jenkins-agent"],
            "max_per_name_error": 2, "max_per_name_reason": "Too many agents."}
    leaf = _ec2(_build(ec2={"rules": [rule]}), instances={"eu-central-1": [
        _fleet("jenkins-agent-1", 4, timedelta(hours=2))]})
    assert leaf.reason[0].text.endswith("— Too many agents.")


def test_a_name_no_rule_matches_is_judged_by_the_blocks_own_levels() -> None:
    """The block is not "sensible numbers for everything"; it is what the check
    says about a name nobody has classified — and `0` asks to hear about any."""
    leaf = _ec2(_build(ec2={"max_per_name_warn": 0, "rules": [LOADTEST_RULE]}),
                instances={"eu-central-1": [[_instance("something-new")]]})
    assert leaf.reason[0].code is StatusCode.WARN


# --- the ec2 aspect: rules that are refused --------------------------------

@pytest.mark.parametrize("rules,message", [
    ("not a list", "must be a list"),
    ([["not", "a", "mapping"]], "must be a mapping"),
    ([{"prefixes": ["web-"]}], "needs a 'name'"),
    ([{"name": "  ", "prefixes": ["web-"]}], "needs a 'name'"),
    ([{"name": "a", "prefixes": ["web-"]}, {"name": "A", "names": ["x"]}],
     "already called that"),
    ([{"name": "a", "prefixes": ["web-"], "max_per_nam_warn": 1}],
     "unknown key"),
    ([{"name": "a"}], "at least one of"),
    ([{"name": "a", "regexes": ["([unclosed"]}], "not a regular expression"),
    ([{"name": "a", "prefixes": [""]}], "non-empty string"),
    ([{"name": "a", "prefixes": "web-"}], "must be a list"),
    ([{"name": "a", "unnamed": "yes"}], "true or false"),
    ([{"name": "a", "prefixes": ["web-"], "ignore": "yes"}], "true or false"),
    ([{"name": "a", "prefixes": ["web-"], "ignore": True,
       "max_per_name_warn": 2}], "cannot be written beside"),
    ([{"name": "a", "prefixes": ["web-"], "max_age": "3d"}],
     "accepts only null"),
    ([{"name": "a", "prefixes": ["web-"], "max_age": None,
       "max_age_warn": "3d"}], "cannot be written beside"),
])
def test_a_bad_rule_is_refused_by_name(rules: object, message: str) -> None:
    with pytest.raises(CheckError, match=message):
        AwsCheck.from_config(_config(ec2={"rules": rules}), Path("."))


def test_a_refusal_names_the_rule_it_is_about() -> None:
    """Five aspects and a list: a message that said only "unknown key" would
    send somebody reading the whole file."""
    with pytest.raises(CheckError, match="the web fleet"):
        AwsCheck.from_config(_config(ec2={"rules": [
            {"name": "the web fleet", "prefixes": ["web-"], "nonsense": 1}]}),
            Path("."))


# --- the ec2 aspect: rules that match nothing ------------------------------

def test_a_rule_that_matches_nothing_goes_to_the_log_and_not_to_a_node(
        caplog: pytest.LogCaptureFixture) -> None:
    """A regex with a typo in it is a fact about the *configuration*. Coloring
    a card over it would send an operator hunting through an account where
    nothing is wrong."""
    check = _build(ec2={"rules": [
        {"name": "typo", "prefixes": ["laodtest-"], "max_per_name_warn": 0}]})
    _stub(check, instances={"eu-central-1": [[_instance("prometheus")]]})
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        result = check.run()
    assert "typo" in caplog.text and "ec2 rule(s) matched no name" in caplog.text
    assert "typo" not in " ".join(_texts(_child(_child(result, "live"), EC2)))


def test_the_unmatched_rules_line_is_said_only_when_the_set_changes(
        caplog: pytest.LogCaptureFixture) -> None:
    """At `frequency: 60s` an unconditional line is fourteen hundred identical
    records a day about a typo that was true at breakfast."""
    check = _build(ec2={"rules": [
        {"name": "typo", "prefixes": ["laodtest-"], "max_per_name_warn": 0}]})
    _stub(check, instances={"eu-central-1": [[_instance("prometheus")]]})
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        check.run()
        caplog.clear()
        check.run()
    assert "matched no name" not in caplog.text


def test_a_rule_that_starts_matching_is_said_once_too(
        caplog: pytest.LogCaptureFixture) -> None:
    check = _build(ec2={"rules": [
        {"name": "web", "prefixes": ["web-"], "max_per_name_warn": 0}]})
    _stub(check, instances={"eu-central-1": [[_instance("prometheus")]]})
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        check.run()
        caplog.clear()
        _stub(check, instances={"eu-central-1": [[_instance("web-1")]]})
        check.run()
    assert "every ec2 rule now matches a name" in caplog.text


def test_an_aspect_that_grades_only_through_its_rules_is_not_called_silent(
        caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        _build(ec2={"rules": [
            {"name": "web", "prefixes": ["web-"], "max_per_name_warn": 0}]})
    assert "grades nothing" not in caplog.text


def test_a_red_line_sorts_above_a_warning_one() -> None:
    leaf = _ec2(_graded(), instances={"eu-central-1": [[
        _instance("jenkins", up=timedelta(hours=2)),
        _instance("jenkins", up=timedelta(hours=1)),
        _instance("ancient", up=timedelta(days=30))]]})
    assert [entry.code for entry in leaf.reason] == [
        StatusCode.ERROR, StatusCode.WARN, StatusCode.OK]
    assert "ancient" in leaf.reason[0].text


def test_the_report_carries_the_age_too() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("jenkins", up=timedelta(days=2)),
        _instance("prometheus")]]})
    assert leaf.report.splitlines() == ["- jenkins: 1 (2d)", "- prometheus: 1"]


@pytest.mark.parametrize(("up", "text"), [
    (timedelta(seconds=45), "< 1m"), (timedelta(minutes=59), "59m"),
    (timedelta(hours=1), "1h"), (timedelta(hours=23, minutes=30), "23h 30m"),
    (timedelta(days=1), "1d"), (timedelta(days=13, hours=23), "13d 23h"),
])
def test_an_age_is_written_the_way_the_rest_of_the_page_writes_one(
        up: timedelta, text: str) -> None:
    """`coarse_span`, not a fourth spelling of our own: an age on a card is a
    **bound** on a surface nobody re-renders while it is read, which is the
    reading that module's `coarse_span` exists for. The exact-size rendering
    (`format_span`) is for a measurement, and it is what the *thresholds* in the
    config summary use."""
    leaf = _ec2(_build(), instances={"eu-central-1": [[_instance("x", up=up)]]})
    assert leaf.reason[0].text.endswith(f": 1 ({text})")


def test_a_configured_threshold_is_written_as_a_size_not_as_a_bound() -> None:
    summary = _build(ec2={"max_age_warn": "7d", "max_age_error": "14d"},
                     **{"lambda": {"error_max_age": "36h"}}).config_summary()
    assert "**instance age:** warn above 7d, error above 14d" in summary
    assert "**lambda error graded within:** 1d 12h" in summary


def test_a_judgment_is_one_entry_on_the_card_levels_and_sentence() -> None:
    """Two entries would read as two settings — and "what is said about an
    instance that is too old", with no threshold above it, would be a sentence
    nobody can trigger."""
    summary = _build(ec2={"max_age_error": "40d",
                          "max_age_reason": "Too old to be patched."
                          }).config_summary()
    assert ("- **instance age:** error above 40d — Too old to be patched."
            in summary)


def test_the_rules_are_a_nested_list_in_the_order_they_decide() -> None:
    """The order they are consulted is the order they decide in, so a card that
    listed them any other way would describe a different config."""
    summary = _build(ec2={
        "max_age_error": "40d",
        "rules": [
            {"name": "scratch", "prefixes": ["tmp-"], "ignore": True},
            {"name": "load tests", "prefixes": ["loadtest-"],
             "max_per_name_warn": 15},
        ]}).config_summary()
    assert "- **instance rules:** checked in order, first match wins" in summary
    assert summary.index("**scratch**") < summary.index("**load tests**")
    assert "  - **scratch** — neither listed nor counted" in summary


def test_a_rule_is_shown_on_the_card_as_it_will_act_not_as_it_was_written() -> None:
    """It names one level and inherits the rest; what a reader needs from this
    card is what the check will actually do to those names."""
    summary = _build(ec2={
        "max_age_error": "40d",
        "rules": [{"name": "load tests", "prefixes": ["loadtest-"],
                   "max_per_name_warn": 15}]}).config_summary()
    assert ("  - **load tests** — per name: warn above 15; age: error above 40d"
            in summary)


def test_a_check_with_no_rules_has_no_rules_entry() -> None:
    assert "instance rules" not in _build(ec2=GRADED_EC2).config_summary()


def test_the_shipped_ec2_prose_describes_the_keys_the_aspect_has() -> None:
    """Shipped prose is the piece most likely to rot, because no test fails when
    it goes stale — so this one does."""
    about = _build().subnode_labels[EC2]["about"]
    for present in ("max_per_name_warn", "max_age_error", "rules:",
                    "unnamed: true", "first", "range"):
        assert present in about, present
    for gone in ("fleet_size", "fleet_max_age", "ignore_name_patterns"):
        assert gone not in about, gone


def test_a_pair_that_grades_nothing_is_left_off_the_card() -> None:
    """There is no honest way to render a comparison that never runs, and an
    empty line beside "instance age" would read as a threshold of none."""
    summary = _build(ec2={"max_per_name_warn": 1}).config_summary()
    assert "instances per name" in summary
    assert "instance age" not in summary


@pytest.mark.parametrize("block", [
    {"max_age_error": "nonsense"}, {"fleet_max_age": "later"},
    {"fleet_size": 0}, {"fleet_size": True}, {"max_age_error": 0},
    {"max_age_warn": True},
])
def test_bad_age_settings_are_refused(block: dict[str, Any]) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(ec2=block), Path("."))


def test_an_instance_computes_its_own_age_and_never_a_negative_one() -> None:
    future = Instance(instance_id="i-1", name="a", region="r", state="running",
                      launched=NOW + timedelta(hours=1))
    assert future.age_seconds(NOW) == 0
    assert Instance(instance_id="i-2", name="a", region="r",
                    state="running").age_seconds(NOW) is None


# --- the lambda aspect ----------------------------------------------------

def _lambda(check: AwsCheck, **stub: Any) -> CheckResult:
    _stub(check, **stub)
    return _child(_child(check.run(), "live"), LAMBDA)


def _line(leaf: CheckResult, name: str) -> str:
    for entry in leaf.reason:
        if f"[{name}]" in entry.text:
            return entry.text
    raise AssertionError(f"no line for {name!r} in {[e.text for e in leaf.reason]}")


def _entry(leaf: CheckResult, name: str) -> Any:
    for entry in leaf.reason:
        if f"[{name}]" in entry.text:
            return entry
    raise AssertionError(f"no entry for {name!r}")


ONE_FUNCTION = {"eu-central-1": [["running-collector-lambda"]]}


def test_a_clean_function_reports_its_last_run() -> None:
    leaf = _lambda(_build(), functions=ONE_FUNCTION,
                   metrics={"running-collector-lambda":
                            {"errors": 0, "age": timedelta(hours=2)}},
                   messages={"running-collector-lambda": "REPORT RequestId: 1"})
    entry = _entry(leaf, "running-collector-lambda")
    assert entry.code is StatusCode.OK
    assert entry.text.endswith(": no errors, last run 2h ago · log: REPORT")


def test_a_recent_error_burns() -> None:
    leaf = _lambda(_build(), functions=ONE_FUNCTION,
                   metrics={"running-collector-lambda":
                            {"errors": 3, "age": timedelta(minutes=20)}},
                   messages={"running-collector-lambda": "REPORT RequestId: 1"})
    entry = _entry(leaf, "running-collector-lambda")
    assert entry.code is StatusCode.ERROR
    assert "3 errors, last run 20m ago" in entry.text


def test_one_error_is_singular() -> None:
    leaf = _lambda(_build(), functions=ONE_FUNCTION,
                   metrics={"running-collector-lambda":
                            {"errors": 1, "age": timedelta(minutes=5)}})
    assert "1 error, last run 5m ago" in _line(leaf, "running-collector-lambda")


def test_an_error_older_than_the_grace_is_reported_but_not_graded() -> None:
    """The original's reasoning, kept: past a fortnight CloudWatch has condensed
    the error into a bucket with the successful runs around it, so the count no
    longer means the last run failed."""
    leaf = _lambda(_build(), functions=ONE_FUNCTION,
                   metrics={"running-collector-lambda":
                            {"errors": 2, "age": timedelta(days=20)}})
    entry = _entry(leaf, "running-collector-lambda")
    assert entry.code is StatusCode.OK
    assert "too old to grade" in entry.text


def test_the_grace_is_configurable() -> None:
    stub = {"functions": ONE_FUNCTION,
            "metrics": {"running-collector-lambda":
                        {"errors": 2, "age": timedelta(days=20)}}}
    strict = _lambda(_build(**{"lambda": {"error_max_age": "30d"}}), **stub)
    assert _entry(strict, "running-collector-lambda").code is StatusCode.ERROR


def test_a_function_with_no_data_point_anywhere_warns() -> None:
    """Not the same as zero errors: a scheduled job nobody has invoked in 455
    days is not a healthy one."""
    leaf = _lambda(_build(), functions=ONE_FUNCTION)
    entry = _entry(leaf, "running-collector-lambda")
    assert entry.code is StatusCode.WARN
    assert "no recent invocations" in entry.text


def test_an_error_in_the_last_log_line_burns_even_with_a_clean_metric() -> None:
    """The metric lags; the log does not."""
    leaf = _lambda(_build(), functions=ONE_FUNCTION,
                   metrics={"running-collector-lambda":
                            {"errors": 0, "age": timedelta(minutes=1)}},
                   messages={"running-collector-lambda":
                             "2026-08-10T12:00:00Z ERROR Unhandled exception"})
    entry = _entry(leaf, "running-collector-lambda")
    assert entry.code is StatusCode.ERROR
    assert "log: ERROR" in entry.text


@pytest.mark.parametrize(("message", "expected"), [
    ("INIT_START Runtime Version: python:3.13", "log: INIT_START"),
    ("START RequestId: abc", "log: START"),
    ("END RequestId: abc", "log: END"),
    (None, "no log event"),
    ("just some print output", "no status word in the last log line"),
])
def test_the_status_word_of_the_last_log_event(message: str | None,
                                               expected: str) -> None:
    leaf = _lambda(_build(), functions=ONE_FUNCTION,
                   metrics={"running-collector-lambda":
                            {"errors": 0, "age": timedelta(minutes=1)}},
                   messages={"running-collector-lambda": message})
    assert expected in _line(leaf, "running-collector-lambda")


def test_a_function_that_has_never_run_has_no_log_stream() -> None:
    leaf = _lambda(_build(), functions=ONE_FUNCTION,
                   metrics={"running-collector-lambda":
                            {"errors": 0, "age": timedelta(minutes=1)}})
    assert "no log stream" in _line(leaf, "running-collector-lambda")


def test_the_log_reading_can_be_switched_off_entirely() -> None:
    check = _build(**{"lambda": {"read_log_status": False}})
    built = _stub(check, functions=ONE_FUNCTION,
                  metrics={"running-collector-lambda":
                           {"errors": 0, "age": timedelta(minutes=1)}},
                  messages={"running-collector-lambda": "REPORT"})
    check.run()
    # Two API calls per function per run is the expensive half of this aspect.
    assert all(not session.log_calls for session in built)


def test_an_ignored_function_is_skipped_by_its_whole_name() -> None:
    """A rule matching by exact `names:` says what the old `ignore:` list said —
    and a neighbor whose name merely starts the same is untouched."""
    leaf = _lambda(_build(**{"lambda": {"rules": [
        {"name": "the old collector", "names": ["running-collector-lambda"],
         "ignore": True}]}}),
                   functions={"eu-central-1": [["running-collector-lambda",
                                                "running-collector-lambda-v2"]]})
    assert "[running-collector-lambda]" not in " ".join(_texts(leaf))
    assert "running-collector-lambda-v2" in " ".join(_texts(leaf))
    assert "1 function in scope" in _texts(leaf)[-1]


def test_a_lambda_rule_moves_the_gate_for_one_function() -> None:
    """`error_max_age` is a *gate*, not a threshold to split into levels: it
    decides whether the newest error is graded at all. A rule moves it for the
    functions that need a different window."""
    block = {"error_max_age": "1d", "rules": [
        {"name": "the slow batch job", "prefixes": ["batch-"],
         "error_max_age": "30d"}]}
    leaf = _lambda(_build(**{"lambda": block}),
                   functions={"eu-central-1": [["batch-nightly", "api-handler"]]},
                   metrics={"batch-nightly": {"errors": 2, "age": timedelta(days=5)},
                            "api-handler": {"errors": 2, "age": timedelta(days=5)}})
    assert _entry(leaf, "batch-nightly").code is StatusCode.ERROR
    assert _entry(leaf, "api-handler").code is StatusCode.OK


def test_a_function_can_be_expected_to_be_silent() -> None:
    """A function nobody invoked warns, which is right for a scheduled job and
    wrong for a handler that runs when somebody calls it."""
    block = {"rules": [{"name": "on-demand handlers", "prefixes": ["api-"],
                        "expect_invocations": False}]}
    leaf = _lambda(_build(**{"lambda": block}),
                   functions={"eu-central-1": [["api-handler", "nightly-job"]]})
    assert _entry(leaf, "api-handler").code is StatusCode.OK
    assert _entry(leaf, "nightly-job").code is StatusCode.WARN


def test_a_silent_function_says_why_it_is_a_finding() -> None:
    block = {"silent_reason": "This job runs on a schedule; silence means it did not."}
    leaf = _lambda(_build(**{"lambda": block}),
                   functions={"eu-central-1": [["nightly-job"]]})
    assert _entry(leaf, "nightly-job").text.endswith(
        "This job runs on a schedule; silence means it did not.")


def test_a_function_graded_for_errors_says_why() -> None:
    block = {"error_reason": "Check the dead-letter queue before retrying."}
    leaf = _lambda(_build(**{"lambda": block}),
                   functions={"eu-central-1": [["api-handler"]]},
                   metrics={"api-handler": {"errors": 3,
                                            "age": timedelta(hours=1)}})
    entry = _entry(leaf, "api-handler")
    assert entry.code is StatusCode.ERROR
    assert entry.text.endswith("Check the dead-letter queue before retrying.")


def test_a_lambda_rule_with_no_sentence_says_its_name() -> None:
    block = {"rules": [{"name": "the payment handlers", "prefixes": ["pay-"],
                        "error_max_age": "30d"}]}
    leaf = _lambda(_build(**{"lambda": block}),
                   functions={"eu-central-1": [["pay-capture"]]},
                   metrics={"pay-capture": {"errors": 1,
                                            "age": timedelta(hours=2)}})
    assert _entry(leaf, "pay-capture").text.endswith("the payment handlers")


def test_reading_the_log_status_can_be_switched_off_per_function() -> None:
    """Two API calls per function, so which functions are worth paying for is not
    always the whole account."""
    block = {"rules": [{"name": "the chatty ones", "prefixes": ["api-"],
                        "read_log_status": False}]}
    leaf = _lambda(_build(**{"lambda": block}),
                   functions={"eu-central-1": [["api-handler", "nightly-job"]]},
                   metrics={"api-handler": {"errors": 0, "age": timedelta(hours=1)},
                            "nightly-job": {"errors": 0, "age": timedelta(hours=1)}},
                   messages={"api-handler": "ERROR boom",
                             "nightly-job": "REPORT fine"})
    assert "log:" not in _entry(leaf, "api-handler").text
    assert "log: REPORT" in _entry(leaf, "nightly-job").text


def test_a_sentence_that_could_never_be_shown_is_refused() -> None:
    with pytest.raises(CheckError, match="could never be shown"):
        AwsCheck.from_config(_config(**{"lambda": {
            "expect_invocations": False,
            "silent_reason": "Never seen."}}), Path("."))


def test_a_lambda_rule_may_not_carry_settings_beside_ignore() -> None:
    with pytest.raises(CheckError, match="cannot be written beside"):
        AwsCheck.from_config(_config(**{"lambda": {"rules": [
            {"name": "x", "prefixes": ["a-"], "ignore": True,
             "error_max_age": "1d"}]}}), Path("."))


def test_every_page_of_functions_is_read() -> None:
    """The original read `list_functions.functions` — one page, so an account
    past fifty functions silently lost the rest."""
    leaf = _lambda(_build(), functions={"eu-central-1": [["one"], ["two"]]})
    assert "2 functions in scope (eu-central-1)" in _texts(leaf)[-1]


def test_the_metric_is_asked_once_per_period_not_once_per_function() -> None:
    check = _build()
    built = _stub(check, functions={"eu-central-1": [["a", "b", "c"]]},
                  metrics={name: {"errors": 0, "age": timedelta(minutes=1)}
                           for name in "abc"})
    check.run()
    calls = built[1].metric_calls          # the live account's session
    assert len(calls) == 1                 # one call, three queries
    assert len(calls[0]) == 3


def test_a_function_answering_at_one_minute_is_not_asked_again() -> None:
    check = _build()
    built = _stub(check, functions={"eu-central-1": [["fine", "coarse"]]},
                  metrics={"fine": {"errors": 0, "age": timedelta(minutes=1)},
                           "coarse": {"errors": 0, "age": timedelta(days=40),
                                      "period": 3600}})
    check.run()
    calls = built[1].metric_calls
    periods = [call[0]["MetricStat"]["Period"] for call in calls]
    assert periods == [60, 300, 3600]      # widening only while something is left
    asked_last = [query["MetricStat"]["Metric"]["Dimensions"][0]["Value"]
                  for query in calls[-1]]
    assert asked_last == ["coarse"]


def test_a_batch_larger_than_the_api_limit_is_split() -> None:
    names = [f"fn-{n:04d}" for n in range(501)]
    check = _build()
    built = _stub(check, functions={"eu-central-1": [names]},
                  metrics={name: {"errors": 0, "age": timedelta(minutes=1)}
                           for name in names})
    check.run()
    sizes = [len(call) for call in built[1].metric_calls]
    assert sizes == [500, 1]


def test_the_display_name_is_shortened_but_the_slug_is_not() -> None:
    """A pin is keyed on the slug, so it must survive somebody editing the
    cosmetic rules."""
    check = _build(**{"lambda": {"shorten": [
        {"from": "-lambda"}, {"from": "running-"},
        {"from": "-reporter", "to": "-rp"}]}})
    leaf = _lambda(check, functions={
        "eu-central-1": [["running-collector-reporter-lambda"]]})
    entry = leaf.reason[0]
    assert "[collector-rp]" in entry.text
    assert entry.slug == "eu-central-1-running-collector-reporter-lambda"
    assert "functions/running-collector-reporter-lambda" in entry.text


def test_shorten_rules_apply_in_order() -> None:
    check = _build(**{"lambda": {"shorten": [
        {"from": "load-", "to": "performance-"}, {"from": "performance-"}]}})
    leaf = _lambda(check, functions={"eu-central-1": [["load-runner"]]})
    assert "[runner]" in leaf.reason[0].text


def test_a_name_shortened_to_nothing_still_has_a_label() -> None:
    check = _build(**{"lambda": {"shorten": [{"from": "gone"}]}})
    leaf = _lambda(check, functions={"eu-central-1": [["gone"]]})
    assert "[(unnamed)]" in leaf.reason[0].text


def test_a_region_whose_functions_cannot_be_listed_is_its_own_warn_line() -> None:
    check = _build(accounts=[{"name": "live", "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _lambda(check, functions={"eu-central-1": [["survivor"]]},
                   metrics={"survivor": {"errors": 0, "age": timedelta(minutes=1)}},
                   lambda_unreadable={"eu-west-1"})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text.startswith("eu-west-1: functions cannot be read")
    assert "survivor" in " ".join(_texts(leaf))


def test_the_worst_function_sorts_first_and_the_scope_line_last() -> None:
    leaf = _lambda(_build(), functions={"eu-central-1": [["quiet", "loud"]]},
                   metrics={"quiet": {"errors": 0, "age": timedelta(minutes=1)},
                            "loud": {"errors": 9, "age": timedelta(minutes=1)}})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert "loud" in leaf.reason[0].text
    assert leaf.reason[-1].slug == "scope"


def test_the_lambda_report_lists_the_full_names() -> None:
    leaf = _lambda(_build(), functions={"eu-central-1": [["running-a", "b"]]},
                   metrics={"running-a": {"errors": 0, "age": timedelta(minutes=1)},
                            "b": {"errors": 0, "age": timedelta(minutes=1)}})
    assert leaf.report.splitlines() == [
        "- [b](https://eu-central-1.console.aws.amazon.com/lambda/home"
        "?region=eu-central-1#/functions/b)",
        "- [running-a](https://eu-central-1.console.aws.amazon.com/lambda/home"
        "?region=eu-central-1#/functions/running-a)"]


def test_the_lambda_leaf_declares_its_own_display_text() -> None:
    labels = _build().subnode_labels[LAMBDA]
    assert labels["title"] == "Lambda functions"
    assert "`Errors` metric" in labels["about"]


def test_lambda_defaults() -> None:
    """`error_max_age` keeps its default where the other aspects' clocks lost
    theirs: past it CloudWatch has condensed the count into a bucket with the
    successful runs around it, which is a fact about CloudWatch rather than an
    opinion about an estate."""
    settings = _build().lambda_
    assert settings.rules == ()
    assert settings.error_max_age_seconds == 14 * 86400
    assert settings.expect_invocations is True
    assert settings.read_log_status is True
    assert settings.shorten == ()
    assert settings.short_name("untouched") == "untouched"


@pytest.mark.parametrize("block", [
    {"ignore": "one"}, {"error_max_age": "soon"}, {"error_max_age": 0},
    {"shorten": [{"to": "x"}]}, {"shorten": [{"from": ""}]},
    {"shorten": [{"from": "a", "too": "b"}]}, {"shorten": "strip"},
    {"read_logs": True},
])
def test_bad_lambda_settings_are_refused(block: dict[str, Any]) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(**{"lambda": block}), Path("."))


def test_a_function_reading_defaults_to_nothing_known() -> None:
    reading = FunctionReading(name="f", region="r")
    assert (reading.errors, reading.last_run, reading.log_status) == (None, None, "")
    assert LambdaConfig().short_name("f") == "f"


# --- the codepipeline aspect ----------------------------------------------
#
# Ported from `var/alarm/code_pipeline.rb`. Each test below is written from the
# sentence the port makes about the original — either "this is what it did" or
# "this is what it could not say" — with values that make the sentence false if
# the code is wrong.


def _pipelines(check: AwsCheck, **stub: Any) -> CheckResult:
    _stub(check, **stub)
    return _child(_child(check.run(), "live"), CODEPIPELINE)


def _execution(status: str = "Succeeded", *,
               started: timedelta | None = timedelta(hours=2)) -> dict[str, Any]:
    row: dict[str, Any] = {"status": status}
    if started is not None:
        row["startTime"] = NOW - started
    return row


ONE_PIPELINE: dict[str, list[list[str]]] = {"eu-central-1": [["running-deploy"]]}


def test_a_succeeded_pipeline_says_when_that_run_started() -> None:
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [_execution()]})
    entry = _entry(leaf, "running-deploy")
    assert entry.code is StatusCode.OK
    assert entry.text.endswith(": Succeeded, started 2h ago")


def test_an_in_progress_pipeline_warns_as_the_original_did() -> None:
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution("InProgress", started=timedelta(minutes=12))]})
    entry = _entry(leaf, "running-deploy")
    assert entry.code is StatusCode.WARN
    assert entry.text.endswith(": InProgress, started 12m ago")


@pytest.mark.parametrize("status",
                         ["Failed", "Stopped", "Stopping", "Cancelled",
                          "Superseded"])
def test_everything_that_is_not_succeeded_or_in_progress_is_an_error(
        status: str) -> None:
    """The original's `elsif pipeline_status != 'Succeeded'` branch, kept whole:
    the newest thing this pipeline did was not a deployment."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [_execution(status)]})
    assert _entry(leaf, "running-deploy").code is StatusCode.ERROR


def test_an_unknown_pipeline_status_is_not_a_quiet_ok() -> None:
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [_execution("Reticulating")]})
    assert _entry(leaf, "running-deploy").code is StatusCode.WARN


def test_the_pipeline_state_map_can_be_overridden_one_status_at_a_time() -> None:
    check = _build(codepipeline={"state_map": {"Superseded": "OK"}})
    assert check.codepipeline.code_for("Superseded") is StatusCode.OK
    assert check.codepipeline.code_for("Failed") is StatusCode.ERROR   # untouched
    assert check.codepipeline.code_for("Succeeded") is StatusCode.OK


def test_a_pipeline_status_is_matched_whatever_case_it_is_written_in() -> None:
    """CodePipeline shouts none of its statuses and CloudWatch shouts all of
    them, so a config that writes one in the other's style must still bind."""
    check = _build(codepipeline={"state_map": {"SUPERSEDED": "WARN"}})
    assert check.codepipeline.code_for("Superseded") is StatusCode.WARN
    assert check.codepipeline.code_for("superseded") is StatusCode.WARN


#: What an installation writes now that the package ships no staleness clock —
#: the month the aspect used to assume.
STALE_AFTER_31D: dict[str, Any] = {"max_age_warn": "31d"}


def test_a_success_older_than_the_warn_level_warns_and_says_so() -> None:
    """The original's `execution.start_time < Time.now - 31*24*60*60` rule, now
    written down by the installation rather than assumed by the package."""
    leaf = _pipelines(_build(codepipeline=STALE_AFTER_31D), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=32))]})
    entry = _entry(leaf, "running-deploy")
    assert entry.code is StatusCode.WARN
    assert entry.text.endswith(": Succeeded, but that run started 32d ago")


def test_a_success_inside_max_age_is_not_downgraded() -> None:
    """The boundary itself, because `>` and `>=` are one character apart and the
    31-day default is what the original wrote."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=31))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.OK


def test_the_stale_rule_does_not_rescue_a_failure() -> None:
    """It only ever downgrades an OK. A month-old failure is still a failure —
    which is what the original's `elsif` chain said too."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution("Failed", started=timedelta(days=90))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.ERROR


def test_the_staleness_clock_is_configuration() -> None:
    leaf = _pipelines(_build(codepipeline={"max_age_warn": "1d"}),
                      pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=2))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.WARN


def test_a_pipeline_rule_gives_a_set_of_them_its_own_clock() -> None:
    """A pipeline that runs nightly and one that runs at a release are not stale
    at the same age, which one global number could never say."""
    block = {"max_age_warn": "31d", "rules": [
        {"name": "nightly builds", "prefixes": ["nightly-"],
         "max_age_warn": "36h"}]}
    leaf = _pipelines(_build(codepipeline=block),
                      pipelines={"eu-central-1": [["nightly-build", "release"]]},
                      executions={"nightly-build": [
                          _execution(started=timedelta(days=2))],
                          "release": [_execution(started=timedelta(days=2))]})
    assert _entry(leaf, "nightly-build").code is StatusCode.WARN
    assert _entry(leaf, "release").code is StatusCode.OK


def test_a_pipeline_staleness_level_can_reach_error() -> None:
    """It could only ever warn before, however long ago the last release was."""
    leaf = _pipelines(_build(codepipeline={"max_age_warn": "31d",
                                           "max_age_error": "90d"}),
                      pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=100))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.ERROR


def test_a_pipeline_rule_can_switch_the_clock_off() -> None:
    """A release pipeline runs when somebody releases; it is never stale."""
    block = {"max_age_warn": "31d", "rules": [
        {"name": "release pipelines", "prefixes": ["running-"],
         "max_age": None}]}
    leaf = _pipelines(_build(codepipeline=block), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=400))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.OK


def test_a_stale_pipeline_says_why() -> None:
    block = {"max_age_warn": "31d",
             "max_age_reason": "Nobody has released through this in months."}
    leaf = _pipelines(_build(codepipeline=block), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=40))]})
    assert _entry(leaf, "running-deploy").text.endswith(
        "started 40d ago — Nobody has released through this in months.")


def test_a_stale_pipeline_with_no_sentence_says_the_rules_name() -> None:
    block = {"rules": [{"name": "nightly builds", "prefixes": ["running-"],
                        "max_age_warn": "36h"}]}
    leaf = _pipelines(_build(codepipeline=block), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=2))]})
    assert _entry(leaf, "running-deploy").text.endswith("— nightly builds")


def test_only_a_success_is_judged_stale() -> None:
    """A failure is already the finding; telling somebody it is also old is noise
    on the line they are going to act on."""
    leaf = _pipelines(_build(codepipeline=STALE_AFTER_31D), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution("Failed", started=timedelta(days=90))]})
    entry = _entry(leaf, "running-deploy")
    assert entry.code is StatusCode.ERROR
    assert "but that run started" not in entry.text


def test_a_pipeline_aspect_with_no_clock_grades_only_the_status() -> None:
    """The package ships no staleness clock, and an installation that writes none
    still gets what a status means — which is a fact about CodePipeline."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=400))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.OK


def test_a_pipeline_rule_cannot_ask_for_the_unnamed_group() -> None:
    """Only EC2 has instances nobody named; a pipeline is named by existing, so
    `unnamed:` there is a rule that can never match."""
    with pytest.raises(CheckError, match="unknown key"):
        AwsCheck.from_config(_config(codepipeline={"rules": [
            {"name": "nothing", "unnamed": True}]}), Path("."))


def test_a_pipeline_that_has_never_run_is_a_line_and_not_a_silence() -> None:
    """The original built its `Status` *inside* the loop over executions, so a
    pipeline that had never been triggered produced nothing at all and was
    indistinguishable from a pipeline that did not exist."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE, executions={})
    entry = _entry(leaf, "running-deploy")
    assert entry.code is StatusCode.WARN
    assert entry.text.endswith(": never run")


def test_the_newest_execution_decides_whatever_order_they_arrive_in() -> None:
    """The original compared `start_time` across every summary rather than
    trusting the API's order, and so does this."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE, executions={
        "running-deploy": [_execution(started=timedelta(days=3)),
                           _execution("Failed", started=timedelta(hours=1)),
                           _execution(started=timedelta(days=1))]})
    entry = _entry(leaf, "running-deploy")
    assert entry.code is StatusCode.ERROR
    assert entry.text.endswith(": Failed, started 1h ago")


def test_an_execution_without_a_start_time_cannot_win() -> None:
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE, executions={
        "running-deploy": [_execution("Failed", started=None),
                           _execution(started=timedelta(hours=2))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.OK


def test_only_undated_executions_read_as_never_run() -> None:
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE, executions={
        "running-deploy": [_execution("Failed", started=None)]})
    assert _entry(leaf, "running-deploy").text.endswith(": never run")


def test_list_pipelines_is_paginated() -> None:
    """The original read a single page, so an account past the page size
    silently lost the rest."""
    leaf = _pipelines(_build(), pipelines={"eu-central-1": [["one"], ["two"]]},
                      executions={"one": [_execution()],
                                  "two": [_execution()]})
    assert {entry.slug for entry in leaf.reason} == {
        "eu-central-1-one", "eu-central-1-two", "scope"}


def test_one_page_of_executions_is_enough_and_it_is_asked_for_by_size() -> None:
    check = _build()
    built = _stub(check, pipelines=ONE_PIPELINE,
                  executions={"running-deploy": [_execution()]})
    check.run()
    assert built[1].execution_calls == [("running-deploy", 100)]


def test_pipeline_names_can_be_ignored_case_insensitively() -> None:
    leaf = _pipelines(_build(codepipeline={"rules": [
        {"name": "sandboxes", "regexes": ["SANDBOX"], "ignore": True}]}),
                      pipelines={"eu-central-1": [["my-sandbox-deploy", "real"]]},
                      executions={"my-sandbox-deploy": [_execution("Failed")],
                                  "real": [_execution()]})
    # Out of the lines *and* out of the count: an ignored pipeline is out of
    # scope, not a silent zero.
    assert "sandbox" not in " ".join(_texts(leaf))
    assert leaf.reason[-1].text.startswith("1 pipeline in scope")


def test_the_pipeline_display_name_is_shortened_but_the_slug_is_not() -> None:
    check = _build(shorten=[{"from": "-pipeline"}, {"from": "running-"}])
    leaf = _pipelines(check, pipelines={"eu-central-1": [["running-deploy-pipeline"]]},
                      executions={"running-deploy-pipeline": [_execution()]})
    entry = leaf.reason[0]
    assert "[deploy]" in entry.text
    assert entry.slug == "eu-central-1-running-deploy-pipeline"


def test_the_pipeline_link_is_the_one_the_original_built() -> None:
    leaf = _pipelines(_build(), pipelines={"eu-central-1": [["a b"]]},
                      executions={"a b": [_execution()]})
    assert ("[a b](https://eu-central-1.console.aws.amazon.com/codesuite"
            "/codepipeline/pipelines/a%20b/executions?region=eu-central-1)"
            ) in leaf.reason[0].text


def test_the_region_is_in_the_pipeline_slug_but_not_in_a_single_region_line() -> None:
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [_execution()]})
    assert leaf.reason[0].slug == "eu-central-1-running-deploy"
    assert not leaf.reason[0].text.startswith("eu-central-1 / ")


def test_two_regions_put_the_region_on_the_pipeline_line() -> None:
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _pipelines(check, pipelines={"eu-west-1": [["deploy"]]},
                      executions={"deploy": [_execution()]})
    assert leaf.reason[0].text.startswith("eu-west-1 / [deploy]")


def test_a_region_whose_pipelines_cannot_be_read_is_its_own_warn_line() -> None:
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _pipelines(check, pipelines={"eu-central-1": [["survivor"]]},
                      executions={"survivor": [_execution()]},
                      pipelines_unreadable={"eu-west-1"})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text.startswith("eu-west-1: pipelines cannot be read")
    assert "survivor" in " ".join(_texts(leaf))


def test_the_worst_pipeline_sorts_first_and_the_scope_line_last() -> None:
    leaf = _pipelines(_build(), pipelines={"eu-central-1": [["quiet", "loud"]]},
                      executions={"quiet": [_execution()],
                                  "loud": [_execution("Failed")]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert "loud" in leaf.reason[0].text
    assert leaf.reason[-1].slug == "scope"


def test_an_account_with_no_pipelines_reads_ok() -> None:
    """Unlike the alarm aspect's empty reading: an account may legitimately run
    no pipelines, where an account whose CloudWatch has gone quiet is a
    symptom."""
    leaf = _pipelines(_build())
    assert leaf.reason[-1].code is StatusCode.OK
    assert leaf.reason[-1].text == "no pipelines in scope (eu-central-1)"


def test_the_pipeline_report_lists_the_full_names() -> None:
    check = _build(shorten=[{"from": "running-"}])
    leaf = _pipelines(check, pipelines={"eu-central-1": [["running-b", "a"]]},
                      executions={"running-b": [_execution()],
                                  "a": [_execution()]})
    assert leaf.report.splitlines() == [
        "- [a](https://eu-central-1.console.aws.amazon.com/codesuite/codepipeline"
        "/pipelines/a/executions?region=eu-central-1)",
        "- [running-b](https://eu-central-1.console.aws.amazon.com/codesuite"
        "/codepipeline/pipelines/running-b/executions?region=eu-central-1)"]


def test_the_codepipeline_leaf_declares_its_own_display_text() -> None:
    labels = _build().subnode_labels[CODEPIPELINE]
    assert labels["title"] == "CodePipeline"
    assert "never been executed" in labels["about"]


def test_codepipeline_grades_a_status_by_default_and_an_age_never() -> None:
    """What a status *means* is a fact about CodePipeline, so the state map keeps
    its defaults. How long a success stays evidence that the pipeline still works
    depends on how often it is meant to run, so that has none."""
    settings = _build().codepipeline
    assert (settings.age.warn, settings.age.error) == (None, None)
    assert settings.rules == ()
    assert settings.code_for("Succeeded") is StatusCode.OK
    assert settings.code_for("InProgress") is StatusCode.WARN
    assert settings.code_for("Superseded") is StatusCode.ERROR


@pytest.mark.parametrize("block", [
    {"max_age_warn": "soon"}, {"max_age_error": 0}, {"state_map": "ALARM"},
    {"ignore_name_patterns": ["sandbox"]}, {"shorten": "strip"},
    {"max_age_seconds": "1d"}, {"max_age": "31d"},
    {"max_age_warn": "31d", "max_age_error": "7d"},
])
def test_bad_codepipeline_settings_are_refused(block: dict[str, Any]) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(codepipeline=block), Path("."))


# --- the batch aspect ------------------------------------------------------
#
# Ported from `var/alarm/aws_batch.rb`.


def _batch(check: AwsCheck, **stub: Any) -> CheckResult:
    _stub(check, **stub)
    return _child(_child(check.run(), "live"), BATCH)


def _queue(name: str = "nightly", *, state: str = "ENABLED",
           status: str = "VALID", reason: str = "") -> dict[str, Any]:
    return {"jobQueueName": name, "state": state, "status": status,
            "statusReason": reason}


def _millis(ago: timedelta) -> int:
    return int((NOW - ago).timestamp() * 1000)


def _job(name: str, status: str = "SUCCEEDED", *, job_id: str = "j-0",
         created: timedelta | None = None, started: timedelta | None = None,
         stopped: timedelta | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"jobName": name, "jobId": job_id, "status": status}
    for key, ago in (("createdAt", created), ("startedAt", started),
                     ("stoppedAt", stopped)):
        if ago is not None:
            row[key] = _millis(ago)
    return row


ONE_QUEUE: dict[str, list[list[dict[str, Any]]]] = {
    "eu-central-1": [[_queue()]]}


def test_a_succeeded_job_name_reports_when_it_ended_and_how_long_it_ran() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=3),
                                         started=timedelta(hours=3),
                                         stopped=timedelta(hours=2))]]})
    entry = _entry(leaf, "etl")
    assert entry.code is StatusCode.OK
    assert entry.text.endswith(": SUCCEEDED 2h ago, ran 1h")


def test_a_failed_newest_run_reddens_the_line() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "FAILED"): [[_job("etl", "FAILED",
                                      created=timedelta(hours=2),
                                      started=timedelta(hours=2),
                                      stopped=timedelta(hours=2))]]})
    assert _entry(leaf, "etl").code is StatusCode.ERROR


def test_the_newest_finished_run_decides_not_the_worst_one() -> None:
    """`max_by(&:created_at)` in the original, and the reason the aspect is
    watchable at all: a queue that failed last week and has succeeded since is
    green."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "FAILED"): [[_job("etl", "FAILED", job_id="j-old",
                                      created=timedelta(days=7),
                                      started=timedelta(days=7),
                                      stopped=timedelta(days=7))]],
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id="j-new",
                                         created=timedelta(hours=2),
                                         started=timedelta(hours=2),
                                         stopped=timedelta(hours=1))]]})
    entry = _entry(leaf, "etl")
    assert entry.code is StatusCode.OK
    assert "j-new" in entry.text


def test_a_finished_job_without_timestamps_says_so_rather_than_guessing() -> None:
    """The original's `(Timestamp not available)`."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=1))]]})
    assert _entry(leaf, "etl").text.endswith(": SUCCEEDED (no timestamps)")


def test_a_running_job_below_the_limit_is_reported_and_not_graded() -> None:
    """The deviation from the original, which warned at the *existence* of a
    running job — a permanent yellow on any queue that is doing its work."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING",
                                       created=timedelta(minutes=5),
                                       started=timedelta(minutes=4))]]})
    entry = _entry(leaf, "etl")
    assert entry.code is StatusCode.OK
    assert entry.text.endswith(": 1 running (4m)")


def test_a_job_running_past_max_run_time_warns() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING",
                                       created=timedelta(hours=3),
                                       started=timedelta(hours=3))]]})
    entry = _entry(leaf, "etl")
    assert entry.code is StatusCode.WARN
    assert entry.text.endswith(": 1 running (3h)")


def test_the_oldest_running_job_decides_so_a_busy_queue_cannot_reset_it() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNING"): [[
            _job("etl", "RUNNING", job_id="j-1", started=timedelta(minutes=1)),
            _job("etl", "RUNNING", job_id="j-2", started=timedelta(hours=5)),
            _job("etl", "RUNNING", job_id="j-3", started=timedelta(minutes=2))]]})
    entry = _entry(leaf, "etl")
    assert entry.code is StatusCode.WARN
    assert entry.text.endswith(": 3 running (5h)")


def test_max_run_time_is_configuration() -> None:
    leaf = _batch(_build(batch={"max_run_time": "10m"}), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING",
                                       started=timedelta(minutes=20))]]})
    assert _entry(leaf, "etl").code is StatusCode.WARN


def test_a_job_waiting_for_capacity_past_max_wait_time_warns() -> None:
    """The reading the original did not take at all: a RUNNABLE job is not slow,
    it is unplaceable, and the queue looks idle while it happens."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNABLE"): [[_job("etl", "RUNNABLE",
                                        created=timedelta(minutes=35))]]})
    entry = _entry(leaf, "etl")
    assert entry.code is StatusCode.WARN
    assert entry.text.endswith(": 1 waiting for capacity (35m)")


def test_a_job_waiting_below_the_limit_is_reported_and_not_graded() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNABLE"): [[_job("etl", "RUNNABLE",
                                        created=timedelta(minutes=5))]]})
    entry = _entry(leaf, "etl")
    assert entry.code is StatusCode.OK
    assert entry.text.endswith(": 1 waiting for capacity (5m)")


def test_a_wait_is_measured_from_submission_because_it_never_started() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNABLE"): [[_job("etl", "RUNNABLE",
                                        created=timedelta(hours=1),
                                        started=timedelta(minutes=1))]]})
    assert _entry(leaf, "etl").text.endswith(": 1 waiting for capacity (1h)")


def test_every_reading_meets_on_one_line() -> None:
    """The original emitted two statuses per job name — a `.finished` one and a
    `.running` one — which made two nodes and two pins for one thing."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=3),
                                         started=timedelta(hours=3),
                                         stopped=timedelta(hours=2))]],
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING", job_id="j-r",
                                       started=timedelta(minutes=4))]],
        ("nightly", "RUNNABLE"): [[_job("etl", "RUNNABLE", job_id="j-w",
                                        created=timedelta(minutes=5))]]})
    lines = [entry for entry in leaf.reason if "etl" in entry.text]
    assert len(lines) == 1
    assert lines[0].text.endswith(
        ": SUCCEEDED 2h ago, ran 1h · 1 running (4m) · 1 waiting for capacity (5m)")


def test_one_line_per_job_name_not_per_submission() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[
            _job("etl", job_id="j-1", created=timedelta(days=1),
                 started=timedelta(days=1), stopped=timedelta(days=1)),
            _job("etl", job_id="j-2", created=timedelta(hours=2),
                 started=timedelta(hours=2), stopped=timedelta(hours=1)),
            _job("report", job_id="j-3", created=timedelta(hours=2),
                 started=timedelta(hours=2), stopped=timedelta(hours=2))]]})
    assert sorted(entry.slug for entry in leaf.reason) == [
        "eu-central-1-nightly-etl", "eu-central-1-nightly-report", "scope"]


def test_the_same_job_name_in_two_queues_stays_two_pins() -> None:
    leaf = _batch(_build(), queues={"eu-central-1": [[_queue("a"), _queue("b")]]},
                  jobs={("a", "SUCCEEDED"): [[_job("etl", job_id="j-a",
                                                   created=timedelta(hours=1))]],
                        ("b", "SUCCEEDED"): [[_job("etl", job_id="j-b",
                                                   created=timedelta(hours=1))]]})
    assert sorted(entry.slug for entry in leaf.reason) == [
        "eu-central-1-a-etl", "eu-central-1-b-etl", "scope"]


def test_an_empty_queue_warns_as_the_original_did() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE)
    entry = _entry(leaf, "nightly")
    assert entry.code is StatusCode.WARN
    assert entry.text.endswith(": no jobs found")


def test_expect_jobs_is_how_a_deployment_disagrees() -> None:
    """The original hard-coded its exception — `if "nonlive" != entry['name']` —
    which is that deployment's account naming inside a check type."""
    leaf = _batch(_build(batch={"expect_jobs": False}), queues=ONE_QUEUE)
    entry = _entry(leaf, "nightly")
    assert entry.code is StatusCode.OK
    assert entry.text.endswith(": no jobs found")


def test_a_disabled_queue_warns_on_its_own_line() -> None:
    leaf = _batch(_build(), queues={"eu-central-1": [[_queue(state="DISABLED")]]},
                  jobs={("nightly", "SUCCEEDED"): [[
                      _job("etl", created=timedelta(hours=1))]]})
    entry = _entry(leaf, "nightly")
    assert entry.code is StatusCode.WARN
    assert "DISABLED and accepts no new jobs" in entry.text


def test_an_invalid_queue_reddens_and_carries_the_reason() -> None:
    leaf = _batch(_build(), queues={"eu-central-1": [[
        _queue(status="INVALID", reason="CE eu-central-1a is gone")]]},
        jobs={("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=1))]]})
    entry = _entry(leaf, "nightly")
    assert entry.code is StatusCode.ERROR
    assert "the queue is INVALID: CE eu-central-1a is gone" in entry.text


def test_a_healthy_queue_with_jobs_gets_no_line_of_its_own() -> None:
    """Its job lines already name it; a second line would double the card and
    say nothing."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=1))]]})
    assert [entry.slug for entry in leaf.reason] == [
        "eu-central-1-nightly-etl", "scope"]


def test_reaching_the_job_cap_is_said_out_loud() -> None:
    """The original read one page and reported the jobs that fitted as though
    they were all of them."""
    leaf = _batch(_build(batch={"max_jobs": 2}), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id=f"j-{n}",
                                         created=timedelta(hours=n + 1))
                                    for n in range(3)]]})
    assert "only the newest 2 jobs per status were read" in _entry(
        leaf, "nightly").text


def test_a_reading_inside_the_cap_says_nothing_about_it() -> None:
    leaf = _batch(_build(batch={"max_jobs": 3}), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id=f"j-{n}",
                                         created=timedelta(hours=n + 1))
                                    for n in range(3)]]})
    assert [entry.slug for entry in leaf.reason] == [
        "eu-central-1-nightly-etl", "scope"]


def test_job_names_can_be_ignored_case_insensitively() -> None:
    leaf = _batch(_build(batch={"ignore_name_patterns": ["SMOKE"]}),
                  queues=ONE_QUEUE, jobs={
                      ("nightly", "FAILED"): [[_job("smoke-test", "FAILED",
                                                    created=timedelta(hours=1))]],
                      ("nightly", "SUCCEEDED"): [[_job("etl",
                                                       created=timedelta(hours=1))]]})
    assert "smoke" not in " ".join(_texts(leaf))
    assert _entry(leaf, "etl").code is StatusCode.OK


def test_a_queue_can_be_ignored_whole() -> None:
    leaf = _batch(_build(batch={"ignore_queue_patterns": ["scratch"]}),
                  queues={"eu-central-1": [[_queue("scratch-q"), _queue("real")]]})
    assert "scratch" not in " ".join(_texts(leaf))
    assert leaf.reason[-1].text == "1 job queue in scope (eu-central-1)"


def test_all_four_job_statuses_are_read() -> None:
    """Three were the original's; RUNNABLE is the one it never asked for."""
    check = _build()
    built = _stub(check, queues=ONE_QUEUE)
    check.run()
    assert built[1].job_calls == [
        ("nightly", "SUCCEEDED"), ("nightly", "FAILED"),
        ("nightly", "RUNNING"), ("nightly", "RUNNABLE")]


def test_batch_timestamps_are_read_as_milliseconds() -> None:
    """Batch reports Unix *milliseconds*. Read as seconds, a job that stopped
    two hours ago would be dated in 1970."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=2),
                                         started=timedelta(hours=2),
                                         stopped=timedelta(hours=2))]]})
    assert ": SUCCEEDED 2h ago, ran < 1m" in _entry(leaf, "etl").text


def test_the_job_link_is_a_job_id_and_never_an_arn() -> None:
    """An ARN carries the account number, and ADR-0006 keeps that out of a line
    somebody may bookmark or paste into a ticket."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id="j-abc",
                                         created=timedelta(hours=1))]]})
    assert ("[etl](https://eu-central-1.console.aws.amazon.com/batch/home"
            "?region=eu-central-1#jobs/detail/j-abc)"
            ) in _entry(leaf, "etl").text


def test_a_region_whose_queues_cannot_be_read_is_its_own_warn_line() -> None:
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _batch(check, queues={"eu-central-1": [[_queue("survivor")]]},
                  batch_unreadable={"eu-west-1"})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text.startswith("eu-west-1: job queues cannot be read")
    assert "survivor" in " ".join(_texts(leaf))


def test_an_account_with_no_job_queues_reads_ok() -> None:
    leaf = _batch(_build())
    assert leaf.reason[-1].code is StatusCode.OK
    assert leaf.reason[-1].text == "no job queues in scope (eu-central-1)"


def test_the_worst_batch_line_sorts_first_and_the_scope_line_last() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("quiet", created=timedelta(hours=1))]],
        ("nightly", "FAILED"): [[_job("loud", "FAILED",
                                      created=timedelta(hours=1))]]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert "loud" in leaf.reason[0].text
    assert leaf.reason[-1].slug == "scope"


def test_the_batch_report_lists_the_queues_and_how_many_job_names() -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=1)),
                                    _job("report", created=timedelta(hours=1))]]})
    assert leaf.report.splitlines() == [
        "- [nightly](https://eu-central-1.console.aws.amazon.com/batch/home"
        "?region=eu-central-1#queues) — 2 job names"]


def test_the_batch_report_is_ordered_by_name_not_by_what_aws_returned() -> None:
    """A roster is a list somebody reads; it should not re-order itself because
    `describe_job_queues` did."""
    leaf = _batch(_build(), queues={"eu-central-1": [[
        _queue("zulu"), _queue("alpha")]]})
    assert [line.split("](")[0] for line in leaf.report.splitlines()] == [
        "- [alpha", "- [zulu"]


def test_the_config_card_spells_out_a_rule_that_only_strips() -> None:
    summary = _build(shorten=[{"from": "-pipeline"}]).config_summary()
    assert "-pipeline (dropped)" in summary


def test_the_batch_leaf_declares_its_own_display_text() -> None:
    labels = _build().subnode_labels[BATCH]
    assert labels["title"] == "AWS Batch"
    assert "waiting for capacity" in labels["about"]


def test_batch_defaults() -> None:
    settings = _build().batch
    assert settings.expect_jobs is True
    assert settings.max_run_seconds == 2 * 3600
    assert settings.max_wait_seconds == 30 * 60
    assert settings.max_jobs == 100
    assert settings.ignore_name_patterns == ()
    assert settings.ignore_queue_patterns == ()


@pytest.mark.parametrize("block", [
    {"max_jobs": 0}, {"max_jobs": True}, {"max_jobs": "many"},
    {"max_run_time": "soon"}, {"max_wait_time": 0},
    {"ignore_name_patterns": "etl"}, {"shorten": "strip"},
    {"expect_job": False},
])
def test_bad_batch_settings_are_refused(block: dict[str, Any]) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(batch=block), Path("."))


# --- one set of display-name rules for every aspect that names things ------


def test_the_check_level_shorten_reaches_every_naming_aspect() -> None:
    """The old dashboards spelled the same four rules out once per check file.
    The organization's naming is one fact, so it is written once."""
    check = _build(shorten=[{"from": "running-"}, {"from": "-reporter",
                                                  "to": "-rp"}])
    assert check.lambda_.short_name("running-a-reporter") == "a-rp"
    assert check.codepipeline.short_name("running-a-reporter") == "a-rp"
    assert check.batch.short_name("running-a-reporter") == "a-rp"


def test_an_aspect_s_own_shorten_replaces_the_check_s() -> None:
    check = _build(shorten=[{"from": "running-"}],
                   **{"lambda": {"shorten": [{"from": "load-"}]}})
    assert check.lambda_.short_name("load-running-a") == "running-a"
    assert check.codepipeline.short_name("load-running-a") == "load-a"


def test_an_empty_aspect_shorten_opts_out_of_the_check_s() -> None:
    """`shorten: []` is a value, not an absence — it is how one aspect steps out
    of a list the others want."""
    check = _build(shorten=[{"from": "running-"}], batch={"shorten": []})
    assert check.batch.short_name("running-a") == "running-a"
    assert check.lambda_.short_name("running-a") == "a"


def test_a_lambda_only_shorten_block_still_works_on_its_own() -> None:
    """Every config written before the check-level key existed."""
    check = _build(**{"lambda": {"shorten": [{"from": "-lambda"}]}})
    assert check.lambda_.short_name("collector-lambda") == "collector"
    assert check.shorten == ()


def test_the_config_card_names_the_shared_shorten_rules() -> None:
    summary = _build(shorten=[{"from": "running-"},
                              {"from": "-reporter", "to": "-rp"}]).config_summary()
    assert "running- (dropped)" in summary and "-reporter → -rp" in summary


# --- switching an aspect off ----------------------------------------------
#
# The same shape `little-sister-github` uses: `enabled:` sits in the aspect's own
# block, an aspect that says nothing is on, and a switched-off aspect emits no
# node at all rather than a node saying it is off.


def _aspect_names(check: AwsCheck, **stub: Any) -> list[str]:
    _stub(check, **stub)
    return [child.name for child in _child(check.run(), "live").children]


def test_every_aspect_is_on_when_nothing_says_otherwise() -> None:
    """Every config written before this key existed."""
    check = _build()
    assert check.active_aspects() == (CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH)
    assert _aspect_names(check) == list(AwsCheck.ASPECTS)


@pytest.mark.parametrize("aspect", [CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH])
def test_a_disabled_aspect_emits_no_node_at_all(aspect: str) -> None:
    check = _build(**{aspect: {"enabled": False}})
    assert aspect not in check.active_aspects()
    names = _aspect_names(check)
    assert aspect not in names
    assert len(names) == len(AwsCheck.ASPECTS) - 1


def test_the_surviving_aspects_keep_their_order() -> None:
    """`ASPECTS` order, with a hole — not a re-sort."""
    check = _build(ec2={"enabled": False}, codepipeline={"enabled": False})
    assert _aspect_names(check) == [CLOUDWATCH, LAMBDA, BATCH]


def test_a_disabled_aspect_makes_no_api_call() -> None:
    """The half that matters to a role whose policy does not carry that
    service's permissions at all."""
    check = _build(batch={"enabled": False}, codepipeline={"enabled": False})
    built = _stub(check, queues=ONE_QUEUE, pipelines=ONE_PIPELINE)
    check.run()
    asked = {name for name, _ in built[1].clients}
    assert "batch" not in asked and "codepipeline" not in asked
    assert built[1].job_calls == [] and built[1].execution_calls == []
    assert "cloudwatch" in asked          # the ones still on are untouched


def test_a_disabled_aspect_is_named_on_the_card() -> None:
    """A disabled aspect leaves no node, so without this the difference between
    "that aspect is off" and "somebody broke the check" is invisible on the very
    page an operator opens to find out which."""
    summary = _build(batch={"enabled": False}).config_summary()
    assert "**aspects switched off:** batch" in summary


def test_the_card_says_nothing_when_every_aspect_is_on() -> None:
    """A row explaining a feature this check is not using is noise on every card,
    once a minute, forever."""
    assert "aspects switched off" not in _build().config_summary()


def test_a_config_with_every_aspect_off_is_refused() -> None:
    """It would assume each account's role and report nothing about it, while
    looking from the dashboard exactly like a check that does."""
    with pytest.raises(CheckError, match="every aspect disabled"):
        AwsCheck.from_config(
            _config(**{name: {"enabled": False} for name in AwsCheck.ASPECTS}),
            Path("."))


def test_one_aspect_left_on_is_enough() -> None:
    off = {name: {"enabled": False} for name in AwsCheck.ASPECTS if name != EC2}
    check = _build(**off)
    assert check.active_aspects() == (EC2,)


@pytest.mark.parametrize("aspect", [CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH])
def test_a_quoted_yaml_boolean_is_refused_rather_than_read_as_true(
        aspect: str) -> None:
    """`bool("false")` is True, so a quoted `enabled: "false"` would switch the
    aspect **on** while its config says off, and nothing downstream could notice.
    A switch is worth less than nothing if it can silently mean its opposite."""
    with pytest.raises(CheckError, match=f"{aspect}.enabled"):
        AwsCheck.from_config(_config(**{aspect: {"enabled": "false"}}), Path("."))


@pytest.mark.parametrize("block,field", [
    ({"cloudwatch": {"show_healthy": "false"}}, "cloudwatch.show_healthy"),
    ({"cloudwatch": {"include_composite": "no"}}, "cloudwatch.include_composite"),
    ({"lambda": {"read_log_status": "false"}}, "lambda.read_log_status"),
    ({"batch": {"expect_jobs": "false"}}, "batch.expect_jobs"),
])
def test_the_other_switches_are_read_as_strictly(block: dict[str, Any],
                                                 field: str) -> None:
    """The quoted-boolean trap is not special to `enabled` — a quoted
    `show_healthy` silently listing a hundred green alarms is the same failure."""
    with pytest.raises(CheckError, match=field.replace(".", r"\.")):
        AwsCheck.from_config(_config(**block), Path("."))


def test_the_switch_reaches_the_aspect_s_own_settings() -> None:
    check = _build(codepipeline={"enabled": False, "max_age_warn": "1d"})
    assert check.codepipeline.enabled is False
    # …and the rest of the block still parsed, so `enabled` is a knob beside the
    # others rather than a mode that replaces them.
    assert check.codepipeline.age.warn == 86400
    assert check.settings_for(CODEPIPELINE) is check.codepipeline


def test_a_disabled_aspect_does_not_disturb_the_account_s_own_node() -> None:
    check = _build(cloudwatch={"enabled": False})
    _stub(check)
    live = _child(check.run(), "live")
    assert live.code is StatusCode.OK
    assert "regions" in live.config


# --- profiles: which credentials a session is built from ------------------
#
# A profile is the deployment's answer to "several accounts, several logins".
# The claim each test below is written from is that a *configured* profile
# reaches boto3 and nothing else changes — in particular that a config without
# one behaves exactly as it did before the key existed.

PRIMARY = "primary-admin"
SECONDARY = "secondary-admin"


def _profiles(built: list[_FakeSession]) -> list[str]:
    """The profile each session was built with, "" for the ambient chain."""
    return [session.credentials.get("profile_name", "") for session in built]


def test_without_a_profile_boto3_is_asked_for_none() -> None:
    """The case that must not move: every config written before this key."""
    check = _build()
    built = _stub(check)
    check.run()
    assert _profiles(built) == ["", "", ""]      # base + two assumed sessions
    assert check.profile == ""


def test_the_check_s_profile_is_the_session_the_roles_are_assumed_from() -> None:
    check = _build(profile=PRIMARY)
    built = _stub(check)
    check.run()
    # One base session on the profile; the two assumed sessions carry the
    # role's temporary credentials instead, which is what an assumed session is.
    assert _profiles(built) == [PRIMARY, "", ""]
    assert [session.credentials.get("aws_session_token") for session in built[1:]] == [
        "TOK-arn:aws:iam::111:role/monitoring",
        "TOK-arn:aws:iam::222:role/monitoring"]


def test_an_account_overrides_the_check_s_profile_and_leaves_the_others() -> None:
    check = _build(profile=PRIMARY, accounts=[
        {"name": "live", "role_arn": "arn:aws:iam::111:role/monitoring"},
        {"name": "other", "role_arn": "arn:aws:iam::999:role/monitoring",
         "profile": SECONDARY}])
    built = _stub(check)
    check.run()
    assert check.profile_for(check.accounts[0]) == PRIMARY
    assert check.profile_for(check.accounts[1]) == SECONDARY
    # base(PRIMARY) → live's assumed → other's own base(SECONDARY) → other's assumed
    assert _profiles(built) == [PRIMARY, "", SECONDARY, ""]


def test_the_role_is_assumed_from_the_account_s_own_profile() -> None:
    """Composition, not exclusion: `profile` says *from where*, `role_arn` says
    *into what*, and the pair is the ordinary cross-account shape."""
    check = _build(accounts=[{"name": "live", "profile": SECONDARY,
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    built = _stub(check)
    check.run()
    second_session = built[1]
    assert second_session.credentials == {"profile_name": SECONDARY}
    assert ("sts", "eu-central-1") in second_session.clients


def test_a_profile_only_account_is_read_through_the_profile_itself() -> None:
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}])
    sts = _FakeSts()
    built = _stub(check, sts)
    result = check.run()
    assert sts.calls == []                       # nothing to assume
    assert _profiles(built) == [PRIMARY]          # one session, and it is the profile's
    assert _child(result, "live").code is StatusCode.OK


def test_a_profile_only_account_proves_its_credentials_before_the_aspects() -> None:
    """Nothing else in the run would notice an expired login until an aspect
    tried, and then all three would report it in their own words."""
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}])
    built = _stub(check)
    check.run()
    assert built[0].sts.identity_calls == 1


def test_an_ambient_account_spends_no_extra_sts_call() -> None:
    """The preflight is the price of a profile, not of every check."""
    check = _build(accounts=[{"name": "live"}])
    built = _stub(check)
    check.run()
    assert built[0].sts.identity_calls == 0


def test_the_account_card_names_the_profile_and_the_role_together() -> None:
    check = _build(profile=PRIMARY)
    _stub(check)
    live = _child(check.run(), "live")
    assert f"assumed role, from profile {PRIMARY}" in live.config


def test_the_account_card_of_a_profile_only_account_names_the_profile() -> None:
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}])
    _stub(check)
    assert f"profile {PRIMARY}" in _child(check.run(), "live").config


def test_config_summary_names_the_profile_and_its_overrides() -> None:
    check = _build(profile=PRIMARY, accounts=[
        {"name": "live", "role_arn": "arn:aws:iam::111:role/monitoring"},
        {"name": "other", "profile": SECONDARY}])
    summary = check.config_summary()
    assert f"profile {PRIMARY}" in summary and SECONDARY in summary


def test_config_summary_names_per_account_profiles_without_a_default() -> None:
    check = _build(accounts=[{"name": "live", "profile": SECONDARY}])
    assert f"per-account profiles: {SECONDARY}" in check.config_summary()


def test_a_profile_and_static_keys_are_refused_as_a_contradiction() -> None:
    secrets = {"access_key_id": "env://AWS_KEY",
               "secret_access_key": "env://AWS_SECRET"}
    with pytest.raises(CheckError, match="mutually exclusive"):
        AwsCheck.from_config(_config(profile=PRIMARY, secrets=secrets), Path("."))


def test_a_per_account_profile_and_static_keys_are_refused_too() -> None:
    with pytest.raises(CheckError, match="mutually exclusive"):
        AwsCheck.from_config(
            _config(accounts=[{"name": "live", "profile": SECONDARY}],
                    secrets={"access_key_id": "env://AWS_KEY",
                             "secret_access_key": "env://AWS_SECRET"}),
            Path("."))


@pytest.mark.parametrize("profile", ["", "   ", "back`tick", "two\nlines"])
def test_an_unusable_profile_name_is_refused(profile: str) -> None:
    """The name is printed back inside a code span and handed to a subprocess;
    a backtick breaks the first and a newline makes the printed command a
    different command from the one that ran."""
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(profile=profile), Path("."))


def test_a_profile_key_that_was_written_and_left_empty_is_refused() -> None:
    """`profile:` with nothing after it is a typo, not a decision. Reading it as
    "no profile" is how a check falls back to whatever `AWS_PROFILE` says and
    then fails to assume a role it was never meant to assume from there — the
    one failure that looks, on the card, like nothing happened at all."""
    config = _config()
    config["profile"] = None

    with pytest.raises(CheckError, match="must not be empty"):
        AwsCheck.from_config(config, Path("."))


def test_an_account_profile_key_left_empty_is_refused_too() -> None:
    config = _config(accounts=[{"name": "live", "profile": None,
                                "role_arn": "arn:aws:iam::111:role/monitoring"}])

    with pytest.raises(CheckError, match="'live'"):
        AwsCheck.from_config(config, Path("."))


def test_a_profile_that_is_not_text_is_refused_not_stringified() -> None:
    """`profile: 123` used to read as the profile name "123" — a line that
    lost its quoting, stringified into something boto3 and `aws sso login`
    would then be handed. It is the same typo family as a key written and
    left empty, and the identity seam's reader refuses it; the words here are
    this check's own."""
    with pytest.raises(CheckError, match="aws 'profile' must be text, got int"):
        AwsCheck.from_config(_config(profile=123), Path("."))

    with pytest.raises(CheckError, match=r"'live'.*must be text, got bool"):
        AwsCheck.from_config(
            _config(accounts=[{"name": "live", "profile": True,
                               "role_arn": "arn:aws:iam::111:role/monitoring"}]),
            Path("."))


def test_a_config_with_no_profile_key_is_the_ambient_chain_as_before() -> None:
    """The key left out entirely is the case every config written before it
    existed is in, and it has to stay silent."""
    assert AwsCheck.from_config(_config(), Path(".")).profile == ""


# --- what an ambient chain turns out to be ---------------------------------
#
# "ambient credential chain" is honest and unhelpful at the one moment it
# matters: an `AWS_PROFILE` exported for something else — reading a secret, say —
# is then quietly deciding which identity assumes these roles, and `role cannot
# be assumed` is the first anybody hears of it.

def test_the_card_names_the_profile_the_environment_supplies(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_PROFILE", "some-other-thing")
    check = _build()

    assert ("ambient credential chain (AWS_PROFILE=some-other-thing)"
            in check.config_summary())


def test_the_account_line_names_it_too_where_a_role_is_assumed_from_it(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_PROFILE", "some-other-thing")
    check = _build()
    _stub(check)

    assert ("assumed role, from the ambient chain (AWS_PROFILE=some-other-thing)"
            in _child(check.run(), "live").config)


def test_a_configured_profile_says_nothing_about_the_environment(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The environment is only worth naming where it is what decides. A profile
    that was written down wins over it, and the card says the written one."""
    monkeypatch.setenv("AWS_PROFILE", "some-other-thing")
    check = _build(profile=PRIMARY)

    summary = check.config_summary()
    assert f"profile {PRIMARY}" in summary
    assert "AWS_PROFILE" not in summary


def test_without_the_variable_the_line_is_what_it_always_was(
        monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(variable, raising=False)

    assert "ambient credential chain\n" in _build().config_summary() + "\n"


def test_a_bad_per_account_profile_names_the_account() -> None:
    with pytest.raises(CheckError, match="'live'"):
        AwsCheck.from_config(
            _config(accounts=[{"name": "live", "profile": ""}]), Path("."))


# --- the login is the machine's, not the check's --------------------------
#
# What the machine's own bookkeeping does is `tests/test_identity.py`; what the
# *check* does with it is below. The fixture is in both files because the state
# is one process's, and either file run alone has to start from a machine nobody
# has logged into.

@pytest.fixture(autouse=True)
def _forget_logins() -> None:
    """Module state is the point (one browser per machine), so each test starts
    from a machine nobody has logged into yet."""
    identity_module.SSO_LOGINS.forget()


# --- the check renews, once, and reads the account on the retry -----------

def _sso(check: AwsCheck, problem: str = "") -> list[tuple[str, int]]:
    """Replace the one place a subprocess is started; record the attempts."""
    attempts: list[tuple[str, int]] = []

    def login(profile: str, timeout: int) -> str:
        attempts.append((profile, timeout))
        return problem

    check._sso_login = login            # type: ignore[method-assign]
    return attempts


def test_an_expired_login_is_renewed_and_the_account_read_on_the_retry() -> None:
    check = _build(profile=PRIMARY, sso={"login": "always"},
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(expire=1))
    attempts = _sso(check)
    live = _child(check.run(), "live")
    assert attempts == [(PRIMARY, 120)]
    assert live.code is StatusCode.OK
    assert [child.name for child in live.children] == [
        CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH]


def test_a_renewal_that_does_not_help_reddens_the_account_with_the_command() -> None:
    check = _build(profile=PRIMARY, sso={"login": "always"},
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(expire=9))
    _sso(check)
    live = _child(check.run(), "live")
    assert live.code is StatusCode.ERROR
    assert "AWS credentials have expired" in _texts(live)[0]
    assert f"`aws sso login --profile {PRIMARY}`" in _texts(live)[1]
    assert "still refused" in _texts(live)[1]


def test_a_login_that_cannot_run_here_is_the_second_line_of_the_node() -> None:
    check = _build(profile=PRIMARY, sso={"login": "never"},
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(expire=9))
    attempts = _sso(check)
    live = _child(check.run(), "live")
    assert attempts == []               # nothing shelled out
    assert _texts(live)[1] == (
        f"renew it with `aws sso login --profile {PRIMARY}` — "
        "automatic login is off (`sso: login: never`)")


def test_without_a_profile_nothing_advises_running_aws_sso_login() -> None:
    """Advice for a machine that is not this one is worse than none: the
    ambient chain on a server is not renewed by a browser."""
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(expire=9))
    attempts = _sso(check)
    live = _child(check.run(), "live")
    assert attempts == []
    assert "aws sso login" not in _texts(live)[1]
    assert "no profile is configured" in _texts(live)[1]


def test_a_refusal_is_reported_rather_than_renewed() -> None:
    """AccessDenied is AWS saying no; renewing a login would not change it."""
    check = _build(profile=PRIMARY, sso={"login": "always"},
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    attempts = _sso(check)
    live = _child(check.run(), "live")
    assert attempts == []
    assert _texts(live) == ["role cannot be assumed: An error occurred "
                            "(AccessDenied) when calling the AssumeRole "
                            "operation: not allowed"]


def test_a_profile_only_account_that_is_refused_is_not_a_role_problem() -> None:
    """There is no role here, so "role cannot be assumed" would name a thing
    this account does not have."""
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}])
    _stub(check, _FakeSts(deny_identity=True))
    live = _child(check.run(), "live")
    assert live.code is StatusCode.ERROR
    assert _texts(live)[0].startswith("account cannot be read:")


def test_two_stale_accounts_of_one_profile_share_one_login() -> None:
    """Both accounts fail on the same expired token in the same run; the first
    one's login fixed the second one too, and a second browser would only be
    there to find that out."""
    check = _build(profile=PRIMARY, sso={"login": "always"})
    _stub(check, _FakeSts(expire_roles={"arn:aws:iam::111:role/monitoring",
                                        "arn:aws:iam::222:role/monitoring"}))
    attempts = _sso(check)
    result = check.run()
    assert len(attempts) == 1
    assert [child.code for child in result.children] == [StatusCode.OK,
                                                         StatusCode.OK]


def test_auto_asks_the_machine_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """`always` is the escape hatch; `auto` is the default and it declines on a
    machine where a browser would open into nothing."""
    check = _build(profile=PRIMARY,
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    check._profile_config = lambda profile: {}      # type: ignore[method-assign]
    _stub(check, _FakeSts(expire=9))
    attempts = _sso(check)
    live = _child(check.run(), "live")
    assert attempts == []
    assert f"profile {PRIMARY} is not an SSO profile" in _texts(live)[1]


def test_auto_logs_in_on_a_machine_that_can(
        monkeypatch: pytest.MonkeyPatch) -> None:
    check = _build(profile=PRIMARY,
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    check._profile_config = lambda profile: {       # type: ignore[method-assign]
        "sso_session": "corp"}
    monkeypatch.setattr(identity_module.shutil, "which", lambda name: "/usr/bin/aws")
    monkeypatch.setattr(identity_module.sys, "platform", "darwin")
    monkeypatch.setattr(identity_module, "in_container", lambda: False)
    for marker in identity_module.CLOUD_MARKERS:
        monkeypatch.delenv(marker, raising=False)
    _stub(check, _FakeSts(expire=1))
    attempts = _sso(check)
    assert _child(check.run(), "live").code is StatusCode.OK
    assert attempts == [(PRIMARY, 120)]


# --- what the card says it would do ---------------------------------------

def test_the_card_says_the_login_it_would_run_and_how_often() -> None:
    check = _build(profile=PRIMARY, sso={"login": "always", "cooldown": "30m"})
    summary = check.config_summary()
    assert f"`aws sso login --profile {PRIMARY}` on expiry" in summary
    assert "at most once every 30m" in summary


def test_the_card_says_why_it_could_not_log_in_here() -> None:
    """"auto" on a card, with no word on whether auto can work here, would be
    the reassuring version of saying nothing."""
    check = _build(profile=PRIMARY)
    check._profile_config = lambda profile: {}      # type: ignore[method-assign]
    assert (f"not from here — profile {PRIMARY} is not an SSO profile"
            in check.config_summary())


def test_an_ambient_check_carries_no_sso_row_at_all() -> None:
    """Nothing to renew and nothing that would try: a row explaining a feature
    this check is not using would be on every card, once a minute, forever."""
    assert "sso login" not in _build().config_summary()


def test_a_per_account_profile_is_enough_to_get_the_sso_row() -> None:
    check = _build(accounts=[{"name": "live", "profile": SECONDARY}])
    check._profile_config = lambda profile: {}      # type: ignore[method-assign]
    assert f"not from here — profile {SECONDARY}" in check.config_summary()


# --- the sso block --------------------------------------------------------

def test_sso_defaults() -> None:
    settings = _build().sso
    assert settings.login == identity_module.SSO_LOGIN_AUTO
    assert settings.timeout_seconds == 120
    assert settings.cooldown_seconds == 600


def test_the_sso_block_is_read_in_the_units_the_rest_of_the_config_uses() -> None:
    settings = _build(sso={"login": "never", "timeout": "3m",
                           "cooldown": "1h"}).sso
    assert (settings.login, settings.timeout_seconds,
            settings.cooldown_seconds) == ("never", 180, 3600)


@pytest.mark.parametrize("block", [
    {"login": "sometimes"}, {"login": ""}, {"timeout": 0}, {"timeout": "-1m"},
    {"cooldown": "-1m"}, {"timeout": "soon"}, {"relogin": True}, "always",
])
def test_bad_sso_settings_are_refused(block: object) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(sso=block), Path("."))


# --- what the log says when an account could not be looked at --------------
#
# A check that ran and graded badly is *reporting*; a check that could not look
# at an account at all is a different event, and it used to make no sound. The
# engine's own line says the check completed — because it did — and the refusal
# lived only on a card somebody had to go and open. That is how a run whose two
# accounts were both refused read as `check /team/aws: OK` in a log file.


def _unreadable_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [message for message in
            (record.getMessage() for record in caplog.records
             if record.levelname == "ERROR")
            if "could not be read" in message]


def test_an_account_that_could_not_be_read_says_so_in_the_log(
        caplog: pytest.LogCaptureFixture) -> None:
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        check.run()
    lines = _unreadable_lines(caplog)
    assert len(lines) == 2, lines          # the account, then the run summary
    assert "account 'live'" in lines[0]
    assert "arn:aws:iam::111:role/monitoring" in lines[0]
    assert "AccessDenied" in lines[0]


def test_the_line_names_who_we_actually_were(
        caplog: pytest.LogCaptureFixture) -> None:
    """The fact no configuration can supply, and the one this whole thing is for.

    A check says which profile it *meant* to use; what the ambient chain resolved
    to on this machine is decided elsewhere, and being wrong about it is
    invisible — which is exactly how one estate's ambient identity came to be
    assuming another estate's role with nothing in the log saying so.
    """
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        check.run()
    assert "as 111, arn:aws:iam::111:user/fake" in _unreadable_lines(caplog)[0]


def test_the_line_names_the_credentials_the_account_was_read_with(
        caplog: pytest.LogCaptureFixture) -> None:
    check = _build(profile=PRIMARY,
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        check.run()
    assert f"profile {PRIMARY}" in _unreadable_lines(caplog)[0]


def test_without_a_profile_the_line_says_ambient(
        caplog: pytest.LogCaptureFixture) -> None:
    """`ambient credential chain` is the whole diagnosis when a role in another
    estate is being assumed from whatever this machine happened to be."""
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        check.run()
    assert "the ambient credential chain" in _unreadable_lines(caplog)[0]


def test_an_unprovable_identity_still_leaves_the_refusal(
        caplog: pytest.LogCaptureFixture) -> None:
    """A diagnostic that replaces the thing it explains is worse than none: if
    who-we-were cannot be proven, the line drops that clause and keeps the rest."""
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"},
                          deny_identity=True))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        check.run()
    line = _unreadable_lines(caplog)[0]
    assert "AccessDenied" in line
    assert " as " not in line


def test_the_summary_names_how_many_of_how_many(
        caplog: pytest.LogCaptureFixture) -> None:
    """`2 of 2` is the shape of a credential problem and `1 of 3` the shape of
    one account's policy — the count is the diagnosis, so it is on its own line."""
    check = _build(accounts=[
        {"name": "live", "role_arn": "arn:aws:iam::111:role/monitoring"},
        {"name": "backup", "role_arn": "arn:aws:iam::222:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring",
                                  "arn:aws:iam::222:role/monitoring"}))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        check.run()
    assert "2 of 2 account(s) could not be read: live, backup" in \
        _unreadable_lines(caplog)[-1]


def test_a_readable_run_logs_nothing_of_the_kind(
        caplog: pytest.LogCaptureFixture) -> None:
    """The boundary: a check that could look logs no failure here, whatever it
    then grades. An alarm in ALARM is a reading, not a check that could not run."""
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, alarms={"eu-central-1": [[_alarm("api-5xx")]]})
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        result = check.run()
    live = _child(result, "live")
    burning = [entry for child in live.children for entry in child.reason
               if entry.code is StatusCode.ERROR]
    assert burning, "the run has to grade something badly, or this proves nothing"
    assert _unreadable_lines(caplog) == []


def test_a_healthy_run_never_asks_who_it_is(
        caplog: pytest.LogCaptureFixture) -> None:
    """The identity proof is a call, so it is spent on the failure path only."""
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    sts = _FakeSts()
    _stub(check, sts)
    check.run()
    assert sts.identity_calls == 0


# --- the shared console address and the shared coverage line -----------------
#
# Six link builders and four coverage lines were six and four string templates
# that agreed by having been written the same way. These pin what the fold onto
# `_console_url` and `_scope_line` had to preserve exactly — the values are the
# ones the six builders produced before it, captured rather than re-derived.

CONSOLE = "https://eu-central-1.console.aws.amazon.com"
#: A space and a slash, because the two are escaped differently and the console's
#: own fragments carry a literal `/`.
AWKWARD = "a b/c"


@pytest.mark.parametrize("built,expected", [
    (lambda: aws_module._function_link("eu-central-1", AWKWARD),
     f"{CONSOLE}/lambda/home?region=eu-central-1#/functions/a%20b/c"),
    (lambda: aws_module._console_link(
        Alarm(name=AWKWARD, region="eu-central-1", state="ALARM",
              description="", composite=False)),
     f"{CONSOLE}/cloudwatch/home?region=eu-central-1#s=Alarms&alarm=a%20b/c"),
    (lambda: aws_module._instance_link("eu-central-1", AWKWARD),
     f"{CONSOLE}/ec2/home?region=eu-central-1#Instances:search=a%20b/c"),
    (lambda: aws_module._pipeline_link("eu-central-1", AWKWARD),
     f"{CONSOLE}/codesuite/codepipeline/pipelines/a%20b/c/executions"
     "?region=eu-central-1"),
    (lambda: aws_module._job_link("eu-central-1", AWKWARD),
     f"{CONSOLE}/batch/home?region=eu-central-1#jobs/detail/a%20b/c"),
    (lambda: aws_module._queue_link("eu-central-1"),
     f"{CONSOLE}/batch/home?region=eu-central-1#queues"),
])
def test_every_console_link_is_the_address_it_was(built: Any,
                                                  expected: str) -> None:
    assert built() == expected


def test_the_region_is_in_the_host_and_in_the_query() -> None:
    """Twice, which is what the console wants and what six copies each had to
    remember."""
    address = aws_module._console_url("eu-west-1", "batch/home", "queues")

    assert address == ("https://eu-west-1.console.aws.amazon.com/batch/home"
                       "?region=eu-west-1#queues")


def test_a_link_with_no_fragment_carries_no_hash() -> None:
    """CodePipeline's address is a path, so an empty fragment must not leave a
    trailing `#` on it."""
    assert aws_module._console_url("eu-west-1", "codesuite/x") == (
        "https://eu-west-1.console.aws.amazon.com/codesuite/x?region=eu-west-1")


@pytest.mark.parametrize("found,noun,text", [
    (0, "pipeline", "no pipelines in scope (eu-central-1, eu-west-1)"),
    (1, "pipeline", "1 pipeline in scope (eu-central-1, eu-west-1)"),
    (2, "job queue", "2 job queues in scope (eu-central-1, eu-west-1)"),
    (1, "job queue", "1 job queue in scope (eu-central-1, eu-west-1)"),
])
def test_the_coverage_line_counts_and_pluralizes(found: int, noun: str,
                                                 text: str) -> None:
    line = aws_module._scope_line(noun, found, ("eu-central-1", "eu-west-1"))

    assert line.text == text
    assert line.code is StatusCode.OK
    assert line.slug == "scope"


def test_the_coverage_line_grades_only_where_the_caller_says_so() -> None:
    """The wording is shared and the verdict is not: an empty CloudWatch is a
    warning because alarms going quiet is a symptom, where an account may
    legitimately run no EC2 at all."""
    quiet = aws_module._scope_line("alarm", 0, ("eu-central-1",),
                                   code=StatusCode.WARN)
    short = aws_module._scope_line("alarm", 2, ("eu-central-1",),
                                   code=StatusCode.WARN,
                                   tail=", expected at least 5")

    assert quiet.text == "no alarms in scope (eu-central-1)"
    assert quiet.code is StatusCode.WARN
    assert short.text == "2 alarms in scope (eu-central-1), expected at least 5"
    assert short.code is StatusCode.WARN
    # one entry, not two: "expected at least five" is not a finding of its own
    assert short.slug == "scope"
