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


def _config(**overrides: Any) -> dict[str, Any]:
    return {**BASE_CONFIG, **overrides}


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
    # Declared, not stamped (little-sister ADR-0025, 2026-08-19 update): the text
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
    leaf = _ec2(_build(), instances={"eu-central-1": [
        [_instance("prometheus")], [_instance("jenkins"), _instance("jenkins")]]})
    codes = {entry.text.split("[")[-1].split("]")[0]: entry.code
             for entry in leaf.reason if entry.slug != "scope"}
    assert codes == {"jenkins": StatusCode.WARN, "prometheus": StatusCode.OK}


def test_max_per_name_moves_the_line_between_ok_and_warn() -> None:
    instances = {"eu-central-1": [[_instance("jenkins"), _instance("jenkins")]]}
    assert _ec2(_build(), instances=instances).reason[0].code is StatusCode.WARN
    relaxed = _ec2(_build(ec2={"max_per_name": 2}), instances=instances)
    assert relaxed.reason[0].code is StatusCode.OK


def test_a_terminated_instance_is_not_counted() -> None:
    """It lingers in the API for about an hour; counting it would report a
    duplicate that no longer exists."""
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("prometheus"), _instance("prometheus", "terminated"),
        _instance("prometheus", "shutting-down")]]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 1")


def test_a_stopped_instance_is_counted() -> None:
    """A stopped box under a name that should be unique is exactly the leftover
    this aspect is looking for; `ignore_states` is how you disagree."""
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("prometheus"), _instance("prometheus", "stopped")]]})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text.endswith(": 2")


def test_ignore_states_is_configurable() -> None:
    leaf = _ec2(_build(ec2={"ignore_states": ["stopped"]}),
                instances={"eu-central-1": [[
                    _instance("prometheus"), _instance("prometheus", "stopped")]]})
    assert leaf.reason[0].text.endswith(": 1")


def test_instances_without_a_name_tag_become_one_line() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance(None), _instance(None), _instance("prometheus")]]})
    unnamed = [entry for entry in leaf.reason if NO_NAME_TAG in entry.text]
    assert len(unnamed) == 1
    assert unnamed[0].text == f"{NO_NAME_TAG}: 2"
    assert unnamed[0].code is StatusCode.WARN     # two of them, like any name
    assert "](" not in unnamed[0].text            # not a console search


def test_an_ignored_name_is_neither_listed_nor_counted() -> None:
    leaf = _ec2(_build(ec2={"ignore_name_patterns": ["spot-"]}),
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
    leaf = _ec2(_build(), instances={"eu-central-1": [[
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


@pytest.mark.parametrize("maximum", [0, -1, True, "two"])
def test_max_per_name_must_be_a_positive_integer(maximum: object) -> None:
    with pytest.raises(CheckError):
        AwsCheck.from_config(_config(ec2={"max_per_name": maximum}), Path("."))


def test_ec2_defaults() -> None:
    settings = _build().ec2
    assert settings.ignore_states == ("terminated", "shutting-down")
    assert settings.ignore_name_patterns == ()
    assert settings.max_per_name == 1


def test_an_instance_narrows_to_the_fields_the_aspect_uses() -> None:
    instance = Instance(instance_id="i-1", name="a", region="r", state="running")
    assert (instance.name, instance.state) == ("a", "running")


def test_the_ec2_state_match_is_case_insensitive() -> None:
    assert Ec2Config().ignored_state("Terminated")


# --- the ec2 aspect: age --------------------------------------------------

def test_the_age_of_the_oldest_instance_rides_on_every_line() -> None:
    """Including the healthy ones: it is the reading, not an exception report."""
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("prometheus", up=timedelta(days=12)),
        _instance("jenkins", up=timedelta(hours=5)),
        _instance("jenkins", up=timedelta(days=3))]]})
    lines = {entry.text.split("](")[0].lstrip("["): entry.text
             for entry in leaf.reason if entry.slug != "scope"}
    assert lines["jenkins"].endswith(": 2 (3d)")      # the oldest of the two
    assert lines["prometheus"].endswith(": 1 (12d)")


def test_an_instance_past_max_age_turns_the_line_red() -> None:
    """An instance is patched by being replaced, so age is a security reading —
    true of a single, perfectly tidy instance."""
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("prometheus", up=timedelta(days=15))]]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert leaf.reason[0].text.endswith(": 1 (15d)")


def test_just_under_two_weeks_is_still_ok() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("prometheus", up=timedelta(days=13, hours=23))]]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 1 (13d 23h)")


def test_max_age_is_configurable() -> None:
    instances = {"eu-central-1": [[_instance("prometheus", up=timedelta(days=3))]]}
    assert _ec2(_build(), instances=instances).reason[0].code is StatusCode.OK
    strict = _ec2(_build(ec2={"max_age": "2d"}), instances=instances)
    assert strict.reason[0].code is StatusCode.ERROR


def test_age_outranks_the_duplicate_warning() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[
        _instance("jenkins", up=timedelta(days=20)),
        _instance("jenkins", up=timedelta(hours=1))]]})
    assert leaf.reason[0].code is StatusCode.ERROR      # not the WARN of a count
    assert leaf.reason[0].text.endswith(": 2 (20d)")


def test_an_instance_without_a_launch_time_is_graded_by_count_alone() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[_instance("prometheus")]]})
    assert leaf.reason[0].code is StatusCode.OK
    assert leaf.reason[0].text.endswith(": 1")          # no age invented


# --- the ec2 aspect: fleets -----------------------------------------------

def test_a_young_fleet_warns_but_does_not_burn() -> None:
    """More than `fleet_size` under one name is deliberate — a load test, say —
    so it gets the short clock instead of the fortnight, and three hours is
    inside it."""
    leaf = _ec2(_build(), instances={"eu-central-1": [
        _fleet("loadtest-2026-08-09", 11, timedelta(hours=3))]})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text.endswith(": 11 (3h)")


def test_a_fleet_still_up_after_four_hours_turns_red() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [
        _fleet("loadtest-2026-08-09", 11, timedelta(hours=5))]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert leaf.reason[0].text.endswith(": 11 (5h)")


def test_the_fleet_clock_applies_only_above_fleet_size() -> None:
    """Ten instances five hours old are not a fleet by default, so they are
    judged by the fortnight and stay a WARN; eleven are."""
    ten = _ec2(_build(), instances={"eu-central-1": [
        _fleet("loadtest-2026-08-09", 10, timedelta(hours=5))]})
    assert ten.reason[0].code is StatusCode.WARN
    eleven = _ec2(_build(), instances={"eu-central-1": [
        _fleet("loadtest-2026-08-09", 11, timedelta(hours=5))]})
    assert eleven.reason[0].code is StatusCode.ERROR


def test_fleet_size_and_fleet_max_age_are_configurable() -> None:
    instances = {"eu-central-1": [
        _fleet("loadtest-2026-08-09", 4, timedelta(hours=2))]}
    assert _ec2(_build(), instances=instances).reason[0].code is StatusCode.WARN
    tuned = _ec2(_build(ec2={"fleet_size": 3, "fleet_max_age": "1h"}),
                 instances=instances)
    assert tuned.reason[0].code is StatusCode.ERROR


def test_the_oldest_member_decides_a_fleet_not_the_newest() -> None:
    rolling = _fleet("loadtest-2026-08-09", 10, timedelta(minutes=5))
    rolling.append(_instance("loadtest-2026-08-09", instance_id="i-old",
                             up=timedelta(hours=6)))
    leaf = _ec2(_build(), instances={"eu-central-1": [rolling]})
    assert leaf.reason[0].code is StatusCode.ERROR
    assert leaf.reason[0].text.endswith(": 11 (6h)")


def test_a_red_line_sorts_above_a_warning_one() -> None:
    leaf = _ec2(_build(), instances={"eu-central-1": [[
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
    summary = _build(ec2={"max_age": "14d", "fleet_max_age": "90m"},
                     **{"lambda": {"error_max_age": "36h"}}).config_summary()
    assert "**instance age before red:** 14d" in summary
    assert "red after 1h 30m" in summary
    assert "**lambda error graded within:** 1d 12h" in summary


def test_ec2_age_defaults_are_a_fortnight_and_four_hours() -> None:
    settings = _build().ec2
    assert settings.max_age_seconds == 14 * 86400
    assert settings.fleet_size == 10
    assert settings.fleet_max_age_seconds == 4 * 3600


@pytest.mark.parametrize("block", [
    {"max_age": "nonsense"}, {"fleet_max_age": "later"},
    {"fleet_size": 0}, {"fleet_size": True}, {"max_age": 0},
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
    leaf = _lambda(_build(**{"lambda": {"ignore": ["running-collector-lambda"]}}),
                   functions={"eu-central-1": [["running-collector-lambda",
                                                "running-collector-lambda-v2"]]})
    assert "[running-collector-lambda]" not in " ".join(_texts(leaf))
    assert "running-collector-lambda-v2" in " ".join(_texts(leaf))
    assert "1 function in scope" in _texts(leaf)[-1]


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
    settings = _build().lambda_
    assert settings.ignore == ()
    assert settings.error_max_age_seconds == 14 * 86400
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


def test_a_success_older_than_max_age_warns_and_says_so() -> None:
    """The original's `execution.start_time < Time.now - 31*24*60*60` rule."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
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


def test_max_age_is_configuration() -> None:
    leaf = _pipelines(_build(codepipeline={"max_age": "1d"}),
                      pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [
                          _execution(started=timedelta(days=2))]})
    assert _entry(leaf, "running-deploy").code is StatusCode.WARN


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
    leaf = _pipelines(_build(codepipeline={"ignore_name_patterns": ["SANDBOX"]}),
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


def test_codepipeline_defaults_are_the_originals() -> None:
    settings = _build().codepipeline
    assert settings.max_age_seconds == 31 * 86400
    assert settings.ignore_name_patterns == ()
    assert settings.code_for("Succeeded") is StatusCode.OK
    assert settings.code_for("InProgress") is StatusCode.WARN
    assert settings.code_for("Superseded") is StatusCode.ERROR


@pytest.mark.parametrize("block", [
    {"max_age": "soon"}, {"max_age": 0}, {"state_map": "ALARM"},
    {"ignore_name_patterns": "sandbox"}, {"shorten": "strip"},
    {"max_age_seconds": "1d"},
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
    check = _build(codepipeline={"enabled": False, "max_age": "1d"})
    assert check.codepipeline.enabled is False
    # …and the rest of the block still parsed, so `enabled` is a knob beside the
    # others rather than a mode that replaces them.
    assert check.codepipeline.max_age_seconds == 86400
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
