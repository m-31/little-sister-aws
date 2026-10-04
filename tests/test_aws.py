"""The ``aws`` check type: the session seam, the account tree, and every aspect.

No live AWS anywhere: every session is built through the check's own
``_new_session`` seam, replaced here. They were written to depend on nothing
outside the module while it was still incubating in a deployment, which is why the
move into this package changed two import lines and nothing else.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from little_sister.checks import CHECK_TYPES, CheckError, CheckResult, Measurement
from little_sister.reasons import RECORD_TIMESTAMP_KEYS
from little_sister.series import SeriesRecord
from little_sister.status import StatusCode, effective_code
from running import measured, run_check

from little_sister_aws import aws as aws_module
from little_sister_aws import identity as identity_module
from little_sister_aws.aws import (
    BATCH,
    CLOUDWATCH,
    CODEPIPELINE,
    CREDENTIALS_UNUSABLE,
    DEFAULT_ROLE_SESSION_NAME,
    EC2,
    LAMBDA,
    NEVER_RUN,
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


#: The field of a fixture's point each of a function's metrics answers from.
_METRIC_FIELDS = {"Errors": "errors", "Invocations": "invocations",
                  "Duration": "duration"}


class _FakeCloudwatch:
    """``get_metric_data`` the way CloudWatch answers it: the points of each query
    that lie in the window asked, newest first, the window's end excluded — and of
    each result whether it was answered, ``Complete``, or ``PartialData`` where a
    page cut its points.

    A function's fixture is one point — ``{"errors": 0, "age": …}`` — or its
    ``runs``, a list of them. A point answers ``Errors`` from its ``errors``,
    ``Invocations`` from its ``invocations`` and ``Duration`` from its ``duration``,
    and a metric it does not name has no data point there. It comes back only at a
    period at least as coarse as the one the fixture says the function has data at
    — which is what makes the 60 → 300 → 3600 fallback testable.

    A fixture's ``refused`` names a metric CloudWatch does not answer —
    ``{"Errors": "InternalError"}``, or the status with the messages sent beside
    it, ``("Forbidden", "…")``. That metric's result carries the status, the
    messages and no point, in a call that succeeds.

    With ``page`` set, an answer comes in pages of that many data points, each with
    a token for the next. CloudWatch ends a page by another count — what the page's
    part of the window could hold — and hands back a token the same way."""

    def __init__(self, paginator: _FakePaginator, metrics: dict[str, Any],
                 calls: list[list[dict[str, Any]]],
                 windows: list[tuple[datetime, datetime, str | None]],
                 page: int | None = None) -> None:
        self._paginator = paginator
        self._metrics = metrics
        self._calls = calls
        self._windows = windows
        self._page = page

    def get_paginator(self, name: str) -> _FakePaginator:
        assert name == "describe_alarms"
        return self._paginator

    def _points(self, query: dict[str, Any], start: datetime,
                end: datetime) -> list[tuple[datetime, float]]:
        stat = query["MetricStat"]
        fixture = self._metrics.get(stat["Metric"]["Dimensions"][0]["Value"])
        if fixture is None:
            return []
        field = _METRIC_FIELDS[stat["Metric"]["MetricName"]]
        points = [(NOW - point["age"], point[field])
                  for point in fixture.get("runs", [fixture])
                  if point.get(field) is not None
                  and stat["Period"] >= point.get("period",
                                                  fixture.get("period", 60))
                  and start <= NOW - point["age"] < end]
        return sorted(points, reverse=True)

    def _refused(self, query: dict[str, Any]) -> dict[str, Any] | None:
        """The result of a query CloudWatch does not answer, by its function's
        ``refused``, and nothing where it answers."""
        metric = query["MetricStat"]["Metric"]
        fixture = self._metrics.get(metric["Dimensions"][0]["Value"]) or {}
        refused = fixture.get("refused", {}).get(metric["MetricName"])
        if refused is None:
            return None
        status, *said = (refused,) if isinstance(refused, str) else refused
        return {"Id": query["Id"], "Timestamps": [], "Values": [],
                "StatusCode": status,
                "Messages": [{"Code": status, "Value": text} for text in said]}

    def get_metric_data(self, *, StartTime: datetime, EndTime: datetime,
                        MetricDataQueries: list[dict[str, Any]],
                        NextToken: str | None = None) -> dict[str, Any]:
        self._calls.append(MetricDataQueries)
        self._windows.append((StartTime, EndTime, NextToken))
        refused = {query["Id"]: refusal for query in MetricDataQueries
                   if (refusal := self._refused(query)) is not None}
        answered = [(query["Id"], self._points(query, StartTime, EndTime))
                    for query in MetricDataQueries if query["Id"] not in refused]
        if self._page is None:
            whole = {query_id: {"Id": query_id,
                                "Timestamps": [stamp for stamp, _ in points],
                                "Values": [value for _, value in points],
                                "StatusCode": "Complete"}
                     for query_id, points in answered}
            # In the order asked, as CloudWatch answers.
            return {"MetricDataResults": [
                refused.get(query["Id"]) or whole[query["Id"]]
                for query in MetricDataQueries]}
        flat = [(query_id, stamp, value) for query_id, points in answered
                for stamp, value in points]
        number = int(NextToken.removeprefix("page-")) if NextToken else 0
        on_page = flat[number * self._page:(number + 1) * self._page]
        # A result whose points go on behind the token says so.
        cut = {query_id for query_id, _, _ in flat[(number + 1) * self._page:]}
        results: dict[str, dict[str, Any]] = {}
        for query_id, stamp, value in on_page:
            result = results.setdefault(
                query_id, {"Id": query_id, "Timestamps": [], "Values": [],
                           "StatusCode": ("PartialData" if query_id in cut
                                          else "Complete")})
            result["Timestamps"].append(stamp)
            result["Values"].append(value)
        answer: dict[str, Any] = {"MetricDataResults": [
            *results.values(), *(refused.values() if number == 0 else ())]}
        if len(flat) > (number + 1) * self._page:
            answer["NextToken"] = f"page-{number + 1}"
        return answer


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
    no stream at all, which is what a never-invoked function looks like.

    A function in ``pages`` answers GetLogEvents the way CloudWatch Logs pages a
    stream: one page per call, newest first, each handing back the backward token
    the next call sends — and handing back the token it was sent where the stream
    ends. ``sent`` records each call's function and the token it sent."""

    def __init__(self, messages: dict[str, str | None], calls: list[str],
                 pages: dict[str, list[tuple[list[str], str]]] | None = None,
                 sent: list[tuple[str, str | None]] | None = None) -> None:
        self._messages = messages
        self._calls = calls
        self._pages = pages or {}
        self._sent = sent if sent is not None else []

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
                       limit: int, startFromHead: bool,
                       nextToken: str | None = None) -> dict[str, Any]:
        assert (limit, startFromHead) == (1, False)
        name = self._name(logGroupName)
        self._sent.append((name, nextToken))
        if name in self._pages:
            pages = self._pages[name]
            asked = sum(1 for called, _ in self._sent if called == name) - 1
            events, token = pages[min(asked, len(pages) - 1)]
            return {"events": [{"message": message} for message in events],
                    "nextBackwardToken": token, "nextForwardToken": f"f/{token}"}
        message = self._messages.get(name)
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
                 batch_unreadable: set[str] | None = None,
                 log_pages: dict[str, list[tuple[list[str], str]]] | None = None,
                 metric_page: int | None = None,
                 ) -> None:
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
        #: Each ``get_metric_data`` call's window and the token it sent, beside
        #: its queries in ``metric_calls``.
        self.metric_windows: list[tuple[datetime, datetime, str | None]] = []
        self.metric_page = metric_page
        self.log_calls: list[str] = []
        self.log_pages = log_pages or {}
        self.log_tokens: list[tuple[str, str | None]] = []
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
            return _FakeLogs(self.messages, self.log_calls, self.log_pages,
                             self.log_tokens)
        if region_name in self.unreadable:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no cloudwatch"}},
                "DescribeAlarms")
        paginator = _FakePaginator(self.alarms.get(region_name, []))
        self.paginators[region_name] = paginator
        return _FakeCloudwatch(paginator, self.metrics, self.metric_calls,
                               self.metric_windows, self.metric_page)


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
          batch_unreadable: set[str] | None = None,
          log_pages: dict[str, list[tuple[list[str], str]]] | None = None,
          metric_page: int | None = None,
          ) -> list[_FakeSession]:
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
                               batch_unreadable=batch_unreadable,
                               log_pages=log_pages, metric_page=metric_page)
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


def _aspect(check: AwsCheck, result: CheckResult, aspect: str,
            account: str = "live") -> CheckResult:
    """One account's aspect in *result*: beneath the account's node where *check*
    names several accounts, and beneath the check's own where it names one and the
    account has no node (ADR-0007 §2)."""
    return _child(_child(result, account) if len(check.accounts) > 1 else result,
                  aspect)


def _nodes(result: CheckResult) -> list[CheckResult]:
    """*result* and every node beneath it, depth first."""
    return [result, *(node for child in result.children for node in _nodes(child))]


def _node(leaf: CheckResult, name: str) -> CheckResult:
    """The one node called *name* beneath *leaf*, wherever it hangs."""
    found = [node for node in _nodes(leaf)[1:] if node.name == name]
    assert len(found) == 1, [node.name for node in _nodes(leaf)]
    return found[0]


def _function(leaf: CheckResult, name: str) -> CheckResult:
    """The node of one function, wherever beneath the `lambda` node it hangs."""
    return _node(leaf, name)


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
    run_check(check)
    assert built[0].credentials == {}


def test_a_secrets_block_resolves_static_keys(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_KEY", "AKIA-configured")
    monkeypatch.setenv("AWS_SECRET", "s3cret")
    check = _build(secrets={"access_key_id": "env://AWS_KEY",
                            "secret_access_key": "env://AWS_SECRET"})
    assert (check.access_key, check.secret_key) == ("AKIA-configured", "s3cret")
    built = _stub(check)
    run_check(check)
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
    run_check(check)
    assert sts.calls == [
        {"RoleArn": "arn:aws:iam::111:role/monitoring",
         "RoleSessionName": "little-sister"},
        {"RoleArn": "arn:aws:iam::222:role/monitoring",
         "RoleSessionName": "little-sister"},
    ]


def test_the_assumed_session_carries_that_account_s_credentials() -> None:
    check = _build()
    built = _stub(check)
    run_check(check)
    tokens = [session.credentials.get("aws_session_token") for session in built]
    assert tokens[1:] == ["TOK-arn:aws:iam::111:role/monitoring",
                          "TOK-arn:aws:iam::222:role/monitoring"]


def test_sts_is_reached_in_the_configured_region() -> None:
    check = _build(sts_region="us-east-1")
    built = _stub(check)
    run_check(check)
    assert ("sts", "us-east-1") in built[0].clients


def test_an_account_without_a_role_arn_is_not_assumed() -> None:
    check = _build(accounts=[{"name": "here"}])
    sts = _FakeSts()
    built = _stub(check, sts)
    run_check(check)
    assert sts.calls == []
    assert len(built) == 1          # the base session, and no second one


def test_no_credentials_at_all_is_one_error_line_and_no_children() -> None:
    check = _build()

    def refuse(**credentials: str) -> Any:
        raise NoCredentialsError()

    check._new_session = refuse         # type: ignore[method-assign]
    result = run_check(check)
    assert result.code is StatusCode.ERROR
    assert result.children == ()
    assert "no usable AWS credentials" in _texts(result)[0]


# --- the tree -------------------------------------------------------------

def test_the_root_carries_one_child_per_account_in_config_order() -> None:
    check = _build()
    _stub(check)
    result = run_check(check)
    assert [child.name for child in result.children] == ["live", "backup"]


def test_each_account_carries_one_child_per_aspect() -> None:
    check = _build()
    _stub(check)
    live = _child(run_check(check), "live")
    assert [child.name for child in live.children] == [
        CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH]
    assert AwsCheck.ASPECTS == (CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH)


def test_the_root_grades_nothing_and_says_only_what_is_watched() -> None:
    """An account that failed is red on its own node and reaches the container
    by roll-up; repeating it here would report one fact twice. So the root
    declares nothing of its own — `UNDEFINED`, a container that carries a
    sentence — and what it shows is what its accounts roll up to (ADR-0005 §6)."""
    check = _build()
    _stub(check, _FakeSts(refuse={"arn:aws:iam::222:role/monitoring"}))
    result = run_check(check)
    assert result.code is StatusCode.UNDEFINED
    assert _texts(result) == ["2 accounts, 2 account/region pairs in scope"]
    assert effective_code(result.stored_code,
                          [child.stored_code for child in result.children]
                          ) is StatusCode.ERROR


def test_the_scope_counts_each_account_s_own_regions() -> None:
    check = _build(regions=["eu-central-1", "us-east-1"])
    _stub(check)
    # live inherits two regions, backup overrides to one: three pairs, not four.
    assert _texts(run_check(check)) == ["2 accounts, 3 account/region pairs in scope"]


def test_an_unassumable_account_reddens_its_own_node_only() -> None:
    check = _build()
    _stub(check, _FakeSts(refuse={"arn:aws:iam::222:role/monitoring"}))
    result = run_check(check)
    backup = _child(result, "backup")
    assert backup.code is StatusCode.ERROR
    assert backup.children == ()
    assert "role cannot be assumed" in _texts(backup)[0]
    assert _child(result, "live").code is StatusCode.OK
    assert _child(_child(result, "live"), CLOUDWATCH).reason


def test_an_account_publishes_its_own_title_about_and_config() -> None:
    check = _build(accounts=[{"name": "live"},
                             {"name": "backup", "title": "Backup (Ireland)",
                              "about": "Off-site copies.",
                              "regions": ["eu-west-1"]}])
    _stub(check)
    backup = _child(run_check(check), "backup")
    assert backup.title == "Backup (Ireland)"
    assert backup.about == "Off-site copies."
    assert "eu-west-1" in backup.config


def test_the_root_report_is_the_configured_scope_not_the_reachable_one() -> None:
    """`report` is presence, never a status claim (little-sister ADR-0044)."""
    check = _build()
    _stub(check, _FakeSts(refuse={"arn:aws:iam::222:role/monitoring"}))
    assert run_check(check).report == ("- **live** — eu-central-1\n"
                                  "- **backup** — eu-west-1")


# --- the cloudwatch aspect ------------------------------------------------

def _cloudwatch(check: AwsCheck, **stub: Any) -> CheckResult:
    _stub(check, **stub)
    return _aspect(check, run_check(check), CLOUDWATCH)


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
    result = run_check(check)
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


def test_one_declaration_serves_every_account_s_aspect_of_that_name() -> None:
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
    accounts = [_child(run_check(check), name) for name in ("live", "backup")]
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
    for account in (_child(run_check(check), name) for name in ("live", "backup")):
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
    result = run_check(check)
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
    return _aspect(check, run_check(check), EC2)


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
        result = run_check(check)
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
        run_check(check)
        caplog.clear()
        run_check(check)
    assert "matched no name" not in caplog.text


def test_a_rule_that_starts_matching_is_said_once_too(
        caplog: pytest.LogCaptureFixture) -> None:
    check = _build(ec2={"rules": [
        {"name": "web", "prefixes": ["web-"], "max_per_name_warn": 0}]})
    _stub(check, instances={"eu-central-1": [[_instance("prometheus")]]})
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        run_check(check)
        caplog.clear()
        _stub(check, instances={"eu-central-1": [[_instance("web-1")]]})
        run_check(check)
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
    return _aspect(check, run_check(check), LAMBDA)


def _line(leaf: CheckResult, name: str) -> str:
    return str(_entry(leaf, name).text)


def _entry(leaf: CheckResult, name: str) -> Any:
    """The line that names *name*, on *leaf* or on a node beneath it — a function's
    line stands on the function's own node (ADR-0006 §9)."""
    lines = [entry for node in _nodes(leaf) for entry in node.reason_entries]
    for entry in lines:
        if f"[{name}]" in entry.text:
            return entry
    raise AssertionError(
        f"no line for {name!r} in {[entry.text for entry in lines]}")


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


def _paged_log_line(pages: list[tuple[list[str], str]]
                    ) -> tuple[str, list[str | None]]:
    """The function's line over a stream that answers page by page, and the token
    each GetLogEvents call sent, in order."""
    check = _one_account()
    built = _stub(check, functions=ONE_FUNCTION,
                  metrics={"running-collector-lambda":
                           {"errors": 0, "age": timedelta(minutes=1)}},
                  messages={"running-collector-lambda": None},
                  log_pages={"running-collector-lambda": pages})
    leaf = _aspect(check, run_check(check), LAMBDA)
    sent = [token for session in built for name, token in session.log_tokens
            if name == "running-collector-lambda"]
    return _line(leaf, "running-collector-lambda"), sent


def test_an_empty_page_of_a_log_stream_is_not_its_end() -> None:
    """GetLogEvents may answer an empty page while the stream still has events, so
    the read follows the backward token it was handed to the newest event."""
    line, sent = _paged_log_line([([], "b-1"), (["REPORT RequestId: 1"], "b-2")])
    assert line.endswith(" · log: REPORT")
    assert sent == [None, "b-1"]


def test_a_log_stream_ends_where_its_token_comes_back_unchanged() -> None:
    line, sent = _paged_log_line([([], "b-1"), ([], "b-1")])
    assert line.endswith(" · no log event")
    assert sent == [None, "b-1"]


def test_the_log_read_stops_after_three_more_empty_pages_and_says_so() -> None:
    """One page and at most three more, since the read is already two calls a
    function — and then the note says the newest event was not reached, not that
    there is none."""
    line, sent = _paged_log_line([([], f"b-{page}") for page in range(1, 10)])
    assert line.endswith(" · newest log event not reached in 4 pages")
    assert sent == [None, "b-1", "b-2", "b-3"]


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
    run_check(check)
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
    assert [node.name for node in leaf.children] == ["running-collector-lambda-v2"]
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
    run_check(check)
    calls = built[1].metric_calls          # the live account's session
    assert len(calls) == 1                 # one call, three queries
    assert len(calls[0]) == 3


def test_a_function_answering_at_one_minute_is_not_asked_again() -> None:
    check = _build()
    built = _stub(check, functions={"eu-central-1": [["fine", "coarse"]]},
                  metrics={"fine": {"errors": 0, "age": timedelta(minutes=1)},
                           "coarse": {"errors": 0, "age": timedelta(days=40),
                                      "period": 3600}})
    run_check(check)
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
    run_check(check)
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
    entry = _entry(leaf, "collector-rp")
    assert entry.slug == "eu-central-1-running-collector-reporter-lambda"
    assert "functions/running-collector-reporter-lambda" in entry.text


def test_shorten_rules_apply_in_order() -> None:
    check = _build(**{"lambda": {"shorten": [
        {"from": "load-", "to": "performance-"}, {"from": "performance-"}]}})
    leaf = _lambda(check, functions={"eu-central-1": [["load-runner"]]})
    assert "[runner]" in _function(leaf, "load-runner").reason[0].text


def test_a_name_shortened_to_nothing_still_has_a_label() -> None:
    check = _build(**{"lambda": {"shorten": [{"from": "gone"}]}})
    leaf = _lambda(check, functions={"eu-central-1": [["gone"]]})
    assert "[(unnamed)]" in _function(leaf, "gone").reason[0].text


def test_a_region_whose_functions_cannot_be_listed_is_its_own_warn_line() -> None:
    """Where the account reads one region, the region has no node, and the line
    stays `lambda`'s own (ADR-0006 §9) — above the scope line, which counts
    nothing."""
    leaf = _lambda(_build(), lambda_unreadable={"eu-central-1"})
    assert leaf.reason[0].code is StatusCode.WARN
    assert leaf.reason[0].text.startswith("eu-central-1: functions cannot be read")
    assert _texts(leaf)[-1] == "no functions in scope (eu-central-1)"
    assert leaf.children == ()


def test_the_functions_stand_in_name_order_and_the_worst_one_reddens_its_own_node(
        ) -> None:
    leaf = _lambda(_build(), functions={"eu-central-1": [["quiet", "loud"]]},
                   metrics={"quiet": {"errors": 0, "age": timedelta(minutes=1)},
                            "loud": {"errors": 9, "age": timedelta(minutes=1)}})
    assert [node.name for node in leaf.children] == ["loud", "quiet"]
    assert [node.stored_code for node in leaf.children] == [StatusCode.ERROR,
                                                            StatusCode.OK]
    # What is `lambda`'s own is its count, and that grades nothing.
    assert [entry.slug for entry in leaf.reason] == ["scope"]
    assert leaf.stored_code is StatusCode.OK


def test_the_lambda_report_lists_the_full_names() -> None:
    leaf = _lambda(_build(), functions={"eu-central-1": [["running-a", "b"]]},
                   metrics={"running-a": {"errors": 0, "age": timedelta(minutes=1)},
                            "b": {"errors": 0, "age": timedelta(minutes=1)}})
    assert leaf.report.splitlines() == [
        "- [b](https://eu-central-1.console.aws.amazon.com/lambda/home"
        "?region=eu-central-1#/functions/b)",
        "- [running-a](https://eu-central-1.console.aws.amazon.com/lambda/home"
        "?region=eu-central-1#/functions/running-a)"]


def test_the_lambda_aspect_declares_its_own_display_text() -> None:
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
    return _aspect(check, run_check(check), CODEPIPELINE)


def _execution(status: str = "Succeeded", *,
               started: timedelta | None = timedelta(hours=2),
               updated: timedelta | None = None,
               eid: str = "") -> dict[str, Any]:
    row: dict[str, Any] = {"status": status}
    if started is not None:
        row["startTime"] = NOW - started
    if updated is not None:
        row["lastUpdateTime"] = NOW - updated
    if eid:
        row["pipelineExecutionId"] = eid
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
    assert [node.name for node in leaf.children] == ["one", "two"]
    assert {entry.slug for node in _nodes(leaf) for entry in node.reason} == {
        "eu-central-1-one", "eu-central-1-two", "scope"}


def test_one_page_of_executions_is_enough_and_it_is_asked_for_by_size() -> None:
    check = _build()
    built = _stub(check, pipelines=ONE_PIPELINE,
                  executions={"running-deploy": [_execution()]})
    run_check(check)
    assert built[1].execution_calls == [("running-deploy", 100)]


def test_pipeline_names_can_be_ignored_case_insensitively() -> None:
    leaf = _pipelines(_build(codepipeline={"rules": [
        {"name": "sandboxes", "regexes": ["SANDBOX"], "ignore": True}]}),
                      pipelines={"eu-central-1": [["my-sandbox-deploy", "real"]]},
                      executions={"my-sandbox-deploy": [_execution("Failed")],
                                  "real": [_execution()]})
    # Out of the nodes *and* out of the count: an ignored pipeline is out of
    # scope, not a silent zero.
    assert [node.name for node in leaf.children] == ["real"]
    assert "sandbox" not in " ".join(
        text for node in _nodes(leaf) for text in _texts(node))
    assert leaf.reason[-1].text.startswith("1 pipeline in scope")


def test_the_pipeline_display_name_is_shortened_but_the_slug_is_not() -> None:
    check = _build(shorten=[{"from": "-pipeline"}, {"from": "running-"}])
    leaf = _pipelines(check, pipelines={"eu-central-1": [["running-deploy-pipeline"]]},
                      executions={"running-deploy-pipeline": [_execution()]})
    entry = _entry(leaf, "deploy")
    assert entry.slug == "eu-central-1-running-deploy-pipeline"


def test_the_pipeline_link_is_the_one_the_original_built() -> None:
    leaf = _pipelines(_build(), pipelines={"eu-central-1": [["a b"]]},
                      executions={"a b": [_execution()]})
    assert ("[a b](https://eu-central-1.console.aws.amazon.com/codesuite"
            "/codepipeline/pipelines/a%20b/executions?region=eu-central-1)"
            ) in _entry(leaf, "a b").text


def test_the_region_is_in_the_pipeline_slug_and_never_on_its_line() -> None:
    """The line stands on the pipeline's own node, beneath its region's where the
    account reads several, so the level says the region and the line does not
    (ADR-0007 §3) — and the slug keeps it, as ADR-0001 has it."""
    leaf = _pipelines(_build(), pipelines=ONE_PIPELINE,
                      executions={"running-deploy": [_execution()]})
    entry = _entry(leaf, "running-deploy")
    assert entry.slug == "eu-central-1-running-deploy"
    assert entry.text.startswith("[running-deploy](")

    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _pipelines(check, pipelines={"eu-west-1": [["deploy"]]},
                      executions={"deploy": [_execution()]})
    (line,) = _child(_child(leaf, "eu-west-1"), "deploy").reason
    assert line.text.startswith("[deploy](")
    assert line.slug == "eu-west-1-deploy"


def test_a_region_whose_pipelines_cannot_be_read_says_so_where_it_stands() -> None:
    """On `codepipeline` where the account reads one region, and on the region's
    own node where it reads several — a WARN either way, under the slug it had."""
    one = _pipelines(_one_account(), pipelines_unreadable={"eu-central-1"})
    assert [(entry.slug, entry.code) for entry in one.reason] == [
        ("read-eu-central-1", StatusCode.WARN), ("scope", StatusCode.OK)]
    assert one.reason[0].text.startswith("eu-central-1: pipelines cannot be read")

    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _pipelines(check, pipelines={"eu-central-1": [["survivor"]]},
                      executions={"survivor": [_execution()]},
                      pipelines_unreadable={"eu-west-1"})
    read, unread = leaf.children
    assert [node.name for node in read.children] == ["survivor"]
    assert (unread.name, unread.stored_code, unread.children) == (
        "eu-west-1", StatusCode.WARN, ())
    assert unread.reason[0].slug == "read-eu-west-1"
    assert unread.reason[0].text.startswith("eu-west-1: pipelines cannot be read")
    assert [entry.slug for entry in leaf.reason] == ["scope"]


def test_the_pipelines_stand_in_name_order_and_the_worst_reddens_its_own_node(
        ) -> None:
    leaf = _pipelines(_build(), pipelines={"eu-central-1": [["quiet", "loud"]]},
                      executions={"quiet": [_execution()],
                                  "loud": [_execution("Failed")]})
    assert [(node.name, node.stored_code) for node in leaf.children] == [
        ("loud", StatusCode.ERROR), ("quiet", StatusCode.OK)]
    assert [entry.slug for entry in leaf.reason] == ["scope"]


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


def test_the_codepipeline_aspect_declares_its_own_display_text() -> None:
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
    return _aspect(check, run_check(check), BATCH)


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
    lines = [entry for node in _nodes(leaf) for entry in node.reason
             if "etl" in entry.text]
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
    queue = _child(leaf, "nightly")
    assert [(node.name, [entry.slug for entry in node.reason])
            for node in queue.children] == [
        ("etl", ["eu-central-1-nightly-etl"]),
        ("report", ["eu-central-1-nightly-report"])]


def test_the_same_job_name_in_two_queues_stays_two_pins() -> None:
    leaf = _batch(_build(), queues={"eu-central-1": [[_queue("a"), _queue("b")]]},
                  jobs={("a", "SUCCEEDED"): [[_job("etl", job_id="j-a",
                                                   created=timedelta(hours=1))]],
                        ("b", "SUCCEEDED"): [[_job("etl", job_id="j-b",
                                                   created=timedelta(hours=1))]]})
    assert [(queue.name, [(node.name, node.reason[0].slug)
                          for node in queue.children])
            for queue in leaf.children] == [
        ("a", [("etl", "eu-central-1-a-etl")]),
        ("b", [("etl", "eu-central-1-b-etl")])]


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
    """Its job names stand beneath it; a line of its own would say nothing."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=1))]]})
    queue = _child(leaf, "nightly")
    assert (queue.stored_code, _texts(queue)) == (StatusCode.OK, [])
    assert [entry.slug for node in _nodes(leaf) for entry in node.reason] == [
        "scope", "eu-central-1-nightly-etl"]


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
    assert _texts(_child(leaf, "nightly")) == []


def test_job_names_can_be_ignored_case_insensitively() -> None:
    leaf = _batch(_build(batch={"ignore_name_patterns": ["SMOKE"]}),
                  queues=ONE_QUEUE, jobs={
                      ("nightly", "FAILED"): [[_job("smoke-test", "FAILED",
                                                    created=timedelta(hours=1))]],
                      ("nightly", "SUCCEEDED"): [[_job("etl",
                                                       created=timedelta(hours=1))]]})
    assert [node.name for node in _child(leaf, "nightly").children] == ["etl"]
    assert "smoke" not in " ".join(
        text for node in _nodes(leaf) for text in _texts(node))
    assert _entry(leaf, "etl").code is StatusCode.OK


def test_a_queue_can_be_ignored_whole() -> None:
    leaf = _batch(_build(batch={"ignore_queue_patterns": ["scratch"]}),
                  queues={"eu-central-1": [[_queue("scratch-q"), _queue("real")]]})
    assert [node.name for node in leaf.children] == ["real"]
    assert leaf.reason[-1].text == "1 job queue in scope (eu-central-1)"


def test_all_four_job_statuses_are_read() -> None:
    """Three were the original's; RUNNABLE is the one it never asked for."""
    check = _build()
    built = _stub(check, queues=ONE_QUEUE)
    run_check(check)
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
    """An ARN carries the account number, and ADR-0001 keeps that out of a line
    somebody may bookmark or paste into a ticket."""
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id="j-abc",
                                         created=timedelta(hours=1))]]})
    assert ("[etl](https://eu-central-1.console.aws.amazon.com/batch/home"
            "?region=eu-central-1#jobs/detail/j-abc)"
            ) in _entry(leaf, "etl").text


def test_a_region_whose_queues_cannot_be_read_says_so_where_it_stands() -> None:
    """On `batch` where the account reads one region, and on the region's own node
    where it reads several — a WARN either way, under the slug it had."""
    one = _batch(_one_account(), batch_unreadable={"eu-central-1"})
    assert [(entry.slug, entry.code) for entry in one.reason] == [
        ("read-eu-central-1", StatusCode.WARN), ("scope", StatusCode.OK)]
    assert one.reason[0].text.startswith("eu-central-1: job queues cannot be read")

    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/m",
                              "regions": ["eu-central-1", "eu-west-1"]}])
    leaf = _batch(check, queues={"eu-central-1": [[_queue("survivor")]]},
                  batch_unreadable={"eu-west-1"})
    read, unread = leaf.children
    assert [node.name for node in read.children] == ["survivor"]
    assert (unread.name, unread.stored_code, unread.children) == (
        "eu-west-1", StatusCode.WARN, ())
    assert unread.reason[0].slug == "read-eu-west-1"
    assert unread.reason[0].text.startswith("eu-west-1: job queues cannot be read")
    assert [entry.slug for entry in leaf.reason] == ["scope"]


def test_an_account_with_no_job_queues_reads_ok() -> None:
    leaf = _batch(_build())
    assert leaf.reason[-1].code is StatusCode.OK
    assert leaf.reason[-1].text == "no job queues in scope (eu-central-1)"


def test_the_job_names_stand_in_name_order_and_the_worst_reddens_its_own_node(
        ) -> None:
    leaf = _batch(_build(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("quiet", created=timedelta(hours=1))]],
        ("nightly", "FAILED"): [[_job("loud", "FAILED",
                                      created=timedelta(hours=1))]]})
    assert [(node.name, node.stored_code)
            for node in _child(leaf, "nightly").children] == [
        ("loud", StatusCode.ERROR), ("quiet", StatusCode.OK)]
    assert [entry.slug for entry in leaf.reason] == ["scope"]


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


def test_the_batch_aspect_declares_its_own_display_text() -> None:
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
    return [child.name for child in _child(run_check(check), "live").children]


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
    run_check(check)
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
    live = _child(run_check(check), "live")
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
    run_check(check)
    assert _profiles(built) == ["", "", ""]      # base + two assumed sessions
    assert check.profile == ""


def test_the_check_s_profile_is_the_session_the_roles_are_assumed_from() -> None:
    check = _build(profile=PRIMARY)
    built = _stub(check)
    run_check(check)
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
    run_check(check)
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
    run_check(check)
    second_session = built[1]
    assert second_session.credentials == {"profile_name": SECONDARY}
    assert ("sts", "eu-central-1") in second_session.clients


def test_a_profile_only_account_is_read_through_the_profile_itself() -> None:
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}])
    sts = _FakeSts()
    built = _stub(check, sts)
    result = run_check(check)
    assert sts.calls == []                       # nothing to assume
    assert _profiles(built) == [PRIMARY]          # one session, and it is the profile's
    # Read: the one account's aspects hang beneath the check's own node.
    assert [child.name for child in result.children] == list(AwsCheck.ASPECTS)


def test_a_profile_only_account_proves_its_credentials_before_the_aspects() -> None:
    """Nothing else in the run would notice an expired login until an aspect
    tried, and then all three would report it in their own words."""
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}])
    built = _stub(check)
    run_check(check)
    assert built[0].sts.identity_calls == 1


def test_an_ambient_account_spends_no_extra_sts_call() -> None:
    """The preflight is the price of a profile, not of every check."""
    check = _build(accounts=[{"name": "live"}])
    built = _stub(check)
    run_check(check)
    assert built[0].sts.identity_calls == 0


def test_the_account_card_names_the_profile_and_the_role_together() -> None:
    check = _build(profile=PRIMARY)
    _stub(check)
    live = _child(run_check(check), "live")
    assert f"assumed role, from profile {PRIMARY}" in live.config


def test_the_account_card_of_a_profile_only_account_names_the_profile() -> None:
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}, {"name": "other"}])
    _stub(check)
    assert f"profile {PRIMARY}" in _child(run_check(check), "live").config


def test_config_summary_names_the_profile_and_its_overrides() -> None:
    check = _build(profile=PRIMARY, accounts=[
        {"name": "live", "role_arn": "arn:aws:iam::111:role/monitoring"},
        {"name": "other", "profile": SECONDARY}])
    summary = check.config_summary()
    assert f"profile {PRIMARY}" in summary and SECONDARY in summary


def test_config_summary_names_per_account_profiles_without_a_default() -> None:
    check = _build(accounts=[{"name": "live", "profile": SECONDARY},
                             {"name": "other"}])
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
            in _child(run_check(check), "live").config)


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
#
# Most of the checks below name one account, which has no node of its own: what
# refused it is said on the check's node, and its aspects hang there once it is
# read (ADR-0007 §2).

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
    node = run_check(check)
    assert attempts == [(PRIMARY, 120)]
    assert node.code is StatusCode.UNDEFINED
    assert [child.name for child in node.children] == [
        CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH]


def test_a_renewal_that_does_not_help_reddens_the_account_with_the_command() -> None:
    check = _build(profile=PRIMARY, sso={"login": "always"},
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(expire=9))
    _sso(check)
    node = run_check(check)
    assert node.code is StatusCode.ERROR
    assert "AWS credentials have expired" in _texts(node)[0]
    assert f"`aws sso login --profile {PRIMARY}`" in _texts(node)[1]
    assert "still refused" in _texts(node)[1]


def test_a_login_that_cannot_run_here_is_the_second_line_of_the_node() -> None:
    check = _build(profile=PRIMARY, sso={"login": "never"},
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(expire=9))
    attempts = _sso(check)
    node = run_check(check)
    assert attempts == []               # nothing shelled out
    assert _texts(node)[1] == (
        f"renew it with `aws sso login --profile {PRIMARY}` — "
        "automatic login is off (`sso: login: never`)")


def test_without_a_profile_nothing_advises_running_aws_sso_login() -> None:
    """Advice for a machine that is not this one is worse than none: the
    ambient chain on a server is not renewed by a browser."""
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(expire=9))
    attempts = _sso(check)
    node = run_check(check)
    assert attempts == []
    assert "aws sso login" not in _texts(node)[1]
    assert "no profile is configured" in _texts(node)[1]


def test_a_refusal_is_reported_rather_than_renewed() -> None:
    """AccessDenied is AWS saying no; renewing a login would not change it."""
    check = _build(profile=PRIMARY, sso={"login": "always"},
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    attempts = _sso(check)
    node = run_check(check)
    assert attempts == []
    assert _texts(node) == ["role cannot be assumed: An error occurred "
                            "(AccessDenied) when calling the AssumeRole "
                            "operation: not allowed"]


def test_a_profile_only_account_that_is_refused_is_not_a_role_problem() -> None:
    """There is no role here, so "role cannot be assumed" would name a thing
    this account does not have."""
    check = _build(profile=PRIMARY, accounts=[{"name": "live"}])
    _stub(check, _FakeSts(deny_identity=True))
    node = run_check(check)
    assert node.code is StatusCode.ERROR
    assert _texts(node)[0].startswith("account cannot be read:")


def test_two_stale_accounts_of_one_profile_share_one_login() -> None:
    """Both accounts fail on the same expired token in the same run; the first
    one's login fixed the second one too, and a second browser would only be
    there to find that out."""
    check = _build(profile=PRIMARY, sso={"login": "always"})
    _stub(check, _FakeSts(expire_roles={"arn:aws:iam::111:role/monitoring",
                                        "arn:aws:iam::222:role/monitoring"}))
    attempts = _sso(check)
    result = run_check(check)
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
    node = run_check(check)
    assert attempts == []
    assert f"profile {PRIMARY} is not an SSO profile" in _texts(node)[1]


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
    assert run_check(check).children       # read, on the retry
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
        run_check(check)
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
        run_check(check)
    assert "as 111, arn:aws:iam::111:user/fake" in _unreadable_lines(caplog)[0]


def test_the_line_names_the_credentials_the_account_was_read_with(
        caplog: pytest.LogCaptureFixture) -> None:
    check = _build(profile=PRIMARY,
                   accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        run_check(check)
    assert f"profile {PRIMARY}" in _unreadable_lines(caplog)[0]


def test_without_a_profile_the_line_says_ambient(
        caplog: pytest.LogCaptureFixture) -> None:
    """`ambient credential chain` is the whole diagnosis when a role in another
    estate is being assumed from whatever this machine happened to be."""
    check = _build(accounts=[{"name": "live",
                              "role_arn": "arn:aws:iam::111:role/monitoring"}])
    _stub(check, _FakeSts(refuse={"arn:aws:iam::111:role/monitoring"}))
    with caplog.at_level(logging.ERROR, logger="little_sister_aws.aws"):
        run_check(check)
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
        run_check(check)
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
        run_check(check)
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
        result = run_check(check)
    burning = [entry for child in result.children for entry in child.reason
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
    run_check(check)
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


# --- the two halves: what a run reads, and what keeps a history -------------
#
# little-sister ADR-0086 split a check into `measure()` and `grade()`, and this
# package's ADR-0005 says what that asks of this vocabulary. Each test below is one
# sentence of that record, with values that make the sentence false if the code is
# wrong.

ROLE_LIVE = "arn:aws:iam::111:role/monitoring"
ROLE_BACKUP = "arn:aws:iam::222:role/monitoring"

#: What one account answers in every aspect, for the tests about readings rather
#: than about one leaf.
EVERY_ASPECT: dict[str, Any] = {
    "alarms": {"eu-central-1": [[_alarm("api-latency"), _alarm("db-cpu", "OK"),
                                 _alarm("TargetTracking-x", "ALARM")]]},
    "instances": {"eu-central-1": [
        [_instance("web", instance_id="i-1", up=timedelta(hours=3))],
        [_instance("pair", instance_id="i-2", up=timedelta(hours=1)),
         _instance("pair", instance_id="i-3", up=timedelta(hours=2))],
        [_instance("gone", "terminated", instance_id="i-4")]]},
    "functions": {"eu-central-1": [["collector"]]},
    "metrics": {"collector": {"errors": 0, "age": timedelta(minutes=5)}},
    "messages": {"collector": "REPORT RequestId: 1"},
    "pipelines": {"eu-central-1": [["deploy", "idle"]]},
    "executions": {"deploy": [_execution(started=timedelta(hours=1), eid="e-1")]},
    "queues": {"eu-central-1": [[_queue("nightly"), _queue("dormant")]]},
    "jobs": {("nightly", "SUCCEEDED"): [[_job("etl", job_id="j-2",
                                              created=timedelta(hours=2),
                                              stopped=timedelta(hours=1))]],
             ("nightly", "FAILED"): [[_job("etl", "FAILED", job_id="j-1",
                                           created=timedelta(hours=5),
                                           stopped=timedelta(hours=4))]]},
}


def _one_account(**overrides: Any) -> AwsCheck:
    return _build(accounts=[{"name": "live", "role_arn": ROLE_LIVE}], **overrides)


def _readings(check: AwsCheck, sts: _FakeSts | None = None,
              **stub: Any) -> tuple[Measurement, ...]:
    _stub(check, sts, **stub)
    return measured(check)


def _kind(readings: tuple[Measurement, ...], kind: str) -> list[Measurement]:
    return [reading for reading in readings if reading.record["kind"] == kind]


def test_the_grading_reads_nothing_but_the_readings() -> None:
    """Graded again by a check that cannot reach AWS at all, over readings this
    one took, the tree is the one the run itself wrote (little-sister ADR-0086
    decision 6)."""
    check = _build()
    _stub(check, **EVERY_ASPECT)
    taken = measured(check)
    first = run_check(check, measurements=taken)
    blind = _build()

    def unreachable(**credentials: str) -> Any:
        raise AssertionError("the grading asked AWS for something")

    blind._new_session = unreachable     # type: ignore[method-assign]
    assert run_check(blind, measurements=taken) == first


def test_every_age_is_measured_to_the_instant_the_grading_is_handed() -> None:
    check = _build()
    _stub(check, **EVERY_ASPECT)
    taken = measured(check)
    later = run_check(check, measurements=taken, now=NOW + timedelta(days=2))
    assert _line(_child(_child(later, "live"), EC2), "web").endswith(": 1 (2d 3h)")


def test_the_estate_comes_first_then_each_account_then_the_aspects() -> None:
    readings = _readings(_build(), **EVERY_ASPECT)
    assert [reading.record["kind"] for reading in readings[:3]] == [
        "estate", "account", "account"]
    assert [reading.record["account"] for reading in readings[1:3]] == [
        "live", "backup"]
    assert {reading.record["kind"] for reading in readings[3:]} == {
        "alarm", "instance", "function", "pipeline", "queue", "job"}


def test_every_reading_names_its_aspect_its_kind_its_account_and_region() -> None:
    readings = _readings(_build(), **EVERY_ASPECT)
    assert {(reading.record["aspect"], reading.record["kind"])
            for reading in readings} == {
        (None, "estate"), (None, "account"), (CLOUDWATCH, "alarm"),
        (EC2, "instance"), (LAMBDA, "function"), (CODEPIPELINE, "pipeline"),
        (BATCH, "queue"), (BATCH, "job")}
    for reading in readings[1:]:
        assert reading.record["account"] in {"live", "backup"}
    for reading in readings[3:]:
        assert reading.record["region"] == "eu-central-1"


def test_only_a_run_a_pipeline_and_the_estate_have_a_history() -> None:
    """ADR-0005 §3: `series_keep` is one number per check, so every other
    reading is read and graded and kept no longer than its node."""
    readings = _readings(_build(), **EVERY_ASPECT)
    kept = {"estate", "pipeline", "job"}
    assert {reading.record["kind"] for reading in readings if reading.subject} == kept
    assert all(reading.subject for reading in readings
               if reading.record["kind"] in kept)


def test_a_subject_names_the_account_by_its_configured_name() -> None:
    readings = _readings(_build(), **EVERY_ASPECT)
    assert readings[0].subject == "accounts/backup/live"
    assert {reading.subject for reading in _kind(readings, "pipeline")} == {
        "codepipeline/live/eu-central-1/deploy",
        "codepipeline/live/eu-central-1/idle"}
    assert {reading.subject for reading in _kind(readings, "job")} == {
        "batch/live/eu-central-1/nightly/etl"}


def test_the_estate_is_declared_at_construction_its_names_sorted() -> None:
    """So a run that raises is still recorded against it, and reordering the
    configuration does not start a new history."""
    forward = _build(accounts=[{"name": "live"}, {"name": "backup"}])
    backward = _build(accounts=[{"name": "backup"}, {"name": "live"}])
    assert forward.subject == backward.subject == "accounts/backup/live"


def test_every_time_a_record_keeps_is_under_a_name_the_library_reads_as_one() -> None:
    """The node's page can show a record's time in the configured zone only under a
    name little-sister reads as an instant — `at`, `started` or `ended`, at any
    depth — so every time a reading keeps is under one, and each kind that keeps a
    time says which."""
    readings = _readings(_build(), **EVERY_ASPECT)
    kept: dict[str, set[str]] = {}

    def walk(kind: str, value: object, path: str) -> None:
        if isinstance(value, dict):
            for key, below in value.items():
                walk(kind, below, f"{path}.{key}" if path else str(key))
        elif isinstance(value, str):
            try:
                moment = datetime.fromisoformat(value)
            except ValueError:
                return
            if moment.tzinfo is not None:
                kept.setdefault(kind, set()).add(path)

    for reading in readings:
        walk(str(reading.record["kind"]), dict(reading.record), "")
    assert all(path.rsplit(".", 1)[-1] in RECORD_TIMESTAMP_KEYS
               for paths in kept.values() for path in paths), kept
    assert kept == {"instance": {"started"}, "function": {"at"},
                    "pipeline": {"started", "at"},
                    "job": {"created.at", "ended", "at"}}


def test_a_subject_past_what_one_may_hold_is_its_kind_and_a_digest() -> None:
    queue, job = "q" * 128, "j" * 128
    readings = _readings(_one_account(),
                         queues={"eu-central-1": [[_queue(queue)]]},
                         jobs={(queue, "SUCCEEDED"): [[_job(job, job_id="j-1")]],
                               (queue, "FAILED"): [[_job("short", job_id="j-2")]]})
    long_one, short_one = _kind(readings, "job")
    assert long_one.subject.startswith("batch/sha256:")
    assert len(long_one.subject) == len("batch/sha256:") + 32
    assert short_one.subject == f"batch/live/eu-central-1/{queue}/short"


def test_the_parts_of_a_subject_split_back_on_the_slash() -> None:
    """`/` is the one character an account name — a node segment — must not hold,
    and AWS refuses it in regions, queue, job and pipeline names."""
    readings = _readings(_build(accounts=[{"name": "a:b;c=d",
                                           "role_arn": ROLE_LIVE}]),
                         **EVERY_ASPECT)
    (run,) = {reading.subject for reading in _kind(readings, "job")}
    assert run.split("/") == ["batch", "a:b;c=d", "eu-central-1", "nightly", "etl"]


def test_several_runs_of_one_name_in_one_poll_are_several_records() -> None:
    readings = _readings(_one_account(), **EVERY_ASPECT)
    runs = _kind(readings, "job")
    assert [run.identity for run in runs] == ["j-2", "j-1"]
    assert len({run.subject for run in runs}) == 1


def test_a_run_seen_waiting_and_then_finished_is_one_record() -> None:
    """Its identity is the `jobId`, which does not change as the run moves on, and
    its own time is when it finished — nothing while it has not."""
    waiting = _readings(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNABLE"): [[_job("etl", "RUNNABLE", job_id="j-9",
                                        created=timedelta(minutes=5))]]})
    finished = _readings(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id="j-9",
                                         created=timedelta(minutes=5),
                                         started=timedelta(minutes=4),
                                         stopped=timedelta(minutes=1))]]})
    (before,) = _kind(waiting, "job")
    (after,) = _kind(finished, "job")
    assert (before.subject, before.identity) == (after.subject, after.identity)
    assert before.record["at"] is None
    assert datetime.fromisoformat(after.record["at"]) == NOW - timedelta(minutes=1)


def test_a_pipeline_names_the_execution_it_last_ran() -> None:
    executions = [_execution(started=timedelta(hours=5), eid="e-old"),
                  _execution("InProgress", started=timedelta(minutes=3),
                             eid="e-new")]
    readings = _readings(_one_account(), pipelines=ONE_PIPELINE,
                         executions={"running-deploy": executions})
    (running,) = _kind(readings, "pipeline")
    done = _readings(_one_account(), pipelines=ONE_PIPELINE, executions={
        "running-deploy": [_execution(started=timedelta(minutes=3),
                                      eid="e-new")]})
    (finished,) = _kind(done, "pipeline")
    assert (running.identity, running.state) == ("e-new", "")
    assert (finished.subject, finished.identity) == (running.subject, "e-new")
    assert datetime.fromisoformat(running.record["at"]) == NOW - timedelta(minutes=3)


def test_a_pipeline_that_has_never_run_names_that_state() -> None:
    readings = _readings(_one_account(), pipelines=ONE_PIPELINE, executions={})
    (pipeline,) = _kind(readings, "pipeline")
    assert (pipeline.identity, pipeline.state) == ("", NEVER_RUN)
    assert pipeline.record["at"] is None


def test_the_estate_names_each_account_s_outcome_sorted_by_name() -> None:
    check = _build(accounts=[{"name": "live", "role_arn": ROLE_LIVE},
                             {"name": "backup", "role_arn": ROLE_BACKUP}])
    readings = _readings(check, _FakeSts(refuse={ROLE_BACKUP}))
    assert readings[0].state == "backup=unreachable/live=read"
    assert readings[0].record["accounts"] == [
        {"name": "live", "outcome": "read"},
        {"name": "backup", "outcome": "unreachable"}]


def test_the_estate_s_state_is_never_spelled_from_the_error_text() -> None:
    """Two expired logins whose second lines differ are one state; the text is
    in the account's own reading, where the node is written from."""
    quiet = _one_account(profile=PRIMARY, sso={"login": "never"})
    tried = _one_account(profile=PRIMARY, sso={"login": "always"})
    _sso(tried)
    one = _readings(quiet, _FakeSts(expire=9))
    two = _readings(tried, _FakeSts(expire=9))
    assert one[0].state == two[0].state == "live=expired"
    renewals = {_kind(readings, "account")[0].record["renewal"]
                for readings in (one, two)}
    assert len(renewals) == 2
    assert "expired" not in json.dumps(dict(one[0].record["accounts"][0])
                                       ).replace('"expired"', "")


def test_a_name_holding_an_equals_sign_still_spells_apart() -> None:
    """The outcome after a pair's last `=` is from a fixed vocabulary, so the
    spelling splits back into its pairs whatever a name holds."""
    check = _build(accounts=[{"name": "a=read"}, {"name": "b;c"}])
    readings = _readings(check)
    pairs = [pair.rpartition("=") for pair in readings[0].state.split("/")]
    assert [(name, outcome) for name, _, outcome in pairs] == [
        ("a=read", "read"), ("b;c", "read")]


def test_an_estate_spelled_past_what_a_state_may_hold_is_a_digest() -> None:
    check = _build(accounts=[{"name": f"account-number-{n:02d}"}
                             for n in range(20)])
    state = _readings(check)[0].state
    assert state.startswith("sha256:")
    assert len(state) == len("sha256:") + 32


def test_without_credentials_the_estate_is_the_only_reading() -> None:
    check = _build()

    def refuse(**credentials: str) -> Any:
        raise NoCredentialsError()

    check._new_session = refuse         # type: ignore[method-assign]
    (estate,) = measured(check)
    assert estate.state == CREDENTIALS_UNUSABLE
    assert estate.subject == "accounts/backup/live"
    assert estate.record["credentials"] == "Unable to locate credentials"
    assert estate.record["accounts"] == []


def test_an_account_s_failure_text_lives_in_its_own_reading() -> None:
    readings = _readings(_build(), _FakeSts(refuse={ROLE_BACKUP}))
    (backup,) = [reading for reading in _kind(readings, "account")
                 if reading.record["account"] == "backup"]
    assert backup.record["outcome"] == "unreachable"
    assert "AccessDenied" in backup.record["error"]
    assert "AccessDenied" not in json.dumps(dict(readings[0].record))


def test_what_spares_no_request_is_read_and_left_to_the_grading() -> None:
    """ADR-0005 §2: an ignore list that saves no call only chooses what is said —
    the ignored alarm and the terminated box are readings."""
    check = _one_account()
    readings = _readings(check, **EVERY_ASPECT)
    assert "TargetTracking-x" in {reading.record["name"]
                                  for reading in _kind(readings, "alarm")}
    assert "terminated" in {reading.record["state"]
                            for reading in _kind(readings, "instance")}
    result = run_check(check, measurements=readings)
    assert not any("TargetTracking" in text
                   for text in _texts(_child(result, CLOUDWATCH)))


def test_what_spares_a_request_is_decided_while_reading() -> None:
    """A lambda rule's `ignore` spares the metric and the log read, a queue's
    ignore pattern its job listings: neither is read, so neither is a reading."""
    check = _one_account(**{"lambda": {"rules": [
        {"name": "old", "prefixes": ["old-"], "ignore": True}]}},
        batch={"ignore_queue_patterns": ["dormant"]})
    built = _stub(check, **{**EVERY_ASPECT,
                            "functions": {"eu-central-1": [["old-one", "new-one"]]},
                            "messages": {"old-one": "REPORT", "new-one": "REPORT"}})
    readings = measured(check)
    assert [reading.record["name"]
            for reading in _kind(readings, "function")] == ["new-one"]
    assert not any("old-one" in call for session in built
                   for call in session.log_calls)
    assert [reading.record["name"]
            for reading in _kind(readings, "queue")] == ["nightly"]
    assert not any(queue == "dormant" for session in built
                   for queue, _ in session.job_calls)


def test_a_line_one_reading_made_carries_it_and_one_many_made_carries_none() -> None:
    """ADR-0005 §7, line by line."""
    check = _build()
    _stub(check, **EVERY_ASPECT)
    taken = measured(check)
    live = _child(run_check(check, measurements=taken), "live")

    def reading(kind: str, name: str) -> Measurement:
        (found,) = [one for one in _kind(taken, kind)
                    if one.record.get("name") == name
                    and one.record.get("account") == "live"]
        return found

    alarm = _entry(_child(live, CLOUDWATCH), "api-latency")
    assert (alarm.data, alarm.subject) == (
        dict(reading("alarm", "api-latency").record), "")
    assert _entry(_child(live, EC2), "web").data["id"] == "i-1"
    assert _entry(_child(live, EC2), "pair").data is None
    for leaf in live.children:
        (scope,) = [entry for entry in leaf.reason if entry.slug == "scope"]
        assert (scope.data, scope.subject) == (None, "")
    deploy = _entry(_child(live, CODEPIPELINE), "deploy")
    assert (deploy.data, deploy.subject) == (
        dict(reading("pipeline", "deploy").record),
        "codepipeline/live/eu-central-1/deploy")
    dormant = _entry(_child(live, BATCH), "dormant")
    assert dormant.data == dict(reading("queue", "dormant").record)
    etl = _entry(_child(live, BATCH), "etl")
    assert (etl.data, etl.subject) == (None, "batch/live/eu-central-1/nightly/etl")


def test_a_region_that_could_not_be_read_carries_its_reading() -> None:
    check = _one_account()
    _stub(check, unreadable={"eu-central-1"})
    taken = measured(check)
    (unreadable,) = [reading for reading in _kind(taken, "unreadable")
                     if reading.record["aspect"] == CLOUDWATCH]
    leaf = _aspect(check, run_check(check, measurements=taken), CLOUDWATCH)
    (line,) = [entry for entry in leaf.reason if entry.slug == "read-eu-central-1"]
    assert line.data == dict(unreadable.record)
    assert unreadable.record["error"].endswith("no cloudwatch")


def test_free_text_is_clipped_once_and_the_line_says_what_the_record_keeps() -> None:
    check = _one_account()
    _stub(check, alarms={"eu-central-1": [[_alarm("api", description="x" * 1000)]]})
    taken = measured(check)
    (alarm,) = _kind(taken, "alarm")
    assert alarm.record["description"] == "x" * 300
    leaf = _aspect(check, run_check(check, measurements=taken), CLOUDWATCH)
    assert _entry(leaf, "api").text.endswith(" — " + "x" * 300)


class _Wordy(_FakeSts):
    """STS answering with the longest message an answer could carry — a refusal,
    or with ``expire`` an expired token."""

    def assume_role(self, *, RoleArn: str, RoleSessionName: str) -> dict[str, Any]:
        code = "ExpiredToken" if self.expire else "AccessDenied"
        raise ClientError({"Error": {"Code": code, "Message": EMOJI * 2000}},
                          "AssumeRole")


#: One character that JSON writes as twelve bytes — the worst any free text can do.
EMOJI = "\U0001f600"


def test_the_heaviest_reading_of_each_kind_fits_the_default_record_limit(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Every free-text field at its bound, in the alphabet JSON escapes the most:
    the seam weighs a record as `json.dumps` writes it, against 2048 bytes."""
    assert len(EMOJI) == 1

    def unreadable_log(self: Any, **query: Any) -> dict[str, Any]:
        raise ClientError({"Error": {"Code": "AccessDenied",
                                     "Message": EMOJI * 2000}}, "DescribeLogStreams")

    monkeypatch.setattr(_FakeLogs, "describe_log_streams", unreadable_log)
    heavy = {
        "alarms": {"eu-central-1": [[_alarm(EMOJI * 255, description=EMOJI * 1024,
                                            composite=True)]]},
        "instances": {"eu-central-1": [[_instance(
            EMOJI * 256, instance_id="i-" + "f" * 17, up=timedelta(days=3))]]},
        "functions": {"eu-central-1": [["f" * 64]]},
        "metrics": {"f" * 64: {"errors": 999_999, "age": timedelta(minutes=1),
                               "invocations": 999_999, "duration": 900_000.0}},
        "pipelines": {"eu-central-1": [["p" * 100]]},
        "executions": {"p" * 100: [_execution("InProgress",
                                              eid="00000000-0000-4000-8000-000000000000")]},
        "queues": {"eu-central-1": [[_queue("q" * 128, reason=EMOJI * 1024)]]},
        "jobs": {("q" * 128, "FAILED"): [[{
            **_job("j" * 128, "FAILED", job_id="00000000-0000-4000-8000-000000000000",
                   created=timedelta(hours=2), started=timedelta(hours=2),
                   stopped=timedelta(hours=1)),
            "statusReason": EMOJI * 1024}]]},
    }
    readings = _readings(_build(series_keep=1, accounts=[
        {"name": "live", "role_arn": ROLE_LIVE}]), **heavy)
    refused = _readings(_one_account(profile=PRIMARY, sso={"login": "never"}),
                        _Wordy())
    lapsed = _one_account(profile=PRIMARY, sso={"login": "always"})
    _sso(lapsed, EMOJI * 2000)
    expired = _readings(lapsed, _Wordy(expire=9))
    weights: dict[str, int] = {}
    for reading in (*readings, *refused, *expired):
        kind = reading.record["kind"]
        weights[kind] = max(weights.get(kind, 0),
                            len(json.dumps(dict(reading.record))))
    assert _kind(expired, "account")[0].record["outcome"] == "expired"
    assert _kind(readings, "function")[0].record["log_error"]
    assert set(weights) == {"estate", "account", "alarm", "instance", "function",
                            "run", "pipeline", "queue", "job"}
    assert max(weights.values()) <= 2048, weights
    # A run's record is small, so the heaviest of the others stays the heaviest
    # (ADR-0006).
    assert weights["run"] < 300 < weights["alarm"], weights


def test_a_log_that_cannot_be_read_says_what_aws_answered(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The reading keeps what AWS answered; the sentence around it is the line's."""
    def refuse(self: Any, **query: Any) -> dict[str, Any]:
        raise ClientError({"Error": {"Code": "AccessDenied",
                                     "Message": "no logs"}}, "DescribeLogStreams")

    monkeypatch.setattr(_FakeLogs, "describe_log_streams", refuse)
    check = _one_account()
    _stub(check, functions=ONE_FUNCTION,
          metrics={"running-collector-lambda": {"errors": 0,
                                                "age": timedelta(minutes=5)}})
    taken = measured(check)
    (function,) = _kind(taken, "function")
    said = ("An error occurred (AccessDenied) when calling the "
            "DescribeLogStreams operation: no logs")
    assert function.record["log_error"] == said
    assert function.record["log_status"] is None
    leaf = _aspect(check, run_check(check, measurements=taken), LAMBDA)
    assert _entry(leaf, "running-collector-lambda").text.endswith(
        f" · log unreadable: {said}")


def test_readings_no_measurement_of_ours_produced_grade_to_an_error() -> None:
    """Only the engine's own failure record has no estate, and the engine grades
    that run itself; anything else handed over is refused rather than read."""
    result = run_check(_build(), measurements=())
    assert result.code is StatusCode.ERROR
    assert _texts(result) == ["no estate reading to grade — nothing was read"]


def test_an_identifier_past_its_bound_is_a_digest_of_itself() -> None:
    """A clipped identifier could meet another one; a digest cannot."""
    long_id = "j" * 150
    readings = _readings(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id=long_id),
                                    _job("etl", job_id=long_id + "x")]]})
    first, second = _kind(readings, "job")
    assert first.identity.startswith("sha256:") and len(first.identity) == 39
    assert first.identity != second.identity
    assert first.record["id"] == first.identity


def test_an_identifier_with_a_control_character_is_a_digest_of_itself() -> None:
    """An identifier that would not travel is a digest as well — never an answer
    the library refuses."""
    odd = "j-1" + chr(7)
    assert len(odd) == 4
    readings = _readings(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id=odd)]]})
    (run,) = _kind(readings, "job")
    assert run.identity.startswith("sha256:") and len(run.identity) == 39
    assert run.record["id"] == run.identity


def test_a_control_character_in_an_account_name_is_digested_not_refused() -> None:
    """A configuration that loaded before this conversion still loads: a subject
    that would not travel is its kind and a digest, never a refusal."""
    check = _build(accounts=[{"name": "live\u0007"}])
    assert check.subject.startswith("accounts/sha256:")
    assert _readings(check)[0].state.startswith("sha256:")


# --- a function's runs (ADR-0006) -----------------------------------------------
#
# Each test below is one sentence of ADR-0006, with values that make the sentence
# false if the code is wrong. What a check keeps of a function is bound here and no
# engine runs: a type's own test stands in the engine's place (little-sister
# ADR-0113 decision 4).

#: The one function most of these tests read, as a subject spells it.
COLLECTOR = "lambda/live/eu-central-1/collector"
ONE_COLLECTOR = {"eu-central-1": [["collector"]]}


def _point(age: timedelta, errors: int = 0, invocations: int = 1,
           duration: float = 100.0) -> dict[str, Any]:
    """One one-minute bucket of a function's fixture, by how long ago it began."""
    return {"age": age, "errors": errors, "invocations": invocations,
            "duration": duration}


def _stamp(age: timedelta) -> str:
    """An instant as a record keeps it — the way the seam writes one."""
    return (NOW - age).isoformat().replace("+00:00", "Z")


def _keeping(check: AwsCheck,
             kept: Mapping[str, Sequence[timedelta | tuple[timedelta, timedelta]]]
             | None = None) -> list[str]:
    """Bind what *check* finds kept — each subject's runs, by their ages, each
    read just now or, given as a pair, that long ago — and answer the list every
    subject it asks for lands in."""
    held = kept or {}
    asked: list[str] = []

    def reader(subject: str) -> tuple[SeriesRecord, ...]:
        asked.append(subject)
        runs = [run if isinstance(run, tuple) else (run, timedelta(0))
                for run in held.get(subject, ())]
        return tuple(SeriesRecord({"at": _stamp(age)}, NOW - read, _stamp(age))
                     for age, read in sorted(runs, reverse=True))

    check.bind_kept(reader)
    return asked


def _poll(check: AwsCheck, built: list[_FakeSession]
          ) -> tuple[tuple[Measurement, ...], list[dict[str, Any]]]:
    """One poll of *check*: what it read, and every ``get_metric_data`` call it
    made — the metrics and statistics it asked, at which period, of which
    functions, over which window, and the token it sent."""
    before = len(built)
    readings = measured(check)
    calls = []
    for session in built[before:]:
        for queries, (start, end, token) in zip(session.metric_calls,
                                                session.metric_windows,
                                                strict=True):
            stats = [query["MetricStat"] for query in queries]
            calls.append({
                "asked": {(stat["Metric"]["MetricName"], stat["Stat"],
                           stat["Period"]) for stat in stats},
                "functions": list(dict.fromkeys(
                    stat["Metric"]["Dimensions"][0]["Value"] for stat in stats)),
                "queries": len(queries), "span": end - start, "end": end,
                "token": token})
    return readings, calls


def _at(readings: tuple[Measurement, ...]) -> list[str]:
    """The buckets the runs among *readings* are of, in the order they were read."""
    return [str(run.record["at"]) for run in _kind(readings, "run")]


ERRORS = {("Errors", "Sum", 60)}
IN_FULL = {("Invocations", "Sum", 60), ("Duration", "Maximum", 60)}
HOUR, DAY, FIFTEEN_DAYS = timedelta(hours=1), timedelta(days=1), timedelta(days=15)


def test_every_minute_a_function_was_invoked_in_is_one_run() -> None:
    """ADR-0006 §1 and §2: a run is a one-minute bucket and a record of its own —
    its invocations, its errors, and `duration_ms`, the slowest invocation of the
    minute as a whole number of milliseconds."""
    check = _one_account(series_keep=30)
    _keeping(check)
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(minutes=3), duration=120.4),
                 _point(timedelta(minutes=2), errors=2, invocations=3,
                        duration=1234.6)]}})
    shared = {"aspect": LAMBDA, "kind": "run", "account": "live",
              "region": "eu-central-1", "name": "collector"}
    assert [dict(run.record) for run in _kind(readings, "run")] == [
        {**shared, "at": "2026-08-10T11:57:00Z", "invocations": 1, "errors": 0,
         "duration_ms": 120},
        {**shared, "at": "2026-08-10T11:58:00Z", "invocations": 3, "errors": 2,
         "duration_ms": 1235}]


def test_a_run_names_its_function_and_the_start_of_its_bucket() -> None:
    """§1: the subject is the function, spelled as ADR-0005 §4 spells one, and the
    event is the bucket's start as the record keeps it — so a bucket read again is
    the record it was."""
    check = _one_account(series_keep=30)
    _keeping(check)
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(minutes=3)), _point(timedelta(minutes=2))]}})
    first, _ = _poll(check, built)
    again, _ = _poll(check, built)
    runs = _kind(first, "run")
    assert [(run.subject, run.identity) for run in runs] == [
        (COLLECTOR, "2026-08-10T11:57:00Z"), (COLLECTOR, "2026-08-10T11:58:00Z")]
    assert all(run.identity == run.record["at"] and not run.state for run in runs)
    assert [(run.subject, run.identity) for run in _kind(again, "run")] == [
        (run.subject, run.identity) for run in runs]


def test_the_function_s_reading_stays_what_it_is_and_names_no_subject() -> None:
    """§2: asked on every poll and written as it always was — the newest bucket's
    errors and its time, and the log's status word — with no history of its own,
    and its runs behind it."""
    check = _one_account(series_keep=30)
    _keeping(check)
    readings = _readings(
        check, functions={"eu-central-1": [["collector", "idle"]]},
        metrics={"collector": {"runs": [_point(timedelta(minutes=3)),
                                        _point(timedelta(minutes=2), errors=2)]}},
        messages={"collector": "REPORT RequestId: 1"})
    function = _kind(readings, "function")[0]
    assert dict(function.record) == {
        "aspect": LAMBDA, "kind": "function", "account": "live",
        "region": "eu-central-1", "name": "collector", "errors": 2,
        "at": "2026-08-10T11:58:00Z", "log_status": "REPORT", "log_note": None,
        "log_error": None}
    assert (function.subject, function.identity, function.state) == ("", "", "")
    assert [(reading.record["kind"], reading.record["name"])
            for reading in readings if reading.record["aspect"] == LAMBDA] == [
        ("function", "collector"), ("run", "collector"), ("run", "collector"),
        ("function", "idle")]


def test_with_a_series_kept_a_function_s_runs_are_a_fourth_history() -> None:
    """§1 amends ADR-0005 §3: beside a Batch job's runs, a pipeline's executions
    and the estate, a function's runs name a subject — and its own reading still
    names none."""
    check = _one_account(series_keep=30)
    _keeping(check)
    readings = _readings(check, **{**EVERY_ASPECT, "metrics": {"collector": {
        "runs": [_point(timedelta(minutes=5))]}}})
    assert {reading.record["kind"] for reading in readings if reading.subject} == {
        "estate", "pipeline", "job", "run"}
    assert {run.subject for run in _kind(readings, "run")} == {COLLECTOR}


def test_where_a_check_keeps_no_series_no_history_is_asked_for() -> None:
    """§3: the aspect reads what it always read — one call, the fifteen days — and
    not even what was kept."""
    check = _one_account()
    asked = _keeping(check, {COLLECTOR: [timedelta(hours=2)]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(hours=2)), _point(timedelta(minutes=2))]}})
    readings, calls = _poll(check, built)
    assert _kind(readings, "run") == []
    assert asked == []
    assert [(call["asked"], call["span"], call["end"]) for call in calls] == [
        (ERRORS, FIFTEEN_DAYS, NOW)]


@pytest.mark.parametrize(("oldest", "window"), [
    (timedelta(minutes=59), HOUR),
    (timedelta(hours=1), HOUR),
    (timedelta(hours=1, minutes=1), DAY),
    (timedelta(days=1), DAY),
    (timedelta(days=1, minutes=1), FIFTEEN_DAYS),
    (timedelta(days=40), FIFTEEN_DAYS),
])
def test_a_function_is_asked_in_the_smallest_window_that_reaches_its_kept_runs(
        oldest: timedelta, window: timedelta) -> None:
    """§3: the last hour, the last day or the fifteen days — the smallest of the
    three that reaches the oldest run of a series that is full."""
    check = _one_account(series_keep=2)
    _keeping(check, {COLLECTOR: [oldest, timedelta(minutes=30)]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(minutes=30))]}})
    _, calls = _poll(check, built)
    assert (calls[0]["asked"], calls[0]["span"], calls[0]["end"]) == (
        ERRORS, window, NOW)


def test_a_function_whose_kept_runs_do_not_fill_the_series_is_asked_the_fifteen_days(
        ) -> None:
    """§3: two runs of three, both inside the last hour — and the hour is not
    enough, because the series has room for a run the hour does not hold."""
    check = _one_account(series_keep=3)
    _keeping(check, {COLLECTOR: [timedelta(minutes=30), timedelta(minutes=20)]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(minutes=20))]}})
    _, calls = _poll(check, built)
    assert calls[0]["span"] == FIFTEEN_DAYS


def test_a_region_s_functions_are_asked_in_one_call_for_each_window() -> None:
    """§3: one call has one window, so at most three first calls — and a second
    call holds the functions of one window and asks from the oldest bucket it is to
    read, not from where that window began."""
    check = _one_account(series_keep=1)
    subject = "lambda/live/eu-central-1/"
    _keeping(check, {subject + "busy": [timedelta(minutes=10)],
                     subject + "hourly": [timedelta(hours=5)],
                     subject + "daily": [timedelta(days=3)]})
    built = _stub(
        check, functions={"eu-central-1": [["busy", "daily", "fresh", "hourly"]]},
        metrics={"busy": _point(timedelta(minutes=10)),
                 "hourly": _point(timedelta(hours=5)),
                 "daily": _point(timedelta(days=3)),
                 "fresh": _point(timedelta(days=2))})
    readings, calls = _poll(check, built)
    first = [(HOUR, ["busy"]), (DAY, ["hourly"]), (FIFTEEN_DAYS, ["daily", "fresh"])]
    second = [(timedelta(minutes=10), ["busy"]), (timedelta(hours=5), ["hourly"]),
              (timedelta(days=3), ["daily", "fresh"])]
    assert [(call["asked"], call["span"], call["functions"]) for call in calls] == [
        *((ERRORS, span, names) for span, names in first),
        *((IN_FULL, span, names) for span, names in second)]
    # Every function of a call is read from there: the oldest bucket decides.
    assert [(run.record["name"], run.record["invocations"])
            for run in _kind(readings, "run")] == [
        ("busy", 1), ("daily", 1), ("fresh", 1), ("hourly", 1)]


def test_a_window_ends_where_the_period_the_poll_falls_in_began(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """So that its newest bucket is a whole one, at every period: half past seven
    minutes past the hour, the minute's window ends at seven past, the
    five-minute one at five past and the hourly one on the hour."""
    monkeypatch.setattr(aws_module, "_utcnow",
                        lambda: NOW + timedelta(minutes=7, seconds=30))
    check = _one_account()
    built = _stub(check, functions=ONE_COLLECTOR)
    _, calls = _poll(check, built)
    assert [call["end"] - NOW for call in calls] == [
        timedelta(minutes=7), timedelta(minutes=5), timedelta(0)]
    assert [call["span"] for call in calls] == [
        FIFTEEN_DAYS, timedelta(days=63), timedelta(days=455)]


def test_a_second_call_holds_half_as_many_functions_as_a_first() -> None:
    """Two queries a function against the five hundred a call takes."""
    names = [f"fn-{n:03d}" for n in range(251)]
    check = _one_account(series_keep=1)
    _keeping(check)
    built = _stub(check, functions={"eu-central-1": [names]},
                  metrics={name: _point(timedelta(minutes=2)) for name in names})
    readings, calls = _poll(check, built)
    assert [(call["asked"], call["queries"]) for call in calls] == [
        (ERRORS, 251), (IN_FULL, 500), (IN_FULL, 2)]
    assert len(_kind(readings, "run")) == 251


def test_a_poll_reads_in_full_the_buckets_its_history_lacks() -> None:
    """§3: a bucket the kept runs lack is read in full, and one they hold — once
    it is older than the overlap — is not."""
    hours = [timedelta(hours=n) for n in (5, 4, 3, 2)]
    check = _one_account(series_keep=5)
    _keeping(check, {COLLECTOR: hours[:3]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age) for age in hours]}})
    _poll(check, built)                 # the first poll after a start is its own
    readings, _ = _poll(check, built)
    assert _at(readings) == [_stamp(timedelta(hours=2))]


def test_a_bucket_is_read_again_while_it_is_younger_than_an_hour() -> None:
    """§4: its numbers may still grow, so a bucket younger than an hour is read in
    full on every poll although it is kept — and one a poll has read an hour old
    no longer."""
    ages = [timedelta(minutes=n) for n in (61, 60, 59)]
    check = _one_account(series_keep=5)
    _keeping(check, {COLLECTOR: ages})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age) for age in ages]}})
    _poll(check, built)
    readings, _ = _poll(check, built)
    assert _at(readings) == [_stamp(timedelta(minutes=59))]


@pytest.mark.parametrize(("age", "read", "again"), [
    # Last read two minutes after it began, an hour ago: a poll every hour, or a
    # login that expired in between.
    (timedelta(minutes=62), timedelta(minutes=60), True),
    (timedelta(hours=5), timedelta(hours=4, minutes=1), True),
    # Last read an hour after it began, to the minute: that read was the last.
    (timedelta(hours=5), timedelta(hours=4), False),
    (timedelta(minutes=62), timedelta(minutes=1), False),
])
def test_what_counts_is_how_old_a_bucket_was_when_it_was_last_read(
        age: timedelta, read: timedelta, again: bool) -> None:
    """§4: a bucket is read again until a poll has read it an hour old — by what
    its kept run says, and not by how old it is now. A poll that comes an hour
    after the last one still reads again what that one saw young, where a rule by
    the bucket's age would have kept its first numbers until the process started
    anew."""
    check = _one_account(series_keep=5)
    _keeping(check, {COLLECTOR: [(age, read)]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age, errors=1, invocations=2)]}})
    _poll(check, built)                 # the first poll after a start is its own
    readings, _ = _poll(check, built)
    assert [(run.record["at"], run.record["invocations"], run.record["errors"])
            for run in _kind(readings, "run")] == (
        [(_stamp(age), 2, 1)] if again else [])


def test_a_poll_reads_no_bucket_its_series_would_not_keep() -> None:
    """§3: of the buckets its kept runs lack, the newest and as many as the series
    keeps — an older one would leave the series the moment it was kept."""
    hours = [timedelta(hours=n) for n in (5, 4, 3, 2)]
    check = _one_account(series_keep=2)
    _keeping(check)
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age) for age in hours]}})
    assert _at(readings) == [_stamp(timedelta(hours=3)), _stamp(timedelta(hours=2))]


def test_a_function_with_nothing_new_costs_the_one_metric_it_always_cost() -> None:
    """§2: `Invocations` and `Duration` are asked only of a function that has a
    run to read. This one's series is full of its two newest buckets, and the two
    older ones CloudWatch still answers are no reason to ask: they would leave the
    series at once."""
    hours = [timedelta(hours=n) for n in (5, 4, 3, 2)]
    check = _one_account(series_keep=2)
    _keeping(check, {COLLECTOR: hours[2:]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age) for age in hours]}})
    _poll(check, built)
    readings, calls = _poll(check, built)
    assert _at(readings) == []
    assert [(call["asked"], call["queries"]) for call in calls] == [(ERRORS, 1)]


def test_a_run_is_read_in_full_by_a_second_call_of_the_functions_that_have_one(
        ) -> None:
    """§2 and §5: the second call asks `Invocations` and the `Maximum` of
    `Duration`, at the one-minute period, of the function that ran and of no
    other."""
    old = [timedelta(hours=3), timedelta(hours=2)]
    check = _one_account(series_keep=2)
    _keeping(check, {"lambda/live/eu-central-1/idle": old})
    built = _stub(check, functions={"eu-central-1": [["idle", "ran"]]},
                  metrics={"idle": {"runs": [_point(age) for age in old]},
                           "ran": {"runs": [_point(timedelta(hours=2))]}})
    _poll(check, built)
    readings, calls = _poll(check, built)
    assert [(call["asked"], call["functions"]) for call in calls] == [
        (ERRORS, ["idle"]), (ERRORS, ["ran"]), (IN_FULL, ["ran"])]
    assert {run.record["name"] for run in _kind(readings, "run")} == {"ran"}


def test_the_first_poll_after_a_start_reads_again_what_the_series_keeps() -> None:
    """§3: every bucket its first call answered, the newest and as many as the
    series keeps — which repairs one whose numbers grew after its hour — and the
    next poll is back to what its history lacks."""
    hours = [timedelta(hours=n) for n in (5, 4, 3, 2)]
    check = _one_account(series_keep=2)
    _keeping(check, {COLLECTOR: hours[2:]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age) for age in hours]}})
    first, _ = _poll(check, built)
    second, _ = _poll(check, built)
    assert _at(first) == [_stamp(timedelta(hours=3)), _stamp(timedelta(hours=2))]
    assert _at(second) == []


def test_a_region_that_could_not_be_read_has_its_first_poll_still_to_come() -> None:
    """The repair is a region's first poll that read it: one that failed read no
    bucket, so the next one reads them again."""
    hours = [timedelta(hours=3), timedelta(hours=2)]
    check = _one_account(series_keep=2)
    _keeping(check, {COLLECTOR: hours})
    built = _stub(check, lambda_unreadable={"eu-central-1"})
    failed, _ = _poll(check, built)
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age) for age in hours]}})
    readings, _ = _poll(check, built)
    assert [reading.record["kind"] for reading in failed
            if reading.record["aspect"] == LAMBDA] == ["unreadable"]
    assert _at(readings) == [_stamp(age) for age in hours]


def test_the_first_poll_after_a_start_is_each_region_s_own() -> None:
    """One region read and one not: the second poll is the unread region's first,
    and reads again what its series keeps, while the region that was read is back
    to what its history lacks."""
    hours = [timedelta(hours=3), timedelta(hours=2)]
    regions = ["eu-central-1", "eu-west-1"]
    check = _one_account(series_keep=2, regions=regions)
    _keeping(check, {f"lambda/live/{region}/collector": hours for region in regions})
    answers: dict[str, Any] = {
        "functions": {region: [["collector"]] for region in regions},
        "metrics": {"collector": {"runs": [_point(age) for age in hours]}}}
    first, _ = _poll(check, _stub(check, lambda_unreadable={"eu-west-1"}, **answers))
    second, _ = _poll(check, _stub(check, **answers))
    assert [(run.record["region"], run.record["at"])
            for run in _kind(first, "run")] == [
        ("eu-central-1", _stamp(age)) for age in hours]
    assert [(run.record["region"], run.record["at"])
            for run in _kind(second, "run")] == [
        ("eu-west-1", _stamp(age)) for age in hours]


def test_a_function_its_window_holds_no_point_of_is_asked_the_coarser_periods(
        ) -> None:
    """§3: either way — with a series kept as without one — and what a coarser
    period answers is the function's reading and never a run: a run is a
    one-minute bucket."""
    check = _one_account(series_keep=30)
    _keeping(check)
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "errors": 2, "age": timedelta(days=40), "period": 3600}})
    readings, calls = _poll(check, built)
    assert [(call["asked"], call["span"]) for call in calls] == [
        (ERRORS, FIFTEEN_DAYS), ({("Errors", "Sum", 300)}, timedelta(days=63)),
        ({("Errors", "Sum", 3600)}, timedelta(days=455))]
    (function,) = _kind(readings, "function")
    assert (function.record["errors"], function.record["at"]) == (
        2, _stamp(timedelta(days=40)))
    assert _kind(readings, "run") == []


def test_a_function_invoked_all_the_time_answers_its_last_hour() -> None:
    """§8: it shows its newest buckets like any other function, as many as the
    series keeps, costs three metrics on every poll, and answers an hour — not
    the fifteen days — and, of its other two metrics, the half hour that is read."""
    minutes = [timedelta(minutes=n) for n in range(1, 181)]
    check = _one_account(series_keep=30)
    _keeping(check, {COLLECTOR: minutes[:30]})
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(age) for age in minutes]}})
    _poll(check, built)
    readings, calls = _poll(check, built)
    assert [(call["asked"], call["span"], call["queries"]) for call in calls] == [
        (ERRORS, HOUR, 1), (IN_FULL, timedelta(minutes=30), 2)]
    assert _at(readings) == [_stamp(age) for age in reversed(minutes[:30])]


def test_a_bucket_cloudwatch_sent_no_point_for_keeps_a_null() -> None:
    """One shape for every run (little-sister ADR-0085 decision 3): a number the
    second call did not answer stands as `null`, never as a missing key."""
    check = _one_account(series_keep=30)
    _keeping(check)
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={
        "collector": {"errors": 1, "age": timedelta(minutes=2)}})
    (run,) = _kind(readings, "run")
    assert (run.record["invocations"], run.record["errors"],
            run.record["duration_ms"]) == (None, 1, None)


def test_the_newest_bucket_is_the_newest_in_whatever_order_cloudwatch_answers(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`get_metric_data` answers newest first unless told otherwise, and in which
    order its pages arrive is not for this check to assume."""
    newest_first = _FakeCloudwatch._points
    monkeypatch.setattr(
        _FakeCloudwatch, "_points",
        lambda self, query, start, end: newest_first(self, query, start, end)[::-1])
    check = _one_account(series_keep=1)
    _keeping(check)
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(minutes=5), errors=3),
                 _point(timedelta(minutes=2))]}})
    (function,) = _kind(readings, "function")
    assert (function.record["errors"], function.record["at"]) == (
        0, "2026-08-10T11:58:00Z")
    assert _at(readings) == ["2026-08-10T11:58:00Z"]


def test_an_answer_cut_short_is_followed_to_its_end() -> None:
    """CloudWatch cuts an answer and hands back a token for the rest. Followed, a
    function the first page left out is read at the period it answered — whatever
    the check keeps — and not as one with no point in fifteen days."""
    check = _one_account()
    built = _stub(check, functions={"eu-central-1": [["first", "second"]]},
                  metrics={"first": _point(timedelta(minutes=1)),
                           "second": _point(timedelta(minutes=2), errors=4)},
                  metric_page=1)
    readings, calls = _poll(check, built)
    assert [(call["asked"], call["token"]) for call in calls] == [
        (ERRORS, None), (ERRORS, "page-1")]
    second = _kind(readings, "function")[1]
    assert (second.record["errors"], second.record["at"]) == (
        4, "2026-08-10T11:58:00Z")


def test_a_run_s_pages_are_followed_too() -> None:
    check = _one_account(series_keep=30)
    _keeping(check)
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(minutes=3), invocations=7, duration=30.0),
                 _point(timedelta(minutes=2), invocations=9, duration=40.0)]}},
                  metric_page=3)
    readings, calls = _poll(check, built)
    assert [(call["asked"], call["token"]) for call in calls] == [
        (ERRORS, None), (IN_FULL, None), (IN_FULL, "page-1")]
    assert [(run.record["invocations"], run.record["duration_ms"])
            for run in _kind(readings, "run")] == [(7, 30), (9, 40)]


def test_an_answer_that_never_ends_is_a_region_that_could_not_be_read(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Two hundred pages is more than fifteen days of five hundred busy functions
    hold; past it the region says that it could not be read, and why."""
    sent: list[str | None] = []

    def endless(self: Any, **query: Any) -> dict[str, Any]:
        sent.append(query.get("NextToken"))
        return {"MetricDataResults": [], "NextToken": "again"}

    monkeypatch.setattr(_FakeCloudwatch, "get_metric_data", endless)
    check = _one_account()
    leaf = _lambda(check, functions=ONE_COLLECTOR)
    assert sent == [None, *["again"] * 199]
    assert _texts(leaf) == [
        "eu-central-1: functions cannot be read: CloudWatch's answer had not "
        "ended after 200 pages",
        "no functions in scope (eu-central-1)"]


# --- a query CloudWatch did not answer ---------------------------------------


def _unread(readings: tuple[Measurement, ...]) -> list[tuple[str, str]]:
    """The regions `lambda` could not read among *readings*, each with why."""
    return [(str(reading.record["region"]), str(reading.record["error"]))
            for reading in _kind(readings, "unreadable")
            if reading.record["aspect"] == LAMBDA]


def test_a_metric_cloudwatch_did_not_answer_is_a_region_that_could_not_be_read(
        ) -> None:
    """CloudWatch answers each query of a call on its own, and may say of one that
    it could not while the call succeeds. That result carries no point; taken for
    an answer it was a function that never ran, asked again at the coarser periods
    and billed again. It is a read that failed: the region says which metric of
    which function was not answered, no function is read, and nothing more is
    asked."""
    check = _one_account()
    built = _stub(check, functions={"eu-central-1": [["first", "second"]]},
                  metrics={"first": _point(timedelta(minutes=1)),
                           "second": {"refused": {"Errors": "InternalError"}}})
    readings, calls = _poll(check, built)
    assert [call["asked"] for call in calls] == [ERRORS]
    assert _unread(readings) == [
        ("eu-central-1",
         "CloudWatch did not answer Errors of second: InternalError")]
    assert _kind(readings, "function") == []


def test_the_region_says_what_was_not_answered_and_its_nodes_stay() -> None:
    """On the wall: the line a region that could not be read always was, and a
    node that leaves unsaid that its children are complete, so the functions an
    earlier poll wrote stay (little-sister ADR-0109)."""
    check = _one_account()
    leaf = _lambda(check, functions=ONE_COLLECTOR, metrics={
        "collector": {"refused": {"Errors": "InternalError"}}})
    assert _texts(leaf) == [
        "eu-central-1: functions cannot be read: CloudWatch did not answer "
        "Errors of collector: InternalError",
        "no functions in scope (eu-central-1)"]
    assert leaf.children == ()
    assert leaf.children_complete is False


def test_a_run_s_number_cloudwatch_did_not_answer_keeps_nothing_of_the_poll(
        ) -> None:
    """The second call's too. A run kept with an empty number would stay so once
    its bucket is an hour old; so the region could not be read, in CloudWatch's
    own words, no run and no reading of that poll is kept — and the next poll
    reads the run in full."""
    check = _one_account(series_keep=30)
    _keeping(check)
    built = _stub(check, functions=ONE_COLLECTOR, metrics={"collector": {
        **_point(timedelta(minutes=2), invocations=9, duration=40.0),
        "refused": {"Duration": (
            "Forbidden",
            "Authentication too complex to retrieve cross region data")}}})
    readings, calls = _poll(check, built)
    assert [call["asked"] for call in calls] == [ERRORS, IN_FULL]
    assert _unread(readings) == [
        ("eu-central-1",
         "CloudWatch did not answer Duration of collector: Forbidden — "
         "Authentication too complex to retrieve cross region data")]
    assert _kind(readings, "run") == []
    assert _kind(readings, "function") == []

    built = _stub(check, functions=ONE_COLLECTOR, metrics={
        "collector": _point(timedelta(minutes=2), invocations=9, duration=40.0)})
    readings, _ = _poll(check, built)
    assert _unread(readings) == []
    assert [(run.record["invocations"], run.record["duration_ms"])
            for run in _kind(readings, "run")] == [(9, 40)]


@pytest.mark.parametrize("names, others", [
    (["a", "b"], "; 1 more query likewise"),
    (["a", "b", "c"], "; 2 more queries likewise"),
])
def test_the_first_query_not_answered_is_named_and_the_rest_are_counted(
        names: list[str], others: str) -> None:
    check = _one_account()
    readings = _readings(
        check, functions={"eu-central-1": [names]},
        metrics={name: {"refused": {"Errors": "InternalError"}}
                 for name in names})
    assert _unread(readings) == [
        ("eu-central-1",
         f"CloudWatch did not answer Errors of a: InternalError{others}")]


@pytest.mark.parametrize("refused, said", [
    (("InternalError", "one reason", "and another"),
     "InternalError — one reason; and another"),
    (("InternalError", "", "a reason"), "InternalError — a reason"),
    (("InternalError", ""), "InternalError"),
])
def test_what_cloudwatch_says_beside_a_refusal_is_said(
        refused: tuple[str, ...], said: str) -> None:
    """Every message a refused result carries, and nothing for one that is empty."""
    check = _one_account()
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={
        "collector": {"refused": {"Errors": refused}}})
    assert _unread(readings) == [
        ("eu-central-1", f"CloudWatch did not answer Errors of collector: {said}")]


def test_a_word_cloudwatch_has_never_said_is_no_answer_either() -> None:
    """What is listed is the words that answer, `Complete` and `PartialData`, and
    not the words that refuse: a status this type has never seen is not a metric
    with no points."""
    check = _one_account()
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={
        "collector": {"refused": {"Errors": "Throttled"}}})
    assert _unread(readings) == [
        ("eu-central-1",
         "CloudWatch did not answer Errors of collector: Throttled")]


def test_a_result_cut_by_a_page_is_an_answer_that_goes_on(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`PartialData` says that a result's points go on behind the token, which is
    followed: an answer, and nothing a region is refused for."""
    said: list[str] = []
    answered = _FakeCloudwatch.get_metric_data

    def heard(self: Any, **query: Any) -> dict[str, Any]:
        answer = answered(self, **query)
        said.extend(result["StatusCode"] for result in answer["MetricDataResults"])
        return answer

    monkeypatch.setattr(_FakeCloudwatch, "get_metric_data", heard)
    check = _one_account()
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={"collector": {
        "runs": [_point(timedelta(minutes=3), errors=2),
                 _point(timedelta(minutes=2))]}}, metric_page=1)
    assert said == ["PartialData", "Complete"]
    assert _unread(readings) == []
    (function,) = _kind(readings, "function")
    assert (function.record["errors"], function.record["at"]) == (
        0, "2026-08-10T11:58:00Z")


def test_a_result_that_names_no_status_is_read_as_it_always_was(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Only what CloudWatch says was not answered is refused."""
    answered = _FakeCloudwatch.get_metric_data

    def silent(self: Any, **query: Any) -> dict[str, Any]:
        answer = answered(self, **query)
        for result in answer["MetricDataResults"]:
            del result["StatusCode"]
        return answer

    monkeypatch.setattr(_FakeCloudwatch, "get_metric_data", silent)
    check = _one_account()
    readings = _readings(check, functions=ONE_COLLECTOR, metrics={
        "collector": _point(timedelta(minutes=2), errors=4)})
    assert _unread(readings) == []
    (function,) = _kind(readings, "function")
    assert function.record["errors"] == 4


def test_what_is_left_of_an_answer_that_refused_a_query_is_not_asked_for() -> None:
    """The refusal is raised where it is first seen: the first page hands back a
    token for the rest, and the rest is not fetched."""
    check = _one_account()
    built = _stub(check, functions={"eu-central-1": [["first", "second"]]},
                  metrics={"first": {"runs": [_point(timedelta(minutes=3)),
                                              _point(timedelta(minutes=2))]},
                           "second": {"refused": {"Errors": "InternalError"}}},
                  metric_page=1)
    readings, calls = _poll(check, built)
    assert [(call["asked"], call["token"]) for call in calls] == [(ERRORS, None)]
    assert _unread(readings) == [
        ("eu-central-1",
         "CloudWatch did not answer Errors of second: InternalError")]


def test_a_refused_result_this_type_did_not_ask_for_is_named_by_its_id(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _FakeCloudwatch, "get_metric_data",
        lambda self, **query: {"MetricDataResults": [
            {"Id": "x9", "StatusCode": "InternalError"}]})
    check = _one_account()
    readings = _readings(check, functions=ONE_COLLECTOR)
    assert _unread(readings) == [
        ("eu-central-1", "CloudWatch did not answer the query x9: InternalError")]


def test_a_run_s_duration_is_declared_as_a_measure_in_milliseconds() -> None:
    """§7: the type's default, so a deployment that keeps a series draws a
    function's runs to their duration with no key of its own — and a run's counts
    are columns of its readings and no plot."""
    measures = _build().measures
    assert (measures["duration_ms"].unit, measures["duration_ms"].label) == (
        "ms", "Duration")
    assert not {"invocations", "errors"} & set(measures)


def test_a_deployment_takes_the_plot_away_or_adds_a_count() -> None:
    """§7: a count is drawn beside the duration where a deployment asks for it, and
    `duration_ms: null` takes the declared plot away, which leaves a run a tick."""
    added = _build(measures={"invocations": "calls"}).measures
    assert {"duration_ms", "invocations"} <= set(added)
    assert added["invocations"].unit == "calls"
    assert "duration_ms" not in _build(measures={"duration_ms": None}).measures


# --- how long a run and an execution took (ADR-0008) ------------------------------

def _run_record(row: dict[str, Any]) -> Mapping[str, Any]:
    """The record of the one run a queue lists, under the status its row says."""
    readings = _readings(_one_account(), queues=ONE_QUEUE,
                         jobs={("nightly", row["status"]): [[row]]})
    (run,) = _kind(readings, "job")
    return run.record


def _execution_record(row: dict[str, Any]) -> Mapping[str, Any]:
    """The record of a pipeline whose newest execution is *row*."""
    readings = _readings(_one_account(), pipelines=ONE_PIPELINE,
                         executions={"running-deploy": [row]})
    (pipeline,) = _kind(readings, "pipeline")
    return pipeline.record


def test_a_run_says_how_long_it_waited_and_how_long_it_ran() -> None:
    """§1: `wait_s` from when the job was created to when it started, and
    `duration_s` from then to when it stopped."""
    record = _run_record(_job("etl", created=timedelta(minutes=10),
                              started=timedelta(minutes=7, seconds=30),
                              stopped=timedelta(minutes=2, seconds=15)))
    assert (record["wait_s"], record["duration_s"]) == (150, 315)


@pytest.mark.parametrize(("status", "times", "wait", "duration"), [
    # Waiting: it has not started.
    ("RUNNABLE", {"created": timedelta(minutes=9)}, None, None),
    # Running: it has waited, and it has not stopped.
    ("RUNNING", {"created": timedelta(minutes=9), "started": timedelta(minutes=8)},
     60, None),
    # Stopped before it ever started.
    ("FAILED", {"created": timedelta(minutes=9), "stopped": timedelta(minutes=1)},
     None, None),
    # Batch sent no time of creation.
    ("SUCCEEDED", {"started": timedelta(minutes=8), "stopped": timedelta(minutes=3)},
     None, 300),
])
def test_a_run_s_span_is_empty_until_both_its_instants_are_known(
        status: str, times: dict[str, timedelta], wait: int | None,
        duration: int | None) -> None:
    """§3: nothing is counted to the poll's own clock, so a run that is still
    running has waited and has no duration yet — and the record keeps its shape,
    a null where a number is not known."""
    record = _run_record(_job("etl", status, **times))
    assert (record["wait_s"], record["duration_s"]) == (wait, duration)


def test_a_span_is_kept_in_whole_seconds() -> None:
    """§4: Batch stamps a job in milliseconds, and a record keeps the seconds that
    were completed, as a line counts a span — 29 of 29.6, and 29 of 29.4."""
    record = _run_record(_job("etl", created=timedelta(seconds=90),
                              started=timedelta(seconds=60, milliseconds=400),
                              stopped=timedelta(seconds=31)))
    assert (record["wait_s"], record["duration_s"]) == (29, 29)
    assert type(record["wait_s"]) is type(record["duration_s"]) is int


def test_an_instant_before_the_one_it_follows_gives_no_span() -> None:
    """§3: a start before the creation, or a stop before the start, is no span, and
    is not kept as one of no length."""
    record = _run_record(_job("etl", created=timedelta(minutes=5),
                              started=timedelta(minutes=6),
                              stopped=timedelta(minutes=7)))
    assert (record["wait_s"], record["duration_s"]) == (None, None)


def test_instants_that_coincide_are_a_span_of_no_length() -> None:
    """§3: a job that started the moment it was created waited `0`, which is a
    number and no null."""
    record = _run_record(_job("etl", created=timedelta(minutes=5),
                              started=timedelta(minutes=5),
                              stopped=timedelta(minutes=5)))
    assert (record["wait_s"], record["duration_s"]) == (0, 0)


@pytest.mark.parametrize("status", ["Succeeded", "Failed", "Stopped", "Superseded",
                                    "Cancelled", "succeeded", " SUCCEEDED "])
def test_an_execution_that_is_over_says_how_long_it_took(status: str) -> None:
    """§2, §3: from its start to the last change CodePipeline recorded of it, in
    each of the five statuses in which an execution is over — a status being the
    word it is whatever its case and its padding, as `state_map` reads one."""
    record = _execution_record(_execution(
        status, started=timedelta(minutes=20),
        updated=timedelta(minutes=8, seconds=20), eid="e-1"))
    assert record["duration_s"] == 700


@pytest.mark.parametrize("status", ["InProgress", "Stopping", "Paused"])
def test_an_execution_that_is_not_over_has_no_duration(status: str) -> None:
    """§3: its last change is no end. `InProgress` and `Stopping` are an execution
    on its way, and a word CodePipeline adds ends nothing until this type knows
    it."""
    record = _execution_record(_execution(
        status, started=timedelta(minutes=20),
        updated=timedelta(minutes=8, seconds=20), eid="e-1"))
    assert record["duration_s"] is None


def test_an_execution_s_duration_is_whole_seconds_and_no_span_is_none() -> None:
    """§3, §4: the 99 seconds that were completed of 99.6, and nothing where the
    last change lies before the start."""
    took = _execution_record(_execution(
        started=timedelta(seconds=100), updated=timedelta(milliseconds=400)))
    assert took["duration_s"] == 99 and type(took["duration_s"]) is int
    backwards = _execution_record(_execution(
        started=timedelta(minutes=1), updated=timedelta(minutes=2)))
    assert backwards["duration_s"] is None


@pytest.mark.parametrize("newest_first", [True, False])
def test_an_execution_s_duration_is_counted_to_its_own_last_change(
        newest_first: bool) -> None:
    """§2: the newest execution's, wherever in the page it stands — and never the
    last change of another, though that one changed later."""
    old = _execution(started=timedelta(hours=5), updated=timedelta(minutes=5),
                     eid="e-old")
    new = _execution(started=timedelta(minutes=30), updated=timedelta(minutes=10),
                     eid="e-new")
    readings = _readings(_one_account(), pipelines=ONE_PIPELINE, executions={
        "running-deploy": [new, old] if newest_first else [old, new]})
    (pipeline,) = _kind(readings, "pipeline")
    assert (pipeline.record["execution"], pipeline.record["duration_s"]) == (
        "e-new", 1200)


def test_an_execution_no_last_change_is_told_of_and_a_pipeline_never_run_have_none(
        ) -> None:
    """§3: the record keeps its shape on each path — an execution that is over and
    names no last change, one whose last change is no instant, and a pipeline with
    no execution at all."""
    readings = _readings(
        _one_account(),
        pipelines={"eu-central-1": [["deploy", "odd", "idle"]]},
        executions={"deploy": [_execution(eid="e-1")],
                    "odd": [{**_execution(eid="e-2"), "lastUpdateTime": "today"}]})
    deploy, odd, idle = _kind(readings, "pipeline")
    assert (deploy.record["status"], deploy.record["duration_s"]) == (
        "Succeeded", None)
    assert (odd.record["status"], odd.record["duration_s"]) == ("Succeeded", None)
    assert (idle.record["status"], idle.record["duration_s"]) == (None, None)


def test_the_spans_are_declared_as_measures_in_seconds() -> None:
    """§5: the type's default, beside a function's `duration_ms`, so a run and an
    execution are drawn to how long they took with no key of a deployment's own,
    which takes either away by its name."""
    measures = _build().measures
    assert list(measures) == ["duration_ms", "duration_s", "wait_s"]
    assert (measures["duration_s"].unit, measures["duration_s"].label) == (
        "s", "Duration")
    assert (measures["wait_s"].unit, measures["wait_s"].label) == ("s", "Wait")
    assert list(_build(measures={"wait_s": None}).measures) == [
        "duration_ms", "duration_s"]


def test_the_grading_reads_neither_number() -> None:
    """No line changes: a record that carries the two numbers, one kept before a
    run carried them, and one whose numbers are wrong all grade to the same lines
    and the same codes (ADR-0005 §5), shown and for the record alike — under
    thresholds a kept number would trip."""
    check = _one_account(series_keep=30,
                         batch={"max_wait_time": "1m", "max_run_time": "1m"})
    _holding(check)
    readings = _readings(
        check, queues=ONE_QUEUE, pipelines=ONE_PIPELINE,
        jobs={("nightly", "SUCCEEDED"): [[_job(
                  "etl", job_id="j-1", created=timedelta(hours=3),
                  started=timedelta(hours=2, minutes=50),
                  stopped=timedelta(hours=2))]],
              ("nightly", "RUNNING"): [[_job(
                  "etl", "RUNNING", job_id="j-2", created=timedelta(minutes=9),
                  started=timedelta(minutes=8))]],
              ("nightly", "RUNNABLE"): [[_job(
                  "etl", "RUNNABLE", job_id="j-3", created=timedelta(seconds=30))]]},
        executions={"running-deploy": [
            _execution(started=timedelta(minutes=20), updated=timedelta(minutes=5),
                       eid="e-1"),
            _execution("Failed", started=timedelta(hours=2),
                       updated=timedelta(hours=1), eid="e-0")]})
    assert {reading.identity: (reading.record.get("wait_s"),
                               reading.record["duration_s"])
            for reading in readings if "duration_s" in reading.record} == {
        "j-1": (600, 3000), "j-2": (60, None), "j-3": (None, None),
        "e-1": (None, 900), "e-0": (None, 3600)}

    def with_numbers(wrong: int | None) -> list[Measurement]:
        """The readings without their two numbers, or with each set to *wrong*."""
        changed = []
        for reading in readings:
            record = dict(reading.record)
            for key in ("wait_s", "duration_s"):
                if key in record:
                    if wrong is None:
                        del record[key]
                    else:
                        record[key] = wrong
            changed.append(Measurement(record=record, subject=reading.subject,
                                       identity=reading.identity,
                                       state=reading.state))
        return changed

    def said(result: CheckResult) -> list[tuple[Any, ...]]:
        """Each node's name and code, its lines, and what it says for the record."""
        return [(node.name, node.code,
                 [(entry.text, entry.code) for entry in node.reason_entries],
                 [(entry.text, entry.code) for entry in node.for_record])
                for node in _nodes(result)]

    graded = said(run_check(check, measurements=readings))
    assert graded == said(run_check(check, measurements=with_numbers(None)))
    assert graded == said(run_check(check, measurements=with_numbers(1)))
    (line,) = [(text, code) for _, _, lines, _ in graded for text, code in lines
               if "[etl]" in text]
    # The line counts for itself: the run that ended took fifty minutes, and the
    # one in flight has run for eight, past the one it may.
    assert "ran 50m" in line[0] and "1 running (8m)" in line[0]
    assert line[1] is StatusCode.WARN
    # And so does what is said for the record: a span from the record's instants,
    # an age to the instant the grading is handed.
    assert [one for _, _, _, kept in graded for one in kept] == [
        ("Failed", StatusCode.ERROR),
        ("SUCCEEDED, waited 10m, ran 50m", StatusCode.OK),
        ("RUNNING for 8m, past max_run_time", StatusCode.WARN),
        ("RUNNABLE for < 1m", StatusCode.OK)]


def test_a_run_s_record_and_its_line_count_one_span_alike() -> None:
    """§4: the seconds that were completed, as the line counts them — a run of
    3599.6 seconds is 3599 in its record and fifty-nine minutes on its line, where
    the nearest second would have made the record an hour."""
    ran = timedelta(seconds=3599, milliseconds=600)
    row = _job("etl", created=timedelta(minutes=10) + ran,
               started=timedelta(minutes=10) + ran, stopped=timedelta(minutes=10))
    check = _one_account()
    readings = _readings(check, queues=ONE_QUEUE,
                         jobs={("nightly", "SUCCEEDED"): [[row]]})
    (run,) = _kind(readings, "job")
    assert run.record["duration_s"] == 3599
    leaf = _aspect(check, run_check(check, measurements=readings), BATCH)
    assert _entry(leaf, "etl").text.endswith(": SUCCEEDED 10m ago, ran 59m")


@pytest.mark.parametrize(("fraction", "weighs", "weighed"), [
    # Instants on the second, as ADR-0005 §8 weighed a run.
    (timedelta(0), 1213, 1169),
    # Instants with the milliseconds Batch stamps them with: seven bytes on each of
    # the four a run's record keeps.
    (timedelta(milliseconds=1), 1241, 1197),
])
def test_a_run_at_its_bound_with_two_long_spans_weighs_what_the_record_says(
        fraction: timedelta, weighs: int, weighed: int) -> None:
    """Consequences: the longest queue name, job name and reason, and two spans of
    two hundred days, as the seam weighs a record — beside the same run without its
    two numbers, which on the second is the 1169 of ADR-0005 §8."""
    assert len(EMOJI) == 1
    queue, name, reason = "q" * 128, "j" * 128, EMOJI * 1024
    readings = _readings(_one_account(series_keep=1),
                         queues={"eu-central-1": [[_queue(queue, reason=reason)]]},
                         jobs={(queue, "FAILED"): [[{
                             **_job(name, "FAILED",
                                    job_id="00000000-0000-4000-8000-000000000000",
                                    created=timedelta(days=400) + fraction,
                                    started=timedelta(days=200) + fraction,
                                    stopped=timedelta(seconds=1) + fraction),
                             "statusReason": reason}]]})
    (run,) = _kind(readings, "job")
    record = dict(run.record)
    assert (record["wait_s"], record["duration_s"]) == (17_280_000, 17_279_999)
    assert len(json.dumps(record)) == weighs
    del record["wait_s"], record["duration_s"]
    assert len(json.dumps(record)) == weighed


# --- a function's node (ADR-0006 §9) ----------------------------------------------

def _collector(check: AwsCheck, **stub: Any) -> tuple[tuple[Measurement, ...],
                                                    CheckResult]:
    """What *check* read, and the `collector` function's node graded from it."""
    _keeping(check)
    taken = _readings(check, functions=ONE_COLLECTOR, **stub)
    leaf = _aspect(check, run_check(check, measurements=taken), LAMBDA)
    return taken, _function(leaf, "collector")


def test_every_function_has_a_node_beneath_lambda_named_by_what_aws_calls_it(
        ) -> None:
    """§9: one that ran well, one that failed and one that was never invoked
    alike — a node each, with the function's line as its only one."""
    leaf = _lambda(_one_account(),
                   functions={"eu-central-1": [["well", "failed", "never"]]},
                   metrics={"well": _point(timedelta(minutes=1)),
                            "failed": _point(timedelta(minutes=1), errors=3)})
    assert [(node.name, node.stored_code, len(node.reason_entries))
            for node in leaf.children] == [
        ("failed", StatusCode.ERROR, 1), ("never", StatusCode.WARN, 1),
        ("well", StatusCode.OK, 1)]
    assert all(node.children == () for node in leaf.children)


def test_a_display_name_rule_gives_the_node_its_title_and_never_its_path() -> None:
    """§9: `shorten` reaches the title and the line's label, and neither the
    node's name nor the slug."""
    check = _one_account(**{"lambda": {"shorten": [{"from": "running-"}]}})
    leaf = _lambda(check,
                   functions={"eu-central-1": [["running-collector", "plain"]]})
    shortened, untouched = (_function(leaf, "running-collector"),
                            _function(leaf, "plain"))
    assert (shortened.name, shortened.title) == ("running-collector", "collector")
    assert shortened.reason[0].slug == "eu-central-1-running-collector"
    assert shortened.reason[0].text.startswith("[collector](")
    assert (untouched.name, untouched.title) == ("plain", "")


def test_a_function_s_node_says_which_account_and_region_it_is_of() -> None:
    """Its path may name neither — a level stands only where a configuration
    names several — so its description does."""
    _, node = _collector(_one_account())
    assert node.description == "Lambda function in live, eu-central-1"


def test_a_function_s_line_names_the_function_though_its_reading_names_none(
        ) -> None:
    """§9: that is what makes the node stand for the function, and what keeps the
    function's own reading out of the series. The line still carries the reading
    it was written from, under the slug it had."""
    taken, node = _collector(
        _one_account(series_keep=30),
        metrics={"collector": {"runs": [_point(timedelta(minutes=2))]}})
    (function,) = _kind(taken, "function")
    (line,) = node.reason_entries
    assert function.subject == ""
    assert (line.subject, line.data, line.slug) == (
        COLLECTOR, dict(function.record), "eu-central-1-collector")
    assert line.text.endswith(": no errors, last run 2m ago · no log stream")


def test_no_run_has_a_line_of_its_own_and_each_is_said_for_the_record() -> None:
    """§9: how each run the poll read in full stood — `ERROR` where its errors are
    above zero and `OK` where they are not, in a sentence that says its errors and
    its invocations — on a line no node shows, which carries the run's record."""
    taken, node = _collector(
        _one_account(series_keep=30),
        metrics={"collector": {"runs": [
            _point(timedelta(minutes=4)),
            _point(timedelta(minutes=3), errors=1, invocations=12),
            _point(timedelta(minutes=2), errors=2, invocations=3)]}})
    runs = _kind(taken, "run")
    assert len(node.reason_entries) == 1
    assert [(line.code, line.text, line.subject, line.data)
            for line in node.for_record] == [
        (StatusCode.OK, "no errors in 1 invocation", COLLECTOR,
         dict(runs[0].record)),
        (StatusCode.ERROR, "1 error in 12 invocations", COLLECTOR,
         dict(runs[1].record)),
        (StatusCode.ERROR, "2 errors in 3 invocations", COLLECTOR,
         dict(runs[2].record))]
    # The function's own line is graded on its newest bucket, as it always was.
    assert node.stored_code is StatusCode.ERROR


def test_a_run_s_verdict_is_its_own_at_any_age() -> None:
    """§9: the gate that keeps an old error from being graded is the line's. Two
    days after the run, with `error_max_age: 1d`, the function's line no longer
    grades the error — and the run still failed."""
    _, node = _collector(
        _one_account(series_keep=30, **{"lambda": {"error_max_age": "1d"}}),
        metrics={"collector": {"runs": [_point(timedelta(days=2), errors=1)]}})
    (line,) = node.reason_entries
    assert line.code is StatusCode.OK and "too old to grade" in line.text
    assert [entry.code for entry in node.for_record] == [StatusCode.ERROR]


def test_a_run_whose_invocations_were_not_answered_says_its_errors_alone() -> None:
    _, node = _collector(_one_account(series_keep=30), metrics={
        "collector": {"errors": 0, "age": timedelta(minutes=2)}})
    assert [(entry.code, entry.text) for entry in node.for_record] == [
        (StatusCode.OK, "no errors")]


def test_the_node_the_functions_hang_on_says_that_its_children_are_complete(
        ) -> None:
    """§9: where their listing was read whole, so a function that was deleted, or
    that a rule now ignores, leaves with the next good run; where it could not be
    read the node leaves that unsaid, and the functions stay."""
    read = _lambda(_one_account(), functions=ONE_COLLECTOR)
    unread = _lambda(_one_account(), lambda_unreadable={"eu-central-1"})
    assert (read.children_complete, [node.name for node in read.children]) == (
        True, ["collector"])
    assert (unread.children_complete, unread.children) == (False, ())


def test_an_account_with_no_functions_says_that_its_none_are_all_of_them() -> None:
    """Read whole and empty is still read whole: the last function to be deleted
    leaves like any other."""
    leaf = _lambda(_one_account())
    assert (leaf.children, leaf.children_complete) == ((), True)
    assert _texts(leaf) == ["no functions in scope (eu-central-1)"]


def test_a_function_s_node_declares_nothing_of_the_density_trade() -> None:
    """Its line is a function's status and no inventory: on a dense wall a quiet
    function is a chip, and `lambda`, which holds them, keeps its box."""
    _, node = _collector(_one_account())
    assert node.show_when_quiet is None
    assert _one_account().subnode_show_when_quiet[LAMBDA] is True


def test_runs_typed_by_hand_grade_as_the_ones_a_poll_read() -> None:
    """The grading reads the records and nothing else (little-sister ADR-0086
    decision 6): a run this process never read is said for the record like one it
    did, on the node of the function its record names."""
    check = _one_account()
    record = {"aspect": LAMBDA, "account": "live", "region": "eu-central-1",
              "name": "collector"}
    typed = [
        Measurement({"aspect": None, "kind": "estate", "credentials": None,
                     "accounts": [{"name": "live", "outcome": "read"}]},
                    subject="accounts/live", state="live=read"),
        Measurement({"aspect": None, "kind": "account", "account": "live",
                     "outcome": "read", "error": None, "renewal": None}),
        Measurement({**record, "kind": "function", "errors": 0,
                     "at": "2026-08-10T11:58:00Z", "log_status": None,
                     "log_note": None, "log_error": None}),
        Measurement({**record, "kind": "run", "at": "2026-08-01T07:00:00Z",
                     "invocations": 4, "errors": 4, "duration_ms": 900000},
                    subject=COLLECTOR, identity="2026-08-01T07:00:00Z"),
    ]
    node = _function(_child(run_check(check, measurements=typed), LAMBDA),
                     "collector")
    (said,) = node.for_record
    assert (said.code, said.text, said.subject, said.data) == (
        StatusCode.ERROR, "4 errors in 4 invocations", COLLECTOR,
        dict(typed[3].record))
    assert node.stored_code is StatusCode.OK


# --- the tree's shape (ADR-0007) --------------------------------------------------
#
# A level stands in the tree only where the configuration names several of it. Each
# test is one sentence of that record.

TWO_REGIONS = ["eu-central-1", "eu-west-1"]


def test_a_check_that_names_one_account_hangs_its_aspects_beneath_its_own_node(
        ) -> None:
    """§2: the account has no node — its level would say one word in every path —
    and the root still grades nothing and says what is watched."""
    check = _one_account()
    _stub(check, **EVERY_ASPECT)
    result = run_check(check)
    assert [child.name for child in result.children] == list(AwsCheck.ASPECTS)
    assert result.code is StatusCode.UNDEFINED
    assert _texts(result) == ["1 account, 1 account/region pair in scope"]
    assert "live" not in [node.name for node in _nodes(result)]


def test_a_check_that_names_several_accounts_keeps_the_account_s_level() -> None:
    """§1: the tree ADR-0001 §2 drew is the one such a check still has."""
    check = _build()
    _stub(check, **EVERY_ASPECT)
    result = run_check(check)
    assert [child.name for child in result.children] == ["live", "backup"]
    assert [[leaf.name for leaf in account.children]
            for account in result.children] == [list(AwsCheck.ASPECTS)] * 2


def test_what_refused_the_one_account_is_said_on_the_check_s_node() -> None:
    """§2: the reason on a node that is then `ERROR` — a pin on it is the pin on
    the account — with nothing beneath it written, and the scope still reported."""
    check = _one_account()
    _stub(check, _FakeSts(refuse={ROLE_LIVE}))
    result = run_check(check)
    assert result.code is StatusCode.ERROR
    assert _texts(result) == [
        "role cannot be assumed: An error occurred (AccessDenied) when calling "
        "the AssumeRole operation: not allowed"]
    assert result.children == ()
    assert result.report == "- **live** — eu-central-1"


def test_what_is_counted_is_the_configuration_and_never_what_aws_answers() -> None:
    """§1: an account that could not be read is still one of those named, and a
    region that holds nothing still has its level where there are several."""
    two = _build()
    _stub(two, _FakeSts(refuse={ROLE_BACKUP}))
    assert [child.name for child in run_check(two).children] == ["live", "backup"]

    regions = _one_account(regions=TWO_REGIONS)
    leaf = _lambda(regions, functions={"eu-central-1": [["collector"]]})
    assert [(node.name, [function.name for function in node.children],
             node.children_complete) for node in leaf.children] == [
        ("eu-central-1", ["collector"], True), ("eu-west-1", [], True)]


def test_readings_that_name_one_account_keep_the_level_of_a_check_that_names_two(
        ) -> None:
    """§1, where a grading is run over readings this process did not take, and they
    name fewer accounts than the check does: the level is the configuration's, so
    the one account that was read still stands on a node of its own."""
    typed = [
        Measurement({"aspect": None, "kind": "estate", "credentials": None,
                     "accounts": [{"name": "live", "outcome": "read"}]},
                    subject="accounts/live", state="live=read"),
        Measurement({"aspect": None, "kind": "account", "account": "live",
                     "outcome": "read", "error": None, "renewal": None}),
    ]
    result = run_check(_build(), measurements=typed)
    assert [child.name for child in result.children] == ["live"]


def test_a_function_hangs_beneath_its_region_s_node_where_its_account_reads_several(
        ) -> None:
    """§3: that level is what tells two regions' functions of one name apart —
    and nothing has to where an account reads one region."""
    several = _lambda(_one_account(regions=TWO_REGIONS),
                      functions={"eu-central-1": [["collector"]],
                                 "eu-west-1": [["collector", "reporter"]]})
    assert [(region.name, [function.name for function in region.children])
            for region in several.children] == [
        ("eu-central-1", ["collector"]), ("eu-west-1", ["collector", "reporter"])]
    assert _texts(several) == ["3 functions in scope (eu-central-1, eu-west-1)"]
    assert [line.split("(")[0] for line in several.report.splitlines()] == [
        "- eu-central-1 / [collector]", "- eu-west-1 / [collector]",
        "- eu-west-1 / [reporter]"]

    one = _lambda(_one_account(), functions=ONE_COLLECTOR)
    assert [node.name for node in one.children] == ["collector"]
    assert one.report.startswith("- [collector](")


def test_a_function_s_line_prints_no_region_and_its_slug_keeps_it() -> None:
    """§3 and §5: the region is a level where there are several, so the line on a
    function's own node does not repeat it — and a slug keeps every part, as
    ADR-0001 has it."""
    leaf = _lambda(_one_account(regions=TWO_REGIONS),
                   functions={"eu-west-1": [["collector"]]})
    (line,) = _function(leaf, "collector").reason_entries
    assert line.text.startswith("[collector](https://eu-west-1.console")
    assert line.slug == "eu-west-1-collector"


def test_a_function_beneath_its_region_s_node_carries_its_runs_for_the_record(
        ) -> None:
    """A level more changes nothing of what a function's node is: its line names
    the function, with its region, and each run it read is said for the record."""
    check = _one_account(series_keep=30, regions=TWO_REGIONS)
    _keeping(check)
    taken = _readings(check, functions={"eu-west-1": [["collector"]]}, metrics={
        "collector": {"runs": [_point(timedelta(minutes=2), errors=1)]}})
    leaf = _aspect(check, run_check(check, measurements=taken), LAMBDA)
    (node,) = _child(leaf, "eu-west-1").children
    subject = "lambda/live/eu-west-1/collector"
    assert node.reason_entries[0].subject == subject
    assert [(line.code, line.text, line.subject) for line in node.for_record] == [
        (StatusCode.ERROR, "1 error in 1 invocation", subject)]


def test_a_region_s_node_declines_the_density_trade_as_lambda_does() -> None:
    """It is the box that holds a region's functions — read or not, since a flag
    freezes at a node's first fill — and a function's own node declares nothing."""
    leaf = _lambda(_one_account(regions=TWO_REGIONS),
                   functions={"eu-central-1": [["collector"]]},
                   lambda_unreadable={"eu-west-1"})
    assert [node.show_when_quiet for node in leaf.children] == [True, True]
    assert _function(leaf, "collector").show_when_quiet is None


def test_a_region_s_node_grades_nothing_unless_the_region_could_not_be_read(
        ) -> None:
    """§3: named by the region; it says that its children are complete where it was
    read, and where it was not it says so, keeps the nodes it had, and leaves its
    neighbor to remove what is gone."""
    leaf = _lambda(_one_account(regions=TWO_REGIONS),
                   functions={"eu-central-1": [["collector"]]},
                   lambda_unreadable={"eu-west-1"})
    read, unread = leaf.children
    assert (read.name, read.stored_code, _texts(read), read.children_complete) == (
        "eu-central-1", StatusCode.OK, [], True)
    assert (unread.name, unread.stored_code, unread.children,
            unread.children_complete) == ("eu-west-1", StatusCode.WARN, (), False)
    assert _texts(unread)[0].startswith("eu-west-1: functions cannot be read")
    # The regions are configuration: `lambda` has no child a run could find gone,
    # says nothing of them, and keeps the count as its own.
    assert leaf.children_complete is False
    assert _texts(leaf) == ["1 function in scope (eu-central-1, eu-west-1)"]


def test_a_region_s_node_says_which_account_it_is_of() -> None:
    leaf = _lambda(_one_account(regions=TWO_REGIONS))
    assert [node.description for node in leaf.children] == [
        "Lambda functions in live, eu-central-1",
        "Lambda functions in live, eu-west-1"]


def test_a_node_this_type_does_not_name_says_that_a_run_names_it() -> None:
    """little-sister ADR-0118: what is declared for an aspect's name reaches every
    node of that name, unless the node says that a run names it. A function is
    named by AWS, a region and an account by the configuration, so each says so —
    read or not, whatever it is called — and a function its account calls `batch`
    is not shown as the `batch` aspect. An aspect is named by this type, and says
    nothing."""
    regions = _one_account(regions=TWO_REGIONS)
    _stub(regions, functions={"eu-central-1": [["batch", "collector"]]},
          lambda_unreadable={"eu-west-1"})
    result = run_check(regions)
    assert result.dynamic is False
    assert {aspect.dynamic for aspect in result.children} == {False}
    leaf = _child(result, LAMBDA)
    assert [(region.name, region.dynamic) for region in leaf.children] == [
        ("eu-central-1", True), ("eu-west-1", True)]
    assert _function(leaf, "batch").dynamic is True
    assert _function(leaf, "collector").dynamic is True

    one = _lambda(_one_account(),
                  functions={"eu-central-1": [["batch", "collector"]]})
    assert [(node.name, node.dynamic) for node in one.children] == [
        ("batch", True), ("collector", True)]

    several = _build()
    _stub(several, _FakeSts(refuse={ROLE_BACKUP}))
    result = run_check(several)
    assert result.dynamic is False
    assert [(account.name, account.dynamic) for account in result.children] == [
        ("live", True), ("backup", True)]
    assert {aspect.dynamic for aspect in _child(result, "live").children} == {False}


def test_the_shape_is_each_account_s_own() -> None:
    """§1: one check may hold a region's level under the account that reads two
    regions, and none under the account that reads one."""
    check = _build(accounts=[{"name": "wide", "regions": TWO_REGIONS},
                             {"name": "narrow"}])
    _stub(check, functions={"eu-central-1": [["collector"]]})
    result = run_check(check)
    wide = _aspect(check, result, LAMBDA, "wide")
    narrow = _aspect(check, result, LAMBDA, "narrow")
    assert [node.name for node in wide.children] == TWO_REGIONS
    assert [node.name for node in narrow.children] == ["collector"]


def test_the_aspect_is_always_a_level() -> None:
    """§4: a function hangs beneath `lambda` where `lambda` is the one aspect its
    check runs, too — `enabled:` is configuration, and the rule stops before it."""
    off = {"enabled": False}
    check = _one_account(cloudwatch=off, ec2=off, codepipeline=off, batch=off)
    _stub(check, functions=ONE_COLLECTOR)
    result = run_check(check)
    assert [child.name for child in result.children] == [LAMBDA]
    assert [node.name for node in _child(result, LAMBDA).children] == ["collector"]


def test_only_an_aspect_whose_subjects_are_nodes_has_a_region_s_level() -> None:
    """§3: an aspect that writes a line for each thing it reads has no levels
    beneath it, and its lines print the region where an account reads several."""
    check = _one_account(regions=TWO_REGIONS)
    _stub(check, **EVERY_ASPECT)
    result = run_check(check)
    assert {leaf.name: [node.name for node in leaf.children]
            for leaf in result.children} == {
        CLOUDWATCH: [], EC2: [], LAMBDA: TWO_REGIONS, CODEPIPELINE: TWO_REGIONS,
        BATCH: TWO_REGIONS}
    assert _entry(_child(result, CLOUDWATCH), "api-latency").text.startswith(
        "eu-central-1 / ")
    assert _entry(_child(result, EC2), "web").text.startswith("eu-central-1 / ")


def test_a_subject_keeps_every_part_whatever_shape_the_tree_has() -> None:
    """§5: the account and the region are in a subject though neither is in the
    path, so a history is found again after a tree has changed its shape."""
    alone = _one_account(series_keep=30)
    _keeping(alone)
    flat = _readings(alone, functions=ONE_COLLECTOR,
                     metrics={"collector": _point(timedelta(minutes=2))})
    several = _build(series_keep=30,
                     accounts=[{"name": "live", "regions": TWO_REGIONS},
                               {"name": "backup"}])
    _keeping(several)
    deep = _readings(several, functions=ONE_COLLECTOR,
                     metrics={"collector": _point(timedelta(minutes=2))})
    assert {run.subject for run in _kind(flat, "run")} == {COLLECTOR}
    assert COLLECTOR in {run.subject for run in _kind(deep, "run")}


def test_a_region_a_reading_names_and_the_configuration_does_not_keeps_its_node(
        ) -> None:
    """Graded by a configuration that has moved on, no reading is graded away: a
    region the readings name stands behind the regions the configuration names."""
    check = _one_account(regions=TWO_REGIONS)
    typed = [
        Measurement({"aspect": None, "kind": "estate", "credentials": None,
                     "accounts": [{"name": "live", "outcome": "read"}]},
                    subject="accounts/live", state="live=read"),
        Measurement({"aspect": None, "kind": "account", "account": "live",
                     "outcome": "read", "error": None, "renewal": None}),
        Measurement({"aspect": LAMBDA, "kind": "function", "account": "live",
                     "region": "us-east-1", "name": "collector", "errors": 0,
                     "at": "2026-08-10T11:58:00Z", "log_status": None,
                     "log_note": None, "log_error": None}),
        Measurement({"aspect": LAMBDA, "kind": "unreadable", "account": "live",
                     "region": "ap-south-1", "error": "not allowed"}),
    ]
    leaf = _child(run_check(check, measurements=typed), LAMBDA)
    assert [(node.name, [function.name for function in node.children],
             node.stored_code) for node in leaf.children] == [
        ("eu-central-1", [], StatusCode.OK), ("eu-west-1", [], StatusCode.OK),
        ("ap-south-1", [], StatusCode.WARN),
        ("us-east-1", ["collector"], StatusCode.OK)]


def test_one_account_with_no_reading_of_its_own_has_nothing_hung_beneath_it(
        ) -> None:
    """The guard for readings no measurement of ours produced: an estate that
    names the account as read, and no reading of the account."""
    typed = [Measurement({"aspect": None, "kind": "estate", "credentials": None,
                          "accounts": [{"name": "live", "outcome": "read"}]},
                         subject="accounts/live", state="live=read")]
    result = run_check(_one_account(), measurements=typed)
    assert (result.code, result.children) == (StatusCode.UNDEFINED, ())
    assert _texts(result) == ["1 account, 1 account/region pair in scope"]


def test_an_account_s_title_and_about_are_not_shown_and_the_log_says_so_once(
        caplog: pytest.LogCaptureFixture) -> None:
    """§2: they label the account's node, and a check that names one account has
    none. The configuration loads, the check's own labels stand, and the log says
    once, when the check is loaded, which keys are read and not shown."""
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        check = _build(title="AWS", about="The team's account.", accounts=[
            {"name": "live", "title": "Live", "about": "Customer-facing."}])
        _stub(check)
        result = run_check(check)
        run_check(check)
    said = [record.getMessage() for record in caplog.records
            if "not shown" in record.getMessage()]
    assert said == [
        "/team/aws: the 'title' and 'about' of account 'live' are not shown: a "
        "check that names one account has no node for it, and its aspects hang "
        "beneath the check's own. Say them in the check's own 'title' and 'about'."]
    assert (check.title, check.about) == ("AWS", "The team's account.")
    assert all((node.title, node.about) == ("", "") for node in _nodes(result))


def test_the_log_names_the_one_key_an_account_carries(
        caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        _build(accounts=[{"name": "live", "about": "Customer-facing."}])
    assert [record.getMessage() for record in caplog.records
            if "not shown" in record.getMessage()] == [
        "/team/aws: the 'about' of account 'live' is not shown: a check that "
        "names one account has no node for it, and its aspects hang beneath the "
        "check's own. Say it in the check's own 'about'."]


def test_nothing_is_said_of_labels_that_are_shown_or_not_written(
        caplog: pytest.LogCaptureFixture) -> None:
    """Several accounts show theirs on their own nodes, and one account that
    carries neither has nothing to move."""
    with caplog.at_level(logging.INFO, logger="little_sister_aws.aws"):
        _build(accounts=[{"name": "live", "about": "Customer-facing."},
                         {"name": "backup", "title": "Backup"}])
        _build(accounts=[{"name": "live", "about": "  "}])
    assert [record.getMessage() for record in caplog.records
            if "not shown" in record.getMessage()] == []


def test_the_check_s_page_says_its_one_account_s_regions_and_credentials() -> None:
    """§2: what the account's node would have said of its configuration — the
    regions it is read in, its own where it names them, and where its credentials
    come from — the check's page says in its place."""
    alone = _build(profile=PRIMARY, accounts=[
        {"name": "live", "role_arn": ROLE_LIVE, "regions": ["eu-west-1"]}])
    summary = alone.config_summary()
    assert "**regions:** eu-west-1" in summary
    assert "default regions" not in summary
    assert f"**credentials:** assumed role, from profile {PRIMARY}" in summary

    several = _build(profile=PRIMARY).config_summary()
    assert "**default regions:** eu-central-1" in several
    assert f"**credentials:** profile {PRIMARY}" in several


def test_an_account_read_with_configured_keys_says_so(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Static keys are neither a profile nor the ambient chain, and the line that
    says where an account's credentials come from names them."""
    monkeypatch.setenv("AWS_KEY", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_SECRET", "not-a-secret")
    secrets = {"access_key_id": "env://AWS_KEY",
               "secret_access_key": "env://AWS_SECRET"}
    alone = _build(secrets=secrets, accounts=[{"name": "live"}])
    assert "**credentials:** configured keys" in alone.config_summary()
    several = _build(secrets=secrets)
    _stub(several)
    live = _child(run_check(several), "live")
    assert "**credentials:** assumed role, from configured keys" in live.config


def test_the_pin_note_names_the_node_that_silences_the_account() -> None:
    """The account's own where a check names several, and the check's where it
    names one and the account has none — and an aspect whose subjects are nodes
    says that a function's, a pipeline's or a job name's node is what is pinned."""
    several, alone = _build(), _one_account()
    assert several.subnode_labels[EC2]["about"].rstrip().endswith(
        "pin the line you are working on and the rest keeps reporting. The "
        "account node above silences the whole account.")
    assert alone.subnode_labels[EC2]["about"].rstrip().endswith(
        "pin the line you are working on and the rest keeps reporting. The "
        "check's own node above silences the whole account.")
    for aspect, subject in ((LAMBDA, "function"), (CODEPIPELINE, "pipeline"),
                            (BATCH, "job name")):
        assert alone.subnode_labels[aspect]["about"].rstrip().endswith(
            f"Each {subject}'s node can be put into maintenance on its own — pin "
            f"the {subject} you are working on and the rest keeps reporting. The "
            "check's own node above silences the whole account."), aspect
        assert several.subnode_labels[aspect]["about"].rstrip().endswith(
            f"pin the {subject} you are working on and the rest keeps reporting. "
            "The account node above silences the whole account."), aspect
    assert alone.subnode_labels[CLOUDWATCH]["about"].rstrip().endswith(
        "pin the line you are working on and the rest keeps reporting. The "
        "check's own node above silences the whole account.")
    # A token nothing declared would stand in the text as it was written.
    assert not any("pin_note" in labels["about"]
                   for labels in alone.subnode_labels.values())


# --- a job name's node, a queue's and a pipeline's (ADR-0009) ---------------------
#
# Each test below is one sentence of ADR-0009, with values that make the sentence
# false if the code is wrong. What a check keeps of a pipeline is bound here, as a
# function's kept runs are, and no engine runs (little-sister ADR-0113 decision 4).

#: The one job name and the one pipeline most of these tests read, as a subject
#: spells each.
ETL = "batch/live/eu-central-1/nightly/etl"
DEPLOY = "codepipeline/live/eu-central-1/running-deploy"

#: A page of four executions, the newest first: one on its way, one that failed, one
#: a newer one overtook, and one that deployed.
FOUR_EXECUTIONS = [
    _execution("InProgress", started=timedelta(minutes=5), eid="e-4"),
    _execution("Failed", started=timedelta(hours=1), updated=timedelta(minutes=50),
               eid="e-3"),
    _execution("Superseded", started=timedelta(hours=2), updated=timedelta(hours=1),
               eid="e-2"),
    _execution(started=timedelta(days=1), updated=timedelta(hours=23), eid="e-1")]


def _holding(check: AwsCheck,
             held: Mapping[str, Sequence[Any]] | None = None) -> list[str]:
    """Bind what *check* finds kept of a pipeline, and answer the list every subject
    it asks for lands in. An execution is given as the id it names and the status
    its record keeps — `None` for a record that keeps none — and then started as
    many days ago as its place from the end of the list, the last one a day ago; a
    third value says how long ago it started instead. A record given whole is
    handed over as it is."""
    kept = held or {}
    asked: list[str] = []

    def reader(subject: str) -> tuple[SeriesRecord, ...]:
        asked.append(subject)
        executions = kept.get(subject, ())
        records: list[SeriesRecord] = []
        for index, one in enumerate(executions):
            if isinstance(one, SeriesRecord):
                records.append(one)
                continue
            eid, status, *started = one
            ago = started[0] if started else timedelta(
                days=len(executions) - index)
            records.append(SeriesRecord(
                {"at": _stamp(ago),
                 **({} if status is None else {"status": status})}, NOW, eid))
        return tuple(records)

    check.bind_kept(reader)
    return asked


def _executions_read(check: AwsCheck, page: Sequence[dict[str, Any]],
                     held: Sequence[Any] = ()
                     ) -> tuple[tuple[Measurement, ...], list[str]]:
    """One poll of the one pipeline whose executions are *page*, by a check that
    holds *held* of it: what the poll read, and the subjects whose history it
    asked for."""
    asked = _holding(check, {DEPLOY: held})
    taken = _readings(check, pipelines=ONE_PIPELINE,
                      executions={"running-deploy": list(page)})
    return taken, asked


def _deploy(check: AwsCheck, taken: Sequence[Measurement]) -> CheckResult:
    """The `running-deploy` pipeline's node, graded from what *check* read."""
    return _node(_aspect(check, run_check(check, measurements=taken), CODEPIPELINE),
                 "running-deploy")


def test_a_job_name_has_a_node_beneath_its_queue_s_named_by_what_aws_calls_it(
        ) -> None:
    """§1: one whose newest run succeeded, one whose failed and one that only waits
    alike — a node each beneath its queue's, with the job name's line as its only
    one, and the queues and the job names in name order."""
    leaf = _batch(
        _one_account(),
        queues={"eu-central-1": [[_queue("nightly"), _queue("hourly")]]},
        jobs={("nightly", "SUCCEEDED"): [[_job("well", job_id="j-1",
                                               created=timedelta(hours=1))]],
              ("nightly", "FAILED"): [[_job("failed", "FAILED", job_id="j-2",
                                            created=timedelta(hours=1))]],
              ("hourly", "RUNNABLE"): [[_job("waiting", "RUNNABLE", job_id="j-3",
                                             created=timedelta(hours=1))]]})
    assert [(queue.name, [(node.name, node.stored_code, len(node.reason_entries))
                          for node in queue.children])
            for queue in leaf.children] == [
        ("hourly", [("waiting", StatusCode.WARN, 1)]),
        ("nightly", [("failed", StatusCode.ERROR, 1), ("well", StatusCode.OK, 1)])]
    assert all(node.children == ()
               for queue in leaf.children for node in queue.children)
    # `batch` keeps the count, which is of queues, and nothing else of its own.
    assert _texts(leaf) == ["2 job queues in scope (eu-central-1)"]


def test_a_queue_is_a_level_where_an_account_holds_one_queue_alone() -> None:
    """§2: a queue is nothing a configuration names, so its level does not come and
    go with the queues AWS answers."""
    leaf = _batch(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=1))]]})
    assert [(queue.name, [node.name for node in queue.children])
            for queue in leaf.children] == [("nightly", ["etl"])]


def test_a_queue_s_node_carries_what_the_queue_says_of_itself() -> None:
    """§2: that it is invalid or disabled, holds no jobs or was read only in part —
    on a line that carries the queue's reading and names no subject, under the slug
    it had — and nothing at all where there is nothing to say."""
    check = _one_account()
    taken = _readings(
        check,
        queues={"eu-central-1": [[_queue("idle", state="DISABLED"), _queue()]]},
        jobs={("nightly", "SUCCEEDED"): [[_job("etl",
                                               created=timedelta(hours=1))]]})
    idle, nightly = _aspect(check, run_check(check, measurements=taken),
                            BATCH).children
    (reading,) = [queue for queue in _kind(taken, "queue")
                  if queue.record["name"] == "idle"]
    (line,) = idle.reason_entries
    assert (line.code, line.subject, line.data, line.slug) == (
        StatusCode.WARN, "", dict(reading.record), "eu-central-1-idle")
    assert line.text == (
        "[idle](https://eu-central-1.console.aws.amazon.com/batch/home"
        "?region=eu-central-1#queues): the queue is DISABLED and accepts no new "
        "jobs · no jobs found")
    assert (nightly.stored_code, nightly.reason_entries, nightly.for_record) == (
        StatusCode.OK, (), ())


def test_a_queue_s_node_says_that_its_job_names_are_complete_in_every_run_that_lists_it(
        ) -> None:
    """§2: so a job name that stopped running leaves with the next run — the last
    one too. A queue read at its cap says it as well: a name whose runs are no
    longer among those read would otherwise stand stale beneath it, and it returns
    with its next run (little-sister ADR-0109 decision 3)."""
    jobs = {("nightly", "SUCCEEDED"): [[
        _job("etl", job_id="j-0", created=timedelta(hours=1)),
        _job("etl", job_id="j-1", created=timedelta(hours=2)),
        _job("weekly", job_id="j-2", created=timedelta(days=6))]]}
    whole = _child(_batch(_one_account(batch={"max_jobs": 3}), queues=ONE_QUEUE,
                          jobs=jobs), "nightly")
    capped = _child(_batch(_one_account(batch={"max_jobs": 2}), queues=ONE_QUEUE,
                           jobs=jobs), "nightly")
    empty = _child(_batch(_one_account(), queues=ONE_QUEUE), "nightly")
    assert (whole.children_complete, [node.name for node in whole.children],
            _texts(whole)) == (True, ["etl", "weekly"], [])
    assert (capped.children_complete, [node.name for node in capped.children]) == (
        True, ["etl"])
    assert _texts(capped)[0].endswith(
        ": only the newest 2 jobs per status were read")
    assert (empty.children_complete, empty.children) == (True, ())


def test_the_node_the_queues_hang_on_says_that_its_children_are_complete() -> None:
    """§8: where their listing was read, so a queue that was deleted, or that
    `ignore_queue_patterns` now names, leaves with the next good run; where it
    could not be read the node leaves that unsaid, and the queues stay."""
    read = _batch(_one_account(), queues=ONE_QUEUE)
    unread = _batch(_one_account(), batch_unreadable={"eu-central-1"})
    none = _batch(_one_account())
    assert (read.children_complete, [node.name for node in read.children]) == (
        True, ["nightly"])
    assert (unread.children_complete, unread.children) == (False, ())
    assert (none.children_complete, none.children) == (True, ())


def test_a_job_name_s_line_names_the_job_name_and_carries_no_run() -> None:
    """§3: written from every run of the name, so it carries none of them — and it
    names the one object they all are, which is what makes the node stand for the
    job name. Its sentence is the one it had, under the slug it had."""
    leaf = _batch(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", job_id="j-1",
                                         created=timedelta(hours=3),
                                         started=timedelta(hours=3),
                                         stopped=timedelta(hours=2))]],
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING", job_id="j-2",
                                       started=timedelta(minutes=4))]]})
    (line,) = _node(leaf, "etl").reason_entries
    assert (line.subject, line.data, line.slug) == (
        ETL, None, "eu-central-1-nightly-etl")
    assert line.text == (
        "[etl](https://eu-central-1.console.aws.amazon.com/batch/home"
        "?region=eu-central-1#jobs/detail/j-1): SUCCEEDED 2h ago, ran 1h · "
        "1 running (4m)")


def test_a_job_name_whose_runs_neither_ended_nor_run_nor_wait_says_so() -> None:
    """§3, §4: the measuring half asks Batch for no other status, so only a reading
    this process did not take names one. Its job name has its node all the same,
    since the run is kept under the name: the line says what is true of the name
    and grades nothing against it, and nothing is said of the run for the record."""
    batch = _batch(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNING"): [[_job("etl", "STARTING", job_id="j-1",
                                       created=timedelta(minutes=2))]]})
    node = _node(batch, "etl")
    (line,) = node.reason_entries
    assert (line.subject, line.code, line.text.split("): ")[-1]) == (
        ETL, StatusCode.OK, "no run finished, running or waiting")
    assert node.for_record == ()


def test_a_job_name_s_line_prints_neither_its_region_nor_its_queue() -> None:
    """§3: the levels say both where an account reads several regions, and nothing
    has to say the region where it reads one — and a slug keeps every part, as
    ADR-0001 has it. A queue's own line prints no region either."""
    leaf = _batch(_one_account(regions=TWO_REGIONS),
                  queues={"eu-west-1": [[_queue(state="DISABLED")]]},
                  jobs={("nightly", "SUCCEEDED"): [[
                      _job("etl", created=timedelta(hours=1))]]})
    queue = _child(_child(leaf, "eu-west-1"), "nightly")
    (said,) = queue.reason_entries
    (line,) = _child(queue, "etl").reason_entries
    assert (said.slug, line.slug) == ("eu-west-1-nightly", "eu-west-1-nightly-etl")
    assert said.text.startswith("[nightly](https://eu-west-1.console")
    assert line.text.startswith("[etl](https://eu-west-1.console")
    assert line.subject == "batch/live/eu-west-1/nightly/etl"

    one = _batch(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job("etl", created=timedelta(hours=1))]]})
    assert _node(one, "etl").reason[0].text.startswith("[etl](")


def test_every_run_a_poll_read_is_said_for_the_record_with_a_verdict_of_its_own(
        ) -> None:
    """§4: one that succeeded passes and one that failed fails, in a sentence that
    says how long it waited and how long it ran; one that still runs or waits
    passes, and says for how long — each on a line no node shows, which carries the
    run's record and names its job name."""
    check = _one_account()
    taken = _readings(check, queues=ONE_QUEUE, jobs={
        ("nightly", "SUCCEEDED"): [[_job(
            "etl", job_id="j-1", created=timedelta(hours=3),
            started=timedelta(hours=2, minutes=50), stopped=timedelta(hours=2))]],
        ("nightly", "FAILED"): [[_job(
            "etl", "FAILED", job_id="j-2", created=timedelta(hours=5),
            started=timedelta(hours=4, minutes=58),
            stopped=timedelta(hours=4, minutes=45))]],
        ("nightly", "RUNNING"): [[_job(
            "etl", "RUNNING", job_id="j-3", created=timedelta(minutes=9),
            started=timedelta(minutes=4))]],
        ("nightly", "RUNNABLE"): [[_job(
            "etl", "RUNNABLE", job_id="j-4", created=timedelta(minutes=5))]]})
    node = _node(_aspect(check, run_check(check, measurements=taken), BATCH), "etl")
    runs = _kind(taken, "job")
    assert len(node.reason_entries) == 1
    assert [(line.code, line.text, line.subject, line.data)
            for line in node.for_record] == [
        (StatusCode.OK, "SUCCEEDED, waited 10m, ran 50m", ETL,
         dict(runs[0].record)),
        (StatusCode.ERROR, "FAILED, waited 2m, ran 13m", ETL, dict(runs[1].record)),
        (StatusCode.OK, "RUNNING for 4m", ETL, dict(runs[2].record)),
        (StatusCode.OK, "RUNNABLE for 5m", ETL, dict(runs[3].record))]


@pytest.mark.parametrize(("status", "times", "code", "text"), [
    ("RUNNING", {"started": timedelta(hours=2)}, StatusCode.OK, "RUNNING for 2h"),
    ("RUNNING", {"started": timedelta(hours=2, seconds=1)}, StatusCode.WARN,
     "RUNNING for 2h, past max_run_time"),
    ("RUNNABLE", {"created": timedelta(minutes=30)}, StatusCode.OK,
     "RUNNABLE for 30m"),
    ("RUNNABLE", {"created": timedelta(minutes=30, seconds=1)}, StatusCode.WARN,
     "RUNNABLE for 30m, past max_wait_time"),
    # A wait is counted from when the job was created: it never started.
    ("RUNNABLE", {"created": timedelta(hours=1), "started": timedelta(minutes=1)},
     StatusCode.WARN, "RUNNABLE for 1h, past max_wait_time"),
    # A run counts from when it started, however long it waited before.
    ("RUNNING", {"created": timedelta(hours=9), "started": timedelta(minutes=1)},
     StatusCode.OK, "RUNNING for 1m"),
    # No instant to count from: nothing to hold against the bound.
    ("RUNNING", {}, StatusCode.OK, "RUNNING"),
    ("RUNNABLE", {}, StatusCode.OK, "RUNNABLE"),
    # A finished run says the spans its instants give, and no more.
    ("SUCCEEDED", {"started": timedelta(minutes=9), "stopped": timedelta(minutes=4)},
     StatusCode.OK, "SUCCEEDED, ran 5m"),
    ("FAILED", {"created": timedelta(minutes=9), "stopped": timedelta(minutes=4)},
     StatusCode.ERROR, "FAILED"),
])
def test_a_run_in_flight_warns_for_the_record_once_it_is_past_its_bound(
        status: str, times: dict[str, timedelta], code: StatusCode,
        text: str) -> None:
    """§4: past `max_run_time` where it runs and past `max_wait_time` where it
    waits, the bounds its job name's line is graded by — *more than*, as there."""
    leaf = _batch(_one_account(), queues=ONE_QUEUE,
                  jobs={("nightly", status): [[_job("etl", status, **times)]]})
    assert [(line.code, line.text) for line in _node(leaf, "etl").for_record] == [
        (code, text)]


def test_the_bounds_a_run_is_held_against_are_the_configuration_s() -> None:
    check = _one_account(batch={"max_run_time": "10m", "max_wait_time": "2m"})
    leaf = _batch(check, queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING", job_id="j-1",
                                       started=timedelta(minutes=20))]],
        ("nightly", "RUNNABLE"): [[_job("etl", "RUNNABLE", job_id="j-2",
                                        created=timedelta(minutes=3))]]})
    assert [(line.code, line.text) for line in _node(leaf, "etl").for_record] == [
        (StatusCode.WARN, "RUNNING for 20m, past max_run_time"),
        (StatusCode.WARN, "RUNNABLE for 3m, past max_wait_time")]


def test_a_run_s_verdict_for_the_record_is_measured_to_the_instant_it_is_graded(
        ) -> None:
    """§4: graded again three hours on, over the reading the poll took, a run that
    was within its bound is past it."""
    check = _one_account()
    taken = _readings(check, queues=ONE_QUEUE, jobs={
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING",
                                       started=timedelta(minutes=4))]]})
    later = run_check(check, measurements=taken, now=NOW + timedelta(hours=3))
    assert [(line.code, line.text)
            for line in _node(_aspect(check, later, BATCH), "etl").for_record] == [
        (StatusCode.WARN, "RUNNING for 3h 4m, past max_run_time")]


def test_a_run_takes_its_last_verdict_from_the_poll_that_reads_it_finished(
        ) -> None:
    """§4: read running past its bound it warns, and read finished it is the same
    run, by its `jobId`, and says how it ended."""
    def said(status: str, **times: timedelta
             ) -> list[tuple[str, StatusCode | None, str]]:
        check = _one_account()
        taken = _readings(check, queues=ONE_QUEUE, jobs={
            ("nightly", status): [[_job("etl", status, job_id="j-9", **times)]]})
        node = _node(_aspect(check, run_check(check, measurements=taken), BATCH),
                     "etl")
        (run,) = _kind(taken, "job")
        return [(run.identity, line.code, line.text) for line in node.for_record]

    assert said("RUNNING", created=timedelta(hours=4),
                started=timedelta(hours=3)) == [
        ("j-9", StatusCode.WARN, "RUNNING for 3h, past max_run_time")]
    assert said("SUCCEEDED", created=timedelta(hours=4), started=timedelta(hours=3),
                stopped=timedelta(minutes=1)) == [
        ("j-9", StatusCode.OK, "SUCCEEDED, waited 1h, ran 2h 59m")]


def test_a_retry_in_flight_passes_for_the_record_and_leaves_its_job_name_red(
        ) -> None:
    """§3, §4: the line is the name's, graded on its newest finished run, so a
    retry submitted after a failure does not turn it green; each run's verdict is
    its own."""
    leaf = _batch(_one_account(), queues=ONE_QUEUE, jobs={
        ("nightly", "FAILED"): [[_job("etl", "FAILED", job_id="j-1",
                                      created=timedelta(hours=1),
                                      started=timedelta(hours=1),
                                      stopped=timedelta(minutes=50))]],
        ("nightly", "RUNNING"): [[_job("etl", "RUNNING", job_id="j-2",
                                       created=timedelta(minutes=5),
                                       started=timedelta(minutes=4))]]})
    node = _node(leaf, "etl")
    assert node.stored_code is StatusCode.ERROR
    assert [line.code for line in node.for_record] == [
        StatusCode.ERROR, StatusCode.OK]


def test_runs_typed_by_hand_are_said_for_the_record_as_the_ones_a_poll_read(
        ) -> None:
    """The grading reads the records and nothing else (little-sister ADR-0086
    decision 6): a run this process never read stands on its job name's node like
    one it did, kept before a record carried its two spans — and one in a status
    this aspect does not read is said nothing of."""
    record = {"aspect": BATCH, "account": "live", "region": "eu-central-1"}

    def run(job_id: str, status: str) -> Measurement:
        return Measurement(
            {**record, "kind": "job", "queue": "nightly", "name": "etl",
             "id": job_id, "status": status, "reason": None,
             "created": {"at": "2026-08-10T09:00:00Z"},
             "started": "2026-08-10T09:10:00Z", "ended": "2026-08-10T10:00:00Z",
             "at": "2026-08-10T10:00:00Z"},
            subject=ETL, identity=job_id)

    typed = [
        Measurement({"aspect": None, "kind": "estate", "credentials": None,
                     "accounts": [{"name": "live", "outcome": "read"}]},
                    subject="accounts/live", state="live=read"),
        Measurement({"aspect": None, "kind": "account", "account": "live",
                     "outcome": "read", "error": None, "renewal": None}),
        Measurement({**record, "kind": "queue", "name": "nightly",
                     "state": "ENABLED", "status": "VALID", "reason": None,
                     "capped": False}),
        run("j-1", "FAILED"), run("j-2", "PENDING")]
    node = _node(_child(run_check(_one_account(), measurements=typed), BATCH),
                 "etl")
    (said,) = node.for_record
    assert (said.code, said.text, said.subject, said.data) == (
        StatusCode.ERROR, "FAILED, waited 10m, ran 50m", ETL,
        dict(typed[3].record))
    assert node.reason[0].subject == ETL


def test_a_job_name_the_list_hides_is_not_kept() -> None:
    """§7: the measuring half leaves out the runs of a name `ignore_name_patterns`
    hides, so the name has no series and no node — and a run read before the list
    named it is said nothing of, and has no node either."""
    jobs = {("nightly", "FAILED"): [[_job("smoke-test", "FAILED", job_id="j-1",
                                          created=timedelta(hours=1))]],
            ("nightly", "SUCCEEDED"): [[_job("etl", job_id="j-2",
                                             created=timedelta(hours=1))]]}
    hiding = _one_account(batch={"ignore_name_patterns": ["SMOKE"]})
    assert [run.record["name"] for run in _kind(
        _readings(hiding, queues=ONE_QUEUE, jobs=jobs), "job")] == ["etl"]

    before = _readings(_one_account(), queues=ONE_QUEUE, jobs=jobs)
    assert sorted(run.record["name"] for run in _kind(before, "job")) == [
        "etl", "smoke-test"]
    queue = _child(_child(run_check(hiding, measurements=before), BATCH),
                   "nightly")
    assert [node.name for node in queue.children] == ["etl"]
    assert {line.subject for node in _nodes(queue)
            for line in node.for_record} == {ETL}

    bare = _child(_batch(_one_account(batch={
        "ignore_name_patterns": ["smoke", "etl"]}), queues=ONE_QUEUE, jobs=jobs),
        "nightly")
    assert bare.children == ()
    assert _texts(bare)[0].endswith(": no jobs found")


def test_a_display_name_rule_gives_a_job_name_and_a_pipeline_a_title_and_no_path(
        ) -> None:
    """§1: `shorten` reaches the node's title and its line's label, and neither the
    node's name nor the slug — and a queue is named as it is, whatever the rules
    say."""
    check = _one_account(shorten=[{"from": "running-"}])
    _stub(check, queues={"eu-central-1": [[_queue("running-queue")]]},
          jobs={("running-queue", "SUCCEEDED"): [[
              _job("running-etl", job_id="j-1", created=timedelta(hours=1)),
              _job("plain", job_id="j-2", created=timedelta(hours=1))]]},
          pipelines={"eu-central-1": [["running-deploy", "bare"]]},
          executions={"running-deploy": [_execution()], "bare": [_execution()]})
    result = run_check(check)
    queue = _child(_child(result, BATCH), "running-queue")
    assert (queue.name, queue.title) == ("running-queue", "")
    short, untouched = _child(queue, "running-etl"), _child(queue, "plain")
    assert (short.name, short.title) == ("running-etl", "etl")
    assert short.reason[0].slug == "eu-central-1-running-queue-running-etl"
    assert short.reason[0].text.startswith("[etl](")
    assert (untouched.name, untouched.title) == ("plain", "")
    pipelines = _child(result, CODEPIPELINE)
    deploy, bare = _child(pipelines, "running-deploy"), _child(pipelines, "bare")
    assert (deploy.name, deploy.title) == ("running-deploy", "deploy")
    assert deploy.reason[0].slug == "eu-central-1-running-deploy"
    assert deploy.reason[0].text.startswith("[deploy](")
    assert (bare.name, bare.title) == ("bare", "")


def test_a_queue_a_job_name_and_a_pipeline_say_where_they_are_and_who_names_them(
        ) -> None:
    """§1, §2: a path may name neither the account nor the region, so each node's
    description does — a job name's queue is in every path. Each is named by AWS
    and says so (little-sister ADR-0118), so a queue called `lambda` is not the
    `lambda` aspect. A queue's node is the box its job names stand in and declines
    the density trade; a job name's and a pipeline's declare nothing of it."""
    check = _one_account()
    _stub(check, queues={"eu-central-1": [[_queue("lambda")]]},
          jobs={("lambda", "SUCCEEDED"): [[_job("ec2",
                                                created=timedelta(hours=1))]]},
          pipelines={"eu-central-1": [["batch"]]},
          executions={"batch": [_execution()]})
    result = run_check(check)
    queue = _child(_child(result, BATCH), "lambda")
    job, pipeline = _child(queue, "ec2"), _child(_child(result, CODEPIPELINE),
                                                 "batch")
    assert [(node.description, node.dynamic, node.show_when_quiet)
            for node in (queue, job, pipeline)] == [
        ("Batch job queue in live, eu-central-1", True, True),
        ("Batch job name in live, eu-central-1", True, None),
        ("CodePipeline pipeline in live, eu-central-1", True, None)]
    assert {aspect.dynamic for aspect in result.children} == {False}
    assert check.subnode_show_when_quiet[BATCH] is True
    assert check.subnode_show_when_quiet[CODEPIPELINE] is True


@pytest.mark.parametrize(("aspect", "stub", "unreadable", "noun", "described"), [
    (BATCH, {"queues": {"eu-central-1": [[_queue("nightly")]]}},
     "batch_unreadable", "job queues", "Batch job queues in live"),
    (CODEPIPELINE, {"pipelines": {"eu-central-1": [["deploy"]]},
                    "executions": {"deploy": [_execution()]}},
     "pipelines_unreadable", "pipelines", "CodePipeline pipelines in live"),
])
def test_a_queue_and_a_pipeline_hang_beneath_their_region_s_node_where_several_are_read(
        aspect: str, stub: dict[str, Any], unreadable: str, noun: str,
        described: str) -> None:
    """§8, by ADR-0007 §3: a region's node is named by the region and grades nothing
    of its own unless the region could not be read; it says that its children are
    complete where it was read, declines the density trade and says that the
    configuration names it — and the aspect's node keeps the count and says
    nothing of its children."""
    check = _one_account(regions=TWO_REGIONS)
    _stub(check, **stub, **{unreadable: {"eu-west-1"}})
    leaf = _child(run_check(check), aspect)
    read, unread = leaf.children
    assert (read.name, read.stored_code, _texts(read), read.children_complete,
            len(read.children)) == ("eu-central-1", StatusCode.OK, [], True, 1)
    assert (unread.name, unread.stored_code, unread.children,
            unread.children_complete) == ("eu-west-1", StatusCode.WARN, (), False)
    assert _texts(unread)[0].startswith(f"eu-west-1: {noun} cannot be read")
    assert [(node.description, node.show_when_quiet, node.dynamic)
            for node in leaf.children] == [
        (f"{described}, eu-central-1", True, True),
        (f"{described}, eu-west-1", True, True)]
    assert (leaf.children_complete, leaf.description, leaf.dynamic) == (
        False, described, False)
    assert [entry.slug for entry in leaf.reason] == ["scope"]


def test_two_regions_queues_of_one_name_are_told_apart_by_their_region_s_level(
        ) -> None:
    """§8: and by nothing else in a path — while each job name's subject, and the
    roster, name the region."""
    leaf = _batch(_one_account(regions=TWO_REGIONS),
                  queues={"eu-central-1": [[_queue()]], "eu-west-1": [[_queue()]]},
                  jobs={("nightly", "SUCCEEDED"): [[
                      _job("etl", created=timedelta(hours=1))]]})
    assert [(region.name, [(queue.name, [node.name for node in queue.children])
                           for queue in region.children])
            for region in leaf.children] == [
        ("eu-central-1", [("nightly", ["etl"])]),
        ("eu-west-1", [("nightly", ["etl"])])]
    assert _texts(leaf) == ["2 job queues in scope (eu-central-1, eu-west-1)"]
    assert [line.split("]")[0] for line in leaf.report.splitlines()] == [
        "- eu-central-1 / [nightly", "- eu-west-1 / [nightly"]
    assert {line.subject for node in _nodes(leaf) for line in node.reason_entries
            if line.subject} == {ETL, "batch/live/eu-west-1/nightly/etl"}


def test_every_pipeline_has_a_node_beneath_codepipeline_named_by_what_aws_calls_it(
        ) -> None:
    """§1: one that deployed, one that failed and one that never ran alike — a node
    each, in name order, with the pipeline's line as its only one."""
    leaf = _pipelines(_one_account(),
                      pipelines={"eu-central-1": [["well", "failed", "never"]]},
                      executions={"well": [_execution()],
                                  "failed": [_execution("Failed")]})
    assert [(node.name, node.stored_code, len(node.reason_entries))
            for node in leaf.children] == [
        ("failed", StatusCode.ERROR, 1), ("never", StatusCode.WARN, 1),
        ("well", StatusCode.OK, 1)]
    assert all(node.children == () for node in leaf.children)


def test_a_pipeline_s_line_carries_its_newest_execution() -> None:
    """§5: the record of the reading it was written from, and the pipeline as its
    subject — the reading's own, and what makes the node stand for the pipeline. A
    check that keeps no series reads that execution and no other."""
    check = _one_account()
    taken = _readings(check, pipelines=ONE_PIPELINE, executions={"running-deploy": [
        _execution(started=timedelta(days=1), eid="e-1"),
        _execution("Failed", started=timedelta(hours=1), eid="e-2")]})
    (newest,) = _kind(taken, "pipeline")
    node = _deploy(check, taken)
    (line,) = node.reason_entries
    assert (newest.identity, newest.subject) == ("e-2", DEPLOY)
    assert (line.subject, line.data, line.slug) == (
        DEPLOY, dict(newest.record), "eu-central-1-running-deploy")
    assert line.text.endswith(": Failed, started 1h ago")
    assert node.for_record == ()


@pytest.mark.parametrize("newest_first", [True, False])
def test_a_poll_reads_every_execution_its_pipeline_s_history_lacks(
        newest_first: bool) -> None:
    """§5: from the page the aspect already asks for, whatever order it lists them
    in — so a pipeline's series is whole from its first poll — the newest first,
    each a reading of the pipeline that names its own execution and says how long
    it took."""
    page = FOUR_EXECUTIONS if newest_first else list(reversed(FOUR_EXECUTIONS))
    taken, asked = _executions_read(_one_account(series_keep=30), page)
    assert asked == [DEPLOY]
    assert [(one.identity, one.subject, one.record["status"],
             one.record["duration_s"]) for one in _kind(taken, "pipeline")] == [
        ("e-4", DEPLOY, "InProgress", None), ("e-3", DEPLOY, "Failed", 600),
        ("e-2", DEPLOY, "Superseded", 3600), ("e-1", DEPLOY, "Succeeded", 3600)]


def test_an_execution_its_history_holds_finished_is_not_read_again() -> None:
    """§5: one it holds unfinished is, so an execution a newer one overtook while it
    ran is read to its end — and neither a word this type does not know nor a
    record that keeps no status ends anything. A status is the word it is whatever
    its case and its padding."""
    taken, _ = _executions_read(
        _one_account(series_keep=30), FOUR_EXECUTIONS,
        [("e-1", "Paused"), ("e-2", "Superseded"), ("e-3", "InProgress")])
    assert [one.identity for one in _kind(taken, "pipeline")] == [
        "e-4", "e-3", "e-1"]
    unsaid, _ = _executions_read(
        _one_account(series_keep=30), FOUR_EXECUTIONS,
        [("e-1", None), ("e-2", "Superseded"), ("e-3", "Failed"),
         ("e-4", "InProgress")])
    assert [one.identity for one in _kind(unsaid, "pipeline")] == ["e-4", "e-1"]
    settled, _ = _executions_read(
        _one_account(series_keep=30), FOUR_EXECUTIONS,
        [("e-1", "Succeeded"), ("e-2", "superseded"), ("e-3", " FAILED "),
         ("e-4", "InProgress")])
    assert [one.identity for one in _kind(settled, "pipeline")] == ["e-4"]


def test_an_execution_that_was_the_newest_is_read_once_more_behind_a_newer_one(
        ) -> None:
    """§5: what stood for it was its pipeline's line, so the poll that first finds a
    newer execution reads it behind that one, and it is said for the record as any
    execution behind the newest is. The next poll leaves it alone."""
    check = _one_account(series_keep=30)
    taken, _ = _executions_read(check, FOUR_EXECUTIONS, [
        ("e-1", "Succeeded"), ("e-2", "Superseded"), ("e-3", "Failed")])
    assert [one.identity for one in _kind(taken, "pipeline")] == ["e-4", "e-3"]
    assert [(line.code, line.text)
            for line in _deploy(check, taken).for_record] == [
        (StatusCode.ERROR, "Failed")]
    after, _ = _executions_read(_one_account(series_keep=30), FOUR_EXECUTIONS, [
        ("e-1", "Succeeded"), ("e-2", "Superseded"), ("e-3", "Failed"),
        ("e-4", "InProgress")])
    assert [one.identity for one in _kind(after, "pipeline")] == ["e-4"]


def test_two_kept_executions_of_one_instant_were_both_the_newest() -> None:
    """§5: which of two that started at one instant carried the line, when they
    started does not say. While one of them is the page's newest, neither is read
    behind it; once a newer execution has started, both are read once more, and the
    poll after that leaves both alone. An older one the history holds finished is
    left alone throughout."""
    hour = timedelta(hours=1)
    first = _execution("Failed", started=hour, eid="e-a")
    second = _execution(started=hour, eid="e-b")
    before = _execution(started=timedelta(hours=2), eid="e-0")
    held = [("e-0", "Succeeded", timedelta(hours=2)),
            ("e-a", "Failed", hour), ("e-b", "Succeeded", hour)]
    for page, newest in (([first, second, before], "e-a"),
                         ([second, first, before], "e-b")):
        taken, _ = _executions_read(_one_account(series_keep=30), page, held)
        assert [one.identity for one in _kind(taken, "pipeline")] == [newest]
    newer = _execution("InProgress", started=timedelta(minutes=5), eid="e-c")
    taken, _ = _executions_read(_one_account(series_keep=30),
                                [newer, first, second, before], held)
    assert [one.identity for one in _kind(taken, "pipeline")] == [
        "e-c", "e-a", "e-b"]
    after, _ = _executions_read(
        _one_account(series_keep=30), [newer, first, second, before],
        [*held, ("e-c", "InProgress", timedelta(minutes=5))])
    assert [one.identity for one in _kind(after, "pipeline")] == ["e-c"]


def test_a_new_execution_of_the_kept_newest_s_own_instant_overtakes_it() -> None:
    """§5: the page's newest is told from the history's by the execution it names
    and not by when it started. One that started at the instant the kept newest
    did, and that CodePipeline lists first, has overtaken it: the kept one is read
    once more, and left alone once both are kept."""
    hour = timedelta(hours=1)
    new = _execution(started=hour, eid="e-n")
    known = _execution(started=hour, eid="e-p")
    held = [("e-p", "Succeeded", hour)]
    taken, _ = _executions_read(_one_account(series_keep=30), [new, known], held)
    assert [one.identity for one in _kind(taken, "pipeline")] == ["e-n", "e-p"]
    after, _ = _executions_read(_one_account(series_keep=30), [new, known],
                                [*held, ("e-n", "Succeeded", hour)])
    assert [one.identity for one in _kind(after, "pipeline")] == ["e-n"]


def test_the_history_s_newest_is_the_one_that_started_last_wherever_it_stands(
        ) -> None:
    """§5: found by when each kept execution started and not by its place — and a
    record of the pipeline from before it ever ran, which names no execution and no
    start, is none of them."""
    never = SeriesRecord({"name": "running-deploy", "status": None, "at": None},
                         NOW, state=NEVER_RUN)
    taken, _ = _executions_read(_one_account(series_keep=30), FOUR_EXECUTIONS, [
        ("e-3", "Failed", timedelta(hours=1)), never,
        ("e-1", "Succeeded", timedelta(days=1)),
        ("e-2", "Superseded", timedelta(hours=2))])
    assert [one.identity for one in _kind(taken, "pipeline")] == ["e-4", "e-3"]


def test_a_newest_execution_without_an_id_is_the_history_s_newest_all_the_same(
        ) -> None:
    """§5: kept, it is a record that names no execution, and the one before it is
    read once more and then left alone — not on every poll."""
    nameless = _execution("InProgress", started=timedelta(minutes=5))
    known = _execution(started=timedelta(hours=1), eid="e-1")
    held = [("e-1", "Succeeded", timedelta(hours=1))]
    taken, _ = _executions_read(_one_account(series_keep=30), [nameless, known],
                                held)
    assert [one.identity for one in _kind(taken, "pipeline")] == ["", "e-1"]
    after, _ = _executions_read(
        _one_account(series_keep=30), [nameless, known],
        [*held, ("", "InProgress", timedelta(minutes=5))])
    assert [one.identity for one in _kind(after, "pipeline")] == [""]


def test_a_success_grown_stale_is_no_warning_once_a_newer_execution_started(
        ) -> None:
    """§6: how old a success may get is asked of the newest execution alone. While
    it is the newest, a success past `max_age` warns on its pipeline's line; read
    behind a newer one, it passed."""
    block = {"max_age_warn": "31d", "max_age_reason": "Nobody released in months."}
    stale = _execution(started=timedelta(days=40), updated=timedelta(days=40),
                       eid="e-1")
    alone = _one_account(series_keep=30, codepipeline=block)
    taken, _ = _executions_read(alone, [stale])
    assert _deploy(alone, taken).stored_code is StatusCode.WARN
    check = _one_account(series_keep=30, codepipeline=block)
    taken, _ = _executions_read(
        check, [_execution("InProgress", started=timedelta(minutes=5), eid="e-2"),
                stale], [("e-1", "Succeeded")])
    assert [(line.data["execution"], line.code, line.text)
            for line in _deploy(check, taken).for_record] == [
        ("e-1", StatusCode.OK, "Succeeded")]


def test_an_execution_superseded_as_the_newest_loses_its_error_behind_a_newer_one(
        ) -> None:
    """§6: the map grades `Superseded` an error on the line of a pipeline whose
    newest execution it is; once a newer one has started, nothing is said of it."""
    over = _execution("Superseded", started=timedelta(hours=1), eid="e-1")
    alone = _one_account(series_keep=30)
    taken, _ = _executions_read(alone, [over])
    assert _deploy(alone, taken).stored_code is StatusCode.ERROR
    check = _one_account(series_keep=30)
    taken, _ = _executions_read(
        check, [_execution(started=timedelta(minutes=5), eid="e-2"), over],
        [("e-1", "Superseded")])
    assert [one.identity for one in _kind(taken, "pipeline")] == ["e-2", "e-1"]
    assert _deploy(check, taken).for_record == ()


def test_two_executions_that_started_at_one_instant_stand_in_the_order_they_came_in(
        ) -> None:
    """§5: the first of them is the newest, in the page the measuring half reads
    and among the readings the grading is handed."""
    first = _execution("Failed", started=timedelta(hours=1), eid="e-a")
    second = _execution(started=timedelta(hours=1), eid="e-b")
    for page, newest, other in (([first, second], "e-a", "e-b"),
                                ([second, first], "e-b", "e-a")):
        check = _one_account(series_keep=30)
        taken, _ = _executions_read(check, page)
        assert [one.identity for one in _kind(taken, "pipeline")] == [newest, other]
        node = _deploy(check, taken)
        assert [line.data["execution"] for line in node.reason_entries] == [newest]
        assert [line.data["execution"] for line in node.for_record] == [other]


def test_a_pipeline_s_history_is_asked_by_its_own_account_and_region() -> None:
    """§5: a subject names the account and the region the pipeline was read in
    (ADR-0005 §4), whichever comes first in the configuration."""
    check = _build(series_keep=30)
    asked = _holding(check)
    _readings(check, pipelines={"eu-central-1": [["deploy"]],
                                "eu-west-1": [["deploy"]]},
              executions={"deploy": FOUR_EXECUTIONS})
    assert asked == ["codepipeline/live/eu-central-1/deploy",
                     "codepipeline/backup/eu-west-1/deploy"]


@pytest.mark.parametrize(("keep", "read"), [
    (1, ["e-4"]), (2, ["e-4", "e-3"]), (3, ["e-4", "e-3", "e-2"]),
    (30, ["e-4", "e-3", "e-2", "e-1"])])
def test_a_poll_reads_no_more_executions_than_the_series_keeps(
        keep: int, read: list[str]) -> None:
    """§5: the newest of the page, as many as the series keeps — an older one would
    leave the series the moment it was kept."""
    taken, _ = _executions_read(_one_account(series_keep=keep), FOUR_EXECUTIONS)
    assert [one.identity for one in _kind(taken, "pipeline")] == read


def test_a_check_that_keeps_no_series_reads_the_newest_execution_alone() -> None:
    """§5: nothing would keep the rest, so no history is asked for — and the newest
    is found wherever in the page it stands."""
    taken, asked = _executions_read(_one_account(),
                                    list(reversed(FOUR_EXECUTIONS)))
    assert ([one.identity for one in _kind(taken, "pipeline")], asked) == (
        ["e-4"], [])
    single, asked = _executions_read(_one_account(series_keep=1), FOUR_EXECUTIONS)
    assert ([one.identity for one in _kind(single, "pipeline")], asked) == (
        ["e-4"], [])


def test_an_older_execution_without_an_id_or_a_status_is_not_read() -> None:
    """§5: without an id it would be a new record at every poll, without a status
    it says nothing, and without a start it has no place — and none of them takes
    the place of one the series would keep."""
    page = [_execution("InProgress", started=timedelta(minutes=5), eid="e-4"),
            _execution("Failed", started=timedelta(hours=1)),
            _execution("", started=timedelta(hours=2), eid="e-2"),
            _execution("Failed", started=None, eid="e-0"),
            _execution(started=timedelta(days=1), eid="e-1")]
    for keep in (30, 2):
        taken, _ = _executions_read(_one_account(series_keep=keep), page)
        assert [one.identity for one in _kind(taken, "pipeline")] == ["e-4", "e-1"]


def test_reading_more_executions_asks_codepipeline_for_no_more() -> None:
    """§5: one page of a pipeline's executions, as before — the page its newest was
    always found in."""
    check = _one_account(series_keep=30)
    _holding(check)
    built = _stub(check, pipelines=ONE_PIPELINE,
                  executions={"running-deploy": FOUR_EXECUTIONS})
    assert len(_kind(measured(check), "pipeline")) == 4
    assert [session.execution_calls for session in built
            if session.execution_calls] == [[("running-deploy", 100)]]


def test_every_execution_read_beside_the_newest_is_said_for_the_record_by_its_status(
        ) -> None:
    """§6: the verdict its status has in `state_map`, as the line's has, in a
    sentence that is the status — on a line no node shows, which carries the
    execution's record and names its pipeline."""
    check = _one_account(series_keep=30)
    taken, _ = _executions_read(check, [
        _execution(started=timedelta(minutes=5), eid="e-5"),
        _execution("Failed", started=timedelta(hours=1), eid="e-4"),
        _execution("InProgress", started=timedelta(hours=2), eid="e-3"),
        _execution("Reticulating", started=timedelta(hours=3), eid="e-2"),
        _execution(started=timedelta(days=1), eid="e-1")])
    node = _deploy(check, taken)
    older = _kind(taken, "pipeline")[1:]
    assert len(node.reason_entries) == 1
    assert node.stored_code is StatusCode.OK
    assert [(line.code, line.text, line.subject, line.data)
            for line in node.for_record] == [
        (StatusCode.ERROR, "Failed", DEPLOY, dict(older[0].record)),
        (StatusCode.WARN, "InProgress", DEPLOY, dict(older[1].record)),
        (StatusCode.WARN, "Reticulating", DEPLOY, dict(older[2].record)),
        (StatusCode.OK, "Succeeded", DEPLOY, dict(older[3].record))]


def test_a_state_map_grades_an_older_execution_as_it_grades_the_newest() -> None:
    """§6: a deployment that says a failure is fine says it of every execution."""
    check = _one_account(series_keep=30,
                         codepipeline={"state_map": {"Failed": "OK"}})
    taken, _ = _executions_read(check, FOUR_EXECUTIONS)
    assert [(line.text, line.code) for line in _deploy(check, taken).for_record] == [
        ("Failed", StatusCode.OK), ("Succeeded", StatusCode.OK)]


@pytest.mark.parametrize("state_map", [
    {}, {"Superseded": "OK"}, {"SUPERSEDED": "ERROR"}])
def test_nothing_is_said_for_the_record_of_an_execution_that_was_superseded(
        state_map: dict[str, str]) -> None:
    """§6: it neither failed nor deployed, so it gets no line, whatever the map
    says of its status — and its reading is read and kept all the same."""
    check = _one_account(series_keep=30, codepipeline={"state_map": state_map})
    taken, _ = _executions_read(check, FOUR_EXECUTIONS)
    assert "e-2" in [one.identity for one in _kind(taken, "pipeline")]
    assert [line.data["execution"] for line in _deploy(check, taken).for_record] == [
        "e-3", "e-1"]


@pytest.mark.parametrize("word", ["superseded", " SUPERSEDED "])
def test_a_superseded_execution_is_the_word_whatever_its_case_and_its_padding(
        word: str) -> None:
    """§6: a status is read as `state_map` reads one."""
    check = _one_account(series_keep=30)
    taken, _ = _executions_read(check, [
        _execution(started=timedelta(minutes=5), eid="e-2"),
        _execution(word, started=timedelta(hours=1), eid="e-1")])
    assert [one.identity for one in _kind(taken, "pipeline")] == ["e-2", "e-1"]
    assert _deploy(check, taken).for_record == ()


def test_the_newest_execution_stands_on_the_line_whatever_order_its_readings_come_in(
        ) -> None:
    """§5: the grading finds it by when it started, so readings handed over in
    another order grade to the same line and the same lines for the record."""
    check = _one_account(series_keep=30)
    taken, _ = _executions_read(check, FOUR_EXECUTIONS)

    def said(readings: Sequence[Measurement]) -> tuple[list[str], list[str]]:
        node = _deploy(check, readings)
        return ([line.data["execution"] for line in node.reason_entries],
                sorted(line.data["execution"] for line in node.for_record))

    assert said(taken) == said(tuple(reversed(taken))) == (["e-4"], ["e-1", "e-3"])


def test_a_reading_that_names_no_execution_stands_behind_one_that_does() -> None:
    """§5: handed a pipeline's reading from before its first execution beside one of
    that execution, the grading writes the line from the execution — and says nothing
    for the record of a reading that names none."""
    check = _one_account()
    never = _readings(check, pipelines=ONE_PIPELINE, executions={})
    ran = _readings(check, pipelines=ONE_PIPELINE, executions={"running-deploy": [
        _execution("Failed", started=timedelta(hours=1), eid="e-1")]})
    node = _deploy(check, [*never, *_kind(ran, "pipeline")])
    (line,) = node.reason_entries
    assert (line.data["execution"], line.code) == ("e-1", StatusCode.ERROR)
    assert node.for_record == ()


def test_the_node_the_pipelines_hang_on_says_that_its_children_are_complete(
        ) -> None:
    """§8: where their listing was read, so a pipeline that was deleted, or that a
    rule now ignores, leaves with the next good run; where it could not be read the
    node leaves that unsaid, and the pipelines stay."""
    read = _pipelines(_one_account(), pipelines=ONE_PIPELINE)
    unread = _pipelines(_one_account(), pipelines_unreadable={"eu-central-1"})
    none = _pipelines(_one_account())
    assert (read.children_complete, [node.name for node in read.children]) == (
        True, ["running-deploy"])
    assert (unread.children_complete, unread.children) == (False, ())
    assert (none.children_complete, none.children) == (True, ())


def test_a_pipeline_is_counted_once_however_many_of_its_executions_a_poll_read(
        ) -> None:
    """§8: the count and the roster are of pipelines."""
    check = _one_account(series_keep=30)
    taken, _ = _executions_read(check, FOUR_EXECUTIONS)
    leaf = _aspect(check, run_check(check, measurements=taken), CODEPIPELINE)
    assert _texts(leaf) == ["1 pipeline in scope (eu-central-1)"]
    assert [node.name for node in leaf.children] == ["running-deploy"]
    assert leaf.report.splitlines() == [
        "- [running-deploy](https://eu-central-1.console.aws.amazon.com/codesuite"
        "/codepipeline/pipelines/running-deploy/executions?region=eu-central-1)"]
