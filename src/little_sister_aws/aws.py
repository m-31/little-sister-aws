"""The ``aws`` check type: one node per account, one node per aspect beneath it.

**One** check type reads every service, and the tree carries what a flat list
would otherwise have to label each line with::

    /team/aws                      this check's node — what is watched
      /team/aws/live               one node per account, its own session
        /team/aws/live/cloudwatch  one node per aspect
        /team/aws/live/ec2
        /team/aws/live/lambda
        /team/aws/live/codepipeline
        /team/aws/live/batch
      /team/aws/backup
        /team/aws/backup/cloudwatch
        …

Account first, aspect second, because the account is what an operator acts on as
a group: "staging is down for the migration" is one maintenance pin against one
node, where a flat list of every alarm would be forty. Each account's node also
absorbs its own bad news — a role that cannot be assumed reddens that account and
leaves the others reporting.

``cloudwatch``, ``ec2``, ``lambda``, ``codepipeline`` and ``batch`` are the
aspects today; SageMaker and autoscaling follow, sharing the same session, the
same frequency and the same node.

**boto3, deliberately.** The rest of the family reaches its provider over stdlib
``urllib``; signing SigV4 by hand for ``sts:AssumeRole`` and the CloudWatch API
would be a signing implementation and its test suite, bought for one dependency
saved. Everything imported from little-sister below is part of its check-authoring
surface (``architecture.md`` §11) — including ``little_sister.spans``, which is
how the library writes a span of time, so the ages on these lines read the way
the rest of the page does instead of inventing a fourth spelling. That surface is
what this module will pin with ``require_api(1)`` when it becomes
``little-sister-aws``.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import boto3
import botocore.session
from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError
from little_sister.checks import (
    Check,
    CheckError,
    CheckResult,
    Entry,
    coerce_code,
    config_markdown,
    parse_duration,
    parse_secret_refs,
    parse_subnodes,
    plain,
    register,
    resolve_text,
)
from little_sister.reasons import slug
from little_sister.spans import coarse_span, format_span
from little_sister.status import StatusCode

if TYPE_CHECKING:
    # The service clients, for their **types** only: `boto3-stubs`' per-service
    # extras are a dev dependency, so these names must not be imported at run
    # time. They are why ADR-0006 bought the extras at all — without them every
    # client is a bare `BaseClient` and strict mypy checks nothing on the one
    # call path that matters.
    from mypy_boto3_batch.client import BatchClient
    from mypy_boto3_batch.literals import JobStatusType
    from mypy_boto3_batch.type_defs import JobQueueDetailTypeDef
    from mypy_boto3_codepipeline.client import CodePipelineClient

#: This module's own logger. little-sister configures the root handlers, so an
#: ordinary module logger's records land in the same place under a name that says
#: who emitted them.
logger = logging.getLogger(__name__)

#: The region a single-region estate is most likely to mean. It is a default
#: rather than a constant now: ``regions`` is a list, and an account may override
#: it — a backup account living in Ireland is the case that made this necessary.
DEFAULT_REGIONS = ("eu-central-1",)

#: What the assumed session is called — the string CloudTrail shows beside every
#: call this check makes. It names *the reader*, which is the useful thing for
#: somebody reading an audit log, so the default names this package. An
#: installation that wants its own history in CloudTrail sets ``role_session_name``
#: and gets it; an estate that wants its own name in CloudTrail sets one, which is
#: configuration rather than something every installation inherits.
DEFAULT_ROLE_SESSION_NAME = "little-sister"

#: Where the ``AssumeRole`` call itself is made. STS has a global endpoint, but the
#: a regional endpoint is the faster and more available of the two.
DEFAULT_STS_REGION = "eu-central-1"

#: ``sso.login`` — when the check may run ``aws sso login`` itself.
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
#: an engine worker thread for as long as it runs.
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

#: The aspect names. Each is one string in **four** places: :attr:`AwsCheck.ASPECTS`,
#: the child's ``name`` (and so its node path), the :data:`SUBNODES` key its
#: built-in title/about is read from, and the configuration block its knobs — and
#: its ``enabled:`` switch — live under. They drifted once in the `github` port and
#: the leaf silently lost its display text.
#:
#: `github` keeps an ``ASPECT_CONFIG_KEY`` map because one of its seven aspects
#: reads a block named for the *feature* rather than for the node. Nothing here
#: differs, so the name is used directly; the day one does, that map is the shape
#: to copy, because renaming either half is a breaking change for somebody.
CLOUDWATCH = "cloudwatch"
EC2 = "ec2"
LAMBDA = "lambda"
CODEPIPELINE = "codepipeline"
BATCH = "batch"



#: Alarm names carrying one of these (case-insensitively, as a **substring**) are
#: not reported and not counted. Deliberately a substring and *not* a regex: an
#: alarm name is something somebody typed, and the common case is skipping a family
#: of them by a shared word.
#:
#: One default, and it is AWS's own naming rather than anybody's convention:
#: Application Auto Scaling generates ``TargetTracking`` alarms for every scaling
#: policy, and they are noise on every estate that has one. Anything else belongs in
#: a deployment's own list.
DEFAULT_IGNORE_NAME_PATTERNS = ("targettracking",)

#: An alarm whose name starts with this is tagged on its line. It is **empty by
#: default**, because a naming convention for alarms is an organization's, not a
#: check type's. Where an estate sorts alarms by a name prefix, the tree already
#: carries the account, so what is left of that split is a word — one that appears
#: only where a deployment says which prefix earns it.
DEFAULT_TAG_PREFIX = ""

#: What a line says when an alarm carries no description of its own — the field is
#: optional in CloudWatch and frequently empty.
NO_DESCRIPTION = "Alarm has no description!"

#: ``StateValue`` → the code that line reports. ``ALARM`` is the only failure.
#: ``INSUFFICIENT_DATA`` is a **WARN** rather than the cheaper reading: grading
#: everything that is not ``ALARM`` as OK makes an alarm whose metric has stopped
#: arriving look exactly like an alarm that is fine.
DEFAULT_STATE_MAP = {
    "ALARM": StatusCode.ERROR,
    "INSUFFICIENT_DATA": StatusCode.WARN,
    "OK": StatusCode.OK,
}

#: Instance states that are not an instance any more. A terminated instance lingers
#: in ``describe_instances`` for about an hour, and counting it would report a
#: duplicate that no longer exists — which is the one thing this aspect measures.
DEFAULT_EC2_IGNORE_STATES = ("terminated", "shutting-down")

#: What instances without a ``Name`` tag are grouped under. One line rather than
#: one line per instance: twenty unnamed boxes are a single fact.
NO_NAME_TAG = "(no Name tag)"

#: How long an instance may run before its line turns red. An instance is patched
#: by being replaced, so age *is* the security reading: a box that has not been
#: rebooted in a fortnight is running a fortnight-old kernel, whatever the
#: dashboard says about its metrics.
DEFAULT_MAX_AGE_SECONDS = 14 * 86400

#: More instances than this under one name is not a duplicate, it is a **fleet** —
#: a load test, a batch expansion, something deliberate. A fleet is judged by how
#: long it has been up rather than by how many it is.
DEFAULT_FLEET_SIZE = 10

#: How long a fleet may run before its line turns red. Hours, not weeks: a fleet
#: nobody tore down is the expensive kind of leftover.
DEFAULT_FLEET_MAX_AGE_SECONDS = 4 * 3600

#: CloudWatch keeps one-minute points for 15 days, five-minute for 63 and hourly
#: for 455, and returns nothing at all outside the window it is asked for. So a
#: function's newest error count is looked for in that order — the finest
#: resolution first, widening only where nothing came back. These are retention
#: facts, not preferences, which is why they are not configurable.
_ERROR_PERIODS = ((60, 15), (300, 63), (3600, 455))

#: ``get_metric_data`` takes 500 queries per call. Batching by function is the
#: whole reason this aspect costs three API calls per account instead of three per
#: function, rather than one call per function.
_METRIC_BATCH = 500

#: The words a Lambda runtime writes at the start of a log line. The last event's
#: word says how the newest invocation ended, and ``ERROR`` is the one that counts.
_LOG_STATUS = re.compile(r"\b(INIT_START|START|END|REPORT|ERROR)\b")

#: How recent an error has to be before it is graded rather than merely reported.
#: The reasoning: past this, CloudWatch has condensed the bucket
#: the error sits in together with the successful runs around it, so a non-zero
#: count no longer means "the last run failed" — and a real, persistent error will
#: have been seen while it was fresh.
DEFAULT_ERROR_MAX_AGE_SECONDS = 14 * 86400

#: ``PipelineExecutionStatus`` → the code that line reports, keyed in lower case
#: because CodePipeline spells its statuses in mixed case where CloudWatch shouts
#: them. ``InProgress`` is a warning and
#: *everything* that is not ``Succeeded`` is an error — a stopped, cancelled or
#: superseded run still means the newest thing this pipeline did was not a
#: deployment.
DEFAULT_PIPELINE_STATE_MAP = {
    "succeeded": StatusCode.OK,
    "inprogress": StatusCode.WARN,
    "failed": StatusCode.ERROR,
    "stopped": StatusCode.ERROR,
    "stopping": StatusCode.ERROR,
    "cancelled": StatusCode.ERROR,
    "superseded": StatusCode.ERROR,
}

#: How long a pipeline may coast on a successful run before that success stops
#: being evidence that it still works. A month is roughly "nobody has released
#: since the last release cycle".
DEFAULT_PIPELINE_MAX_AGE_SECONDS = 31 * 86400

#: How many executions of one pipeline are read to find the newest.
#: ``list_pipeline_executions`` returns them newest first and caps a page at 100,
#: so one page settles the question; the maximum is asked for because the
#: newest is decided by comparing every summary returned rather than by trusting
#: that order, which costs one comparison.
_EXECUTIONS_PAGE = 100

#: The Batch job statuses this aspect reads. The first two are a *finished* run,
#: the third is work in flight. ``RUNNABLE`` is the fourth and the one easiest to
#: leave out: the queue accepted the job and no compute environment has capacity
#: for it, so it waits, silently, and the queue looks idle while it does.
#: Typed as Batch's own literal, so a fifth status invented here is a mypy error
#: rather than an ``InvalidParameterValue`` at run time — which is exactly what
#: the per-service stubs are for.
BATCH_FINISHED_STATUSES: tuple[JobStatusType, ...] = ("SUCCEEDED", "FAILED")
BATCH_RUNNING_STATUS: JobStatusType = "RUNNING"
BATCH_WAITING_STATUS: JobStatusType = "RUNNABLE"
BATCH_STATUSES: tuple[JobStatusType, ...] = (
    *BATCH_FINISHED_STATUSES, BATCH_RUNNING_STATUS, BATCH_WAITING_STATUS)

#: How long a Batch job may run before its line warns. Warning at the *existence*
#: of a running job would be a permanent yellow on any queue that is doing its
#: work, and a permanent yellow is a light people stop reading.
DEFAULT_BATCH_MAX_RUN_SECONDS = 2 * 3600

#: How long a job may sit in ``RUNNABLE`` before its line warns. This is the
#: reading easiest to omit: a job that cannot be placed is not
#: slow, it is stuck, and the queue looks idle while it happens.
DEFAULT_BATCH_MAX_WAIT_SECONDS = 30 * 60

#: How many jobs are read per queue per status. ``list_jobs`` returns the newest
#: first. One page is the natural bound and this is that page size, made a knob —
#: and reaching it is **said out loud on the line** rather than quietly truncating
#: the answer.
DEFAULT_BATCH_MAX_JOBS = 100

#: Worst first, then in-flight, then healthy (little-sister ADR-0042): the card is
#: clamped by ``reason_cap``, so a firing alarm must not sit below forty green ones.
_CODE_RANK = {StatusCode.ERROR: 0, StatusCode.WARN: 1,
              StatusCode.UNDEFINED: 2, StatusCode.OK: 3}

#: The sentence each aspect's `about` ends with, written once and referenced as
#: `{pin_note}` (little-sister ADR-0025).
PIN_NOTE = ("Each line can be put into maintenance on its own — pin the line you "
            "are working on and the rest keeps reporting. The account node above "
            "silences the whole account.")

#: Built-in display text for the aspect leaves this check emits — **type-inherent**,
#: so it is written once here rather than copied into every deployment's config.
#: `{account}`, `{regions}` and `{pin_note}` expand per node. A check config's
#: `subnodes:` block replaces one of these, or extends it where it writes
#: `{default}` into its own text; `nodes.yaml` still wins over both, per path.
SUBNODES: dict[str, dict[str, str]] = {
    CLOUDWATCH: {
        "title": "CloudWatch alarms",
        "about": """\
Every CloudWatch alarm in the **{account}** account ({regions}), metric and
composite alike, with the state it is in. Alarms whose name contains one of the
check's `ignore_name_patterns` are neither listed nor counted. The first line
says how many alarms were seen at all, which is the reading that catches a
credential that has quietly stopped seeing anything.

{pin_note}
""",
    },
    EC2: {
        "title": "EC2 instances",
        "about": """\
The EC2 instances in the **{account}** account ({regions}), grouped by their
`Name` tag: one line per name, with how many instances carry it and how long the
**oldest** of them has been up — `prometheus: 1 (12d)`.

Two things turn a line red, and they are different questions. **Age** is the
security reading: an instance is patched by being replaced, so one that has run
past `max_age` is that far behind on kernel fixes — true of a single, perfectly
tidy instance. **A fleet** — more instances under one name than `fleet_size` — is
read as deliberate rather than as a duplicate and gets the shorter clock
`fleet_max_age` instead: many is fine, many for hours is a load test nobody tore
down. Short of both, a name carried by more instances than `max_per_name` warns,
because a second box under a name that should be unique is usually a deploy that
did not clean up after itself.

Terminated and shutting-down instances are not counted; they linger in the API
for about an hour and would report a duplicate that no longer exists.

{pin_note}
""",
    },
    LAMBDA: {
        "title": "Lambda functions",
        "about": """\
Every Lambda function in the **{account}** account ({regions}), one line each,
with how its newest invocation went. Two independent readings meet on that line:
the **`Errors` metric** for the most recent period CloudWatch still has data for,
and the **status word of the last log event** — `REPORT` for a clean finish,
`ERROR` for a runtime failure that the metric may not have caught up with yet.

A function nobody has invoked in the retention window warns rather than passing:
a silent scheduled job is not a healthy one. An error older than `error_max_age`
is reported but not graded, because by then CloudWatch has condensed it into a
bucket with the successful runs around it and the count no longer means what it
says.

{pin_note}
""",
    },
    CODEPIPELINE: {
        "title": "CodePipeline",
        "about": """\
Every CodePipeline pipeline in the **{account}** account ({regions}), one line
each, showing what its **most recent execution** did and when that execution
started.

`Succeeded` passes, `InProgress` warns while it is in flight, and everything
else — `Failed`, `Stopped`, `Stopping`, `Cancelled`, `Superseded` — is an error,
because the newest thing the pipeline did was not a deployment. A success is
also only good for so long: past `max_age` the line warns instead, on the
grounds that a pipeline nobody has run in a month is a pipeline nobody knows
still works.

A pipeline that has **never been executed** warns rather than being left out.
It has nothing to report, which is itself the report.

{pin_note}
""",
    },
    BATCH: {
        "title": "AWS Batch",
        "about": """\
The AWS Batch job queues in the **{account}** account ({regions}) and the jobs
in them, one line per job *name* per queue — jobs are submitted over and over
under the same name, so the name is the thing worth watching and a single
submission is not.

Each line carries up to three readings at once: how the newest **finished** run
ended and how long it took, how many are **running** and how long the oldest of
those has been going, and how many are **runnable** — accepted by the queue and
waiting for capacity that has not appeared. A failure is an error; a run past
`max_run_time` or a wait past `max_wait_time` warns.

A queue gets a line of its own only when there is something to say about the
queue itself: it is `DISABLED` and taking no new work, its status is `INVALID`,
it holds no jobs at all, or there were more jobs than `max_jobs` and the reading
is of the newest ones only.

{pin_note}
""",
    },
}


@dataclass(frozen=True)
class Account:
    """One AWS account this check reads, and its own node in the tree.

    ``name`` is ours, not Amazon's: it is the node's path segment, so it has to be
    stable and it has to be unique. ``role_arn`` may be empty — that account is
    then read with the ambient credentials, which is what makes a single-account
    install and local development work without a role to assume. ``regions``
    empty means "the check's default"; an account that names its own overrides it
    outright rather than adding to it. ``profile`` behaves the same way against
    the check's own: it names the ``~/.aws/config`` profile the role is assumed
    **from**, and empty means the check's — which, empty in turn, means the
    ambient chain, ``AWS_PROFILE`` included.
    """

    name: str
    role_arn: str = ""
    regions: tuple[str, ...] = ()
    profile: str = ""
    title: str = ""
    about: str = ""


@dataclass(frozen=True)
class Alarm:
    """One alarm, narrowed out of the API payload at the read seam.

    Nothing downstream touches a boto3 response: the aspect grades, sorts and
    renders *this*, which is why its tests need no AWS-shaped fixtures.
    """

    name: str
    region: str
    state: str
    description: str
    composite: bool = False


@dataclass(frozen=True)
class _Aspect:
    """What every aspect's configuration block carries, whatever it reads.

    ``enabled`` lives **in the aspect's own block**, beside the knobs that shape
    it, so a config is read top to bottom — and an aspect that says nothing is on,
    which is what every config written before this key existed says. Switched off,
    the aspect emits no node and makes no API call: see :meth:`AwsCheck.active_aspects`.
    """

    enabled: bool = True


@dataclass(frozen=True)
class CloudwatchConfig(_Aspect):
    """The `cloudwatch:` block."""

    ignore_name_patterns: tuple[str, ...] = DEFAULT_IGNORE_NAME_PATTERNS
    tag_prefix: str = DEFAULT_TAG_PREFIX

    @property
    def tag_word(self) -> str:
        """What a matching alarm is tagged with — the prefix, without the
        separator it ends in. Derived rather than configured a second time: a
        deployment that writes `tag_prefix: "sre-"` means the word is `sre`,
        and a second knob to say so again is a second thing to get wrong.
        """
        return self.tag_prefix.strip("-_ .:").lower()
    include_composite: bool = True
    show_healthy: bool = False
    expect_min_alarms: int = 1
    state_map: dict[str, StatusCode] = field(
        default_factory=lambda: dict(DEFAULT_STATE_MAP))

    def ignored(self, alarm_name: str) -> bool:
        lowered = alarm_name.lower()
        return any(pattern in lowered for pattern in self.ignore_name_patterns)

    def code_for(self, state: str) -> StatusCode:
        # An unknown state is not a quiet OK: AWS adding a fourth one should be
        # visible, and a `state_map` entry is how a deployment answers it.
        return self.state_map.get(state.upper(), StatusCode.WARN)


@dataclass(frozen=True)
class Instance:
    """One EC2 instance, narrowed out of the API payload at the read seam."""

    instance_id: str
    name: str
    region: str
    state: str
    #: When AWS says it was launched. ``None`` when the payload carried no
    #: ``LaunchTime`` — the age then goes unreported rather than guessed at.
    launched: datetime | None = None

    def age_seconds(self, now: datetime) -> int | None:
        if self.launched is None:
            return None
        return max(0, int((now - self.launched).total_seconds()))


@dataclass(frozen=True)
class FunctionReading:
    """One Lambda function as this aspect sees it, narrowed at the read seam.

    ``errors`` is ``None`` when CloudWatch had no data point at all in any of its
    retention windows — a different fact from zero errors, and graded differently.
    """

    name: str
    region: str
    errors: int | None = None
    last_run: datetime | None = None
    log_status: str = ""
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Shortened(_Aspect):
    """The display-name substitutions an aspect that names things applies.

    Shared, because three aspects name things and the *organization's* naming is
    one fact, and it is the estate's rather than this type's. The rules are
    resolved at parse time —
    an aspect that names none inherits the check's — so what reaches here is
    already the answer, and every aspect asks it the same way.
    """

    shorten: tuple[tuple[str, str], ...] = ()

    def short_name(self, name: str) -> str:
        """The display name, after this deployment's substitutions — applied in
        order, so an earlier rule can feed a later one."""
        for old, new in self.shorten:
            name = name.replace(old, new)
        return name or "(unnamed)"


@dataclass(frozen=True)
class LambdaConfig(_Shortened):
    """The `lambda:` block."""

    ignore: tuple[str, ...] = ()
    error_max_age_seconds: int = DEFAULT_ERROR_MAX_AGE_SECONDS
    read_log_status: bool = True


@dataclass(frozen=True)
class Ec2Config(_Aspect):
    """The `ec2:` block."""

    ignore_states: tuple[str, ...] = DEFAULT_EC2_IGNORE_STATES
    ignore_name_patterns: tuple[str, ...] = ()
    max_per_name: int = 1
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
    fleet_size: int = DEFAULT_FLEET_SIZE
    fleet_max_age_seconds: int = DEFAULT_FLEET_MAX_AGE_SECONDS

    def ignored_state(self, state: str) -> bool:
        return state.lower() in self.ignore_states

    def ignored(self, name: str) -> bool:
        lowered = name.lower()
        return any(pattern in lowered for pattern in self.ignore_name_patterns)

    def code_for(self, count: int, age: int | None) -> StatusCode:
        """One group's verdict, worst rule first.

        Age outranks count because the two say different things. A count is a
        tidiness reading — something was left behind. An age is a **security**
        reading: an instance is patched by being replaced, so one that has run
        for a fortnight is a fortnight behind on kernel fixes, and that is true
        of a single, perfectly tidy instance.

        A group larger than ``fleet_size`` is read as a deliberate fleet rather
        than as a duplicate, and gets the shorter clock: many is fine, many *for
        hours* is a load test nobody tore down.
        """
        if age is not None:
            limit = (self.fleet_max_age_seconds if count > self.fleet_size
                     else self.max_age_seconds)
            if age > limit:
                return StatusCode.ERROR
        return StatusCode.OK if count <= self.max_per_name else StatusCode.WARN


@dataclass(frozen=True)
class PipelineReading:
    """One pipeline and its newest execution, narrowed at the read seam.

    ``status`` is empty when the pipeline has never been executed at all — which
    is a different fact from every failure status there is, and the one the
    original could not report because it built no line for it.
    """

    name: str
    region: str
    status: str = ""
    started: datetime | None = None


@dataclass(frozen=True)
class CodePipelineConfig(_Shortened):
    """The `codepipeline:` block."""

    ignore_name_patterns: tuple[str, ...] = ()
    max_age_seconds: int = DEFAULT_PIPELINE_MAX_AGE_SECONDS
    state_map: dict[str, StatusCode] = field(
        default_factory=lambda: dict(DEFAULT_PIPELINE_STATE_MAP))

    def ignored(self, name: str) -> bool:
        lowered = name.lower()
        return any(pattern in lowered for pattern in self.ignore_name_patterns)

    def code_for(self, status: str) -> StatusCode:
        # An unknown status is not a quiet OK, for the reason the alarm aspect
        # gives: AWS adding an eighth one should be visible, and a `state_map`
        # entry is how a deployment answers it.
        return self.state_map.get(status.strip().lower(), StatusCode.WARN)


@dataclass(frozen=True)
class Job:
    """One Batch job summary, narrowed at the read seam.

    Batch reports its timestamps as Unix **milliseconds**; they are datetimes by
    the time they reach here, so nothing downstream has to remember that.
    """

    job_id: str
    name: str
    status: str
    created: datetime | None = None
    started: datetime | None = None
    stopped: datetime | None = None


@dataclass(frozen=True)
class JobQueue:
    """One Batch job queue, narrowed at the read seam. ``state`` is whether it
    accepts work (``ENABLED`` / ``DISABLED``) and ``status`` whether AWS could
    build it at all (``VALID`` / ``INVALID`` / …) — two different failures that
    two failures worth telling apart."""

    name: str
    region: str
    state: str = ""
    status: str = ""
    status_reason: str = ""


@dataclass(frozen=True)
class QueueReading:
    """One queue and the jobs read from it. ``capped`` says the ``max_jobs``
    limit cut the answer short, which is a fact about the *reading* and belongs
    on the card rather than in a log nobody opens."""

    queue: JobQueue
    jobs: tuple[Job, ...] = ()
    capped: bool = False


@dataclass(frozen=True)
class BatchConfig(_Shortened):
    """The `batch:` block."""

    ignore_name_patterns: tuple[str, ...] = ()
    ignore_queue_patterns: tuple[str, ...] = ()
    expect_jobs: bool = True
    max_run_seconds: int = DEFAULT_BATCH_MAX_RUN_SECONDS
    max_wait_seconds: int = DEFAULT_BATCH_MAX_WAIT_SECONDS
    max_jobs: int = DEFAULT_BATCH_MAX_JOBS

    def ignored(self, name: str) -> bool:
        lowered = name.lower()
        return any(pattern in lowered for pattern in self.ignore_name_patterns)

    def ignored_queue(self, name: str) -> bool:
        lowered = name.lower()
        return any(pattern in lowered for pattern in self.ignore_queue_patterns)


# --- renewing an expired SSO login ------------------------------------------
#
# A named profile is normally an SSO profile, and an SSO login expires — eight
# hours by default, i.e. once a working day. Everything *inside* that window
# botocore already handles: the short-lived role credentials behind the profile
# are refreshed silently, and this check builds a fresh session per run anyway,
# so it picks them up for free. What is left is the outer window, where the only
# fix is a human at a browser — and on a developer's machine that is a command
# this process can run itself. `var/account/s3_copy.py` does exactly this for a
# long copy; the difference here is that a *check* runs unattended, every minute,
# possibly on a server, so the same idea needs three guards it does not: a
# capability test (:func:`login_capability`), a timeout, and a cooldown.


@dataclass(frozen=True)
class SsoConfig:
    """The ``sso:`` block: whether, and how hard, to renew a login."""

    login: str = SSO_LOGIN_AUTO
    timeout_seconds: int = DEFAULT_SSO_LOGIN_TIMEOUT_SECONDS
    cooldown_seconds: int = DEFAULT_SSO_LOGIN_COOLDOWN_SECONDS


def is_credential_error(error: BaseException) -> bool:
    """True when *error* means the credentials went stale rather than that AWS
    said no. The two need opposite answers: a stale credential is worth renewing
    and retrying, an ``AccessDenied`` is worth reporting."""
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
    function of what it looks at** on purpose: the answer is a sentence the
    dashboard prints, so it is a sentence worth testing directly, and each
    reason below is somebody's actual machine rather than a hypothetical.

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


def login_command(profile: str) -> str:
    """The command a human would run — printed on the node when we cannot."""
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
    """``aws sso login`` bookkeeping, shared by every check in the process.

    The browser and the SSO token cache belong to the **machine**, not to a
    check. Two checks pointed at one profile must not both open a login, and the
    cooldown that stops a browser re-opening every minute has to be the same one
    for both — a per-check attribute would give each of them their own. So this
    is deliberately module state, one instance (:data:`SSO_LOGINS`) keyed by
    profile name, and the per-profile lock is what serialises the two accounts
    of one profile that go stale in the same run.
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

        Inside *cooldown* seconds of the previous attempt the previous verdict is
        returned **without running anything**. That covers both directions: a
        login that nobody completed is not re-opened a minute later, and a login
        that just succeeded is not run twice because a second account noticed the
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


def _flag(value: object, where: str) -> bool:
    """A configuration boolean that must actually be one.

    ``bool("false")`` is ``True``, so a quoted YAML boolean — ``enabled: "false"``
    — would switch an aspect **on** while its config says off, and nothing
    downstream could notice: the aspect would simply report. A switch is worth
    less than nothing if it can silently mean its opposite.

    Lifted from `little-sister-github`, which learned it first; the family rule is
    that plumbing solved once is not solved again, and the two copies are the
    argument for this belonging on the library's surface at the third.
    """
    if not isinstance(value, bool):
        raise CheckError(f"aws '{where}' must be true or false")
    return value


def _lowered_list(value: object, where: str, default: tuple[str, ...]
                  ) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list):
        raise CheckError(f"{where} must be a list")
    return tuple(str(item).strip().lower() for item in value)


def _parse_regions(value: object, where: str) -> tuple[str, ...]:
    """A region list. A bare string is accepted as the one-region case."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise CheckError(f"{where} must be a non-empty list of region names")
    regions = tuple(str(region).strip() for region in value)
    if not all(regions):
        raise CheckError(f"{where} must not contain an empty region name")
    if len(set(regions)) != len(regions):
        raise CheckError(f"{where} must not repeat a region")
    return regions


def _parse_profile(value: object, where: str) -> str:
    """An ``~/.aws/config`` profile name.

    Refused characters, and why there is a rule at all: the name is printed back
    to the operator **inside a Markdown code span** (``aws sso login --profile
    …``), and it is passed to a subprocess. A backtick would break out of the
    first; a newline would make the printed command a different command from the
    one that runs. Neither is a legal profile name anyway.
    """
    profile = str(value).strip()
    if not profile:
        raise CheckError(f"{where} must not be empty")
    if any(ch in profile for ch in "`\n\r"):
        raise CheckError(f"{where} must not contain a backtick or a newline")
    return profile


def _parse_sso(value: object) -> SsoConfig:
    """The ``sso:`` block — whether the check may renew an expired login."""
    if value is None:
        return SsoConfig()
    if not isinstance(value, dict):
        raise CheckError("aws 'sso' must be a mapping")
    known = {"login", "timeout", "cooldown"}
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        raise CheckError(
            f"unknown key(s) in 'sso': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    login = str(value.get("login", SSO_LOGIN_AUTO)).strip().lower()
    if login not in SSO_LOGIN_MODES:
        raise CheckError(
            f"aws 'sso.login' must be one of {', '.join(SSO_LOGIN_MODES)} "
            f"(got {login!r})")
    timeout = parse_duration(value.get("timeout"),
                             DEFAULT_SSO_LOGIN_TIMEOUT_SECONDS)
    if timeout <= 0:
        # Zero would not mean "no timeout" here, it would mean "kill it before
        # it starts" — and an unbounded login holds an engine worker forever.
        raise CheckError("aws 'sso.timeout' must be greater than zero")
    cooldown = parse_duration(value.get("cooldown"),
                             DEFAULT_SSO_LOGIN_COOLDOWN_SECONDS)
    if cooldown < 0:
        raise CheckError("aws 'sso.cooldown' must not be negative")
    return SsoConfig(login=login, timeout_seconds=timeout,
                     cooldown_seconds=cooldown)


def _parse_accounts(value: object) -> tuple[Account, ...]:
    """The ``accounts:`` list — every account this check reads, and its node."""
    if not isinstance(value, list) or not value:
        raise CheckError(
            "aws check requires a non-empty 'accounts:' list, each entry a "
            "mapping with a 'name' and an optional 'role_arn'")
    known = {"name", "role_arn", "regions", "profile", "title", "about"}
    accounts: list[Account] = []
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, dict):
            raise CheckError("each 'accounts:' entry must be a mapping")
        name = str(entry.get("name", "")).strip()
        if not name:
            raise CheckError("each 'accounts:' entry must have a 'name'")
        if name in seen:
            # Not a merge: the name is the node's path segment, so two accounts
            # sharing one would silently collapse into a single node.
            raise CheckError(f"duplicate account name {name!r} in 'accounts:'")
        unknown = sorted(str(key) for key in entry if str(key) not in known)
        if unknown:
            raise CheckError(
                f"unknown key(s) in account {name!r}: {', '.join(unknown)} "
                f"(an account takes: {', '.join(sorted(known))})")
        seen.add(name)
        regions = entry.get("regions")
        profile = entry.get("profile")
        accounts.append(Account(
            name=name,
            role_arn=str(entry.get("role_arn", "")).strip(),
            regions=(() if regions is None
                     else _parse_regions(regions, f"account {name!r} 'regions'")),
            profile=("" if profile is None
                     else _parse_profile(profile, f"account {name!r} 'profile'")),
            title=str(entry.get("title", "")),
            about=str(entry.get("about", "")),
        ))
    return tuple(accounts)


def _parse_cloudwatch(value: object) -> CloudwatchConfig:
    if value is None:
        return CloudwatchConfig()
    if not isinstance(value, dict):
        raise CheckError("aws 'cloudwatch' must be a mapping")
    known = {"enabled", "ignore_name_patterns", "tag_prefix",
             "include_composite", "show_healthy", "expect_min_alarms",
             "state_map"}
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        raise CheckError(
            f"unknown key(s) in 'cloudwatch': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    patterns = value.get("ignore_name_patterns")
    if patterns is None:
        patterns = list(DEFAULT_IGNORE_NAME_PATTERNS)
    if not isinstance(patterns, list):
        raise CheckError("cloudwatch 'ignore_name_patterns' must be a list")
    minimum = value.get("expect_min_alarms", 1)
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        # Zero would switch the coverage backstop off while still looking set —
        # a check that expects nothing cannot notice that it saw nothing.
        raise CheckError(
            "cloudwatch 'expect_min_alarms' must be an integer of at least 1")
    state_map = dict(DEFAULT_STATE_MAP)
    configured = value.get("state_map")
    if configured is not None:
        if not isinstance(configured, dict):
            raise CheckError("cloudwatch 'state_map' must be a mapping")
        state_map.update({str(state).upper(): coerce_code(code)
                          for state, code in configured.items()})
    return CloudwatchConfig(
        # `_flag`, not `bool`, on every one of these: the quoted-boolean trap the
        # helper documents is not special to `enabled`, and `show_healthy: "false"`
        # silently listing a hundred green alarms is the same failure.
        enabled=_flag(value.get("enabled", True), "cloudwatch.enabled"),
        ignore_name_patterns=tuple(str(pattern).lower() for pattern in patterns),
        tag_prefix=str(value.get("tag_prefix", DEFAULT_TAG_PREFIX)),
        include_composite=_flag(value.get("include_composite", True),
                                "cloudwatch.include_composite"),
        show_healthy=_flag(value.get("show_healthy", False),
                           "cloudwatch.show_healthy"),
        expect_min_alarms=minimum,
        state_map=state_map,
    )


def _parse_ec2(value: object) -> Ec2Config:
    if value is None:
        return Ec2Config()
    if not isinstance(value, dict):
        raise CheckError("aws 'ec2' must be a mapping")
    known = {"enabled", "ignore_states", "ignore_name_patterns",
             "max_per_name", "max_age", "fleet_size", "fleet_max_age"}
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        raise CheckError(
            f"unknown key(s) in 'ec2': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    maximum = value.get("max_per_name", 1)
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
        raise CheckError("ec2 'max_per_name' must be an integer of at least 1")
    fleet = value.get("fleet_size", DEFAULT_FLEET_SIZE)
    if isinstance(fleet, bool) or not isinstance(fleet, int) or fleet < 1:
        raise CheckError("ec2 'fleet_size' must be an integer of at least 1")
    max_age = parse_duration(value.get("max_age"), DEFAULT_MAX_AGE_SECONDS)
    fleet_max_age = parse_duration(value.get("fleet_max_age"),
                                   DEFAULT_FLEET_MAX_AGE_SECONDS)
    for label, seconds in (("max_age", max_age),
                           ("fleet_max_age", fleet_max_age)):
        if seconds < 1:
            raise CheckError(f"ec2 '{label}' must be a duration of at least 1s")
    return Ec2Config(
        enabled=_flag(value.get("enabled", True), "ec2.enabled"),
        ignore_states=_lowered_list(value.get("ignore_states"),
                                    "ec2 'ignore_states'",
                                    DEFAULT_EC2_IGNORE_STATES),
        ignore_name_patterns=_lowered_list(
            value.get("ignore_name_patterns"), "ec2 'ignore_name_patterns'", ()),
        max_per_name=maximum,
        max_age_seconds=max_age,
        fleet_size=fleet,
        fleet_max_age_seconds=fleet_max_age,
    )


def _parse_shorten(value: object, where: str = "aws 'shorten'"
                   ) -> tuple[tuple[str, str], ...]:
    """The display-name substitutions, in order: a list of `{from:, to:}` maps.
    `to` defaults to empty, which is the common case (strip a prefix)."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise CheckError(f"{where} must be a list of {{from:, to:}} maps")
    rules: list[tuple[str, str]] = []
    for rule in value:
        if not isinstance(rule, dict) or "from" not in rule:
            raise CheckError(
                "each 'shorten' rule must be a mapping with a 'from' (and an "
                "optional 'to', which defaults to empty)")
        unknown = sorted(str(key) for key in rule if str(key) not in {"from", "to"})
        if unknown:
            raise CheckError(
                f"unknown key(s) in a 'shorten' rule: {', '.join(unknown)}")
        source = str(rule["from"])
        if not source:
            raise CheckError("a 'shorten' rule's 'from' must not be empty")
        rules.append((source, str(rule.get("to", ""))))
    return tuple(rules)


def _inherited_shorten(value: dict[str, Any], where: str,
                       default: tuple[tuple[str, str], ...]
                       ) -> tuple[tuple[str, str], ...]:
    """An aspect's display-name rules: its own if it wrote any, the check's
    otherwise — the same inheritance `regions:` and `profile:` already use.

    ``shorten: []`` is a *value*, not an absence: it is how one aspect opts out
    of a check-level list the others want.
    """
    if "shorten" not in value:
        return default
    return _parse_shorten(value.get("shorten"), where)


def _parse_lambda(value: object, shorten: tuple[tuple[str, str], ...] = ()
                  ) -> LambdaConfig:
    if value is None:
        return LambdaConfig(shorten=shorten)
    if not isinstance(value, dict):
        raise CheckError("aws 'lambda' must be a mapping")
    known = {"enabled", "ignore", "error_max_age", "read_log_status",
             "shorten"}
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        raise CheckError(
            f"unknown key(s) in 'lambda': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    ignore = value.get("ignore") or []
    if not isinstance(ignore, list):
        raise CheckError("lambda 'ignore' must be a list of function names")
    max_age = parse_duration(value.get("error_max_age"),
                             DEFAULT_ERROR_MAX_AGE_SECONDS)
    if max_age < 1:
        raise CheckError("lambda 'error_max_age' must be a duration of at least 1s")
    return LambdaConfig(
        # Whole function names, not substrings: a Lambda name is an identifier
        # somebody typed once, and a substring would catch its neighbours.
        ignore=tuple(str(name) for name in ignore),
        error_max_age_seconds=max_age,
        enabled=_flag(value.get("enabled", True), "lambda.enabled"),
        read_log_status=_flag(value.get("read_log_status", True),
                              "lambda.read_log_status"),
        shorten=_inherited_shorten(value, "lambda 'shorten'", shorten),
    )


def _parse_codepipeline(value: object,
                        shorten: tuple[tuple[str, str], ...] = ()
                        ) -> CodePipelineConfig:
    if value is None:
        return CodePipelineConfig(shorten=shorten)
    if not isinstance(value, dict):
        raise CheckError("aws 'codepipeline' must be a mapping")
    known = {"enabled", "ignore_name_patterns", "max_age", "state_map",
             "shorten"}
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        raise CheckError(
            f"unknown key(s) in 'codepipeline': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    max_age = parse_duration(value.get("max_age"),
                             DEFAULT_PIPELINE_MAX_AGE_SECONDS)
    if max_age < 1:
        raise CheckError(
            "codepipeline 'max_age' must be a duration of at least 1s")
    state_map = dict(DEFAULT_PIPELINE_STATE_MAP)
    configured = value.get("state_map")
    if configured is not None:
        if not isinstance(configured, dict):
            raise CheckError("codepipeline 'state_map' must be a mapping")
        # Keyed in lower case, because a config that writes `InProgress` and one
        # that writes `IN_PROGRESS`… only the first is a CodePipeline status, but
        # neither should turn into a silently ignored entry.
        state_map.update({str(status).strip().lower(): coerce_code(code)
                          for status, code in configured.items()})
    return CodePipelineConfig(
        enabled=_flag(value.get("enabled", True), "codepipeline.enabled"),
        ignore_name_patterns=_lowered_list(
            value.get("ignore_name_patterns"),
            "codepipeline 'ignore_name_patterns'", ()),
        max_age_seconds=max_age,
        state_map=state_map,
        shorten=_inherited_shorten(value, "codepipeline 'shorten'", shorten),
    )


def _parse_batch(value: object, shorten: tuple[tuple[str, str], ...] = ()
                 ) -> BatchConfig:
    if value is None:
        return BatchConfig(shorten=shorten)
    if not isinstance(value, dict):
        raise CheckError("aws 'batch' must be a mapping")
    known = {"enabled", "ignore_name_patterns", "ignore_queue_patterns",
             "expect_jobs", "max_run_time", "max_wait_time", "max_jobs",
             "shorten"}
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        raise CheckError(
            f"unknown key(s) in 'batch': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    max_jobs = value.get("max_jobs", DEFAULT_BATCH_MAX_JOBS)
    if isinstance(max_jobs, bool) or not isinstance(max_jobs, int) or max_jobs < 1:
        raise CheckError("batch 'max_jobs' must be an integer of at least 1")
    max_run = parse_duration(value.get("max_run_time"),
                             DEFAULT_BATCH_MAX_RUN_SECONDS)
    max_wait = parse_duration(value.get("max_wait_time"),
                              DEFAULT_BATCH_MAX_WAIT_SECONDS)
    for label, seconds in (("max_run_time", max_run),
                           ("max_wait_time", max_wait)):
        if seconds < 1:
            raise CheckError(
                f"batch '{label}' must be a duration of at least 1s")
    return BatchConfig(
        enabled=_flag(value.get("enabled", True), "batch.enabled"),
        ignore_name_patterns=_lowered_list(
            value.get("ignore_name_patterns"),
            "batch 'ignore_name_patterns'", ()),
        ignore_queue_patterns=_lowered_list(
            value.get("ignore_queue_patterns"),
            "batch 'ignore_queue_patterns'", ()),
        expect_jobs=_flag(value.get("expect_jobs", True),
                          "batch.expect_jobs"),
        max_run_seconds=max_run,
        max_wait_seconds=max_wait,
        max_jobs=max_jobs,
        shorten=_inherited_shorten(value, "batch 'shorten'", shorten),
    )


def _function_link(region: str, name: str) -> str:
    return (f"https://{region}.console.aws.amazon.com/lambda/home?region={region}"
            f"#/functions/{urllib.parse.quote(name)}")


def _console_link(alarm: Alarm) -> str:
    """The alarm in the console. The older ``#s=Alarms`` fragment, which the
    console still redirects, works for both alarm kinds."""
    quoted = urllib.parse.quote(alarm.name)
    return (f"https://{alarm.region}.console.aws.amazon.com/cloudwatch/home"
            f"?region={alarm.region}#s=Alarms&alarm={quoted}")


def _utcnow() -> datetime:
    """The clock, behind one function, so a test can hold it still."""
    return datetime.now(UTC)


def _instance_link(region: str, name: str) -> str:
    """The console, filtered to the instances carrying this name."""
    return (f"https://{region}.console.aws.amazon.com/ec2/home?region={region}"
            f"#Instances:search={urllib.parse.quote(name)}")


def _state_phrase(state: str) -> str:
    return {"ALARM": "in ALARM",
            "INSUFFICIENT_DATA": "insufficient data",
            "OK": "OK"}.get(state.upper(), plain(state))


def _pipeline_link(region: str, name: str) -> str:
    """The pipeline's execution history in the console."""
    return (f"https://{region}.console.aws.amazon.com/codesuite/codepipeline"
            f"/pipelines/{urllib.parse.quote(name)}/executions?region={region}")


def _job_link(region: str, job_id: str) -> str:
    """One Batch job's detail page.

    A job id, not the queue's ARN: the console will take an ARN here and an ARN
    carries the account number, which is exactly the string ADR-0006 keeps out
    of a line somebody may bookmark or paste into a ticket.
    """
    return (f"https://{region}.console.aws.amazon.com/batch/home?region={region}"
            f"#jobs/detail/{urllib.parse.quote(job_id)}")


def _queue_link(region: str) -> str:
    """The queue list, for the same reason: the per-queue page is addressed by
    ARN and the list is not."""
    return (f"https://{region}.console.aws.amazon.com/batch/home"
            f"?region={region}#queues")


def _worst(first: StatusCode, second: StatusCode) -> StatusCode:
    """The more serious of two codes, on the card's own order."""
    return first if _CODE_RANK.get(first, 3) <= _CODE_RANK.get(second, 3) else second


def _scope_line(noun: str, found: int, regions: tuple[str, ...]) -> Entry:
    """How many of a thing were seen at all (little-sister ADR-0043).

    OK when the answer is none, unlike the alarm aspect's: an account may
    legitimately run no pipelines and no Batch queues, where an account whose
    CloudWatch has gone quiet has probably lost its credential. The two readings
    differ on purpose, and this is the half that does not grade.
    """
    where = ", ".join(plain(region) for region in regions)
    if not found:
        return Entry(slug("scope"), f"no {noun}s in scope ({where})",
                     StatusCode.OK)
    return Entry(slug("scope"),
                 f"{found} {noun if found == 1 else noun + 's'} in scope "
                 f"({where})", StatusCode.OK)


@register("aws")
class AwsCheck(Check):
    """Read one or more AWS accounts; one child per account, one per aspect."""

    #: The aspects each account node carries, in the order they are reported.
    ASPECTS: tuple[str, ...] = (CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH)

    def __init__(self, *, accounts: tuple[Account, ...],
                 regions: tuple[str, ...] = DEFAULT_REGIONS,
                 role_session_name: str = DEFAULT_ROLE_SESSION_NAME,
                 sts_region: str = DEFAULT_STS_REGION,
                 profile: str = "",
                 sso: SsoConfig | None = None,
                 cloudwatch: CloudwatchConfig | None = None,
                 ec2: Ec2Config | None = None,
                 lambda_: LambdaConfig | None = None,
                 codepipeline: CodePipelineConfig | None = None,
                 batch: BatchConfig | None = None,
                 shorten: tuple[tuple[str, str], ...] = (),
                 subnodes: dict[str, dict[str, str]] | None = None,
                 access_key_ref: str = "", secret_key_ref: str = "",
                 **kwargs: Any) -> None:
        # `**kwargs` and nothing spelled out: the fields every check shares grow,
        # and a constructor that names them stops binding when the next one lands
        # (little-sister ADR-0049).
        super().__init__(**kwargs)
        self.accounts = accounts
        self.regions = regions
        self.role_session_name = role_session_name
        self.sts_region = sts_region
        # The default profile every account inherits. Empty is not a value here,
        # it is the *absence* of one: boto3 then reads the ambient chain exactly
        # as it did before this key existed, `AWS_PROFILE` included.
        self.profile = profile
        self.sso = sso or SsoConfig()
        self.cloudwatch = cloudwatch or CloudwatchConfig()
        self.ec2 = ec2 or Ec2Config()
        # ``lambda`` is a keyword, so the attribute cannot carry the aspect's
        # name. The **config key** is `lambda:` — the name the aspect registers
        # under — and only Python's grammar is trailing an underscore here.
        self.lambda_ = lambda_ or LambdaConfig()
        self.codepipeline = codepipeline or CodePipelineConfig()
        self.batch = batch or BatchConfig()
        # The check-level default the three naming aspects inherit. Kept as an
        # attribute although the parser has already folded it into each aspect:
        # it is what `config_summary()` reports, and reporting the resolved copy
        # from one aspect would name a rule the others might not be using.
        self.shorten = shorten
        self.subnodes = subnodes or {}
        # Static keys are the exception, not the rule — the ambient chain (an
        # instance profile, a task role, an SSO session) is how this normally runs.
        # Resolved **here**, once, from the reference the config names, never
        # during a run (little-sister ADR-0023).
        self.access_key = self.resolve_secret(access_key_ref) if access_key_ref else ""
        self.secret_key = self.resolve_secret(secret_key_ref) if secret_key_ref else ""

    @classmethod
    def _extra_from_config(cls, config: dict[str, Any],
                           base_dir: Path) -> dict[str, Any]:
        session_name = str(
            config.get("role_session_name", DEFAULT_ROLE_SESSION_NAME)).strip()
        if not session_name:
            raise CheckError("aws 'role_session_name' must not be empty")
        sts_region = str(config.get("sts_region", DEFAULT_STS_REGION)).strip()
        if not sts_region:
            raise CheckError("aws 'sts_region' must not be empty")
        regions = config.get("regions")
        profile = config.get("profile")
        accounts = _parse_accounts(config.get("accounts"))
        # Parsed before the aspects, because each of them inherits it.
        shorten = _parse_shorten(config.get("shorten"))
        extra: dict[str, Any] = {
            "accounts": accounts,
            "regions": (DEFAULT_REGIONS if regions is None
                        else _parse_regions(regions, "aws 'regions'")),
            "role_session_name": session_name,
            "sts_region": sts_region,
            "profile": ("" if profile is None
                        else _parse_profile(profile, "aws 'profile'")),
            "sso": _parse_sso(config.get("sso")),
            "cloudwatch": _parse_cloudwatch(config.get("cloudwatch")),
            "ec2": _parse_ec2(config.get("ec2")),
            "lambda_": _parse_lambda(config.get("lambda"), shorten),
            "codepipeline": _parse_codepipeline(
                config.get("codepipeline"), shorten),
            "batch": _parse_batch(config.get("batch"), shorten),
            "shorten": shorten,
            "subnodes": parse_subnodes(config),
        }
        blocks = (extra["cloudwatch"], extra["ec2"], extra["lambda_"],
                  extra["codepipeline"], extra["batch"])
        if not any(block.enabled for block in blocks):
            # The account nodes would still prove their credentials, so this is
            # not literally nothing — but a check whose every aspect is off reads
            # nothing about any account it opens, while looking from the dashboard
            # exactly like one that does. Deleting the check says that out loud;
            # this config whispers it.
            raise CheckError(
                "aws check has every aspect disabled — it would assume each "
                "account's role and report nothing about it. Remove the check "
                "instead.")
        if "secrets" in config:
            # Optional as a block, all-or-nothing inside it: a check with half a
            # key pair would fall back to the ambient chain and read the wrong
            # account without saying so.
            if extra["profile"] or any(account.profile for account in accounts):
                # Not a precedence question — a contradiction. A profile *is* a
                # set of credentials, so a config that names both has said two
                # different things about which account it reads, and picking one
                # silently is how a check ends up watching the wrong estate.
                raise CheckError(
                    "aws 'profile' and a 'secrets:' block are mutually "
                    "exclusive: a profile carries its own credentials")
            references = parse_secret_refs(
                config, "access_key_id", "secret_access_key")
            extra["access_key_ref"] = references["access_key_id"]
            extra["secret_key_ref"] = references["secret_access_key"]
        return extra

    def settings_for(self, aspect: str) -> _Aspect:
        """One aspect's configuration block.

        Spelled out rather than reached by ``getattr``: the attribute names are
        already written in the constructor and in the builder map, and a
        ``getattr`` here would hand mypy an ``Any`` — which is the opposite of
        what this module buys its typed clients for.
        """
        return {CLOUDWATCH: self.cloudwatch, EC2: self.ec2,
                LAMBDA: self.lambda_, CODEPIPELINE: self.codepipeline,
                BATCH: self.batch}[aspect]

    def active_aspects(self) -> tuple[str, ...]:
        """The aspects this check runs, in :attr:`ASPECTS` order — every aspect
        its config did not switch off."""
        return tuple(name for name in self.ASPECTS
                     if self.settings_for(name).enabled)

    def regions_for(self, account: Account) -> tuple[str, ...]:
        """An account's regions: its own if it named any, the check's otherwise."""
        return account.regions or self.regions

    def profile_for(self, account: Account) -> str:
        """An account's profile: its own if it named one, the check's otherwise.

        Empty all the way down is the case that has to keep working untouched —
        it is every config written before this key existed.
        """
        return account.profile or self.profile

    def config_summary(self) -> str:
        return config_markdown({
            "accounts": ", ".join(plain(account.name)
                                  for account in self.accounts),
            "default regions": ", ".join(plain(region)
                                         for region in self.regions),
            "role session name": plain(self.role_session_name),
            "credentials": self._credentials_summary(),
            "sso login": self._sso_summary(),
            "ignored alarm names containing": ", ".join(
                plain(pattern)
                for pattern in self.cloudwatch.ignore_name_patterns) or None,
            "healthy alarms listed": "yes" if self.cloudwatch.show_healthy else "no",
            "instances allowed per name": str(self.ec2.max_per_name),
            # `format_span` here, and `coarse_span` on the lines: a configured
            # threshold is a size, exactly stated, while an age is a bound.
            "instance age before red": format_span(self.ec2.max_age_seconds),
            "a fleet is more than": (f"{self.ec2.fleet_size} instances, red after "
                                     f"{format_span(self.ec2.fleet_max_age_seconds)}"),
            "lambda log status read": ("yes" if self.lambda_.read_log_status
                                       else "no"),
            "lambda functions ignored": ", ".join(
                plain(name) for name in self.lambda_.ignore) or None,
            "lambda error graded within": format_span(
                self.lambda_.error_max_age_seconds),
            "pipeline success stales after": format_span(
                self.codepipeline.max_age_seconds),
            "batch job running before red": format_span(
                self.batch.max_run_seconds),
            "batch job waiting before red": format_span(
                self.batch.max_wait_seconds),
            "batch jobs read per queue and status": str(self.batch.max_jobs),
            # Only when there are any: a disabled aspect leaves no node, so
            # without this line the difference between "that aspect is off" and
            # "somebody broke the check" is invisible on the very page an operator
            # opens to find out which.
            "aspects switched off": ", ".join(
                plain(name) for name in self.ASPECTS
                if not self.settings_for(name).enabled) or None,
            "display names shortened by": ", ".join(
                f"{plain(old)} → {plain(new)}" if new
                else f"{plain(old)} (dropped)"
                for old, new in self.shorten) or None,
        })

    def _credentials_summary(self) -> str:
        """Which of the three credential sources this check is on, named on the
        card so that "it reads nothing" and "it reads the wrong account" are
        different-looking problems."""
        if self.profile:
            overrides = sorted({account.profile for account in self.accounts
                                if account.profile and account.profile != self.profile})
            named = f"profile {plain(self.profile)}"
            if overrides:
                return (f"{named} (and "
                        f"{', '.join(plain(name) for name in overrides)})")
            return named
        per_account = sorted({account.profile for account in self.accounts
                              if account.profile})
        if per_account:
            return "per-account profiles: " + ", ".join(
                plain(name) for name in per_account)
        return "configured keys" if self.access_key else "ambient credential chain"

    def _sso_summary(self) -> str | None:
        """What this check would do about an expired login, decided **now** —
        the answer depends on the machine, and a card that said "auto" without
        saying whether auto can actually work here would be the reassuring
        version of nothing.

        Dropped entirely where there is no profile anywhere and nothing that
        would try regardless: a row explaining a feature this check is not using
        is noise on every card, once a minute, forever.
        """
        profile = self.profile or next(
            (account.profile for account in self.accounts if account.profile), "")
        if not profile and self.sso.login != SSO_LOGIN_ALWAYS:
            return None
        problem = self._login_problem(profile)
        if problem:
            return f"not from here — {problem}"
        return (f"`{login_command(profile)}` on expiry, at most once every "
                f"{format_span(self.sso.cooldown_seconds)}")

    def _meta(self, name: str, account: Account) -> tuple[str, str]:
        """The (title, about) for aspect ``name`` under ``account``: this type's
        built-in :data:`SUBNODES` text, which the config's `subnodes:` block
        replaces — or extends, where it writes `{default}` (ADR-0025)."""
        default = SUBNODES.get(name, {})
        configured = self.subnodes.get(name, {})
        tokens = {"account": account.name,
                  "regions": ", ".join(self.regions_for(account)),
                  "pin_note": PIN_NOTE}
        return (resolve_text(configured.get("title", ""),
                             default.get("title", ""), tokens),
                resolve_text(configured.get("about", ""),
                             default.get("about", ""), tokens))

    # --- the session seam -------------------------------------------------

    def _new_session(self, *, aws_access_key_id: str = "",
                     aws_secret_access_key: str = "",
                     aws_session_token: str = "",
                     profile_name: str = "") -> Session:
        """The one place a boto3 session is built — and so the one seam a test
        replaces. Empty credentials mean the ambient chain; an empty profile
        means whichever one that chain would pick for itself."""
        return boto3.Session(
            aws_access_key_id=aws_access_key_id or None,
            aws_secret_access_key=aws_secret_access_key or None,
            aws_session_token=aws_session_token or None,
            profile_name=profile_name or None)

    def _base_session(self) -> Session:
        """The session the roles are assumed *from*.

        Three sources, and they are ordered by how specific they are. A profile
        wins because it is the one that was written down here; static keys are
        next; the ambient chain is what is left, and is still the normal case on
        a server. A profile and static keys together cannot reach this method —
        `_extra_from_config` refuses that config.
        """
        if self.profile:
            return self._new_session(profile_name=self.profile)
        if self.access_key and self.secret_key:
            return self._new_session(aws_access_key_id=self.access_key,
                                     aws_secret_access_key=self.secret_key)
        return self._new_session()

    def _base_for(self, base: Session, account: Account) -> Session:
        """The session *this* account is read through: the check's, unless the
        account named a profile of its own. Building one per account only where
        an account asked for one keeps the shared case one session, which is
        what it was before profiles existed."""
        if account.profile:
            return self._new_session(profile_name=account.profile)
        return base

    def _session_for(self, base: Session, account: Account) -> Session:
        """One account's session, assuming its role when it names one."""
        if not account.role_arn:
            return base
        sts = base.client("sts", region_name=self.sts_region)
        credentials = sts.assume_role(
            RoleArn=account.role_arn,
            RoleSessionName=self.role_session_name)["Credentials"]
        return self._new_session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"])

    def _opened(self, base: Session, account: Account) -> Session:
        """One account's session with its credentials **proven**.

        Assuming the role is itself the proof where there is a role: it is a
        call, and stale credentials fail it. A profile-only account touches AWS
        nowhere until an aspect does, so one `sts:GetCallerIdentity` is spent
        here to force the question — which is what makes an expired login *this
        account's node*, once, instead of three aspects each reporting the same
        thing in their own words. Nothing is spent where no profile is
        configured: that path is exactly as it was.
        """
        session = self._session_for(self._base_for(base, account), account)
        if not account.role_arn and self.profile_for(account):
            session.client("sts",
                           region_name=self.sts_region).get_caller_identity()
        return session

    # --- renewing an expired login ----------------------------------------

    def _profile_config(self, profile: str) -> Mapping[str, Any]:
        """What ``~/.aws/config`` says about *profile*, or nothing if it says
        nothing. Its own seam, so a test can answer for a machine it is not
        running on."""
        try:
            scoped = botocore.session.Session(profile=profile).get_scoped_config()
        except BotoCoreError:      # ProfileNotFound, an unreadable config file
            return {}
        return dict(scoped)

    def _login_problem(self, profile: str) -> str:
        """Why an automatic login could not happen for *profile* — ``""`` when
        it could. The whole environment is read here and nowhere else, so
        :func:`login_capability` stays a pure function of its arguments."""
        if self.sso.login == SSO_LOGIN_NEVER:
            return "automatic login is off (`sso: login: never`)"
        if self.sso.login == SSO_LOGIN_ALWAYS:
            return ""
        return login_capability(
            profile=profile,
            profile_config=self._profile_config(profile),
            aws_cli=shutil.which("aws"),
            environ=os.environ,
            platform=sys.platform,
            container=in_container())

    def _sso_login(self, profile: str, timeout: int) -> str:
        """The one place a subprocess is started — and so the one seam a test
        replaces, the same bargain :meth:`_new_session` makes for boto3."""
        return run_sso_login(profile, timeout)

    def _renew(self, account: Account) -> str:
        """Renew this account's login. ``""`` when AWS is worth asking again."""
        profile = self.profile_for(account)
        problem = self._login_problem(profile)
        if problem:
            return problem
        return SSO_LOGINS.renew(profile, timeout=self.sso.timeout_seconds,
                                cooldown=self.sso.cooldown_seconds,
                                login=self._sso_login)

    # --- reading ----------------------------------------------------------

    def _describe_alarms(self, session: Session, region: str) -> list[Alarm]:
        """Every alarm in one region of one account, narrowed at the seam.

        ``describe_alarms`` returns **only metric alarms** unless ``AlarmTypes``
        says otherwise, which is an easy blind spot to inherit without deciding to.
        """
        client = session.client("cloudwatch", region_name=region)
        paginator = client.get_paginator("describe_alarms")
        pages = (paginator.paginate(AlarmTypes=["CompositeAlarm", "MetricAlarm"])
                 if self.cloudwatch.include_composite
                 else paginator.paginate(AlarmTypes=["MetricAlarm"]))
        alarms: list[Alarm] = []
        for page in pages:
            for composite, rows in ((False, page.get("MetricAlarms", [])),
                                    (True, page.get("CompositeAlarms", []))):
                for row in rows:
                    name = str(row.get("AlarmName", "")).strip()
                    if not name:
                        continue
                    alarms.append(Alarm(
                        name=name,
                        region=region,
                        state=str(row.get("StateValue", "")),
                        description=str(row.get("AlarmDescription", "")
                                        or NO_DESCRIPTION),
                        composite=composite))
        return alarms

    def _describe_instances(self, session: Session, region: str) -> list[Instance]:
        """Every instance in one region of one account, narrowed at the seam."""
        client = session.client("ec2", region_name=region)
        instances: list[Instance] = []
        for page in client.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for row in reservation.get("Instances", []):
                    state = row.get("State")
                    name = ""
                    for tag in row.get("Tags", []):
                        if tag.get("Key") == "Name":
                            name = str(tag.get("Value", "")).strip()
                            break
                    instances.append(Instance(
                        instance_id=str(row.get("InstanceId", "")),
                        name=name,
                        region=region,
                        state=str(state.get("Name", "")) if state else "",
                        launched=row.get("LaunchTime")))
        return instances

    # --- the cloudwatch aspect --------------------------------------------

    def _alarm_entry(self, alarm: Alarm, code: StatusCode,
                     show_region: bool) -> Entry:
        settings = self.cloudwatch
        tags = [tag for tag, on in
                ((settings.tag_word, bool(settings.tag_prefix)
                  and alarm.name.startswith(settings.tag_prefix)),
                 ("composite", alarm.composite)) if on]
        where = f"{plain(alarm.region)} / " if show_region else ""
        suffix = f" ({', '.join(tags)})" if tags else ""
        return Entry(
            # The region is in the slug whether or not it is in the text: a pin
            # must not re-point the day a second region is configured.
            slug(alarm.region, alarm.name),
            f"{where}[{plain(alarm.name)}]({_console_link(alarm)}): "
            f"{_state_phrase(alarm.state)}{suffix} — {plain(alarm.description)}",
            code)

    def _scope_entry(self, counted: int, regions: tuple[str, ...]) -> Entry:
        """The coverage backstop (little-sister ADR-0043), as a coded line so it
        sorts with the rest: a credential that has stopped seeing anything looks
        exactly like a healthy account until something says how many it saw."""
        where = ", ".join(plain(region) for region in regions)
        minimum = self.cloudwatch.expect_min_alarms
        if not counted:
            return Entry(slug("scope"), f"no alarms in scope ({where})",
                         StatusCode.WARN)
        noun = "alarm" if counted == 1 else "alarms"
        if counted < minimum:
            return Entry(slug("scope"),
                         f"{counted} {noun} in scope ({where}), expected at "
                         f"least {minimum}", StatusCode.WARN)
        return Entry(slug("scope"), f"{counted} {noun} in scope ({where})",
                     StatusCode.OK)

    @staticmethod
    def _roster(alarms: list[Alarm], show_region: bool) -> str:
        """What the run *found*: presence without a verdict (ADR-0044). The count
        can alarm and lives in a reason; these names cannot and live here."""
        return "\n".join(
            f"- {f'{plain(alarm.region)} / ' if show_region else ''}"
            f"[{plain(alarm.name)}]({_console_link(alarm)})"
            for alarm in alarms)

    def _cloudwatch_aspect(self, account: Account,
                           session: Session) -> CheckResult:
        settings = self.cloudwatch
        regions = self.regions_for(account)
        show_region = len(regions) > 1
        failures: list[Entry] = []
        entries: list[Entry] = []
        found: list[Alarm] = []
        for region in regions:
            try:
                alarms = self._describe_alarms(session, region)
            except (BotoCoreError, ClientError) as error:
                # A read failure has no honest alarm state, so it stays a WARN
                # line of its own rather than being graded as one.
                failures.append(Entry(
                    slug("read", region),
                    f"{plain(region)}: alarms cannot be read: {plain(error)}",
                    StatusCode.WARN))
                continue
            for alarm in alarms:
                if settings.ignored(alarm.name):
                    continue
                found.append(alarm)
                code = settings.code_for(alarm.state)
                if code is StatusCode.OK and not settings.show_healthy:
                    continue
                entries.append(self._alarm_entry(alarm, code, show_region))
        # The scope line goes last so an OK one ends the list rather than
        # sitting between the findings and the healthy lines; a WARN one still
        # floats up with the sort.
        reason = [*failures, *entries, self._scope_entry(len(found), regions)]
        reason.sort(key=lambda entry: _CODE_RANK.get(
            entry.code or StatusCode.OK, 3))
        title, about = self._meta(CLOUDWATCH, account)
        # No `code` of its own: the lines carry theirs, and declaring both is
        # refused at construction (little-sister ADR-0042).
        return CheckResult(reason=list(reason), name=CLOUDWATCH,
                           description=f"CloudWatch alarms in {account.name}",
                           report=self._roster(found, show_region),
                           title=title, about=about)

    # --- the ec2 aspect ----------------------------------------------------

    def _ec2_aspect(self, account: Account, session: Session) -> CheckResult:
        settings = self.ec2
        regions = self.regions_for(account)
        show_region = len(regions) > 1
        failures: list[Entry] = []
        groups: dict[tuple[str, str], list[Instance]] = {}
        found = 0
        now = _utcnow()
        for region in regions:
            try:
                instances = self._describe_instances(session, region)
            except (BotoCoreError, ClientError) as error:
                failures.append(Entry(
                    slug("read", region),
                    f"{plain(region)}: instances cannot be read: {plain(error)}",
                    StatusCode.WARN))
                continue
            for instance in instances:
                if settings.ignored_state(instance.state):
                    continue
                name = instance.name or NO_NAME_TAG
                if instance.name and settings.ignored(instance.name):
                    continue
                found += 1
                groups.setdefault((region, name), []).append(instance)
        counts = {key: len(members) for key, members in groups.items()}
        ages = {key: self._oldest(members, now)
                for key, members in groups.items()}
        entries = [self._instance_entry(region, name, counts[(region, name)],
                                        ages[(region, name)], show_region)
                   for (region, name) in sorted(groups)]
        reason = [*failures, *entries, self._instance_scope_entry(found, regions)]
        reason.sort(key=lambda entry: _CODE_RANK.get(
            entry.code or StatusCode.OK, 3))
        title, about = self._meta(EC2, account)
        return CheckResult(reason=list(reason), name=EC2,
                           description=f"EC2 instances in {account.name}",
                           report=self._instance_roster(counts, ages,
                                                        show_region),
                           title=title, about=about)

    @staticmethod
    def _oldest(members: list[Instance], now: datetime) -> int | None:
        """The age of the oldest instance under a name — the one the group is
        graded on, because it is the one that has been unpatched longest."""
        ages = [age for age in (member.age_seconds(now) for member in members)
                if age is not None]
        return max(ages) if ages else None

    def _instance_entry(self, region: str, name: str, count: int,
                        age: int | None, show_region: bool) -> Entry:
        where = f"{plain(region)} / " if show_region else ""
        # The no-name group is not a name, so it is not a console search either.
        label = (plain(name) if name == NO_NAME_TAG
                 else f"[{plain(name)}]({_instance_link(region, name)})")
        # The age rides on **every** line, healthy ones included: it is the
        # reading, not the exception report, and a line that only shows it when
        # it is bad teaches nobody what normal looks like.
        # `coarse_span`, not `format_span`: an age is a **bound** on a card
        # nobody re-renders while it is being read, so it states its largest one
        # or two units and stops (little-sister's `spans` module). The exact
        # measurement would be out of date before the sentence ended.
        suffix = f" ({coarse_span(age)})" if age is not None else ""
        return Entry(slug(region, name), f"{where}{label}: {count}{suffix}",
                     self.ec2.code_for(count, age))

    @staticmethod
    def _instance_scope_entry(found: int, regions: tuple[str, ...]) -> Entry:
        """How many instances were seen at all. Unlike the alarm aspect's, an
        empty one is **not** a warning: an account may legitimately run no EC2 at
        all, where an account whose CloudWatch suddenly shows nothing is a
        symptom."""
        where = ", ".join(plain(region) for region in regions)
        if not found:
            return Entry(slug("scope"), f"no instances in scope ({where})",
                         StatusCode.OK)
        noun = "instance" if found == 1 else "instances"
        return Entry(slug("scope"), f"{found} {noun} in scope ({where})",
                     StatusCode.OK)

    @staticmethod
    def _instance_roster(counts: dict[tuple[str, str], int],
                         ages: dict[tuple[str, str], int | None],
                         show_region: bool) -> str:
        lines = []
        for key in sorted(counts):
            region, name = key
            age = ages.get(key)
            where = f"{plain(region)} / " if show_region else ""
            suffix = f" ({coarse_span(age)})" if age is not None else ""
            lines.append(f"- {where}{plain(name)}: {counts[key]}{suffix}")
        return "\n".join(lines)

    # --- the lambda aspect -------------------------------------------------

    def _list_functions(self, session: Session, region: str) -> list[str]:
        """Every function name in one region, **paginated** — one page stops at
        fifty, and an account past that would silently lose the rest."""
        client = session.client("lambda", region_name=region)
        names: list[str] = []
        for page in client.get_paginator("list_functions").paginate():
            for row in page.get("Functions", []):
                name = str(row.get("FunctionName", "")).strip()
                if name:
                    names.append(name)
        return names

    def _error_counts(self, session: Session, region: str, names: list[str],
                      now: datetime) -> dict[str, tuple[int, datetime]]:
        """The newest ``Errors`` data point per function, from the finest
        resolution that still has one.

        Batched: one call per period for up to 500 functions, rather than one per
        function per period. Functions that answered at a finer period are not asked
        again at a coarser one.
        """
        client = session.client("cloudwatch", region_name=region)
        found: dict[str, tuple[int, datetime]] = {}
        pending = list(names)
        for period, days in _ERROR_PERIODS:
            if not pending:
                break
            # Align the window to the period, so the newest bucket is a whole one
            # rather than the fraction elapsed so far.
            end = datetime.fromtimestamp(
                int(now.timestamp()) // period * period, tz=UTC)
            start = end - timedelta(days=days)
            still_pending: list[str] = []
            for offset in range(0, len(pending), _METRIC_BATCH):
                batch = pending[offset:offset + _METRIC_BATCH]
                results = client.get_metric_data(
                    StartTime=start, EndTime=end,
                    MetricDataQueries=[{
                        "Id": f"e{index}",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Lambda",
                                "MetricName": "Errors",
                                "Dimensions": [{"Name": "FunctionName",
                                                "Value": name}],
                            },
                            "Period": period,
                            "Stat": "Sum",
                        },
                    } for index, name in enumerate(batch)],
                ).get("MetricDataResults", [])
                by_id = {str(result.get("Id", "")): result for result in results}
                for index, name in enumerate(batch):
                    result = by_id.get(f"e{index}", {})
                    values = result.get("Values") or []
                    stamps = result.get("Timestamps") or []
                    # Newest first: `get_metric_data` scans TimestampDescending
                    # unless told otherwise.
                    if values and stamps:
                        found[name] = (int(values[0]), stamps[0])
                    else:
                        still_pending.append(name)
            pending = still_pending
        return found

    def _log_reading(self, session: Session, region: str,
                     name: str) -> tuple[str, str]:
        """The status word of the function's newest log event, and a note when
        there is none. A function that has never run has no log group at all,
        which is a sentence rather than a failure."""
        client = session.client("logs", region_name=region)
        group = f"/aws/lambda/{name}"
        try:
            streams = client.describe_log_streams(
                logGroupName=group, orderBy="LastEventTime", descending=True,
                limit=1).get("logStreams", [])
            if not streams:
                return "", "no log stream"
            events = client.get_log_events(
                logGroupName=group,
                logStreamName=str(streams[0].get("logStreamName", "")),
                limit=1, startFromHead=False).get("events", [])
            if not events:
                return "", "no log event"
            message = str(events[0].get("message", ""))
            match = _LOG_STATUS.search(message)
            if match is None:
                return "", "no status word in the last log line"
            return match.group(1), ""
        except (BotoCoreError, ClientError) as error:
            return "", f"log unreadable: {plain(error)}"

    def _read_functions(self, session: Session, region: str,
                        now: datetime) -> list[FunctionReading]:
        settings = self.lambda_
        names = [name for name in self._list_functions(session, region)
                 if name not in settings.ignore]
        errors = self._error_counts(session, region, names, now)
        readings: list[FunctionReading] = []
        for name in sorted(names):
            count, last_run = errors.get(name, (None, None))
            status, note = ("", "")
            if settings.read_log_status:
                status, note = self._log_reading(session, region, name)
            readings.append(FunctionReading(
                name=name, region=region, errors=count, last_run=last_run,
                log_status=status, notes=(note,) if note else ()))
        return readings

    def _function_entry(self, reading: FunctionReading, now: datetime,
                        show_region: bool) -> Entry:
        settings = self.lambda_
        age = (None if reading.last_run is None
               else max(0, int((now - reading.last_run).total_seconds())))
        parts: list[str] = []
        code = StatusCode.OK
        if reading.errors is None:
            # Not the same as zero errors: CloudWatch had no data point at all in
            # 455 days. A scheduled job nobody has invoked is not a healthy one.
            parts.append("no recent invocations")
            code = StatusCode.WARN
        elif reading.errors == 0:
            parts.append(f"no errors, last run {coarse_span(age or 0)} ago")
        elif age is not None and age <= settings.error_max_age_seconds:
            parts.append(f"{reading.errors} error"
                         f"{'s' if reading.errors != 1 else ''}, "
                         f"last run {coarse_span(age)} ago")
            code = StatusCode.ERROR
        else:
            parts.append(f"{reading.errors} error"
                         f"{'s' if reading.errors != 1 else ''} but the last run "
                         f"was {coarse_span(age or 0)} ago — too old to grade")
        if reading.log_status:
            parts.append(f"log: {plain(reading.log_status)}")
            if reading.log_status == "ERROR":
                code = StatusCode.ERROR
        parts.extend(plain(note) for note in reading.notes)
        where = f"{plain(reading.region)} / " if show_region else ""
        label = plain(settings.short_name(reading.name))
        return Entry(slug(reading.region, reading.name),
                     f"{where}[{label}]"
                     f"({_function_link(reading.region, reading.name)}): "
                     f"{' · '.join(parts)}",
                     code)

    def _lambda_aspect(self, account: Account, session: Session) -> CheckResult:
        regions = self.regions_for(account)
        show_region = len(regions) > 1
        now = _utcnow()
        failures: list[Entry] = []
        readings: list[FunctionReading] = []
        for region in regions:
            try:
                readings.extend(self._read_functions(session, region, now))
            except (BotoCoreError, ClientError) as error:
                failures.append(Entry(
                    slug("read", region),
                    f"{plain(region)}: functions cannot be read: {plain(error)}",
                    StatusCode.WARN))
        entries = [self._function_entry(reading, now, show_region)
                   for reading in readings]
        scope = self._function_scope_entry(len(readings), regions)
        reason = [*failures, *entries, scope]
        reason.sort(key=lambda entry: _CODE_RANK.get(
            entry.code or StatusCode.OK, 3))
        title, about = self._meta(LAMBDA, account)
        return CheckResult(reason=list(reason), name=LAMBDA,
                           description=f"Lambda functions in {account.name}",
                           report=self._function_roster(readings, show_region),
                           title=title, about=about)

    @staticmethod
    def _function_scope_entry(found: int, regions: tuple[str, ...]) -> Entry:
        where = ", ".join(plain(region) for region in regions)
        if not found:
            return Entry(slug("scope"), f"no functions in scope ({where})",
                         StatusCode.OK)
        noun = "function" if found == 1 else "functions"
        return Entry(slug("scope"), f"{found} {noun} in scope ({where})",
                     StatusCode.OK)

    def _function_roster(self, readings: list[FunctionReading],
                         show_region: bool) -> str:
        return "\n".join(
            f"- {f'{plain(reading.region)} / ' if show_region else ''}"
            f"[{plain(reading.name)}]"
            f"({_function_link(reading.region, reading.name)})"
            for reading in readings)

    # --- the codepipeline aspect -------------------------------------------

    @staticmethod
    def _list_pipeline_names(client: CodePipelineClient) -> list[str]:
        """Every pipeline in one region, **paginated**: an account past one page
        would otherwise silently lose the rest."""
        names: list[str] = []
        for page in client.get_paginator("list_pipelines").paginate():
            for row in page.get("pipelines", []):
                name = str(row.get("name", "")).strip()
                if name:
                    names.append(name)
        return names

    @staticmethod
    def _newest_execution(client: CodePipelineClient, name: str
                          ) -> tuple[str, datetime | None]:
        """The pipeline's most recent execution: its status and when it started.

        ``("", None)`` when the pipeline has never been executed — the case the
        original dropped on the floor, because it only ever built a ``Status``
        inside the loop over executions.
        """
        summaries = client.list_pipeline_executions(
            pipelineName=name, maxResults=_EXECUTIONS_PAGE,
        ).get("pipelineExecutionSummaries", [])
        newest: dict[str, Any] | None = None
        for summary in summaries:
            started = summary.get("startTime")
            if started is None:
                continue
            # Compared rather than trusting the API's newest-first order: it costs
            # one comparison and does not depend on a documented ordering.
            if newest is None or started > newest["startTime"]:
                newest = dict(summary)
        if newest is None:
            return "", None
        return str(newest.get("status", "")), newest["startTime"]

    def _read_pipelines(self, session: Session,
                        region: str) -> list[PipelineReading]:
        """One region's pipelines, narrowed at the seam. One client for the
        region, not one per pipeline."""
        client = session.client("codepipeline", region_name=region)
        readings: list[PipelineReading] = []
        for name in self._list_pipeline_names(client):
            if self.codepipeline.ignored(name):
                continue
            status, started = self._newest_execution(client, name)
            readings.append(PipelineReading(name=name, region=region,
                                            status=status, started=started))
        return readings

    def _pipeline_entry(self, reading: PipelineReading, now: datetime,
                        show_region: bool) -> Entry:
        settings = self.codepipeline
        age = (None if reading.started is None
               else max(0, int((now - reading.started).total_seconds())))
        if not reading.status:
            # A pipeline that has never been executed. Reporting nothing for it
            # would make a pipeline created and never triggered indistinguishable
            # from one that does not exist.
            code, phrase = StatusCode.WARN, "never run"
        else:
            code = settings.code_for(reading.status)
            # "started N ago" rather than "N ago": `startTime` is what was read,
            # and for an `InProgress` run it is the only honest thing to say.
            when = f", started {coarse_span(age)} ago" if age is not None else ""
            phrase = f"{plain(reading.status)}{when}"
            if (code is StatusCode.OK and age is not None
                    and age > settings.max_age_seconds):
                # A success this old is not evidence the pipeline still works.
                code = StatusCode.WARN
                phrase = (f"{plain(reading.status)}, but that run started "
                          f"{coarse_span(age)} ago")
        where = f"{plain(reading.region)} / " if show_region else ""
        label = plain(settings.short_name(reading.name))
        return Entry(
            # The full name, as everywhere else: the slug is a stored key and a
            # cosmetic `shorten` rule must not be able to re-point a pin.
            slug(reading.region, reading.name),
            f"{where}[{label}]({_pipeline_link(reading.region, reading.name)}): "
            f"{phrase}",
            code)

    def _codepipeline_aspect(self, account: Account,
                             session: Session) -> CheckResult:
        regions = self.regions_for(account)
        show_region = len(regions) > 1
        now = _utcnow()
        failures: list[Entry] = []
        readings: list[PipelineReading] = []
        for region in regions:
            try:
                readings.extend(self._read_pipelines(session, region))
            except (BotoCoreError, ClientError) as error:
                failures.append(Entry(
                    slug("read", region),
                    f"{plain(region)}: pipelines cannot be read: {plain(error)}",
                    StatusCode.WARN))
        entries = [self._pipeline_entry(reading, now, show_region)
                   for reading in readings]
        reason = [*failures, *entries,
                  _scope_line("pipeline", len(readings), regions)]
        reason.sort(key=lambda entry: _CODE_RANK.get(
            entry.code or StatusCode.OK, 3))
        title, about = self._meta(CODEPIPELINE, account)
        return CheckResult(reason=list(reason), name=CODEPIPELINE,
                           description=f"CodePipeline pipelines in {account.name}",
                           report=self._pipeline_roster(readings, show_region),
                           title=title, about=about)

    @staticmethod
    def _pipeline_roster(readings: list[PipelineReading],
                         show_region: bool) -> str:
        return "\n".join(
            f"- {f'{plain(reading.region)} / ' if show_region else ''}"
            f"[{plain(reading.name)}]"
            f"({_pipeline_link(reading.region, reading.name)})"
            for reading in sorted(readings, key=lambda r: (r.region, r.name)))

    # --- the batch aspect --------------------------------------------------

    @staticmethod
    def _describe_job_queues(client: BatchClient
                             ) -> list[JobQueueDetailTypeDef]:
        rows: list[JobQueueDetailTypeDef] = []
        for page in client.get_paginator("describe_job_queues").paginate():
            rows.extend(page.get("jobQueues", []))
        return rows

    @staticmethod
    def _job_time(value: object) -> datetime | None:
        """One Batch timestamp. Batch reports Unix **milliseconds**, so the
        conversion lives at the seam and nothing downstream carries the fact."""
        if not isinstance(value, int | float) or isinstance(value, bool):
            return None
        return datetime.fromtimestamp(value / 1000.0, tz=UTC)

    def _list_jobs(self, client: BatchClient, queue: str,
                   status: JobStatusType) -> tuple[list[Job], bool]:
        """Up to ``max_jobs`` jobs of one status in one queue, and whether the
        cap cut the answer short.

        A single page read silently would report the jobs that fitted as though
        they were all of them, so the bound is configuration and reaching it is a
        sentence on the card.
        """
        limit = self.batch.max_jobs
        jobs: list[Job] = []
        for page in client.get_paginator("list_jobs").paginate(
                jobQueue=queue, jobStatus=status):
            for row in page.get("jobSummaryList", []):
                if len(jobs) >= limit:
                    return jobs, True
                name = str(row.get("jobName", "")).strip()
                if not name:
                    continue
                jobs.append(Job(
                    job_id=str(row.get("jobId", "")),
                    name=name,
                    status=str(row.get("status", "")).upper(),
                    created=self._job_time(row.get("createdAt")),
                    started=self._job_time(row.get("startedAt")),
                    stopped=self._job_time(row.get("stoppedAt"))))
        return jobs, False

    def _read_queues(self, session: Session, region: str) -> list[QueueReading]:
        """One region's job queues and the jobs in them, narrowed at the seam."""
        settings = self.batch
        client = session.client("batch", region_name=region)
        readings: list[QueueReading] = []
        for row in self._describe_job_queues(client):
            name = str(row.get("jobQueueName", "")).strip()
            if not name or settings.ignored_queue(name):
                continue
            queue = JobQueue(name=name, region=region,
                             state=str(row.get("state", "")),
                             status=str(row.get("status", "")),
                             status_reason=str(row.get("statusReason", "")))
            jobs: list[Job] = []
            capped = False
            for status in BATCH_STATUSES:
                found, cut = self._list_jobs(client, name, status)
                jobs.extend(found)
                capped = capped or cut
            readings.append(QueueReading(queue=queue, jobs=tuple(jobs),
                                         capped=capped))
        return readings

    def _queue_entry(self, reading: QueueReading, job_names: int,
                     show_region: bool) -> Entry | None:
        """A line about the *queue*, and only when the queue has something to
        say for itself.

        A healthy queue full of jobs is already described by its job lines, and
        a second line repeating its name would double the card for nothing. What
        earns one: it takes no new work, AWS could not build it, it holds
        nothing at all, or the reading was capped.
        """
        settings = self.batch
        queue = reading.queue
        code = StatusCode.OK
        notes: list[str] = []
        if queue.status.upper() == "INVALID":
            code = _worst(code, StatusCode.ERROR)
            because = (f": {plain(queue.status_reason)}"
                       if queue.status_reason else "")
            notes.append(f"the queue is INVALID{because}")
        if queue.state.upper() == "DISABLED":
            code = _worst(code, StatusCode.WARN)
            notes.append("the queue is DISABLED and accepts no new jobs")
        if not job_names:
            # Whether an empty queue is worth saying so about is the installation's
            # call, not this type's — hence the knob rather than a rule.
            notes.append("no jobs found")
            if settings.expect_jobs:
                code = _worst(code, StatusCode.WARN)
        if reading.capped:
            notes.append(f"only the newest {settings.max_jobs} jobs per status "
                         f"were read")
        if not notes:
            return None
        where = f"{plain(queue.region)} / " if show_region else ""
        return Entry(slug(queue.region, queue.name),
                     f"{where}[{plain(queue.name)}]({_queue_link(queue.region)}): "
                     f"{' · '.join(notes)}",
                     code)

    @staticmethod
    def _elapsed(since: datetime | None, now: datetime) -> int | None:
        if since is None:
            return None
        return max(0, int((now - since).total_seconds()))

    def _finished_phrase(self, job: Job, now: datetime) -> str:
        """How the newest finished run of this job name ended.

        Ages rather than a wall-clock timestamp and an `HH:MM:SS` duration: an age
        needs no timezone, and the library writes spans in one spelling for the
        whole page.
        """
        ended = self._elapsed(job.stopped, now)
        ran = (None if job.stopped is None or job.started is None
               else max(0, int((job.stopped - job.started).total_seconds())))
        if ended is None:

            return f"{plain(job.status)} (no timestamps)"
        took = f", ran {coarse_span(ran)}" if ran is not None else ""
        return f"{plain(job.status)} {coarse_span(ended)} ago{took}"

    def _job_entry(self, queue: JobQueue, name: str, jobs: list[Job],
                   now: datetime, show_region: bool) -> Entry:
        """One line per job *name* per queue, carrying every reading at once.

        Splitting the finished and the running reading into two lines would make
        two nodes and two pins for one thing an operator thinks of as one thing.
        They meet on one line, the way the lambda aspect's metric and log readings
        do.
        """
        settings = self.batch
        finished = [job for job in jobs if job.status in BATCH_FINISHED_STATUSES]
        running = [job for job in jobs if job.status == BATCH_RUNNING_STATUS]
        waiting = [job for job in jobs if job.status == BATCH_WAITING_STATUS]
        code = StatusCode.OK
        parts: list[str] = []

        newest = self._newest_job(finished)
        if newest is not None:
            code = _worst(code, StatusCode.OK if newest.status == "SUCCEEDED"
                          else StatusCode.ERROR)
            parts.append(self._finished_phrase(newest, now))
        if running:
            longest = self._longest(running, lambda job: job.started, now)
            for_how_long = f" ({coarse_span(longest)})" if longest is not None else ""
            parts.append(f"{len(running)} running{for_how_long}")
            if longest is not None and longest > settings.max_run_seconds:
                code = _worst(code, StatusCode.WARN)
        if waiting:
            # Waiting is measured from submission, because a RUNNABLE job has
            # never started — that is the whole complaint.
            longest = self._longest(waiting, lambda job: job.created, now)
            for_how_long = f" ({coarse_span(longest)})" if longest is not None else ""
            parts.append(f"{len(waiting)} waiting for capacity{for_how_long}")
            if longest is not None and longest > settings.max_wait_seconds:
                code = _worst(code, StatusCode.WARN)
        if not parts:                                   # pragma: no cover
            parts.append("no runs read")

        link_to = newest or self._newest_job(jobs)
        label = plain(settings.short_name(name))
        linked = (f"[{label}]({_job_link(queue.region, link_to.job_id)})"
                  if link_to is not None and link_to.job_id else label)
        where = f"{plain(queue.region)} / " if show_region else ""
        return Entry(
            # Queue *and* name: the same job name may be submitted to two queues,
            # and those are two different things to put into maintenance.
            slug(queue.region, queue.name, name),
            f"{where}{plain(queue.name)} / {linked}: {' · '.join(parts)}",
            code)

    @staticmethod
    def _newest_job(jobs: list[Job]) -> Job | None:
        """The most recently submitted of these, or ``None``. Submission time,
        because it is the one timestamp every job has."""
        dated = [job for job in jobs if job.created is not None]
        if not dated:
            return jobs[0] if jobs else None
        return max(dated, key=lambda job: job.created or datetime.min)

    @staticmethod
    def _longest(jobs: list[Job], when: Callable[[Job], datetime | None],
                 now: datetime) -> int | None:
        """How long the oldest of these has been in its state. The oldest
        decides, so a queue that keeps starting fresh jobs cannot reset the
        clock on the one that is stuck."""
        ages = [max(0, int((now - stamp).total_seconds()))
                for stamp in (when(job) for job in jobs) if stamp is not None]
        return max(ages) if ages else None

    def _batch_aspect(self, account: Account, session: Session) -> CheckResult:
        settings = self.batch
        regions = self.regions_for(account)
        show_region = len(regions) > 1
        now = _utcnow()
        failures: list[Entry] = []
        entries: list[Entry] = []
        roster: list[str] = []
        queues = 0
        for region in regions:
            try:
                readings = self._read_queues(session, region)
            except (BotoCoreError, ClientError) as error:
                failures.append(Entry(
                    slug("read", region),
                    f"{plain(region)}: job queues cannot be read: {plain(error)}",
                    StatusCode.WARN))
                continue
            for reading in readings:
                queues += 1
                groups: dict[str, list[Job]] = {}
                for job in reading.jobs:
                    if settings.ignored(job.name):
                        continue
                    groups.setdefault(job.name, []).append(job)
                queue_entry = self._queue_entry(reading, len(groups), show_region)
                if queue_entry is not None:
                    entries.append(queue_entry)
                for name in sorted(groups):
                    entries.append(self._job_entry(
                        reading.queue, name, groups[name], now, show_region))
                where = f"{plain(region)} / " if show_region else ""
                names = "no job names" if not groups else (
                    f"{len(groups)} job name{'' if len(groups) == 1 else 's'}")
                roster.append(f"- {where}"
                              f"[{plain(reading.queue.name)}]({_queue_link(region)})"
                              f" — {names}")
        reason = [*failures, *entries, _scope_line("job queue", queues, regions)]
        reason.sort(key=lambda entry: _CODE_RANK.get(
            entry.code or StatusCode.OK, 3))
        title, about = self._meta(BATCH, account)
        return CheckResult(reason=list(reason), name=BATCH,
                           description=f"Batch job queues in {account.name}",
                           report="\n".join(sorted(roster)),
                           title=title, about=about)

    # --- the tree ---------------------------------------------------------

    def _account_result(self, base: Session, account: Account) -> CheckResult:
        """One account's node: its aspects, or the reason there are none."""
        session, failure = self._open(base, account)
        if session is None:
            # This account's problem, and this account's node. The others keep
            # reporting, which is the whole reason the tree branches here.
            return CheckResult(
                StatusCode.ERROR, failure,
                name=account.name, title=account.title, about=account.about,
                config=self._account_config(account))
        builders = {CLOUDWATCH: self._cloudwatch_aspect,
                    EC2: self._ec2_aspect,
                    LAMBDA: self._lambda_aspect,
                    CODEPIPELINE: self._codepipeline_aspect,
                    BATCH: self._batch_aspect}
        # A switched-off aspect emits no node **and makes no API call** — which is
        # the half that matters to a role whose policy does not carry that
        # service's permissions at all.
        children = tuple(builders[name](account, session)
                         for name in self.active_aspects())
        return CheckResult(StatusCode.OK, [], name=account.name,
                           children=children, title=account.title,
                           about=account.about,
                           config=self._account_config(account))

    def _open(self, base: Session, account: Account
              ) -> tuple[Session | None, list[str]]:
        """Open *account*'s session, renewing an expired login once if it can.

        Returns the session and no reasons, or no session and the reasons the
        node will carry. The retry is the point of the whole exercise: an SSO
        login expires roughly once a working day, and on the machine where that
        happens the fix is a command this process can run — so it runs it, once,
        and asks AWS again rather than reddening three accounts until somebody
        notices the dashboard.
        """
        try:
            return self._opened(base, account), []
        except (BotoCoreError, ClientError) as error:
            if not is_credential_error(error):
                return None, [self._unreachable(account, error)]
            problem = self._renew(account)
            if problem:
                return None, self._expired(account, error, problem)
            try:
                # A *new* base session: the one above cached the credentials
                # that just expired, and the login wrote a fresh token beside it.
                return self._opened(self._base_session(), account), []
            except (BotoCoreError, ClientError) as again:
                return None, self._expired(
                    account, again,
                    "the login was renewed and the credentials are still refused")

    def _unreachable(self, account: Account, error: BaseException) -> str:
        """AWS said no, and it was not about the credentials being stale."""
        if account.role_arn:
            return f"role cannot be assumed: {plain(error)}"
        return f"account cannot be read: {plain(error)}"

    def _expired(self, account: Account, error: BaseException,
                 problem: str) -> list[str]:
        """Two lines: what went wrong, and what to do about it.

        The second line is a line of its own rather than a suffix on the first
        because it is the actionable half, and a boto3 credential message is
        long enough to push it off the edge of a card. Without a profile there
        is no command to print — telling a server to run `aws sso login` would
        be advice for a machine that is not this one — so the reason why nothing
        was renewed stands on its own instead.
        """
        profile = self.profile_for(account)
        second = (f"renew it with `{login_command(profile)}` — {problem}"
                  if profile else problem)
        return [f"AWS credentials have expired: {plain(error)}", second]

    def _account_config(self, account: Account) -> str:
        return config_markdown({
            "regions": ", ".join(plain(region)
                                 for region in self.regions_for(account)),
            "credentials": self._account_credentials(account),
        })

    def _account_credentials(self, account: Account) -> str:
        """Where this account's credentials come from, in one line.

        Both halves, where there are two: a profile that assumes a role is the
        normal cross-account shape, and reading only one of them off the card
        would send somebody to fix the wrong end of it.
        """
        profile = self.profile_for(account)
        if account.role_arn:
            return (f"assumed role, from profile {plain(profile)}" if profile
                    else "assumed role")
        return f"profile {plain(profile)}" if profile else "ambient credential chain"

    def _scope_reason(self) -> str:
        pairs = sum(len(self.regions_for(account)) for account in self.accounts)
        accounts = "account" if len(self.accounts) == 1 else "accounts"
        pair_noun = "pair" if pairs == 1 else "pairs"
        return (f"{len(self.accounts)} {accounts}, {pairs} account/region "
                f"{pair_noun} in scope")

    def _scope_report(self) -> str:
        return "\n".join(
            f"- **{plain(account.name)}** — "
            f"{', '.join(plain(region) for region in self.regions_for(account))}"
            for account in self.accounts)

    def run(self) -> CheckResult:
        try:
            base = self._base_session()
        except (BotoCoreError, ClientError) as error:
            # Nothing can be read at all — the whole branch goes red rather than
            # every account inventing the same excuse.
            return CheckResult(
                StatusCode.ERROR,
                [f"no usable AWS credentials: {plain(error)}"],
                report=self._scope_report())
        children = tuple(self._account_result(base, account)
                         for account in self.accounts)
        logger.info("%s: read %d account(s): %s", self.path, len(children),
                    ", ".join(account.name for account in self.accounts))
        # The root stays OK and says only what is watched: an account that failed
        # is red on its own node and reaches this container by roll-up, so
        # repeating it here would report one fact twice.
        return CheckResult(StatusCode.OK, [self._scope_reason()],
                           children=children, report=self._scope_report())
