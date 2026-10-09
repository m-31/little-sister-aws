"""The ``aws`` check type: one node per aspect, beneath one node per account where a
check names several.

**One** check type reads every service, and the tree carries what a flat list
would otherwise have to label each line with::

    /team/aws                      this check's node — what is watched
      /team/aws/live               one node per account, its own session
        /team/aws/live/cloudwatch  one node per aspect
        /team/aws/live/ec2
        /team/aws/live/lambda
          /team/aws/live/lambda/collector    one node per function
        /team/aws/live/codepipeline
          /team/aws/live/codepipeline/deploy    one node per pipeline
        /team/aws/live/batch
          /team/aws/live/batch/nightly       one node per job queue
            /team/aws/live/batch/nightly/etl    one node per job name
      /team/aws/backup
        /team/aws/backup/cloudwatch
        …

Account first, aspect second, because the account is what an operator acts on as
a group: "staging is down for the migration" is one maintenance pin against one
node, where a flat list of every alarm would be forty. Each account's node also
absorbs its own bad news — a role that cannot be assumed reddens that account and
leaves the others reporting.

**A level stands only where the configuration names several of it** (ADR-0007).
Those reasons are reasons to tell accounts apart, so a check that names one account
has no account level: its aspects hang beneath the check's own node —
``/team/aws/lambda/collector`` — and that node says what refused the account. A
function, a pipeline and a job queue hang beneath their region's node where their
account reads several regions — ``…/lambda/eu-west-1/collector`` — and directly
beneath their aspect where it reads one. What is counted is the configuration,
never what AWS answers, so a tree changes its shape when its configuration does and
at no other time. A job queue is the one level AWS names, and it stands in every
tree: a job name hangs beneath its queue's node (ADR-0009).

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
what this package pins with ``require_api(3)``.

**A run is two halves** (little-sister ADR-0086). :meth:`AwsCheck.measure` reads
every account and hands back one reading per thing it read — the estate first, then
each account's own, then each aspect's in the order it read them — and
:meth:`AwsCheck.grade` builds the tree above out of those readings and the
configuration alone, so the same verdict can be reached again over readings this
process did not take. A reading has a history only where there is one to keep: a
Batch job's runs, a pipeline's executions, the estate (ADR-0005) and a Lambda
function's runs (ADR-0006) — and a job name, a pipeline and a function each stand on
a node of their own, which is where the library shows that history (ADR-0006 §9,
ADR-0009).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import urllib.parse
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError
from little_sister.checks import (
    Check,
    CheckError,
    CheckResult,
    Entry,
    Measurement,
    coerce_code,
    config_markdown,
    parse_duration,
    parse_secret_refs,
    plain,
    register,
)
from little_sister.reasons import MAX_SUBJECT_LENGTH, clip, slug
from little_sister.spans import coarse_span, format_span
from little_sister.status import StatusCode

from little_sister_aws._rules import (
    UNGRADED,
    Rule,
    Threshold,
    parse_pair,
    parse_rules,
    resolved,
    rule_for,
    sentence_for,
    threshold_keys,
)
from little_sister_aws.identity import (
    DEFAULT_ROLE_SESSION_NAME,
    DEFAULT_STS_REGION,
    SSO_LOGIN_ALWAYS,
    SSO_LOGINS,
    Identity,
    OptionalTextError,
    SsoBlockError,
    SsoConfig,
    ambient_profile,
    base_session,
    caller_identity,
    is_credential_error,
    login_command,
    login_problem,
    new_session,
    open_session,
    parse_optional_text,
    parse_sso_block,
    read_profile_config,
    run_sso_login,
)

if TYPE_CHECKING:
    # The record a check's history holds, for its type only: what `kept()` answers.
    from little_sister.series import SeriesRecord

    # The service clients, for their **types** only: `boto3-stubs`' per-service
    # extras are a dev dependency, so these names must not be imported at run
    # time. They are why ADR-0001 §3 bought the extras at all — without them every
    # client is a bare `BaseClient` and strict mypy checks nothing on the one
    # call path that matters.
    from mypy_boto3_batch.client import BatchClient
    from mypy_boto3_batch.literals import JobStatusType
    from mypy_boto3_batch.type_defs import JobQueueDetailTypeDef
    from mypy_boto3_cloudwatch.client import CloudWatchClient
    from mypy_boto3_cloudwatch.type_defs import MetricDataQueryTypeDef
    from mypy_boto3_codepipeline.client import CodePipelineClient

#: This module's own logger. little-sister configures the root handlers, so an
#: ordinary module logger's records land in the same place under a name that says
#: who emitted them.
logger = logging.getLogger(__name__)

#: The region a single-region estate is most likely to mean. It is a default
#: rather than a constant now: ``regions`` is a list, and an account may override
#: it — a backup account living in Ireland is the case that made this necessary.
DEFAULT_REGIONS = ("eu-central-1",)

#: The aspect names. Each is one string in **four** places: :attr:`AwsCheck.ASPECTS`,
#: the child's ``name`` (and so its node path), the :data:`SUBNODES` key its
#: built-in title/about is read from, and the configuration block its knobs — and
#: its ``enabled:`` switch — live under. They drifted once in the `github` port and
#: the aspect silently lost its display text.
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

#: Free text a reading keeps — an alarm's description, the reason AWS gives for a
#: queue's or a job's status, an error AWS answered with, a name AWS lets somebody
#: type — is clipped **once**, in the measuring half, to this many characters and then
#: to this many of the bytes the seam weighs a record in (little-sister ADR-0086
#: decision 7), and the line is written from what was kept. A name AWS limits to
#: ASCII is never cut; the byte budget shortens only a name written in an alphabet
#: JSON escapes. The bounds are the ones `little-sister-github` and
#: `little-sister-wiz` keep, so the family clips one way (ADR-0005 §8).
_TEXT_CHARS = 300
_TEXT_BYTES = 600
#: A status, a state or an identifier AWS mints is short, and is held to this.
_WORD_BYTES = 100

#: The three outcomes an account's reading can name, and so the only words that can
#: follow the last `=` of a pair in the estate's state (ADR-0005 §6): the account
#: opened; AWS said no; its login had expired and was not renewed, or was renewed
#: and still refused.
READ = "read"
UNREACHABLE = "unreachable"
EXPIRED = "expired"
#: The estate's state where the credentials themselves did not open, and so no
#: account was tried at all.
CREDENTIALS_UNUSABLE = "credentials=unusable"
#: The state a pipeline's reading names when it has never been executed: there is
#: no execution to name, and a pipeline that stays unrun is one spell (ADR-0005 §5).
NEVER_RUN = "never-run"
#: The second line of an expired account whose login was renewed and is refused all
#: the same.
RENEWED_STILL_REFUSED = ("the login was renewed and the credentials are still "
                         "refused")


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

#: There is no default age, and no default count. An instance is patched by being
#: replaced, so age *is* the security reading — but how long a box may run before
#: that reading is a finding is a fact about somebody's estate, and this package has
#: never seen it. What survives as a default is what is true of **AWS**
#: (``DEFAULT_EC2_IGNORE_STATES`` above), never what is true of an installation.

#: There is no fleet size and no fleet clock any more. A group larger than some
#: number used to be read as a deliberate fleet and judged by a shorter clock —
#: which keyed on the *reading* rather than on the name, and could therefore only
#: ever be one rule for every estate. A known fleet is a name a rule matches
#: (`prefixes: [loadtest-]`), and an unknown one is what the block's own levels are
#: for: they are not "sensible numbers for everything", they are what the check
#: says about a name nobody has classified.

#: CloudWatch keeps one-minute points for 15 days, five-minute for 63 and hourly
#: for 455, and returns nothing at all outside the window it is asked for. So a
#: function's newest error count is looked for in that order — the finest
#: resolution first, widening only where nothing came back. These are retention
#: facts, not preferences, which is why they are not configurable.
_ERROR_PERIODS = ((60, 15), (300, 63), (3600, 455))

#: ``get_metric_data`` takes 500 queries per call. Batching by function is the
#: whole reason this aspect costs a few API calls per region rather than a few per
#: function.
_METRIC_BATCH = 500

#: A function's **run** is a one-minute bucket of CloudWatch's metric (ADR-0006 §1),
#: so its runs are read at the finest of the periods above, and only as far back as
#: CloudWatch keeps that period.
_RUN_PERIOD, _RUN_DAYS = _ERROR_PERIODS[0]

#: The windows a function is asked in, where its check keeps a series: the last
#: hour, the last day, or the days CloudWatch keeps a one-minute point for. A
#: function is asked in the smallest that reaches the oldest run its series keeps,
#: and in the largest where its kept runs do not fill the series (ADR-0006 §3) — so
#: a function invoked every minute answers its last hour where the series keeps no
#: more than an hour of it, a day up to a day of it, and only past that the 21,600
#: points of fifteen days. One call has one window, so a region's functions are
#: asked in at most three calls. Constants of this type, as the retention periods
#: are: how far back a series reaches is the deployment's ``series_keep``, and which
#: window then holds it is arithmetic.
_RUN_WINDOWS = (timedelta(hours=1), timedelta(days=1), timedelta(days=_RUN_DAYS))

#: A bucket is read in full on every poll until one has read it this old (ADR-0006
#: §4): its numbers may still grow after it first appears — an invocation that began
#: in its minute and ended later. Lambda delays a point by no more than a function's
#: longest run, fifteen minutes, and an hour is four times that. How late CloudWatch
#: delivers is a fact about CloudWatch, so it is no setting. What counts is how old
#: the bucket was when it was last read, which its kept run says, and never how old
#: it is now: a poll that comes an hour after the last still reads again what that
#: one saw young.
_RUN_OVERLAP = timedelta(hours=1)

#: How many pages of one ``get_metric_data`` answer are followed. CloudWatch ends a
#: page where its part of the window could hold 100,800 points — the queries times
#: the periods in that part, whatever the metrics hold — and hands back a token for
#: the next; five hundred functions asked their fifteen days are 108 such pages,
#: however seldom they run, so this is a bound no answer meets — and one that ends
#: a token which never ends, on a thread nothing can stop.
_METRIC_PAGES = 200

#: What a ``get_metric_data`` result says of itself where CloudWatch answered its
#: query (the API reference, *MetricDataResult*): ``Complete``, every point of the
#: window, or ``PartialData``, some of them with a token for the rest, which is
#: followed. Any other word says that the query was **not answered** —
#: ``InternalError`` and ``Forbidden`` are the two CloudWatch has — in a call that
#: itself succeeded, and the result's empty list of points is then no reading of
#: the metric. A list of the words that answer, and not of those that refuse: a
#: word this type has never seen is no answer it can read either.
_ANSWERED = ("Complete", "PartialData")

#: The words a Lambda runtime writes at the start of a log line. The last event's
#: word says how the newest invocation ended, and ``ERROR`` is the one that counts.
_LOG_STATUS = re.compile(r"\b(INIT_START|START|END|REPORT|ERROR)\b")

#: How many pages of a function's newest log stream the log read asks for before it
#: says the newest event was not reached: the first, and three more. GetLogEvents may
#: answer an empty page while the stream still has events, and says where the stream
#: ends by handing back the token it was sent; each page is one call on top of the
#: two the read costs when the first page answers.
_LOG_PAGES = 4

#: How recent an error has to be before it is graded rather than merely reported.
#: The reasoning: past this, CloudWatch has condensed the bucket
#: the error sits in together with the successful runs around it, so a non-zero
#: count no longer means "the last run failed" — and a real, persistent error will
#: have been seen while it was fresh.
DEFAULT_ERROR_MAX_AGE_SECONDS = 14 * 86400

#: How long an error the function saw is **held** on its line once clean runs have
#: followed it (ADR-0012). An hour, because an hour is the smallest window any
#: function is asked at one minute, so a hold inside it costs no request anywhere —
#: and because the engine holds its own lines' worst for a window for the same
#: reason: a verdict that stands one tick is two events and no information. A
#: deployment says otherwise per block or per rule; ``0s`` is no hold.
DEFAULT_ERROR_HOLD_SECONDS = 3600

#: The longest hold the type can read: an error is held beside the clean runs that
#: followed it only where both are one-minute points, and CloudWatch keeps those
#: for fifteen days (:data:`_ERROR_PERIODS`). Past that a hold would end silently
#: where the points end, so a longer one is refused where the check loads.
MAX_ERROR_HOLD_SECONDS = 15 * 86400

#: ``PipelineExecutionStatus`` → the code that line reports, keyed in lower case
#: because CodePipeline spells its statuses in mixed case where CloudWatch shouts
#: them. ``Succeeded`` passes and so does ``InProgress``: an execution in flight is a
#: deployment under way, and how long one may take is ``max_run_time`` (ADR-0014
#: §1). *Everything else* is an error — a stopped, canceled or superseded run still
#: means the newest thing this pipeline did was not a deployment.
DEFAULT_PIPELINE_STATE_MAP = {
    "succeeded": StatusCode.OK,
    "inprogress": StatusCode.OK,
    "failed": StatusCode.ERROR,
    "stopped": StatusCode.ERROR,
    "stopping": StatusCode.ERROR,
    "cancelled": StatusCode.ERROR,
    "superseded": StatusCode.ERROR,
}

#: There is no default staleness clock, for the same reason the EC2 aspect has no
#: default age: how long a successful run stays evidence that a pipeline still
#: works depends on how often it is meant to run — nightly, at a release, on a
#: pull request — which is an installation's fact to state and this package's to
#: grade once stated.

#: How many executions of one pipeline one poll asks for: one page, the largest
#: CodePipeline answers. ``list_pipeline_executions`` returns them newest first, and
#: the newest is found by comparing every summary returned rather than by trusting
#: that order. The one a pipeline's line is written from while the newest is in
#: flight, and every one in flight, come out of the same page (ADR-0014 §2), and so,
#: where the check keeps a series, do the executions a poll reads behind the newest
#: (ADR-0009 §5): reading them asks for nothing more.
_EXECUTIONS_PAGE = 100

#: The statuses in which CodePipeline says an execution is over, lowercased as a
#: status word is compared (ADR-0008 §3). What is listed is the words that end one,
#: so `InProgress` and `Stopping` are an execution on its way, and a word
#: CodePipeline adds ends nothing until this type knows it.
_EXECUTION_ENDED = frozenset(
    {"succeeded", "failed", "stopped", "superseded", "cancelled"})

#: The statuses in which an execution is **in flight**, lowercased as a status word
#: is compared: the two words of one on its way (ADR-0008 §3). While one is, its
#: pipeline's line keeps what the newest finished execution did, says what is in
#: flight beside it and is marked running (ADR-0014 §2). Listed rather than derived
#: from :data:`_EXECUTION_ENDED`: a word CodePipeline adds ends nothing, and it is
#: not taken for work in flight either until this type knows it (little-sister
#: ADR-0032 rule 7).
_EXECUTION_IN_FLIGHT = frozenset({"inprogress", "stopping"})

#: The statuses an execution is retried from, lowercased: CodePipeline runs a failed
#: or a stopped execution again, under its own id and from the start it had
#: (ADR-0014 §5). Where the history holds an execution in one of them and the page
#: has it in flight again, its action executions are asked for.
_EXECUTION_RETRIED_FROM = frozenset({"failed", "stopped"})

#: How many of one execution's action executions a poll asks for while the execution
#: is retried: one page, the largest CodePipeline answers.
_ACTIONS_PAGE = 100

#: How long an execution may be in flight before its pipeline's line warns: the
#: default of ``max_run_time``, and the one ``_warn`` / ``_error`` pair of this type
#: that has a default (ADR-0014 §3). ``InProgress`` warned from an execution's first
#: second until then, so thirty minutes takes no warning from an installation that
#: had one and gives none it did not have. ``max_run_time: null`` switches it off.
DEFAULT_PIPELINE_RUN_TIME = Threshold(warn=30 * 60)

#: The status of an execution a newer one overtook, lowercased as a status word is
#: compared. Read behind its pipeline's newest, such an execution is said nothing of
#: for the record: it neither failed nor deployed (ADR-0009 §6).
_SUPERSEDED = "superseded"

#: The Batch job statuses this aspect reads: **every one Batch has**. A queue's node
#: says that its job names are complete in every run that lists it (ADR-0009 §2), so
#: a name whose only listed job is in a status nobody asked for would leave the tree
#: for that poll and come back with the next. Each status is a ``ListJobs`` call of its
#: own, as the call answers them: a filter answers every status at once, but newest
#: first across all of them, and a job that has run or waited for long would fall
#: behind newer ones that finished. Three words are written of the seven:
#:
#: * *finished* — ``SUCCEEDED`` and ``FAILED``;
#: * *running* — ``RUNNING``, and ``STARTING``, which a job passes through on its way
#:   there and which has no start yet to be counted from;
#: * *waiting* — ``RUNNABLE``, the one easiest to leave out: the queue accepted the
#:   job and no compute environment has capacity for it, so it waits, silently, and
#:   the queue looks idle while it does; and ``SUBMITTED`` and ``PENDING``, a job not
#:   yet placed, or held by a job it depends on. An array job's parent is ``PENDING``
#:   while its children run.
#:
#: Typed as Batch's own literal, so a status invented here is a mypy error rather than
#: an ``InvalidParameterValue`` at run time — which is exactly what the per-service
#: stubs are for.
BATCH_FINISHED_STATUSES: tuple[JobStatusType, ...] = ("SUCCEEDED", "FAILED")
BATCH_RUNNING_STATUSES: tuple[JobStatusType, ...] = ("RUNNING", "STARTING")
BATCH_WAITING_STATUSES: tuple[JobStatusType, ...] = (
    "RUNNABLE", "PENDING", "SUBMITTED")
#: The waiting status that waits *for capacity*, which a job name's line names as such
#: where every job it counts as waiting is in it.
BATCH_CAPACITY_STATUS: JobStatusType = "RUNNABLE"
BATCH_STATUSES: tuple[JobStatusType, ...] = (
    *BATCH_FINISHED_STATUSES, *BATCH_RUNNING_STATUSES, *BATCH_WAITING_STATUSES)

#: How long a Batch job may run before its line warns. Warning at the *existence*
#: of a running job would be a permanent yellow on any queue that is doing its
#: work, and a permanent yellow is a light people stop reading.
DEFAULT_BATCH_MAX_RUN_SECONDS = 2 * 3600

#: How long a job may wait — submitted, pending or runnable — before its line warns,
#: counted from its submission. This is the reading easiest to omit: a job that
#: cannot be placed is not slow, it is stuck, and the queue looks idle while it
#: happens. A job held by one it depends on waits too, and so does an array job's
#: parent while its children run: a deployment whose arrays run longer says so in
#: ``max_wait_time``.
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

#: What a record of this type carries as a number worth drawing, declared the way a
#: deployment's own `measures:` block is shaped (little-sister ADR-0092): the field,
#: its unit and its label. `duration_ms` is a function's run's (ADR-0006 §7), the
#: slowest invocation of its minute. `duration_s` is how long a Batch run ran and how
#: long a pipeline's execution took, and `wait_s` how long a Batch run waited before
#: it started (ADR-0008 §5). So a deployment that keeps a series draws a run as a
#: stem to each with no key of its own, and takes a plot away by its field's name,
#: `duration_ms: null`. A run's counts are columns of its readings table and no plot.
MEASURES: dict[str, dict[str, str]] = {
    "duration_ms": {"unit": "ms", "label": "Duration"},
    "duration_s": {"unit": "s", "label": "Duration"},
    "wait_s": {"unit": "s", "label": "Wait"},
}


def _pin_notes(several_accounts: bool) -> dict[str, str]:
    """The sentence each aspect's `about` ends with, written once and referenced as
    `{pin_note}` — and as `{function_pin_note}`, `{pipeline_pin_note}` or
    `{job_pin_note}` by an aspect whose subjects are nodes (little-sister ADR-0025).

    What silences a whole account is the account's node where a check names several
    accounts, and the check's own where it names one and the account has no node
    (ADR-0007 §2). That is configuration, so the two are spelled when the check is
    constructed — which is also when a label token is resolved."""
    above = ("The account node above silences the whole account."
             if several_accounts else
             "The check's own node above silences the whole account.")

    def on_its_node(subject: str) -> str:
        return (f"Each {subject}'s node can be put into maintenance on its own — "
                f"pin the {subject} you are working on and the rest keeps "
                f"reporting. {above}")

    return {
        "pin_note": ("Each line can be put into maintenance on its own — pin the "
                     "line you are working on and the rest keeps reporting. "
                     + above),
        "function_pin_note": on_its_node("function"),
        "pipeline_pin_note": on_its_node("pipeline"),
        "job_pin_note": on_its_node("job name"),
    }

#: Built-in display text for the aspects this check emits — **type-inherent**,
#: so it is written once here rather than copied into every deployment's config.
#: **Declared, not applied**: this map is handed to little-sister as
#: ``subnode_defaults`` and the library resolves it against a deployment's
#: `subnodes:` block — replacing one of these, or extending it where the config
#: writes `{default}` — and the engine writes the result per subnode name.
#: `nodes.yaml` still wins over both, per path. `{pin_note}`, `{function_pin_note}`,
#: `{pipeline_pin_note}` and `{job_pin_note}` are `label_tokens` entries
#: (:func:`_pin_notes`), expanded in either text.
#:
#: **It says "this account" rather than naming one**, and that is the consequence
#: of the library reading the block (little-sister ADR-0025): a
#: label is resolved once per subnode *name*, and every account's `ec2` node is
#: named `ec2`. Neither fact is lost — the node's parent **is** the account,
#: or the check's own where the check names one, and its card carries the regions
#: this check reads for it, and each aspect's own `description` names the account
#: too. A per-account sentence here would have had to be a per-account *label*,
#: which is the one thing this shape does not have.
#:
#: **Four of the five entries also carry ``show_when_quiet``** (little-sister
#: ADR-0063). Those four report a **roster** rather than a diagnosis: they name
#: everything they found, every run, whether or not anything is wrong, so the list
#: is read precisely *because* nothing is — which is what a dense dashboard takes
#: away by folding a quiet node into a chip. That is a fact about the aspect, true
#: in every installation, so it belongs in this map rather than in one deployment's
#: `nodes.yaml`, where it took an entry per aspect **per account**; a deployment
#: that disagrees writes `show_when_quiet: false` in its own `subnodes:` block, or
#: per path in `nodes.yaml`, and both still win.
#:
#: **`cloudwatch` is deliberately absent, and it is the fifth.** It makes the
#: opposite claim about its own lines: `show_healthy: false` drops the quiet ones
#: rather than showing them, so what is left of its list already *is* the
#: diagnosis. A check that has dropped its quiet lines has nothing to declare here.
#: Four of five is also close to the ceiling of what this is for — dense mode buys
#: its height back from the quiet nodes, and a fifth declaration would leave the
#: mechanism nothing to compact.
SUBNODES: dict[str, dict[str, object]] = {
    CLOUDWATCH: {
        "title": "CloudWatch alarms",
        "about": """\
Every CloudWatch alarm in this account, metric and composite alike, with the
state it is in. Alarms whose name contains one of the
check's `ignore_name_patterns` are neither listed nor counted. The first line
says how many alarms were seen at all, which is the reading that catches a
credential that has quietly stopped seeing anything.

{pin_note}
""",
    },
    EC2: {
        "title": "EC2 instances",
        "about": """\
The EC2 instances in this account, grouped by their `Name` tag: one line per
name, with how many boxes carry it and how long they have been up —
`prometheus: 1 (12d)`.

Two independent judgments meet on that line, and they are different questions.
**How many** boxes carry the name: a second one under a name that should be
unique is usually a deploy that did not clean up after itself. **How old** the
oldest of them is: an instance is patched by being replaced, so one that has run
for a fortnight is a fortnight behind on kernel fixes — true of a single,
perfectly tidy box. Each judgment has a warning level and an error level of its
own, the worse of the two colors the line, and each may carry a sentence that
rides on the line when it fires, because a number says how bad and never says
what is wrong.

```yaml
max_per_name_warn: 1
max_per_name_error: 8
max_per_name_reason: "There should be only one of these."
max_age_warn: 31d
max_age_error: 40d
max_age_reason: "Too old to have the latest patch levels."
```

**A level that is not configured is not graded, and this check ships none of
them.** What a name may carry and how long a box may run are facts about your
estate rather than about EC2, so the aspect lists instances and colors nothing
until you say what to color; a `null` switches a judgment off again where a rule
would otherwise supply one. The comparison is *more than*, so
`max_per_name_warn: 1` warns at two — and `0` is how you ask to hear about any
instance under a name at all.

**`rules:` gives a set of names its own limits.** A rule owns names — exact
`names:`, `prefixes:`, `regexes:`, or `unnamed: true` for the boxes nobody named
— and carries the same keys as the block above it:

```yaml
rules:
  - name: load tests
    prefixes: [loadtest-]
    max_per_name_warn: 15      # many is fine...
    max_age_error: 4h          # ...but not for hours
  - name: scratch
    prefixes: [tmp-]
    ignore: true               # neither listed nor counted
```

The **first** rule that matches a name decides, and only that one — so an
exception is a rule written above the rule it excepts. A judgment a rule does not
mention is inherited from the block **whole**, which is what lets a rule loosen
one limit without restating the others. Its limits are applied to **each**
matching name on its own, never to their sum: two load tests carrying ten and
twelve boxes are two lines against the rule's levels, not twenty-two. A judgment
that fires with no sentence of its own says the **rule's name** instead, which at
least says which rule to look at.

So a deliberate fleet is a *name* here, not a size — and the block's own levels
are best read as **what this check says about a name no rule mentions**, rather
than as sensible numbers for everything.

Where a name carries several boxes, their ages are shown as a **range** whose
shape follows what the numbers *print as* rather than how many boxes there are:
boxes that all read alike are one value (`4 (16h)`), exactly two distinct
readings are both shown (`2 (15h 3m, 15h 4m)` — two values are not an interval),
and three or more become youngest to oldest (`4 (1m - 16h)`). A name being rolled
and a name started once and left therefore read differently. The **oldest** is
what the age is graded on.

Terminated and shutting-down instances are not counted; they linger in the API
for about an hour and would report a duplicate that no longer exists.

{pin_note}
""",
        # An inventory: one line per instance name, read *because* nothing is
        # wrong. It keeps its box in a dense view (little-sister ADR-0063).
        "show_when_quiet": True,
    },
    LAMBDA: {
        "title": "Lambda functions",
        "about": """\
Every Lambda function in this account, a node each, whose line says how the
function's newest invocation went. Two independent readings meet on that line:
the **`Errors` metric** for the most recent period CloudWatch still has data for,
and the **status word of the last log event** — `REPORT` for a clean finish,
`ERROR` for a runtime failure that the metric may not have caught up with yet.

**Where the check keeps a series (`series_keep`), a function's runs are kept.** A
run is a one-minute bucket of CloudWatch's metric in which the function was
invoked: its invocations, its errors, and `duration_ms`, the slowest invocation of
that minute. A run failed where it counted an error. The function's node draws its
runs at the times they ran, and this node's Series view shows every function's
runs on one time axis.

A function nobody has invoked in the retention window warns rather than passing:
a silent scheduled job is not a healthy one. A handler that runs only when
somebody calls it is not, though, so `expect_invocations: false` — on the block
or on a rule — says that silence here is fine.

An error older than `error_max_age` is reported but not graded, because by then
CloudWatch has condensed it into a bucket with the successful runs around it and
the count no longer means what it says. That is a **gate**, not a threshold with
levels: it decides whether the newest error is graded at all, and "warn at seven
days, error at fourteen" is not a sentence about a gate. It keeps its default for
the same reason — where the clock ends is a fact about CloudWatch rather than
about your estate.

**An error the function saw is held on its line for `error_hold`** — an hour
unless the block or a rule says otherwise, and never longer than `error_max_age`
where nobody does — so that an error between two clean runs is not ERROR for one
poll and OK the next: while the newest error is younger than the hold the line
stays ERROR and says how many errors the hold holds, when the newest was and
what ran clean since (*1 error in the last 1h, 23m ago · 4 clean runs since, the
last 2m ago*). The newest run being the error reads as it always did.
`error_hold: 0s` is no hold, and a hold written longer than the gate is refused.

`error_reason` and `silent_reason` are the sentences those two judgments say
when they fire, and **`rules:` gives a set of functions its own** — matched by
exact `names:`, by `prefixes:` or by `regexes:`, first match winning, a key the
rule does not name inherited from the block:

```yaml
rules:
  - name: on-demand handlers
    prefixes: [api-]
    expect_invocations: false     # called by somebody, not by a schedule
  - name: the nightly batch
    prefixes: [batch-]
    error_max_age: 30d            # it runs rarely; grade an error for longer
    read_log_status: false        # and do not pay two API calls for it
  - name: retired
    prefixes: [old-]
    ignore: true                  # neither listed nor counted
```

{function_pin_note}
""",
        # A roster: which functions exist at all is the reading, so it is read
        # while everything is fine (little-sister ADR-0063). Each function is a
        # node of its own beneath this one — a chip on a dense wall — and the flag
        # keeps the box that holds them from being folded away.
        "show_when_quiet": True,
    },
    CODEPIPELINE: {
        "title": "CodePipeline",
        "about": """\
Every CodePipeline pipeline in this account, a node each, whose line shows what
the pipeline's **most recent execution** did and when that execution started.

`Succeeded` passes, and everything else — `Failed`, `Stopped`, `Cancelled`,
`Superseded` — is an error, because the newest thing the pipeline did was not a
deployment. `state_map:` is how an installation disagrees with any of that.

**While an execution is in flight** — `InProgress` or `Stopping` — the line keeps
what the newest *finished* execution did and says what is in flight beside it, in
italics: a pipeline whose last execution failed stays red while a new one runs,
and turns green only once one succeeds. What is in flight can make the line worse
and never better. Its status counts as `state_map` says — `InProgress` passes and
`Stopping` is an error — and one in flight for longer than `max_run_time`, 30
minutes unless the check says otherwise, warns.

**Where the check keeps a series (`series_keep`), a pipeline's executions are
kept.** A poll reads the newest, and behind it every execution the pipeline's
history lacks or holds unfinished — as many as the series keeps, and no more than
the hundred one page holds — each with `duration_s`, how long it took, once it is
over. The pipeline's node draws them at the times they started. The one the line
is written from is marked as the line stands, and every other one by what its
status means in `state_map`, raised past `max_run_time` while it is in flight. One
that a newer execution overtook, `Superseded`, is marked as neither: it did not
fail, and it did not deploy.

**A retried stage keeps its pipeline red.** A retry of a failed stage runs the
failed execution again, under its own id, so while it runs no page shows the
failure. Where the check keeps a series, the history does: the execution is
asked about — `ListActionExecutions`, which the role must allow — and the line
keeps the status it had ended in, in italics, until it succeeds, `max_run_time`
counted from the retry's own start. A refusal warns and says why. Without a
series, a retry is read as a first run.

**A success is also only good for so long.** Past `max_age_warn` the line warns
and past `max_age_error` it burns, on the grounds that a pipeline nobody has run
in months is a pipeline nobody knows still works; `max_age_reason` is the
sentence that then rides on the line. Neither level has a default, because how
long a success stays evidence depends on how often the pipeline is *meant* to run
— and only a success is judged this way: a failure is already the finding.

**`rules:` gives a set of pipelines its own clock**, matched by exact `names:`,
by `prefixes:` or by `regexes:`. The first rule that matches decides, a rule that
sets no level inherits the block's, and `ignore: true` drops those pipelines from
the tree and from the count:

```yaml
rules:
  - name: nightly builds
    prefixes: [nightly-]
    max_age_warn: 36h        # it runs every night
  - name: release pipelines
    prefixes: [release-]
    max_age: null            # runs when we release; never stale
    max_run_time: null       # waits at an approval for as long as it takes
```

A pipeline that has **never been executed** warns rather than being left out.
It has nothing to report, which is itself the report.

{pipeline_pin_note}
""",
        # A roster: every pipeline every run, with what it last did. Which
        # pipelines exist is half of what a reader came for (little-sister
        # ADR-0063). Each pipeline is a node of its own beneath this one — a chip on
        # a dense wall — and the flag keeps the box that holds them from being
        # folded away.
        "show_when_quiet": True,
    },
    BATCH: {
        "title": "AWS Batch",
        "about": """\
The AWS Batch job queues in this account, a node each, and beneath a queue's a
node for every job *name* in it — jobs are submitted over and over under the same
name, so the name is the thing worth watching and a single submission is not.

A job name's line carries up to three readings at once: how the newest
**finished** run ended and how long it took, how many are **running** — or
starting — and how long the oldest of those has been going, and how many are
**waiting**, counted from when they were submitted: for capacity that has not
appeared, for a job they depend on, or, an array job, for its children to finish.
A failure is an error; a run past `max_run_time` or a wait past `max_wait_time`
warns. While a job of the name runs or waits, its line is set in italics.

**Where the check keeps a series (`series_keep`), a job name's runs are kept**,
each with `wait_s` and `duration_s`, how long it waited and how long it ran. The
job name's node draws them, each marked by how it stood: a run that succeeded
passes and one that failed fails, and one that still runs or waits passes until
it is past its limit, and warns from then on. A name `ignore_name_patterns` hides
has no node, and none of its runs is kept.

A queue's node says something only when there is something to say about the
queue itself: it is `DISABLED` and taking no new work, its status is `INVALID`,
it holds no jobs at all, or there were more jobs than `max_jobs` and the reading
is of the newest ones only — a job name whose runs are no longer among those has
no node until it runs again.

{job_pin_note}
""",
        # A roster: which job names a queue is carrying, and what each is doing,
        # is worth a glance while nothing is failing (little-sister ADR-0063). Each
        # queue is a node of its own beneath this one, and a job name one beneath
        # its queue's; the flag keeps the box that holds the queues from being
        # folded away, and a queue's node says the same of itself.
        "show_when_quiet": True,
    },
}


@dataclass(frozen=True)
class Account:
    """One AWS account this check reads, and its own node in the tree where the
    check names several (ADR-0007 §1).

    ``name`` is ours, not Amazon's: it is the node's path segment, so it has to be
    stable and it has to be unique. ``role_arn`` may be empty — that account is
    then read with the ambient credentials, which is what makes a single-account
    install and local development work without a role to assume. ``regions``
    empty means "the check's default"; an account that names its own overrides it
    outright rather than adding to it. ``profile`` behaves the same way against
    the check's own: it names the ``~/.aws/config`` profile the role is assumed
    **from**, and empty means the check's — which, empty in turn, means the
    ambient chain, ``AWS_PROFILE`` included.

    ``account_id`` is AWS's own id of the account as far as the configuration says
    it — the entry's ``account_id``, or the one its ``role_arn`` names — and empty
    where it says neither (ADR-0013 §3). It goes into a link where a template names
    it, and nowhere else: a path, a slug, a subject and a record name the account
    by ``name``. ``console_link`` is the account's own template for its links and
    replaces the check's, as ``regions`` and ``profile`` do; empty means the
    check's (ADR-0013 §1).
    """

    name: str
    role_arn: str = ""
    regions: tuple[str, ...] = ()
    profile: str = ""
    title: str = ""
    about: str = ""
    account_id: str = ""
    console_link: str = ""


@dataclass(frozen=True)
class Alarm:
    """One alarm, narrowed out of the API payload at the read seam.

    Nothing downstream touches a boto3 response: the aspect grades, sorts and
    renders *this*, which is why its tests need no AWS-shaped fixtures.
    ``description`` is what AWS sent, empty where it sent none — the line says
    :data:`NO_DESCRIPTION` in its place, because the reading keeps what was read
    and the sentence is the line's.
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
    ``log_note`` says why the log gave no status word where it gave none, and
    ``log_error`` what AWS answered where the log could not be read at all: kept
    apart, because a reading keeps what AWS said and the sentence around it is the
    line's (:attr:`notes`).

    ``error_at`` is the newest bucket with an error in the window the function was
    asked at one minute — the newest run itself, where that run failed — and
    ``clean_since`` the buckets after it, all clean by definition; ``held_errors``
    is what the buckets inside this function's hold count together (ADR-0012). Facts
    from the same answer as the newest run, read at no request more; whether the
    error is still graded is the grading's, against the hold and the clock.
    """

    name: str
    region: str
    errors: int | None = None
    last_run: datetime | None = None
    log_status: str = ""
    log_note: str = ""
    log_error: str = ""
    error_at: datetime | None = None
    held_errors: int = 0
    clean_since: int = 0

    @property
    def notes(self) -> tuple[str, ...]:
        """What the line says about the log, beside its status word."""
        if self.log_error:
            return (f"log unreadable: {plain(self.log_error)}",)
        return (self.log_note,) if self.log_note else ()


@dataclass(frozen=True)
class FunctionRun:
    """One run of a Lambda function, narrowed at the read seam: a one-minute bucket
    of CloudWatch's metric in which the function was invoked (ADR-0006 §1).

    ``at`` is the bucket's start, the minute the function was invoked in — the
    event a run names. ``errors`` is what the first call answered for the bucket;
    ``invocations`` and ``duration_ms`` — the slowest invocation of the minute, in
    whole milliseconds — are the second call's, and ``None`` where CloudWatch sent
    no point for the bucket.
    """

    name: str
    region: str
    at: datetime
    errors: int
    invocations: int | None = None
    duration_ms: int | None = None


class _AnswerNotEnded(BotoCoreError):
    """A ``get_metric_data`` answer whose token was still handed back after
    :data:`_METRIC_PAGES` pages. A read failure like any other, so the region it
    was asked in says that it could not be read, and why."""

    fmt = "CloudWatch's answer had not ended after {pages} pages"


class _NotAnswered(BotoCoreError):
    """A query of a ``get_metric_data`` call that CloudWatch says it did not answer
    (:data:`_ANSWERED`), in a call that itself succeeded. A read failure like any
    other, so the region it was asked in says that it could not be read, and why —
    where its empty list of points, taken for an answer, said that the function
    never ran."""

    fmt = "CloudWatch did not answer {asked}: {status}{said}{others}"


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

    #: How recent an error must be to be **graded** rather than merely reported.
    #: It keeps its default where the other aspects' clocks lost theirs, and the
    #: line is the one ADR-0003 draws: past this, CloudWatch has condensed the
    #: count into a bucket with the successful runs around it, so the number no
    #: longer means what it says. That is a fact about CloudWatch, not an opinion
    #: about somebody's estate.
    error_max_age_seconds: int = DEFAULT_ERROR_MAX_AGE_SECONDS
    #: How long an error is held on the line once clean runs have followed it
    #: (ADR-0012); zero is no hold, and ``None`` is a block that writes none, whose
    #: functions take the default up to their gate (:meth:`hold_for`). A hold that
    #: is written is never longer than the gate — the parser refuses that — since an
    #: error older than the gate is not graded at all.
    error_hold_seconds: int | None = None
    read_log_status: bool = True
    #: Whether a function nobody has invoked in the retention window is a
    #: finding. It is, for a scheduled job; it is not for a handler that runs
    #: when somebody calls it, which is what a rule turns off.
    expect_invocations: bool = True
    error_reason: str = ""
    silent_reason: str = ""
    rules: tuple[Rule, ...] = ()

    def rule_for(self, name: str) -> Rule | None:
        return rule_for(self.rules, name)

    def ignored(self, name: str) -> bool:
        rule = self.rule_for(name)
        return rule is not None and rule.ignore

    def gate_for(self, rule: Rule | None) -> int:
        """How recent an error must be to be graded, for this function.

        Narrowed here rather than trusted: a rule's non-graded overrides are
        carried as ``object``, and the parser is what makes them an ``int`` — so
        this reads them back the way anything reads untyped configuration, and a
        value of the wrong shape falls back rather than reaching a comparison.
        """
        own = None if rule is None else rule.value("error_max_age")
        return own if isinstance(own, int) and not isinstance(own, bool) \
            else self.error_max_age_seconds

    def hold_for(self, rule: Rule | None) -> int:
        """How long an error the function saw is held on its line, for this
        function (ADR-0012 §2): the rule's, or the block's — and where neither
        writes one, an hour or the gate that applies, whichever is shorter, so a
        default never refuses a gate that loaded before the hold existed."""
        own = self.written_hold(rule)
        return own if own is not None else min(DEFAULT_ERROR_HOLD_SECONDS,
                                               self.gate_for(rule))

    def written_hold(self, rule: Rule | None) -> int | None:
        """The hold the configuration writes for this function — the rule's, or
        the block's — and ``None`` where neither writes one."""
        own = None if rule is None else rule.value("error_hold")
        return own if isinstance(own, int) and not isinstance(own, bool) \
            else self.error_hold_seconds

    def expects_invocations(self, rule: Rule | None) -> bool:
        own = None if rule is None else rule.value("expect_invocations")
        return own if isinstance(own, bool) else self.expect_invocations

    def reads_log(self, rule: Rule | None) -> bool:
        own = None if rule is None else rule.value("read_log_status")
        return own if isinstance(own, bool) else self.read_log_status

    def sentence(self, key: str, rule: Rule | None) -> str:
        """The sentence for one of this aspect's judgments: the rule's, the
        block's, or the rule's **name** — the same fallback a graded pair has,
        because a line that says only "3 errors" leaves a reader with the same
        question either way."""
        own = None if rule is None else rule.value(key)
        if isinstance(own, str) and own:
            return own
        block = self.error_reason if key == "error_reason" else self.silent_reason
        if block:
            return block
        return rule.name if rule is not None else ""


@dataclass(frozen=True)
class Ec2Config(_Aspect):
    """The `ec2:` block."""

    ignore_states: tuple[str, ...] = DEFAULT_EC2_IGNORE_STATES
    per_name: Threshold = UNGRADED
    age: Threshold = UNGRADED
    rules: tuple[Rule, ...] = ()

    @property
    def grades(self) -> bool:
        """Whether this block can color a line at all. An aspect that grades
        nothing is a legal **inventory** — which names exist, how many boxes each
        carries and how old they are, read while everything is fine — so it is not
        refused; it is announced once, in the log, by the parser."""
        return (self.per_name.grades or self.age.grades
                or any(rule.ignore or rule.overrides for rule in self.rules))

    def rule_for(self, name: str | None) -> Rule | None:
        """The rule that owns this name, or ``None`` for a name nobody
        classified — which is judged by the block's own levels."""
        return rule_for(self.rules, name)

    def thresholds_for(self, rule: Rule | None) -> tuple[Threshold, Threshold]:
        """The count and age judgments in force for a group, after the one
        matching rule has had its say. Inheritance is **by pair**: a rule that
        wrote either level of a pair owns that pair whole, and a pair it did not
        mention is this block's, whole."""
        return (resolved(rule, "max_per_name", self.per_name),
                resolved(rule, "max_age", self.age))

    def ignored_state(self, state: str) -> bool:
        return state.lower() in self.ignore_states

    def judge(self, name: str | None, count: int,
              age: int | None) -> tuple[StatusCode, tuple[str, ...]]:
        """One group's verdict, and the sentences behind it.

        Two independent judgments meet on one line and the **worse** of them wins,
        which is how age used to outrank count and now needs no special case: a
        count is a tidiness reading — something was left behind — while an age is a
        **security** one, since an instance is patched by being replaced and one
        that has run for a fortnight is a fortnight behind on kernel fixes, true of
        a single, perfectly tidy instance.

        Both judgments contribute their sentence when they fire, count first, so a
        group that is both duplicated and old says both things rather than leaving
        the reader to work out which limit the color came from. A judgment whose
        levels carry no sentence falls back to **the name of the rule** that
        supplied them: a worse sentence than one somebody wrote, and much better
        than a bare color, because it says where in the config the decision was
        made. With no rule there is nothing to name and nothing is added.

        The limits are this group's alone. A rule matching a hundred names judges
        each of them on its own count and its own oldest member; it never sums
        them, because the reading is *this name carries too many boxes*.
        """
        rule = self.rule_for(name)
        per_name, aged_by = self.thresholds_for(rule)
        code = per_name.code_for(count)
        notes = [sentence_for(per_name, rule)] if code is not StatusCode.OK else []
        if age is not None:
            age_code = aged_by.code_for(age)
            if age_code is not StatusCode.OK:
                notes.append(sentence_for(aged_by, rule))
            code = _worst(code, age_code)
        return code, tuple(note for note in notes if note)


@dataclass(frozen=True)
class PipelineReading:
    """One pipeline and one of its executions, narrowed at the read seam: the
    newest, or one behind it that a poll reads for the pipeline's history
    (ADR-0009 §5).

    ``status`` is empty when the pipeline has never been executed at all — which
    is a different fact from every failure status there is, and the one the
    original could not report because it built no line for it. ``execution_id``
    is the id CodePipeline gives the execution: the event this reading is of
    (ADR-0005 §5). ``updated`` is the last change CodePipeline recorded of that
    execution, which is its end once the execution is over (ADR-0008 §2): no line
    says it, and the record's ``duration_s`` is counted to it. ``retry`` is what
    CodePipeline answered of the execution's action executions, asked while it runs
    again after it had ended failed or stopped (ADR-0014 §5), and none otherwise.
    """

    name: str
    region: str
    status: str = ""
    started: datetime | None = None
    execution_id: str = ""
    updated: datetime | None = None
    retry: Retry | None = None


@dataclass(frozen=True)
class Retry:
    """What CodePipeline answered of one execution's action executions, asked while the
    execution runs again after it had ended failed or stopped (ADR-0014 §5): how many
    of them failed and how many were abandoned, and when the first of those that
    started after the last failed or abandoned one had ended began — the retry's own
    start, which ``max_run_time`` counts from. ``error`` is what the call was refused
    with, where it was, and then nothing else is known."""

    failed: int = 0
    abandoned: int = 0
    started: datetime | None = None
    error: str = ""

    @property
    def ended(self) -> str:
        """The status the execution had ended in, as its action executions show it:
        ``Failed`` where one of them failed, ``Stopped`` where one was abandoned, and
        nothing where neither did or nothing was answered — then nothing here says
        that it had ended."""
        if self.error:
            return ""
        if self.failed:
            return "Failed"
        return "Stopped" if self.abandoned else ""


@dataclass(frozen=True)
class CodePipelineConfig(_Shortened):
    """The `codepipeline:` block."""

    age: Threshold = UNGRADED
    run_time: Threshold = DEFAULT_PIPELINE_RUN_TIME
    rules: tuple[Rule, ...] = ()
    state_map: dict[str, StatusCode] = field(
        default_factory=lambda: dict(DEFAULT_PIPELINE_STATE_MAP))

    def rule_for(self, name: str) -> Rule | None:
        return rule_for(self.rules, name)

    def ignored(self, name: str) -> bool:
        rule = self.rule_for(name)
        return rule is not None and rule.ignore

    def age_for(self, rule: Rule | None) -> Threshold:
        """The staleness judgment in force for one pipeline. A pipeline that runs
        nightly and one that runs at a release are not stale at the same age,
        which is the whole reason a rule can carry its own."""
        return resolved(rule, "max_age", self.age)

    def run_time_for(self, rule: Rule | None) -> Threshold:
        """How long an execution of one pipeline may be in flight before its line
        warns. A pipeline that waits at a manual approval and one that deploys in
        five minutes do not overrun at the same age, which is why a rule can carry
        its own — or ``max_run_time: null``, under which nothing overruns
        (ADR-0014 §3)."""
        return resolved(rule, "max_run_time", self.run_time)

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
    ``reason`` is Batch's own ``statusReason``: no line says it, and a kept run
    carries it.
    """

    job_id: str
    name: str
    status: str
    created: datetime | None = None
    started: datetime | None = None
    stopped: datetime | None = None
    reason: str = ""


@dataclass(frozen=True)
class JobQueue:
    """One Batch job queue, narrowed at the read seam. ``state`` is whether it
    accepts work (``ENABLED`` / ``DISABLED``) and ``status`` whether AWS could
    build it at all (``VALID`` / ``INVALID`` / …) — two failures worth telling
    apart."""

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


def _optional_text(entry: Mapping[str, Any], key: str, where: str) -> str:
    """One optional string of this check's configuration, or ``""`` where its key
    is not written: read by the identity seam's reader
    (`identity.parse_optional_text`), and refused in this check's words and as the
    `CheckError` that pins this check and nothing else."""
    try:
        return parse_optional_text(entry, key, where=where)
    except OptionalTextError as error:
        if error.kind == "not-text":
            raise CheckError(f"{where} must be text, got "
                             f"{type(error.got).__name__}") from error
        raise CheckError(f"{where} must not be empty") from error


def _parse_profile(entry: Mapping[str, Any], where: str) -> str:
    """An ``~/.aws/config`` profile name, or ``""`` where none is written.

    The optional-string reading is the identity seam's
    (`identity.parse_optional_text`): a key written and left empty is a typo,
    not "no profile" — reading it as unset is how a check silently falls back
    to whatever ``AWS_PROFILE`` happens to say — and a value that is not text
    is the same typo family, refused rather than stringified.

    What stays here is the **ban**, and why there is one at all: the name is
    printed back to the operator **inside a Markdown code span** (``aws sso
    login --profile …``), and it is passed to a subprocess. A backtick would
    break out of the first; a newline would make the printed command a
    different command from the one that runs. Neither is a legal profile name
    anyway.
    """
    profile = _optional_text(entry, "profile", where)
    if any(ch in profile for ch in "`\n\r"):
        raise CheckError(f"{where} must not contain a backtick or a newline")
    return profile


#: What a ``console_link`` template may name (ADR-0013 §2): the console's address
#: of what a line names, as this type builds it, and the account's id. A token is
#: a name in braces and every value is percent-encoded whole as it goes in, which
#: is how little-sister fills the URL of a configured action (little-sister
#: ADR-0038) — one way to fill a URL template in the family, not two.
CONSOLE_LINK_TOKENS = ("url", "account_id")

#: One token of a template. The library's own spelling of one, so a brace around
#: anything but lower-case letters and underscores is text of the address.
_TOKEN = re.compile(r"\{([a-z_]*)\}")

#: What a template may not hold, beside whitespace and control characters
#: (ADR-0013 §2). The address it produces is written as the destination of a
#: Markdown link and, on the card, inside a code span: a parenthesis, an angle
#: bracket or a backslash would end or bend the first, and a backtick the second.
#: Each is a character a URL carries percent-encoded.
_NOT_IN_A_LINK = "`\\()<>"

#: An AWS account id: twelve digits, and nothing else.
_ACCOUNT_ID = re.compile(r"[0-9]{12}")

#: An IAM role's ARN, for the account it names:
#: ``arn:<partition>:iam::<account id>:role/<path and name>``. The partition is
#: whatever AWS calls it — ``aws``, ``aws-cn``, ``aws-us-gov`` — so none is listed.
_ROLE_ARN = re.compile(r"arn:[^:]+:iam::([0-9]{12}):role/.+")


def _tokens(template: str) -> set[str]:
    """The tokens a template names."""
    return set(_TOKEN.findall(template))


def _parse_console_link(entry: Mapping[str, Any], where: str) -> str:
    """One ``console_link``: the template an account's links are wrapped in, or
    ``""`` where none is written (ADR-0013 §2).

    Read as `profile:` is — a key written and left empty is a typo, and so is a
    value that is not text — and then held to what a template is: written as a
    URL is, naming no token but the two this type fills, and naming ``{url}``,
    without which every link of an account would open one address under a name
    that promises one thing's page. ``{account_id}`` is optional: a template may
    carry an id its author wrote into it, or wrap a link in something that needs
    none. Whether the account under a template **has** the id it names is decided
    once the accounts are read (:func:`_hold_account_ids`).
    """
    template = _optional_text(entry, "console_link", where)
    if not template:
        return ""
    unwritable = sorted({char for char in template
                         if char in _NOT_IN_A_LINK or char.isspace()
                         or ord(char) < 32 or ord(char) == 127})
    if unwritable:
        raise CheckError(
            f"{where} holds {', '.join(repr(char) for char in unwritable)} — "
            f"whitespace, a backtick, a backslash, a parenthesis and an angle "
            f"bracket are written percent-encoded in a URL, and as they are would "
            f"end the link a line writes")
    named = _tokens(template)
    unknown = sorted(named - set(CONSOLE_LINK_TOKENS))
    if unknown:
        raise CheckError(
            f"{where} names {', '.join('{' + token + '}' for token in unknown)} — "
            f"a template may name "
            f"{' and '.join('{' + token + '}' for token in CONSOLE_LINK_TOKENS)}")
    if "url" not in named:
        raise CheckError(
            f"{where} names no {{url}}, so every link would open one address — "
            f"{{url}} is where the console's address of what a line names goes")
    return template


def _role_account(role_arn: str) -> str:
    """The id of the account a role is in, out of the role's ARN, and ``""`` for a
    value that is no IAM role's ARN and so names none (ADR-0013 §3). A role is in
    the account it reads, which is why this id cannot be another account's."""
    found = _ROLE_ARN.fullmatch(role_arn)
    return found.group(1) if found else ""


def _parse_account_id(entry: Mapping[str, Any], name: str, role_arn: str) -> str:
    """AWS's id of one account, as its entry says it (ADR-0013 §3): the
    ``account_id`` it writes, or the one its ``role_arn`` names, and ``""`` where
    it says neither.

    ``account_id`` is the twelve digits of the id. It is written in quotes,
    because YAML reads an unquoted number that starts with ``0`` as another
    number — as an octal one where every digit allows it — and what then arrives
    is no twelve digits, and is refused. An unquoted number that *is* twelve
    digits was written as one, and is taken. Written beside a ``role_arn`` that
    names another account it is refused: a role is in the account it reads, so
    one of the two is wrong. Neither refusal repeats an id.
    """
    named = _role_account(role_arn)
    if "account_id" not in entry:
        return named
    value = entry["account_id"]
    if isinstance(value, int):
        # A number YAML read: twelve digits where it was written as twelve, and
        # anything else — a `true` among them — no id, which the next line says.
        value = str(value)
    if not isinstance(value, str) or not _ACCOUNT_ID.fullmatch(value.strip()):
        raise CheckError(
            f"account {name!r} 'account_id' must be the twelve digits of an AWS "
            f"account id, in quotes — YAML reads an unquoted number that starts "
            f"with 0 as another number")
    written = value.strip()
    if named and written != named:
        raise CheckError(
            f"account {name!r} names two accounts: its 'account_id' is not the "
            f"account its 'role_arn' is in. A role is in the account it reads, so "
            f"one of the two is wrong")
    return written


def _hold_account_ids(accounts: Sequence[Account], console_link: str) -> None:
    """Refuse a template that names ``{account_id}`` over an account whose
    configuration says no id (ADR-0013 §3) — the account's own template, or the
    check's where it wrote none.

    Refused rather than left unwrapped: that account's links would be the
    console's own, which open in whichever account the browser is signed in to,
    beside the wrapped links of every other account — the failure a template is
    set against, kept for one account and said nowhere a reader of the node
    would see it."""
    for account in accounts:
        template = account.console_link or console_link
        if "account_id" not in _tokens(template) or account.account_id:
            continue
        lacking = ("its 'role_arn' names none" if account.role_arn
                   else "it names no 'role_arn' to read one from")
        raise CheckError(
            f"account {account.name!r} has no account id, and the 'console_link' "
            f"its links are wrapped in names {{account_id}}: {lacking}, so write "
            f"'account_id:' on the account")


#: The subject of every ``sso:`` sentence below, and the ``where`` the shared
#: reader stamps on its own factual line — one spelling, so the two cannot
#: disagree about which block they mean.
_SSO_WHERE = "aws 'sso'"


def _sso_message(error: SsoBlockError) -> str:
    """This check's sentence for one refused ``sso:`` block.

    The block's one reader (`identity.parse_sso_block`) hands back parts; the
    words are this check's own and stay here, because the other packages that
    read the same block pin sentences that disagree with these on purpose —
    a wording that lived in the reader would be somebody's broken suite the
    day anyone harmonized it.
    """
    if error.kind == "not-a-mapping":
        return f"{_SSO_WHERE} must be a mapping"
    if error.kind == "unknown-keys":
        return (f"unknown key(s) in {_SSO_WHERE}: {', '.join(error.unknown)} "
                f"(it takes: {', '.join(error.accepted)})")
    if error.kind == "not-a-mode":
        return (f"{_SSO_WHERE}.login must be one of "
                f"{', '.join(error.accepted)} (got {error.got!r})")
    if error.kind == "not-a-duration":
        return f"{_SSO_WHERE}.{error.key}: {error.problem}"
    if error.kind == "not-positive":
        # Zero would not mean "no timeout" here, it would mean "kill it before
        # it starts" — and an unbounded login holds an engine worker forever.
        return f"{_SSO_WHERE}.timeout must be greater than zero"
    if error.kind == "negative":
        return f"{_SSO_WHERE}.cooldown must not be negative"
    return str(error)  # a kind this check has no sentence for yet


def _parse_sso(value: object) -> SsoConfig:
    """The ``sso:`` block — whether the check may renew an expired login.

    Reading it is `identity.parse_sso_block`'s job; what stays here is what is
    the check's alone — its budget (the `SsoConfig` defaults: a generous
    window and a cooldown, both spent on an engine worker), and its refusals,
    worded above and raised as the `CheckError` that pins this check and
    nothing else.
    """
    try:
        return parse_sso_block(value, where=_SSO_WHERE)
    except SsoBlockError as error:
        raise CheckError(_sso_message(error)) from error


def _parse_accounts(value: object) -> tuple[Account, ...]:
    """The ``accounts:`` list — every account this check reads, and its node."""
    if not isinstance(value, list) or not value:
        raise CheckError(
            "aws check requires a non-empty 'accounts:' list, each entry a "
            "mapping with a 'name' and an optional 'role_arn'")
    known = {"name", "role_arn", "regions", "profile", "title", "about",
             "account_id", "console_link"}
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
        role_arn = str(entry.get("role_arn", "")).strip()
        accounts.append(Account(
            name=name,
            role_arn=role_arn,
            regions=(() if regions is None
                     else _parse_regions(regions, f"account {name!r} 'regions'")),
            profile=_parse_profile(entry, f"account {name!r} 'profile'"),
            title=str(entry.get("title", "")),
            about=str(entry.get("about", "")),
            account_id=_parse_account_id(entry, name, role_arn),
            console_link=_parse_console_link(
                entry, f"account {name!r} 'console_link'"),
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


#: What the `ec2` aspect grades, and whether each is a duration — the argument
#: the shared rule parser takes, so the vocabulary has one implementation and each
#: aspect says only what it measures.
EC2_PAIRS = (("max_per_name", False), ("max_age", True))


def _parse_ec2(value: object) -> Ec2Config:
    if value is None:
        return Ec2Config()
    if not isinstance(value, dict):
        raise CheckError("aws 'ec2' must be a mapping")
    known = ({"enabled", "ignore_states", "rules", "max_per_name", "max_age"}
             | threshold_keys("max_per_name") | threshold_keys("max_age"))
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        # The keys this replaced — `max_per_name`, `max_age`, `fleet_size`,
        # `fleet_max_age`, `ignore_name_patterns` — arrive here, and they get the
        # message any typo gets. Deliberate: nothing is owed to a config written
        # against them, and a hint naming each replacement would be a permanent
        # line in the parser for a one-time reading of one error.
        raise CheckError(
            f"unknown key(s) in 'ec2': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    settings = Ec2Config(
        enabled=_flag(value.get("enabled", True), "ec2.enabled"),
        ignore_states=_lowered_list(value.get("ignore_states"),
                                    "ec2 'ignore_states'",
                                    DEFAULT_EC2_IGNORE_STATES),
        per_name=parse_pair(value, "max_per_name", "ec2") or UNGRADED,
        age=parse_pair(value, "max_age", "ec2", duration=True) or UNGRADED,
        rules=parse_rules(value.get("rules"), "ec2", EC2_PAIRS,
                          allow_unnamed=True),
    )
    if settings.enabled and not settings.grades:
        # An omission logs; a contradiction refuses. Grading nothing is a coherent
        # thing to ask for — the roster of names, counts and ages is half of what a
        # reader came for — but it is more often somebody who has not noticed that
        # this package ships no thresholds of its own.
        logger.info("aws 'ec2': the aspect is enabled and grades nothing — no "
                    "max_per_name_warn/_error or max_age_warn/_error is set, "
                    "here or in a rule, so instances are listed and never "
                    "colored")
    return settings


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


#: What a `lambda:` block — and a rule inside it — may say beyond matching names.
#: The aspect has **no graded pair**: `error_max_age` is a *gate* deciding whether
#: the newest error is graded at all, not a threshold to split into levels, and
#: "warn at seven days, error at fourteen" is not a sentence about a gate. What it
#: takes from the vocabulary is the rules and the sentences (ADR-0003).
LAMBDA_RULE_KEYS = ("error_max_age", "error_hold", "read_log_status",
                    "expect_invocations", "error_reason", "silent_reason")


def _sentence(block: dict[str, Any], key: str, where: str) -> str:
    """One configured sentence, refused when it is written and empty."""
    value = block.get(key)
    if value is None:
        return ""
    if not isinstance(value, str) or not value.strip():
        raise CheckError(f"{where} '{key}' must be a non-empty sentence")
    return value.strip()


def _lambda_rule_extra(item: Mapping[str, Any],
                       rule_at: str) -> tuple[tuple[str, object], ...]:
    """The `lambda:` keys a rule may override, read the same way the block reads
    them — a key that is absent is inherited, which is the whole contract."""
    values: list[tuple[str, object]] = []
    if "error_max_age" in item and item["error_max_age"] is not None:
        seconds = parse_duration(item["error_max_age"], 0)
        if seconds < 1:
            raise CheckError(
                f"{rule_at}: 'error_max_age' must be a duration of at least 1s")
        values.append(("error_max_age", seconds))
    if "error_hold" in item and item["error_hold"] is not None:
        values.append(("error_hold", _error_hold(item["error_hold"], rule_at)))
    for key in ("read_log_status", "expect_invocations"):
        if key in item and item[key] is not None:
            values.append((key, _flag(item[key], f"{rule_at}: '{key}'")))
    for key in ("error_reason", "silent_reason"):
        sentence = _sentence(dict(item), key, rule_at)
        if sentence:
            values.append((key, sentence))
    expects = dict(values).get("expect_invocations")
    if dict(values).get("silent_reason") and expects is False:
        raise CheckError(
            f"{rule_at}: 'silent_reason' is set but 'expect_invocations' is "
            f"false, so the sentence could never be shown")
    return tuple(values)


def _error_hold(value: object, where: str) -> int | None:
    """One `error_hold`: a duration, zero for none, and never past what CloudWatch
    keeps at one minute (:data:`MAX_ERROR_HOLD_SECONDS`) — ``None`` where it is not
    written, which leaves the default to :meth:`LambdaConfig.hold_for`."""
    if value is None:
        return None
    seconds = parse_duration(value, DEFAULT_ERROR_HOLD_SECONDS)
    if seconds < 0:
        raise CheckError(f"{where}: 'error_hold' must be a duration, or 0s for none")
    if seconds > MAX_ERROR_HOLD_SECONDS:
        raise CheckError(
            f"{where}: 'error_hold' {format_span(seconds)} is longer than the "
            f"{format_span(MAX_ERROR_HOLD_SECONDS)} CloudWatch keeps a one-minute "
            f"point for, so the hold could not be read to its end")
    return seconds


def _hold_within_gate(hold: int, gate: int, where: str) -> None:
    """A written hold longer than the gate is refused rather than capped: an error
    older than the gate is not graded at all, so the hold's tail would never stand,
    and a knob capped silently stops meaning what it says. The default is no knob
    anybody wrote, and is capped (:meth:`LambdaConfig.hold_for`)."""
    if hold > gate:
        raise CheckError(
            f"{where}: 'error_hold' {format_span(hold)} is longer than "
            f"'error_max_age' {format_span(gate)}, and an error older than the gate "
            f"is not graded — shorten the hold or raise the gate")


def _parse_lambda(value: object, shorten: tuple[tuple[str, str], ...] = ()
                  ) -> LambdaConfig:
    if value is None:
        return LambdaConfig(shorten=shorten)
    if not isinstance(value, dict):
        raise CheckError("aws 'lambda' must be a mapping")
    known = {"enabled", "shorten", "rules"} | set(LAMBDA_RULE_KEYS)
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        # `ignore:` — a list of whole function names — arrives here: ignoring is
        # a rule action now, and a rule matches by exact name, prefix or regex
        # rather than by one of those three being the only spelling.
        raise CheckError(
            f"unknown key(s) in 'lambda': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
    max_age = parse_duration(value.get("error_max_age"),
                             DEFAULT_ERROR_MAX_AGE_SECONDS)
    if max_age < 1:
        raise CheckError("lambda 'error_max_age' must be a duration of at least 1s")
    hold = _error_hold(value.get("error_hold"), "lambda")
    if hold is not None:
        _hold_within_gate(hold, max_age, "lambda")
    expects = _flag(value.get("expect_invocations", True),
                    "lambda.expect_invocations")
    silent = _sentence(value, "silent_reason", "lambda")
    if silent and not expects:
        raise CheckError(
            "lambda 'silent_reason' is set but 'expect_invocations' is false, "
            "so the sentence could never be shown")
    settings = LambdaConfig(
        error_max_age_seconds=max_age,
        error_hold_seconds=hold,
        enabled=_flag(value.get("enabled", True), "lambda.enabled"),
        read_log_status=_flag(value.get("read_log_status", True),
                              "lambda.read_log_status"),
        expect_invocations=expects,
        error_reason=_sentence(value, "error_reason", "lambda"),
        silent_reason=silent,
        rules=parse_rules(value.get("rules"), "lambda", (),
                          extra_keys=LAMBDA_RULE_KEYS,
                          parse_extra=_lambda_rule_extra),
        shorten=_inherited_shorten(value, "lambda 'shorten'", shorten),
    )
    # A rule inherits what it does not name, so a written hold — its own or the
    # block's — is held against the gate that applies to its functions once both
    # are known. A hold nobody wrote is the gate's at most, and needs no holding.
    for rule in settings.rules:
        written = settings.written_hold(rule)
        if written is not None:
            _hold_within_gate(written, settings.gate_for(rule),
                              f"lambda rule {rule.name!r}")
    return settings


#: What the `codepipeline` aspect grades with a threshold of its own: how old a
#: success may grow, and how long an execution may be in flight (ADR-0014 §3). Its
#: other judgment — what a status *means* — is `state_map`, which is a mapping
#: rather than a level and stays as it is.
PIPELINE_PAIRS = (("max_age", True), ("max_run_time", True))


def _parse_codepipeline(value: object,
                        shorten: tuple[tuple[str, str], ...] = ()
                        ) -> CodePipelineConfig:
    if value is None:
        return CodePipelineConfig(shorten=shorten)
    if not isinstance(value, dict):
        raise CheckError("aws 'codepipeline' must be a mapping")
    known = ({"enabled", "state_map", "shorten", "rules", "max_age",
              "max_run_time"}
             | threshold_keys("max_age") | threshold_keys("max_run_time"))
    unknown = sorted(str(key) for key in value if str(key) not in known)
    if unknown:
        # `ignore_name_patterns` arrives here now: ignoring is a rule action, so
        # this aspect speaks one matcher vocabulary like the EC2 one.
        raise CheckError(
            f"unknown key(s) in 'codepipeline': {', '.join(unknown)} "
            f"(it takes: {', '.join(sorted(known))})")
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
    # Absent, the default; written, the pair as it is written, whole — a block that
    # sets one level of it keeps no level of the default's, as a rule that sets one
    # keeps none of the block's (ADR-0003 §4); `null`, nothing (ADR-0014 §3).
    run_time = parse_pair(value, "max_run_time", "codepipeline", duration=True)
    return CodePipelineConfig(
        enabled=_flag(value.get("enabled", True), "codepipeline.enabled"),
        age=parse_pair(value, "max_age", "codepipeline",
                       duration=True) or UNGRADED,
        run_time=DEFAULT_PIPELINE_RUN_TIME if run_time is None else run_time,
        rules=parse_rules(value.get("rules"), "codepipeline", PIPELINE_PAIRS),
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


def _console_url(region: str, path: str, fragment: str = "") -> str:
    """One console address: ``https://<region>.console.aws.amazon.com/<path>``,
    with the region repeated as a query parameter and an optional fragment.

    Every link this type emits is that shape — the five ``<service>/home#…``
    pages and CodePipeline's path-addressed one, whose query simply lands after a
    longer path. They were six string templates that agreed about the host, the
    scheme and the duplicated region by being written the same way six times,
    which is the agreement that stops holding the day one of them is edited.

    The **caller quotes what it interpolates**, because only the caller knows
    which part is a name: a fragment is assembled from literal syntax
    (``s=Alarms&alarm=``) and one untrusted value, and quoting the whole of it
    would escape the syntax as well.

    **It names no account**, and no address built from it does: the console takes
    the account from the browser's session. What opens one account's page in that
    account is a sign-in, and what a link is wrapped in for it is the deployment's
    to say (:func:`_wrapped`, ADR-0013).
    """
    address = f"https://{region}.console.aws.amazon.com/{path}?region={region}"
    return f"{address}#{fragment}" if fragment else address


def _wrapped(template: str, address: str, account_id: str) -> str:
    """*address*, the console's own, as a ``console_link`` template wraps it
    (ADR-0013 §2): ``{url}`` filled with the address and ``{account_id}`` with the
    account's id, each percent-encoded **whole** — a `/`, a `?`, a `#` and a `%`
    of the address among them, so that what arrives at the far end of a sign-in
    is the address this type built and no part of it is read as the wrapper's.

    The template was held to its two tokens where the check loaded
    (:func:`_parse_console_link`), and an account under a template that names
    ``{account_id}`` to having one (:func:`_hold_account_ids`)."""
    filled = {"url": address, "account_id": account_id}
    return _TOKEN.sub(
        lambda token: urllib.parse.quote(filled[token.group(1)], safe=""), template)


def _quoted(value: str) -> str:
    """One name, escaped for a URL — :func:`urllib.parse.quote`'s defaults, which
    leave ``/`` alone because the console's own fragments carry it."""
    return urllib.parse.quote(value)


def _function_link(region: str, name: str) -> str:
    return _console_url(region, "lambda/home", f"/functions/{_quoted(name)}")


def _console_link(alarm: Alarm) -> str:
    """The alarm in the console. The older ``#s=Alarms`` fragment, which the
    console still redirects, works for both alarm kinds."""
    return _console_url(alarm.region, "cloudwatch/home",
                        f"s=Alarms&alarm={_quoted(alarm.name)}")


def _utcnow() -> datetime:
    """The clock, behind one function, so a test can hold it still."""
    return datetime.now(UTC)


def _instance_link(region: str, name: str) -> str:
    """The console, filtered to the instances carrying this name."""
    return _console_url(region, "ec2/home", f"Instances:search={_quoted(name)}")


def _state_phrase(state: str) -> str:
    return {"ALARM": "in ALARM",
            "INSUFFICIENT_DATA": "insufficient data",
            "OK": "OK"}.get(state.upper(), plain(state))


def _pipeline_link(region: str, name: str) -> str:
    """The pipeline's execution history in the console — the one address of the
    six that is a **path** rather than a fragment, which is why the shared builder
    takes the path and not just a service name."""
    return _console_url(
        region, f"codesuite/codepipeline/pipelines/{_quoted(name)}/executions")


def _job_link(region: str, job_id: str) -> str:
    """One Batch job's detail page.

    A job id, not the queue's ARN: the console will take an ARN here and an ARN
    carries the account number, which is exactly the string ADR-0001 keeps out
    of a line somebody may bookmark or paste into a ticket.
    """
    return _console_url(region, "batch/home", f"jobs/detail/{_quoted(job_id)}")


def _queue_link(region: str) -> str:
    """The queue list, for the same reason: the per-queue page is addressed by
    ARN and the list is not."""
    return _console_url(region, "batch/home", "queues")


def _instance_order(key: tuple[str, str | None]) -> tuple[str, bool, str]:
    """Groups in region order, then by name — with the unnamed group last, since
    ``None`` cannot be compared with a string and "nobody named these" is the line
    a reader looks for after the names they know."""
    region, name = key
    return region, name is None, name or ""


def _age_span(ages: Sequence[int]) -> str:
    """How old the members of one group are, as one string.

    A group used to report only its oldest member, which is the verdict but a
    third of the reading: a name whose twenty boxes run from ten minutes to
    sixteen hours is a fleet being rolled, and a name whose twenty are all the
    same age is one that was started once and left. Both read identically as
    ``(16h 10m)``.

    The shape is decided by **how many distinct strings the members render to**,
    never by how many members there are:

    ==========================  ==========================
    they render to              the line shows
    ==========================  ==========================
    one distinct string         ``1d``
    exactly two                 ``15h 3m, 15h 4m``
    three or more               ``10m - 16h 10m``
    ==========================  ==========================

    ``coarse_span`` is lossy on purpose — its largest one or two units and then it
    stops, so two boxes forty minutes apart inside one hour both read ``1d 1h`` —
    and the granularity of the display is the granularity of the fact worth
    reporting: boxes that all render ``1d 1h`` are the same age as far as this
    card is concerned, and ``1d 1h - 1d 1h`` would be noise manufactured out of
    precision the reader was never shown. Two distinct values are not an interval
    either. An interval says *there is a spread and there are members inside it*;
    ``15h 3m, 15h 4m`` says *there are two of them, and here they both are*.

    One renderer, because two surfaces show this — the entry line and the roster —
    and a group whose card and report disagreed about its age would be worse than
    either. ``batch`` reports the oldest of its running jobs the same way and is
    the expected second caller.
    """
    if not ages:
        return ""
    # Distinctness is on the **rendered strings**, never on the seconds: two
    # instances 25 and 40 hours old are both `1d`, and a set over the seconds
    # would print `1d - 1d`.
    rendered = list(dict.fromkeys(coarse_span(age) for age in sorted(ages)))
    if len(rendered) == 1:
        return rendered[0]
    if len(rendered) == 2:
        return f"{rendered[0]}, {rendered[1]}"
    return f"{rendered[0]} - {rendered[-1]}"


def _worst(first: StatusCode, second: StatusCode) -> StatusCode:
    """The more serious of two codes, on the card's own order."""
    return first if _CODE_RANK.get(first, 3) <= _CODE_RANK.get(second, 3) else second


def _kept(text: str) -> str:
    """Free text as a reading keeps it, and as the line will say it — clipped once,
    in characters and then in the bytes the seam weighs (:data:`_TEXT_CHARS`)."""
    return clip(text, chars=_TEXT_CHARS, budget=_TEXT_BYTES)


def _word(text: str) -> str:
    """A status or a state AWS reports, held to :data:`_WORD_BYTES`. AWS's own
    vocabularies are a few letters long, so this is a bound nobody meets."""
    return clip(text, chars=_WORD_BYTES, budget=_WORD_BYTES)


def _digest(text: str) -> str:
    """``sha256:`` and 32 hex digits of *text* — the spelling a subject, a state or an
    identifier takes where its own would not travel: the same text always gives the
    same digest, and two texts in practice never share one."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _identifier(text: str) -> str:
    """An identifier AWS minted — an instance's, a job's, an execution's — kept
    whole, or as a digest of itself past :data:`_WORD_BYTES` or where it would not
    travel (:func:`_travels`): a clipped identifier could meet another one, and a
    digest cannot. AWS mints them short and plain."""
    return (text if len(json.dumps(text)) <= _WORD_BYTES and _travels(text)
            else _digest(text))


def _travels(text: str) -> bool:
    """Whether a subject or a state can go as it is spelled: within the length the
    library allows one, and free of control characters (`check_subject`)."""
    return (len(text) <= MAX_SUBJECT_LENGTH
            and not any(ord(char) < 32 or ord(char) == 127 for char in text))


def _subject(kind: str, *parts: str) -> str:
    """The object a reading is of, as ADR-0005 §4 spells it: its kind, then the
    account by its configured name and the address AWS gives the rest, with `/`
    between the parts — ``batch/live/eu-central-1/nightly/aggregate``.

    `/` is the one character an account name must not hold — it is a node's path
    segment wherever a check names several accounts, and nothing refuses it when
    the check is loaded — and AWS refuses it in a region, a queue, a job, a
    pipeline and a function name; so wherever the account's name holds none a
    subject splits back into its parts, and the kind first keeps a job, a pipeline,
    a function and the estate from ever meeting. Past what a subject may hold — or
    with a control character in an account name — it is the kind and a digest of
    the rest, which is still the kind's and still one object's.
    """
    spelled = "/".join((kind, *parts))
    if _travels(spelled):
        return spelled
    return f"{kind}/{_digest('/'.join(parts))}"


def _estate_state(outcomes: Sequence[tuple[str, str]]) -> str:
    """The state the estate is in, spelled from each account's outcome
    (ADR-0005 §6): ``backup=expired/live=read``.

    Sorted by name, as the estate's subject is, so reordering the configuration
    does not break a spell; the pairs joined by `/`, which a name must not hold;
    and never the error text, so a reworded AWS message does not start one. What
    follows a pair's last `=` is :data:`READ`, :data:`UNREACHABLE` or
    :data:`EXPIRED`, so a `;` or `=` inside a name cannot make two spellings meet,
    and only a spelling that would not travel — past what a state may hold, or with
    a control character in a name — becomes a digest.
    """
    spelled = "/".join(f"{name}={outcome}" for name, outcome in sorted(outcomes))
    return spelled if _travels(spelled) else _digest(spelled)


def _iso(value: datetime | None) -> str | None:
    """A time as a record keeps it: ISO 8601 in UTC, converted at the seam and
    never re-stamped (little-sister ADR-0082, little-sister ADR-0087 decision 6) —
    and always under `at`, `started` or `ended`, at the top of a record or nested
    (`created.at`), the names little-sister reads as an instant (ADR-0005 §1)."""
    return None if value is None else value.astimezone(UTC).isoformat()


def _time(value: object) -> datetime | None:
    """A time a record kept, as the value a line is written from again."""
    return datetime.fromisoformat(value) if isinstance(value, str) else None


def _aligned(moment: datetime, period: int) -> datetime:
    """*moment* moved back to the start of the *period* it falls in, in UTC: where
    a window ends, so that its newest bucket is a whole one."""
    return datetime.fromtimestamp(int(moment.timestamp()) // period * period,
                                  tz=UTC)


def _whole(value: float | None) -> int | None:
    """A number CloudWatch answered as the whole number a record keeps, or nothing
    where it sent none: a count is one already, and a duration is kept in whole
    milliseconds (ADR-0006 §6)."""
    return None if value is None else round(value)


def _seconds(start: datetime | None, end: datetime | None) -> int | None:
    """How long it was from one instant to the next, in the whole seconds a record
    keeps (ADR-0008 §3, §4) — counted as a line counts a span, a second that was
    begun not at all. Nothing where either instant is unknown, and nothing where the
    second lies before the first: that is no span, and is not kept as one of no
    length."""
    if start is None or end is None or end < start:
        return None
    return int((end - start).total_seconds())


def _metric_query(query_id: str, function: str, metric: str, stat: str,
                  period: int) -> MetricDataQueryTypeDef:
    """One query of ``get_metric_data``: one statistic of one of a function's
    metrics, at one period."""
    return {
        "Id": query_id,
        "MetricStat": {
            "Metric": {
                "Namespace": "AWS/Lambda",
                "MetricName": metric,
                "Dimensions": [{"Name": "FunctionName", "Value": function}],
            },
            "Period": period,
            "Stat": stat,
        },
    }


def _asked(queries: Sequence[MetricDataQueryTypeDef], query_id: str) -> str:
    """What the query *query_id* asked, as a line says it: the metric, and the
    function it was asked of — or the id itself, for one this type did not send."""
    for query in queries:
        if query.get("Id") == query_id:
            metric = query["MetricStat"]["Metric"]
            return f"{metric['MetricName']} of {metric['Dimensions'][0]['Value']}"
    return f"the query {query_id}"


def _reading(aspect: str | None, kind: str, account: str | None,
             region: str | None, fields: Mapping[str, Any], *, subject: str = "",
             identity: str = "", state: str = "") -> Measurement:
    """One reading of this check, in the one vocabulary its grading sorts by
    (ADR-0005 §1).

    Every record names the **aspect** it was read for — ``None`` for the estate
    and an account's own reading — and its **kind**, the shape the rest of it has.
    A reading about one account names it as `account`, by its configured name, and
    one about one region names the region; *fields* are the rest, a mapping of
    their own so that a record's `state` — an alarm's, a queue's — is never taken
    for the measurement's. ``subject``, ``identity`` and ``state`` are empty for
    every reading but the four kinds that have a history: the estate, a pipeline,
    a Batch job's run and a Lambda function's run.
    """
    record: dict[str, Any] = {"aspect": aspect, "kind": kind}
    if account is not None:
        record["account"] = account
    if region is not None:
        record["region"] = region
    record.update(fields)
    return Measurement(record=record, subject=subject, identity=identity,
                       state=state)


def _carrying(entry: Entry, reading: Measurement) -> Entry:
    """*entry* as the line of *reading*: the reading's record as its ``data`` and
    the reading's subject as its own (ADR-0005 §7). Every line the grading writes
    out of **one** reading carries it this way, so what the line read stays beside
    what it says, and a kept reading finds the line it stood on
    (little-sister ADR-0087 decision 8). A line written out of many carries none."""
    return replace(entry, subject=reading.subject, data=dict(reading.record))


def _unreadable(aspect: str, account: Account, region: str,
                error: BaseException) -> Measurement:
    """A region one aspect could not read in one account: asked and not answered,
    and a reading all the same (little-sister ADR-0085 decision 3)."""
    return _reading(aspect, "unreadable", account.name, region,
                    {"error": _kept(str(error))})


def _unreadable_entry(reading: Measurement, noun: str) -> Entry:
    """The line an unreadable region has always been: a WARN of its own, since a
    read failure has no honest verdict about what could not be read."""
    record = reading.record
    region = str(record["region"])
    return _carrying(Entry(
        slug("read", region),
        f"{plain(region)}: {noun} cannot be read: {plain(str(record['error']))}",
        StatusCode.WARN), reading)


def _alarm_of(record: Mapping[str, Any]) -> Alarm:
    return Alarm(name=str(record["name"]), region=str(record["region"]),
                 state=str(record["state"]),
                 description=str(record.get("description") or ""),
                 composite=bool(record["composite"]))


def _instance_of(record: Mapping[str, Any]) -> Instance:
    return Instance(instance_id=str(record["id"]),
                    name=str(record.get("name") or ""),
                    region=str(record["region"]), state=str(record["state"]),
                    launched=_time(record.get("started")))


def _function_of(record: Mapping[str, Any]) -> FunctionReading:
    errors = record.get("errors")
    error = record.get("error")
    newest: Mapping[str, Any] = error if isinstance(error, Mapping) else {}
    return FunctionReading(
        name=str(record["name"]), region=str(record["region"]),
        errors=errors if isinstance(errors, int) else None,
        last_run=_time(record.get("at")),
        log_status=str(record.get("log_status") or ""),
        log_note=str(record.get("log_note") or ""),
        log_error=str(record.get("log_error") or ""),
        error_at=_time(newest.get("at")),
        held_errors=_count(newest.get("held")),
        clean_since=_count(newest.get("clean_since")))


def _count(value: object) -> int:
    """A count a record kept, and zero where it kept none."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _errors_held(points: Sequence[tuple[datetime, int]], end: datetime,
                 hold: int) -> tuple[datetime | None, int, int]:
    """What one function's one-minute points, newest first, say of its errors
    (ADR-0012): the newest bucket with an error and how many clean buckets follow
    it, and what the buckets inside the hold — the last *hold* seconds before the
    window's end — count together. Nothing where no bucket errored, and the hold's
    count alone where the hold is nothing."""
    error_at, clean_since = None, 0
    for index, (stamp, count) in enumerate(points):
        if count > 0:
            error_at, clean_since = stamp, index
            break
    since = end - timedelta(seconds=hold)
    held = sum(count for stamp, count in points if stamp >= since)
    return error_at, held, clean_since


def _run_entry(run: Measurement) -> Entry:
    """What the grading says of one run of a function, for the record alone
    (ADR-0006 §9): ``ERROR`` where its errors are above zero and ``OK`` where they
    are not, in a sentence that says its errors and its invocations.

    A run's verdict is its own at any age — the gate that keeps an old error from
    being graded is its function's line's. The line carries the run's record and
    its subject, which is how the kept run finds it (little-sister ADR-0111
    decision 7); no node shows it, so its slug is no key.
    """
    record = run.record
    errors = record.get("errors")
    failed = isinstance(errors, int) and errors > 0
    said = (f"{errors} error{'' if errors == 1 else 's'}" if failed
            else "no errors")
    invocations = record.get("invocations")
    if isinstance(invocations, int):
        said += (f" in {invocations} "
                 f"invocation{'' if invocations == 1 else 's'}")
    return Entry(slug(str(record["region"]), str(record["name"]),
                      str(record["at"])),
                 said, StatusCode.ERROR if failed else StatusCode.OK,
                 subject=run.subject, data=dict(record))


def _started(reading: Measurement) -> datetime:
    """When the execution a pipeline's reading is of started, for finding the
    newest among several: a reading that names no start — a pipeline that never
    ran — stands behind every one that does."""
    return (_time(reading.record.get("started"))
            or datetime.min.replace(tzinfo=UTC))


def _pipeline_of(record: Mapping[str, Any]) -> PipelineReading:
    return PipelineReading(name=str(record["name"]), region=str(record["region"]),
                           status=str(record.get("status") or ""),
                           started=_time(record.get("started")),
                           execution_id=str(record.get("execution") or ""),
                           retry=_retry_of(record.get("retry")))


def _retry_of(value: object) -> Retry | None:
    """The ``retry`` block of a pipeline's record, as the reading it was written from,
    and none where the record keeps none."""
    if not isinstance(value, Mapping):
        return None
    failed, abandoned = value.get("failed"), value.get("abandoned")
    return Retry(failed=failed if isinstance(failed, int) else 0,
                 abandoned=abandoned if isinstance(abandoned, int) else 0,
                 started=_time(value.get("started")),
                 error=str(value.get("error") or ""))


def _ended_in(execution: PipelineReading) -> str:
    """The status an execution in flight on a retry had ended in, as its action
    executions show it (ADR-0014 §5), and nothing for any other."""
    return "" if execution.retry is None else execution.retry.ended


def _begun(execution: PipelineReading) -> datetime | None:
    """When an execution in flight began running as it now runs: the retry's own
    start, for one on a retry, and its start for any other (ADR-0014 §5)."""
    retry = execution.retry
    return (retry.started if retry is not None and retry.ended
            else execution.started)


def _in_flight(status: str) -> bool:
    """Whether an execution in *status* is in flight (:data:`_EXECUTION_IN_FLIGHT`),
    the word read as `state_map` reads one, whatever its case and its padding."""
    return status.strip().lower() in _EXECUTION_IN_FLIGHT


def _gives_verdict(status: str, ended: str) -> bool:
    """Whether an execution in *status* — on a retry from a status *ended*, where it is
    one — says a verdict the line can keep: one that is over, and neither superseded
    nor without a status to say; or one in flight again on a retry, which says the
    one it had ended in (ADR-0014 §2, §5)."""
    word = status.strip().lower()
    if word in _EXECUTION_IN_FLIGHT:
        return bool(ended)
    return bool(word) and word != _SUPERSEDED


def _line_index(executions: Sequence[tuple[str, str]]) -> int:
    """Of a pipeline's executions newest first, each given by the status it is in and
    the one its retry shows it had ended in (nothing where it is on none), the place of
    the one its line is written from (ADR-0014 §2, §5): the newest, unless it is in
    flight — then the newest whose verdict the line can keep (:func:`_gives_verdict`),
    which is the newest itself where it is on a retry. Where none can, the newest
    after all: a pipeline whose first execution runs has nothing else to say."""
    if not executions or not _in_flight(executions[0][0]):
        return 0
    for at, (status, ended) in enumerate(executions):
        if _gives_verdict(status, ended):
            return at
    return 0


def _carried(records: Sequence[SeriesRecord]) -> set[str]:
    """The executions a pipeline's history holds as the one its line was last written
    from, by the ids they name (ADR-0014 §4): the choice :func:`_line_index` makes,
    made over the statuses the records keep and the retries they hold — the kept
    execution that started last, unless it was in flight, and then the newest whose
    verdict the line could keep, which is that one where it was on a retry. Where none
    was, the line was written from the one in flight, which the history holds
    unfinished and so reads again all the same: none is named.

    Of several that started at one instant, when they started does not say which of
    them the line was written from, so each is taken for it. A record that names no
    start — the pipeline's from before it ever ran — is none of them."""
    dated = [(record.at, record.identity, str(record.data.get("status") or ""),
              _retry_of(record.data.get("retry")))
             for record in records if record.at is not None]
    latest = max((at for at, _, _, _ in dated), default=None)
    newest = {identity for at, identity, status, _ in dated
              if at == latest and not _in_flight(status)}
    if newest:
        return newest
    behind = [(at, identity) for at, identity, status, retry in dated
              if _gives_verdict(status, "" if retry is None else retry.ended)]
    last = max((at for at, _ in behind), default=None)
    return {identity for at, identity in behind if at == last}


def _by_status(executions: Sequence[PipelineReading]
               ) -> list[list[PipelineReading]]:
    """*executions* in groups of one status each, in the order each status first
    appears, the word compared as `state_map` compares one — and of one status, those
    on a retry apart from those on a first run, and those whose retry could not be
    read apart from both (ADR-0014 §5)."""
    groups: dict[tuple[str, str], list[PipelineReading]] = {}
    for execution in executions:
        kind = ("retried" if _ended_in(execution)
                else "unread" if execution.retry is not None and execution.retry.error
                else "")
        groups.setdefault((execution.status.strip().lower(), kind),
                          []).append(execution)
    return list(groups.values())


def _queue_of(record: Mapping[str, Any]) -> QueueReading:
    return QueueReading(
        queue=JobQueue(name=str(record["name"]), region=str(record["region"]),
                       state=str(record.get("state") or ""),
                       status=str(record.get("status") or ""),
                       status_reason=str(record.get("reason") or "")),
        capped=bool(record["capped"]))


def _job_of(record: Mapping[str, Any]) -> Job:
    return Job(job_id=str(record.get("id") or ""), name=str(record["name"]),
               status=str(record["status"]),
               created=_time(record["created"]["at"]),
               started=_time(record.get("started")),
               stopped=_time(record.get("ended")),
               reason=str(record.get("reason") or ""))


@dataclass(frozen=True)
class _Refusal:
    """Why an account could not be opened, as its reading keeps it: AWS said no
    (:data:`UNREACHABLE`) or the login had expired (:data:`EXPIRED`), what AWS
    answered, and for an expired login why it was not renewed — or what renewing
    it did."""

    outcome: str
    error: str
    renewal: str = ""


def _scope_line(noun: str, found: int, regions: tuple[str, ...], *,
                code: StatusCode = StatusCode.OK, tail: str = "") -> Entry:
    """How many of a thing were seen at all (little-sister ADR-0043) — the one
    coverage line every aspect writes.

    **The wording is shared and the grading is not.** Four aspects were spelling
    this sentence out separately, three of them identically but for the noun, and
    a fourth that really does say something else: an empty CloudWatch is a
    **warning**, because an account whose alarms have gone quiet has probably lost
    its credential, where an account may legitimately run no EC2, no Lambda, no
    pipelines and no Batch queues. That difference is a judgment about the
    service, so it stays with the aspect and arrives here as ``code`` and
    ``tail`` — what the line *says* is one place, what it *claims* is the
    caller's.

    ``tail`` is appended inside the sentence's own punctuation rather than being
    a second entry, for the reason the aspect cards give elsewhere: two entries
    read as two findings, and *expected at least three* is not a finding of its
    own.
    """
    where = ", ".join(plain(region) for region in regions)
    if not found:
        return Entry(slug("scope"), f"no {noun}s in scope ({where}){tail}", code)
    counted = noun if found == 1 else f"{noun}s"
    return Entry(slug("scope"),
                 f"{found} {counted} in scope ({where}){tail}", code)


@register("aws")
class AwsCheck(Check):
    """Read one or more AWS accounts: one child per aspect, beneath one per account
    where the check names several."""

    #: The aspects each account carries, in the order they are reported.
    ASPECTS: tuple[str, ...] = (CLOUDWATCH, EC2, LAMBDA, CODEPIPELINE, BATCH)

    def __init__(self, *, accounts: tuple[Account, ...],
                 regions: tuple[str, ...] = DEFAULT_REGIONS,
                 role_session_name: str = DEFAULT_ROLE_SESSION_NAME,
                 sts_region: str = DEFAULT_STS_REGION,
                 profile: str = "",
                 console_link: str = "",
                 sso: SsoConfig | None = None,
                 cloudwatch: CloudwatchConfig | None = None,
                 ec2: Ec2Config | None = None,
                 lambda_: LambdaConfig | None = None,
                 codepipeline: CodePipelineConfig | None = None,
                 batch: BatchConfig | None = None,
                 shorten: tuple[tuple[str, str], ...] = (),
                 access_key_ref: str = "", secret_key_ref: str = "",
                 **kwargs: Any) -> None:
        # `**kwargs` and nothing spelled out: the fields every check shares grow,
        # and a constructor that names them stops binding when the next one lands
        # (little-sister ADR-0049). The two declarations beside it are this type's
        # half of the `subnodes:` block: it states the text it ships and the tokens
        # that text reuses, and little-sister does the reading and the resolving
        # (little-sister ADR-0025). `measure_defaults` is its half of the
        # `measures:` block, the same way (little-sister ADR-0092). The object it
        # watches is declared here too, so a run that raises is still recorded
        # against it (little-sister ADR-0086 decision 4): the accounts it reads, by
        # their configured names, sorted — the estate's subject (ADR-0005 §4, §6).
        super().__init__(
            subject=_subject("accounts",
                             *sorted(account.name for account in accounts)),
            subnode_defaults=SUBNODES,
            label_tokens=_pin_notes(len(accounts) > 1),
            measure_defaults=MEASURES,
            **kwargs)
        self.accounts = accounts
        # An account's `title` and `about` label the account's node, and a check
        # that names one account has no such node (ADR-0007 §2): they are read and
        # not shown. A fact about the configuration, so it goes to the log, once,
        # when the check is loaded — and is never refused, since the text is shown
        # again the day the check names a second account.
        if len(accounts) == 1:
            unshown = [key for key, text in (("title", accounts[0].title),
                                             ("about", accounts[0].about))
                       if text.strip()]
            if unshown:
                named = " and ".join(f"'{key}'" for key in unshown)
                one = len(unshown) == 1
                logger.info(
                    "%s: the %s of account %r %s not shown: a check that names one "
                    "account has no node for it, and its aspects hang beneath the "
                    "check's own. Say %s in the check's own %s.",
                    self.path, named, accounts[0].name, "is" if one else "are",
                    "it" if one else "them", named)
        self.regions = regions
        self.role_session_name = role_session_name
        self.sts_region = sts_region
        # The default profile every account inherits. Empty is not a value here,
        # it is the *absence* of one: boto3 then reads the ambient chain exactly
        # as it did before this key existed, `AWS_PROFILE` included.
        self.profile = profile
        # The template every account's links are wrapped in unless the account
        # wrote its own (ADR-0013 §1). Empty is the absence of one, and then a link
        # is the console's own address, as it was before this key existed.
        self.console_link = console_link
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
        # Which rules matched a name during the current run, per aspect, and what
        # was last reported about the ones that did not. A rule that matches
        # nothing is usually a typo, and it is a fact about the **configuration**
        # rather than about the estate — so it goes to the log and never to a
        # node, where it would color a card over a mistake in a file and send
        # somebody hunting through an account where nothing is wrong.
        #
        # Keyed by aspect, because two aspects may reasonably name a rule the same
        # thing: `web` under `ec2:` and `web` under `codepipeline:` are two rules.
        self._matched_rules: dict[str, set[str]] = {}
        self._unmatched_rules: dict[str, frozenset[str]] = {}
        # The regions whose functions this process has read once, by account. The
        # first poll after a start reads in full again every bucket the series
        # would keep, and so repairs a bucket whose numbers grew after its hour
        # (ADR-0006 §3); every later poll reads what its history lacks, and what
        # no poll has read an hour old.
        self._functions_read: set[tuple[str, str]] = set()
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
        accounts = _parse_accounts(config.get("accounts"))
        # The check's own template, and then the one question that takes both: an
        # account under a template that names its id has to have one.
        console_link = _parse_console_link(config, "aws 'console_link'")
        _hold_account_ids(accounts, console_link)
        # Parsed before the aspects, because each of them inherits it.
        shorten = _parse_shorten(config.get("shorten"))
        extra: dict[str, Any] = {
            "accounts": accounts,
            "regions": (DEFAULT_REGIONS if regions is None
                        else _parse_regions(regions, "aws 'regions'")),
            "role_session_name": session_name,
            "sts_region": sts_region,
            "profile": _parse_profile(config, "aws 'profile'"),
            "console_link": console_link,
            "sso": _parse_sso(config.get("sso")),
            "cloudwatch": _parse_cloudwatch(config.get("cloudwatch")),
            "ec2": _parse_ec2(config.get("ec2")),
            "lambda_": _parse_lambda(config.get("lambda"), shorten),
            "codepipeline": _parse_codepipeline(
                config.get("codepipeline"), shorten),
            "batch": _parse_batch(config.get("batch"), shorten),
            "shorten": shorten,
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

    def console_link_for(self, account: Account) -> str:
        """An account's link template: its own if it wrote one, the check's
        otherwise (ADR-0013 §1) — and empty where neither did, which is every
        config written before the key existed."""
        return account.console_link or self.console_link

    def _link(self, account: Account, address: str) -> str:
        """What a line, or a roster, links a name to for *account*: the console's
        own *address*, or that address wrapped in the account's template where the
        configuration sets one (ADR-0013 §1).

        The one place a link's address is decided, for all six kinds of it. The
        console's address names no account and opens in whichever one the browser
        is signed in to; a template is how a deployment says what signs its people
        in to **this** one first."""
        template = self.console_link_for(account)
        if not template:
            return address
        return _wrapped(template, address, account.account_id)

    def _links_summary(self, account: Account) -> str:
        """Where *account*'s console links open, as its card says it (ADR-0013
        §5): the template they are wrapped in, shown as it is written — in a code
        span, which a template can hold no backtick to end — or, where none is
        set, the one thing a reader of a link cannot see in it."""
        template = self.console_link_for(account)
        if not template:
            return "open in whichever account the browser is signed in to"
        return f"through `{template}`"

    def config_summary(self) -> str:
        # A check that names one account stands for it (ADR-0007 §2): the account
        # has no node, so what that node's page would have said — the regions the
        # account is read in and where its credentials come from — is said here.
        alone = self.accounts[0] if len(self.accounts) == 1 else None
        regions = ({"default regions": ", ".join(plain(region)
                                                 for region in self.regions)}
                   if alone is None else
                   {"regions": ", ".join(plain(region)
                                         for region in self.regions_for(alone))})
        return config_markdown({
            "accounts": ", ".join(plain(account.name)
                                  for account in self.accounts),
            **regions,
            "role session name": plain(self.role_session_name),
            "credentials": (self._credentials_summary() if alone is None
                            else self._account_credentials(alone)),
            "sso login": self._sso_summary(),
            # Where the one account's links open (ADR-0013 §5). Several accounts
            # say it on their own cards, each of its own links.
            "console links": (None if alone is None
                              else self._links_summary(alone)),
            "ignored alarm names containing": ", ".join(
                plain(pattern)
                for pattern in self.cloudwatch.ignore_name_patterns) or None,
            "healthy alarms listed": "yes" if self.cloudwatch.show_healthy else "no",
            # `format_span` here, and `coarse_span` on the lines: a configured
            # threshold is a size, exactly stated, while an age is a bound.
            "instances per name": self._pair_summary(self.ec2.per_name, str),
            "instance age": self._pair_summary(self.ec2.age, format_span),
            "instance rules": self._rules_summary(self.ec2.rules,
                                                  self._ec2_rule_effect),
            "lambda log status read": ("yes" if self.lambda_.read_log_status
                                       else "no"),
            "lambda error graded within": format_span(
                self.lambda_.error_max_age_seconds),
            "lambda error held for": format_span(self.lambda_.hold_for(None)),
            "lambda silence is a finding": ("yes" if
                                            self.lambda_.expect_invocations
                                            else "no"),
            "lambda rules": self._rules_summary(self.lambda_.rules,
                                                self._lambda_rule_effect),
            "pipeline success stales after": self._pair_summary(
                self.codepipeline.age, format_span),
            "pipeline execution overruns after": self._pair_summary(
                self.codepipeline.run_time, format_span),
            "pipeline rules": self._rules_summary(
                self.codepipeline.rules, self._pipeline_rule_effect),
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
        if self.access_key:
            return "configured keys"
        return f"ambient credential chain{self._ambient_note()}"

    def _ambient_note(self) -> str:
        """`` (AWS_PROFILE=…)``, where the environment names one — else ``""``.

        A card that says only "ambient credential chain" is honest and unhelpful
        at the one moment it matters: an `AWS_PROFILE` exported for something else
        entirely is then quietly deciding which identity assumes these roles, and
        `role cannot be assumed` is the first anybody hears of it.
        """
        variable, profile = ambient_profile(os.environ)
        return f" ({variable}={plain(profile)})" if profile else ""

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

    # --- the session seam -------------------------------------------------
    #
    # What a session *is* lives in :mod:`little_sister_aws.identity`, because a
    # deployment resolving an AWS-backed secret reference opens one before any
    # check exists. What lives here is the check's own composition: an account's
    # identity is its own profile over the check's, its own role, and the
    # check's session name and STS region.

    def _new_session(self, *, aws_access_key_id: str = "",
                     aws_secret_access_key: str = "",
                     aws_session_token: str = "",
                     profile_name: str = "") -> Session:
        """The one place this check builds a boto3 session — and so the one seam
        a test replaces. It is a method rather than the module function it calls
        for exactly that reason: a fake belongs to one check, not to a process."""
        return new_session(aws_access_key_id=aws_access_key_id,
                           aws_secret_access_key=aws_secret_access_key,
                           aws_session_token=aws_session_token,
                           profile_name=profile_name)

    def identity_for(self, account: Account) -> Identity:
        """How *account* is read: its profile or the check's, its role if it
        names one, and the check's session name and STS region.

        Static keys travel with it and lose to a profile, which is what
        :func:`~little_sister_aws.identity.base_session` decides — a check that
        configured both cannot exist, because `_extra_from_config` refuses it.
        """
        return Identity(profile=self.profile_for(account),
                        access_key=self.access_key,
                        secret_key=self.secret_key,
                        role_arn=account.role_arn,
                        role_session_name=self.role_session_name,
                        sts_region=self.sts_region)

    def _base_session(self) -> Session:
        """The session the roles are assumed *from*, built once per run and
        shared by every account that did not name a profile of its own."""
        return base_session(
            Identity(profile=self.profile, access_key=self.access_key,
                     secret_key=self.secret_key),
            factory=self._new_session)

    def _opened(self, base: Session, account: Account) -> Session:
        """One account's session with its credentials proven.

        *base* is passed only where the account inherits the check's identity.
        An account with a profile of its own gets a session built for that
        profile instead — building one per account only where an account asked
        for one keeps the shared case one session, which is what it was before
        profiles existed.
        """
        return open_session(self.identity_for(account),
                            base=None if account.profile else base,
                            factory=self._new_session)

    # --- renewing an expired login ----------------------------------------

    def _profile_config(self, profile: str) -> Mapping[str, Any]:
        """What ``~/.aws/config`` says about *profile*. Its own seam, so a test
        can answer for a machine it is not running on."""
        return read_profile_config(profile)

    def _login_problem(self, profile: str) -> str:
        """Why an automatic login could not happen for *profile* — ``""`` when
        it could, this check's `sso:` block deciding."""
        return login_problem(profile, self.sso,
                             profile_config=self._profile_config)

    def _sso_login(self, profile: str, timeout: int) -> str:
        """The one place a subprocess is started — and so the one seam a test
        replaces, the same bargain :meth:`_new_session` makes for boto3."""
        return run_sso_login(profile, timeout)

    def _renew(self, account: Account) -> str:
        """Renew this account's login. ``""`` when AWS is worth asking again.

        The budget is this check's: a login runs on an engine worker thread, so
        what it may cost is the check's `sso:` block and not the process's idea
        of a reasonable wait.
        """
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
                        name=_kept(name),
                        region=region,
                        state=_word(str(row.get("StateValue", ""))),
                        description=_kept(
                            str(row.get("AlarmDescription", "") or "")),
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
                        instance_id=_identifier(str(row.get("InstanceId", ""))),
                        name=_kept(name),
                        region=region,
                        state=_word(str(state.get("Name", ""))) if state else "",
                        launched=row.get("LaunchTime")))
        return instances

    # --- the cloudwatch aspect --------------------------------------------

    def _alarm_entry(self, account: Account, alarm: Alarm, code: StatusCode,
                     show_region: bool) -> Entry:
        settings = self.cloudwatch
        tags = [tag for tag, on in
                ((settings.tag_word, bool(settings.tag_prefix)
                  and alarm.name.startswith(settings.tag_prefix)),
                 ("composite", alarm.composite)) if on]
        where = f"{plain(alarm.region)} / " if show_region else ""
        suffix = f" ({', '.join(tags)})" if tags else ""
        described = alarm.description or NO_DESCRIPTION
        return Entry(
            # The region is in the slug whether or not it is in the text: a pin
            # must not re-point the day a second region is configured.
            slug(alarm.region, alarm.name),
            f"{where}[{plain(alarm.name)}]"
            f"({self._link(account, _console_link(alarm))}): "
            f"{_state_phrase(alarm.state)}{suffix} — {plain(described)}",
            code)

    def _scope_entry(self, counted: int, regions: tuple[str, ...]) -> Entry:
        """The coverage backstop (little-sister ADR-0043), as a coded line so it
        sorts with the rest: a credential that has stopped seeing anything looks
        exactly like a healthy account until something says how many it saw.

        This is the aspect whose coverage line **grades**, and the only one: the
        sentence comes from :func:`_scope_line`, the two verdicts are this
        aspect's own.
        """
        minimum = self.cloudwatch.expect_min_alarms
        if not counted:
            return _scope_line("alarm", 0, regions, code=StatusCode.WARN)
        if counted < minimum:
            return _scope_line("alarm", counted, regions, code=StatusCode.WARN,
                               tail=f", expected at least {minimum}")
        return _scope_line("alarm", counted, regions)

    def _roster(self, account: Account, alarms: list[Alarm],
                show_region: bool) -> str:
        """What the run *found*: presence without a verdict (little-sister ADR-0044).
        The count can alarm and lives in a reason; these names cannot and live here."""
        return "\n".join(
            f"- {f'{plain(alarm.region)} / ' if show_region else ''}"
            f"[{plain(alarm.name)}]({self._link(account, _console_link(alarm))})"
            for alarm in alarms)

    def _measure_cloudwatch(self, account: Account,
                            session: Session) -> list[Measurement]:
        """Every alarm in this account's regions, one reading each — the ignored
        ones too, because ``ignore_name_patterns`` spares no request:
        ``describe_alarms`` answers with every alarm either way, so the list only
        chooses what is said, and that is the grading's (ADR-0005 §2). A region
        that cannot be read is a reading of its own."""
        readings: list[Measurement] = []
        for region in self.regions_for(account):
            try:
                alarms = self._describe_alarms(session, region)
            except (BotoCoreError, ClientError) as error:
                readings.append(_unreadable(CLOUDWATCH, account, region, error))
                continue
            readings.extend(
                _reading(CLOUDWATCH, "alarm", account.name, region,
                         {"name": alarm.name, "state": alarm.state,
                          "description": alarm.description or None,
                          "composite": alarm.composite})
                for alarm in alarms)
        return readings

    def _grade_cloudwatch(self, account: Account, readings: Sequence[Measurement],
                          now: datetime) -> CheckResult:
        """The alarms leaf, from its readings: a line per alarm that is not OK —
        or per alarm, with ``show_healthy`` — carrying its reading, a WARN line per
        region that could not be read, and the coverage line last."""
        settings = self.cloudwatch
        regions = self.regions_for(account)
        show_region = len(regions) > 1
        failures: list[Entry] = []
        entries: list[Entry] = []
        found: list[Alarm] = []
        for reading in readings:
            if reading.record["kind"] == "unreadable":
                # A read failure has no honest alarm state, so it stays a WARN
                # line of its own rather than being graded as one.
                failures.append(_unreadable_entry(reading, "alarms"))
                continue
            alarm = _alarm_of(reading.record)
            if settings.ignored(alarm.name):
                continue
            found.append(alarm)
            code = settings.code_for(alarm.state)
            if code is StatusCode.OK and not settings.show_healthy:
                continue
            entries.append(_carrying(
                self._alarm_entry(account, alarm, code, show_region), reading))
        # The scope line goes last so an OK one ends the list rather than
        # sitting between the findings and the healthy lines; a WARN one still
        # floats up with the sort.
        reason = [*failures, *entries, self._scope_entry(len(found), regions)]
        reason.sort(key=lambda entry: _CODE_RANK.get(
            entry.code or StatusCode.OK, 3))
        # No `code` of its own: the lines carry theirs, and declaring both is
        # refused at construction (little-sister ADR-0042).
        return CheckResult(reason=list(reason), name=CLOUDWATCH,
                           description=f"CloudWatch alarms in {account.name}",
                           report=self._roster(account, found, show_region))

    # --- the ec2 aspect ----------------------------------------------------

    def _measure_ec2(self, account: Account,
                     session: Session) -> list[Measurement]:
        """Every instance in this account's regions, one reading each — the
        terminated ones and the ones a rule ignores too, since neither spares a
        request (ADR-0005 §2).

        Per instance, although a line is per name: the line gives the age of every
        box under the name, and a fleet's launch times do not fit one record
        (ADR-0005 §1). Which rules matched a name is noted here, over the names the
        grading will group, because the log line about a rule that matched nothing
        is state between runs and the grading may keep none.
        """
        settings = self.ec2
        readings: list[Measurement] = []
        for region in self.regions_for(account):
            try:
                instances = self._describe_instances(session, region)
            except (BotoCoreError, ClientError) as error:
                readings.append(_unreadable(EC2, account, region, error))
                continue
            for instance in instances:
                if not settings.ignored_state(instance.state):
                    self._note_rule(EC2, settings.rule_for(instance.name or None))
                readings.append(_reading(
                    EC2, "instance", account.name, region,
                    {"id": instance.instance_id, "name": instance.name or None,
                     "state": instance.state,
                     "started": _iso(instance.launched)}))
        return readings

    def _grade_ec2(self, account: Account, readings: Sequence[Measurement],
                   now: datetime) -> CheckResult:
        """The instances leaf, from its readings: a line per name, graded on its
        count and on the age of its oldest box at *now*."""
        settings = self.ec2
        regions = self.regions_for(account)
        show_region = len(regions) > 1
        failures: list[Entry] = []
        # Keyed on the **raw** name, with ``None`` for the instances nobody named:
        # a rule asks about the name AWS returned, and the placeholder a card
        # prints for the unnamed group is display text this package may reword.
        groups: dict[tuple[str, str | None],
                     list[tuple[Instance, Measurement]]] = {}
        for reading in readings:
            if reading.record["kind"] == "unreadable":
                failures.append(_unreadable_entry(reading, "instances"))
                continue
            instance = _instance_of(reading.record)
            if settings.ignored_state(instance.state):
                continue
            # An instance with no `Name` tag reads back as an empty name at
            # the seam; `None` is what the rest of this aspect calls "nobody
            # named this", and the two must not be two states.
            groups.setdefault((instance.region, instance.name or None),
                              []).append((instance, reading))
        # Ignoring happens **after** grouping, because a rule matches a name and
        # a name is a group. An ignored group leaves no line and is not in scope,
        # which is what the flat list of substrings did instance by instance —
        # and it is ordered, so a rule above it can except a name.
        kept = {key: members for key, members in groups.items()
                if not self._ignores(key[1])}
        found = sum(len(members) for members in kept.values())
        counts = {key: len(members) for key, members in kept.items()}
        ages = {key: self._ages([instance for instance, _ in members], now)
                for key, members in kept.items()}
        entries: list[Entry] = []
        for key in sorted(kept, key=_instance_order):
            region, name = key
            entry = self._instance_entry(account, region, name, counts[key],
                                         ages[key], show_region)
            members = kept[key]
            # A line one instance made carries that instance's reading; a line
            # about several carries none, since no one record is what it read
            # (ADR-0005 §7).
            entries.append(_carrying(entry, members[0][1]) if len(members) == 1
                           else entry)
        reason = [*failures, *entries, _scope_line("instance", found, regions)]
        reason.sort(key=lambda entry: _CODE_RANK.get(
            entry.code or StatusCode.OK, 3))
        return CheckResult(reason=list(reason), name=EC2,
                           description=f"EC2 instances in {account.name}",
                           report=self._instance_roster(counts, ages,
                                                        show_region))

    def _ignores(self, name: str | None) -> bool:
        rule = self.ec2.rule_for(name)
        return rule is not None and rule.ignore

    @staticmethod
    def _ages(members: list[Instance], now: datetime) -> tuple[int, ...]:
        """Every age under one name, oldest last.

        All of them, because the line reports a **range** (:func:`_age_span`);
        the last of them, because the group is *graded* on its oldest member —
        the one that has been unpatched longest. An instance whose payload
        carried no launch time contributes nothing rather than a guess.
        """
        return tuple(sorted(
            age for age in (member.age_seconds(now) for member in members)
            if age is not None))

    def _instance_entry(self, account: Account, region: str, name: str | None,
                        count: int, ages: tuple[int, ...],
                        show_region: bool) -> Entry:
        where = f"{plain(region)} / " if show_region else ""
        # The no-name group is not a name, so it is not a console search either.
        label = (plain(NO_NAME_TAG) if name is None else
                 f"[{plain(name)}]"
                 f"({self._link(account, _instance_link(region, name))})")
        # The age rides on **every** line, healthy ones included: it is the
        # reading, not the exception report, and a line that only shows it when
        # it is bad teaches nobody what normal looks like.
        # `coarse_span` inside `_age_span`, not `format_span`: an age is a
        # **bound** on a card nobody re-renders while it is being read, so it
        # states its largest one or two units and stops (little-sister's `spans`
        # module). The exact measurement would be out of date before the sentence
        # ended — and the lossiness is what decides the range's shape.
        span = _age_span(ages)
        suffix = f" ({span})" if span else ""
        # The **oldest** member is what the age is graded on, before this change
        # and after: the range is a reading, and the oldest is the verdict.
        code, notes = self.ec2.judge(name, count, ages[-1] if ages else None)
        # The sentences are configuration, so they are escaped like every other
        # configured text that reaches a line — an instance name gets the same
        # treatment two lines above.
        said = f" — {'; '.join(plain(note) for note in notes)}" if notes else ""
        return Entry(slug(region, name if name is not None else NO_NAME_TAG),
                     f"{where}{label}: {count}{suffix}{said}", code)

    @staticmethod
    def _instance_roster(counts: dict[tuple[str, str | None], int],
                         ages: dict[tuple[str, str | None], tuple[int, ...]],
                         show_region: bool) -> str:
        lines = []
        for key in sorted(counts, key=_instance_order):
            region, name = key
            where = f"{plain(region)} / " if show_region else ""
            span = _age_span(ages.get(key, ()))
            suffix = f" ({span})" if span else ""
            shown = NO_NAME_TAG if name is None else name
            lines.append(f"- {where}{plain(shown)}: {counts[key]}{suffix}")
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

    def _metric_data(self, client: CloudWatchClient, start: datetime, end: datetime,
                     queries: Sequence[MetricDataQueryTypeDef]
                     ) -> dict[str, list[tuple[datetime, float]]]:
        """One ``get_metric_data`` answer, whole: every data point of every query,
        by the query's id, newest first.

        CloudWatch hands an answer back in pages — a page ends where its part of
        the window could hold 100,800 points, whatever the metrics hold — each with
        a token for the next. The token is followed until none comes back, because
        which points a page holds of which query is CloudWatch's to say — and a
        function the first page left out read as one with no point at all, was
        asked again at a coarser period and billed again. :data:`_METRIC_PAGES`
        bounds the following.

        **A query CloudWatch did not answer fails the read** (:data:`_ANSWERED`).
        It answers each query of a call on its own, and may say of one that it
        could not while the call succeeds; that result carries no point, and read
        as an answer it is a function that never ran — asked again at the coarser
        periods, billed again — or a run kept with an empty number. So it raises
        where it is first seen, and what is left of the answer is not asked for:
        the region then says that its functions could not be read, nothing of the
        poll is kept, and the next poll asks again.
        """
        points: dict[str, list[tuple[datetime, float]]] = {}
        token = ""
        for _ in range(_METRIC_PAGES):
            page = (client.get_metric_data(StartTime=start, EndTime=end,
                                           MetricDataQueries=queries,
                                           NextToken=token)
                    if token else
                    client.get_metric_data(StartTime=start, EndTime=end,
                                           MetricDataQueries=queries))
            results = page.get("MetricDataResults", [])
            # A result that names no status is read as it always was: only what
            # CloudWatch says was not answered is refused.
            unanswered = [result for result in results
                          if (result.get("StatusCode") or _ANSWERED[0])
                          not in _ANSWERED]
            if unanswered:
                first = unanswered[0]
                told = "; ".join(
                    text for message in first.get("Messages") or []
                    if (text := str(message.get("Value") or "")))
                more = len(unanswered) - 1
                raise _NotAnswered(
                    asked=_asked(queries, str(first.get("Id", ""))),
                    status=first.get("StatusCode"),
                    said=f" — {told}" if told else "",
                    others=(f"; {more} more "
                            f"{'query' if more == 1 else 'queries'} likewise"
                            if more else ""))
            for result in results:
                # Not `strict`: an answer with a stamp too many loses that stamp,
                # and never the run that read it.
                points.setdefault(str(result.get("Id", "")), []).extend(zip(
                    result.get("Timestamps") or [], result.get("Values") or [],
                    strict=False))
            token = str(page.get("NextToken") or "")
            if not token:
                break
        else:
            raise _AnswerNotEnded(pages=_METRIC_PAGES)
        # `get_metric_data` scans TimestampDescending unless told otherwise, and
        # what order its pages arrive in is not this method's to assume.
        for found in points.values():
            found.sort(key=lambda point: point[0], reverse=True)
        return points

    def _errors(self, client: CloudWatchClient, names: Sequence[str],
                start: datetime, end: datetime, period: int
                ) -> dict[str, list[tuple[datetime, int]]]:
        """Every ``Errors`` data point of each function in one window at one period,
        newest first — and no entry for a function the window holds no point of.

        Batched: one call for up to 500 functions, rather than one per function.
        """
        found: dict[str, list[tuple[datetime, int]]] = {}
        for offset in range(0, len(names), _METRIC_BATCH):
            batch = names[offset:offset + _METRIC_BATCH]
            answer = self._metric_data(client, start, end, [
                _metric_query(f"e{index}", name, "Errors", "Sum", period)
                for index, name in enumerate(batch)])
            for index, name in enumerate(batch):
                points = answer.get(f"e{index}")
                if points:
                    found[name] = [(stamp, int(value)) for stamp, value in points]
        return found

    def _kept_runs(self, account: Account, region: str,
                   name: str) -> dict[datetime, datetime]:
        """The buckets this check keeps as one function's runs, each beside the
        moment a poll last read it: a kept record's own time, and when it was
        observed (little-sister ADR-0113). Empty where the check keeps no series,
        and where nothing of the function is kept yet."""
        return {record.at: record.observed_at
                for record in self.kept(
                    _subject(LAMBDA, account.name, region, _kept(name)))
                if record.at is not None}

    def _window(self, kept: Collection[datetime], end: datetime,
                hold: int) -> timedelta:
        """The window a function is asked in (ADR-0006 §3): the smallest of
        :data:`_RUN_WINDOWS` that reaches the oldest of its kept runs, where they
        fill the series, and the largest where they do not — which is every
        function of a check that keeps no series, asked the fifteen days as it
        always was. It reaches the function's error hold as well (ADR-0012): the
        newest error has to be in the answer for the hold to stand on it, and the
        hold is never longer than the largest window."""
        if not self.series_keep or len(kept) < self.series_keep:
            return _RUN_WINDOWS[-1]
        reach = max(end - min(kept), timedelta(seconds=hold))
        return next((window for window in _RUN_WINDOWS if window >= reach),
                    _RUN_WINDOWS[-1])

    def _read_runs(self, client: CloudWatchClient, account: Account, region: str,
                   asked: Mapping[timedelta, Sequence[str]],
                   points: Mapping[str, Sequence[tuple[datetime, int]]],
                   kept: Mapping[str, Mapping[datetime, datetime]],
                   end: datetime) -> dict[str, list[FunctionRun]]:
        """The runs this poll reads in full, by function, oldest first (ADR-0006
        §3, §4).

        A bucket the first call answered is read in full where the function's kept
        runs lack it, and where no poll has read it since it was as old as the
        overlap, since its numbers may have grown — and every such bucket on the
        first poll after a start, which repairs one that grew after its hour. Never
        a bucket the series would not keep: the newest ``series_keep`` of what the
        first call answered are the function's series after this poll, and an older
        one would leave it the moment it was kept.

        ``Invocations`` and ``Duration`` are asked of the functions that have such
        a bucket and of no others, so a function that did not run costs the one
        metric it always cost — and from the oldest bucket a call is to read, so
        its answer holds little the poll does not read.
        """
        again = (account.name, region) not in self._functions_read
        wanted: dict[str, list[datetime]] = {}
        for name, found in points.items():
            read = kept[name]
            # Newest first, as the first call answered them.
            series = [stamp for stamp, _ in found][:self.series_keep]
            stamps = [stamp for stamp in series
                      if again or stamp not in read
                      or read[stamp] - stamp < _RUN_OVERLAP]
            if stamps:
                wanted[name] = sorted(stamps)
        runs: dict[str, list[FunctionRun]] = {}
        # Two queries a function, so half as many functions to a call. A call
        # holds functions of one window, as the first call did, so that those whose
        # buckets are few minutes old are not asked with one whose are days old.
        half = _METRIC_BATCH // 2
        for window in _RUN_WINDOWS:
            members = [name for name in asked.get(window, ()) if name in wanted]
            for offset in range(0, len(members), half):
                batch = members[offset:offset + half]
                since = min(wanted[name][0] for name in batch)
                answer = self._metric_data(client, since, end, [
                    query for index, name in enumerate(batch) for query in (
                        _metric_query(f"i{index}", name, "Invocations", "Sum",
                                      _RUN_PERIOD),
                        _metric_query(f"d{index}", name, "Duration", "Maximum",
                                      _RUN_PERIOD))])
                for index, name in enumerate(batch):
                    errors = dict(points[name])
                    invocations = dict(answer.get(f"i{index}", ()))
                    durations = dict(answer.get(f"d{index}", ()))
                    runs[name] = [
                        FunctionRun(name=_kept(name), region=region, at=stamp,
                                    errors=errors[stamp],
                                    invocations=_whole(invocations.get(stamp)),
                                    duration_ms=_whole(durations.get(stamp)))
                        for stamp in wanted[name]]
        self._functions_read.add((account.name, region))
        return runs

    def _log_reading(self, session: Session, region: str,
                     name: str) -> tuple[str, str, str]:
        """The status word of the function's newest log event, a note when there
        is none, and what AWS answered when the log could not be read at all. A
        function that has never run has no log group, which is a sentence rather
        than a failure.

        An empty page is not the end of a stream: GetLogEvents may answer one
        while the stream still has events, and the end is the backward token
        coming back the same as the one sent. So an empty page is followed by the
        token it handed back, up to :data:`_LOG_PAGES` pages — past which the note
        says the newest event was not reached, not that there is none."""
        client = session.client("logs", region_name=region)
        group = f"/aws/lambda/{name}"
        try:
            streams = client.describe_log_streams(
                logGroupName=group, orderBy="LastEventTime", descending=True,
                limit=1).get("logStreams", [])
            if not streams:
                return "", "no log stream", ""
            stream = str(streams[0].get("logStreamName", ""))
            sent = ""
            for _ in range(_LOG_PAGES):
                page = (client.get_log_events(
                            logGroupName=group, logStreamName=stream, limit=1,
                            startFromHead=False, nextToken=sent)
                        if sent else client.get_log_events(
                            logGroupName=group, logStreamName=stream, limit=1,
                            startFromHead=False))
                events = page.get("events", [])
                if events:
                    message = str(events[0].get("message", ""))
                    match = _LOG_STATUS.search(message)
                    if match is None:
                        return "", "no status word in the last log line", ""
                    return match.group(1), "", ""
                token = str(page.get("nextBackwardToken") or "")
                if not token or token == sent:
                    return "", "no log event", ""
                sent = token
            return "", f"newest log event not reached in {_LOG_PAGES} pages", ""
        except (BotoCoreError, ClientError) as error:
            return "", "", _kept(str(error))

    def _read_functions(self, session: Session, account: Account, region: str,
                        now: datetime
                        ) -> tuple[list[FunctionReading],
                                   dict[str, list[FunctionRun]]]:
        """One region's functions, narrowed at the seam: each function's reading,
        and — where this check keeps a series — the runs this poll read in full, by
        function.

        **The function's reading is asked on every poll** (ADR-0006 §2): its newest
        ``Errors`` data point, from the finest resolution that still has one. Each
        function is asked at the one-minute period in the window its series reaches
        into (:meth:`_window`), so one answer serves both the reading and the
        question of what is to be read in full (:meth:`_read_runs`); a function its
        window holds no point of is asked the coarser periods, and one that
        answered at a finer period is not asked again at a coarser one.
        """
        settings = self.lambda_
        names = sorted(name for name in self._list_functions(session, region)
                       if not settings.ignored(name))
        client = session.client("cloudwatch", region_name=region)
        # Aligned to the period, so the newest bucket is a whole one rather than
        # the fraction elapsed so far.
        end = _aligned(now, _RUN_PERIOD)
        # Read before anything is asked: what was kept decides the ask
        # (little-sister ADR-0113 decision 3).
        kept = ({name: self._kept_runs(account, region, name) for name in names}
                if self.series_keep else {})
        asked: dict[timedelta, list[str]] = {}
        for name in names:
            hold = settings.hold_for(settings.rule_for(name))
            asked.setdefault(self._window(kept.get(name, ()), end, hold),
                             []).append(name)
        points: dict[str, list[tuple[datetime, int]]] = {}
        for window in _RUN_WINDOWS:
            if window in asked:
                points.update(self._errors(client, asked[window], end - window,
                                           end, _RUN_PERIOD))
        newest = {name: found[0] for name, found in points.items()}
        pending = [name for name in names if name not in points]
        for period, days in _ERROR_PERIODS[1:]:
            if not pending:
                break
            until = _aligned(now, period)
            coarse = self._errors(client, pending, until - timedelta(days=days),
                                  until, period)
            newest.update((name, found[0]) for name, found in coarse.items())
            pending = [name for name in pending if name not in coarse]
        runs = (self._read_runs(client, account, region, asked, points, kept, end)
                if self.series_keep else {})
        readings: list[FunctionReading] = []
        for name in names:
            rule = settings.rule_for(name)
            last_run, count = newest.get(name, (None, None))
            error_at, held_errors, clean_since = _errors_held(
                points.get(name, ()), end, settings.hold_for(rule))
            status, note, failure = ("", "", "")
            # Per function, because the log read is two API calls each — more where
            # a page comes back empty — and the functions worth paying for are not
            # always the whole account.
            if settings.reads_log(rule):
                status, note, failure = self._log_reading(session, region, name)
            readings.append(FunctionReading(
                name=_kept(name), region=region, errors=count, last_run=last_run,
                log_status=status, log_note=note, log_error=failure,
                error_at=error_at, held_errors=held_errors,
                clean_since=clean_since))
        return readings, {_kept(name): found for name, found in runs.items()}

    def _function_entry(self, account: Account, reading: FunctionReading,
                        now: datetime) -> Entry:
        settings = self.lambda_
        rule = settings.rule_for(reading.name)
        age = (None if reading.last_run is None
               else max(0, int((now - reading.last_run).total_seconds())))
        parts: list[str] = []
        said = ""
        code = StatusCode.OK
        if reading.errors is None:
            # Not the same as zero errors: CloudWatch had no data point at all in
            # 455 days. A scheduled job nobody has invoked is not a healthy one —
            # but a handler that runs when somebody calls it is, which is what a
            # rule saying `expect_invocations: false` is for.
            parts.append("no recent invocations")
            if settings.expects_invocations(rule):
                code = StatusCode.WARN
                said = settings.sentence("silent_reason", rule)
        elif reading.errors == 0 and self._held(reading, now, rule):
            # The newest run was clean, but an error inside the hold stands on the
            # line (ADR-0012): how many the hold holds, when the newest was, and
            # what ran clean since — so a reader of the node sees what a reader of
            # the events would.
            hold = format_span(settings.hold_for(rule))
            held = reading.held_errors
            when = coarse_span(int((now - reading.error_at).total_seconds())
                               if reading.error_at is not None else 0)
            newest = "" if held == 1 else "the newest "
            parts.append(f"{held} error{'s' if held != 1 else ''} in the last "
                         f"{hold}, {newest}{when} ago · {reading.clean_since} "
                         f"clean run{'s' if reading.clean_since != 1 else ''} "
                         f"since, the last {coarse_span(age or 0)} ago")
            code = StatusCode.ERROR
            said = settings.sentence("error_reason", rule)
        elif reading.errors == 0:
            parts.append(f"no errors, last run {coarse_span(age or 0)} ago")
        elif age is not None and age <= settings.gate_for(rule):
            parts.append(f"{reading.errors} error"
                         f"{'s' if reading.errors != 1 else ''}, "
                         f"last run {coarse_span(age)} ago")
            if settings.hold_for(rule) and reading.held_errors > reading.errors:
                parts.append(f"{reading.held_errors} in the last "
                             f"{format_span(settings.hold_for(rule))}")
            code = StatusCode.ERROR
            said = settings.sentence("error_reason", rule)
        else:
            parts.append(f"{reading.errors} error"
                         f"{'s' if reading.errors != 1 else ''} but the last run "
                         f"was {coarse_span(age or 0)} ago — too old to grade")
        if reading.log_status:
            parts.append(f"log: {plain(reading.log_status)}")
            if reading.log_status == "ERROR":
                code = StatusCode.ERROR
                said = said or settings.sentence("error_reason", rule)
        parts.extend(plain(note) for note in reading.notes)
        if said:
            parts.append(plain(said))
        # No region on the line, however many the account reads: the line stands
        # on the function's own node, and where there are several regions that
        # node hangs beneath its region's (ADR-0007 §3). The slug keeps the region,
        # as every slug does.
        label = plain(settings.short_name(reading.name))
        link = self._link(account, _function_link(reading.region, reading.name))
        return Entry(slug(reading.region, reading.name),
                     f"[{label}]({link}): {' · '.join(parts)}",
                     code)

    def _held(self, reading: FunctionReading, now: datetime,
              rule: Rule | None) -> bool:
        """Whether an error this function saw still stands on its line (ADR-0012):
        the newest error is younger than the hold that applies to the function. A
        hold of nothing holds nothing, and the hold is never longer than the gate,
        so a held error is always one the gate would grade."""
        hold = self.lambda_.hold_for(rule)
        if not hold or reading.error_at is None:
            return False
        return (now - reading.error_at).total_seconds() <= hold

    def _measure_lambda(self, account: Account,
                        session: Session) -> list[Measurement]:
        """Every function in this account's regions that no rule ignores, one
        reading each — a rule's ``ignore`` and ``read_log_status`` spare the metric
        and the log reads, so they are decided here (ADR-0005 §2) — and, behind
        each function's, one reading for every run of it the poll read in full
        (ADR-0006 §2)."""
        settings = self.lambda_
        now = _utcnow()
        readings: list[Measurement] = []
        for region in self.regions_for(account):
            try:
                functions, runs = self._read_functions(session, account, region,
                                                       now)
            except (BotoCoreError, ClientError) as error:
                readings.append(_unreadable(LAMBDA, account, region, error))
                continue
            for function in functions:
                self._note_rule(LAMBDA, settings.rule_for(function.name))
                readings.append(_reading(
                    LAMBDA, "function", account.name, region,
                    {"name": function.name, "errors": function.errors,
                     "at": _iso(function.last_run),
                     # The newest error nests its instant under `at`, as a job's
                     # creation does (ADR-0005 §1): a time under any other name
                     # is only a string to the surfaces that show a record.
                     "error": (None if function.error_at is None else
                               {"at": _iso(function.error_at),
                                "held": function.held_errors,
                                "clean_since": function.clean_since}),
                     "log_status": function.log_status or None,
                     "log_note": function.log_note or None,
                     "log_error": function.log_error or None}))
                readings.extend(self._function_run(account, run)
                                for run in runs.get(function.name, ()))
        return readings

    @staticmethod
    def _function_run(account: Account, run: FunctionRun) -> Measurement:
        """One run of a function, of the object ADR-0006 §1 gives a history: the
        function, in its account and its region.

        It names its bucket's start as the event it is of, so a bucket read again —
        every poll of its first hour — is one record however often it is read. The
        identity is the instant **as the record keeps it**, taken from the record
        once the seam has written it: one instant spelled with another offset would
        be another event (little-sister ADR-0087 decision 3).
        """
        reading = _reading(
            LAMBDA, "run", account.name, run.region,
            {"name": run.name, "at": _iso(run.at), "invocations": run.invocations,
             "errors": run.errors, "duration_ms": run.duration_ms},
            subject=_subject(LAMBDA, account.name, run.region, run.name))
        return replace(reading, identity=str(reading.record["at"]))

    def _grade_lambda(self, account: Account, readings: Sequence[Measurement],
                      now: datetime) -> CheckResult:
        """The functions' node, from its readings: a node for every function, which
        carries the function's line and says how each run the poll read in full
        stood, for the record (ADR-0006 §9).

        The functions hang beneath their region's node where the account reads
        several regions, and beneath this one where it reads one (ADR-0007 §3).
        What stays this node's own is how many functions are in scope — and, where
        its regions have no nodes of their own, a region that could not be read.
        """
        regions = self.regions_for(account)
        unreadable: dict[str, Measurement] = {}
        functions: dict[str, list[tuple[FunctionReading, Measurement]]] = {}
        runs: dict[tuple[str, str], list[Measurement]] = {}
        for reading in readings:
            record = reading.record
            region = str(record["region"])
            if record["kind"] == "unreadable":
                unreadable[region] = reading
            elif record["kind"] == "function":
                functions.setdefault(region, []).append(
                    (_function_of(record), reading))
            elif record["kind"] == "run":
                runs.setdefault((region, str(record["name"])), []).append(reading)
        found = [function for members in functions.values()
                 for function, _ in members]
        return self._subjects_node(
            account, LAMBDA, "functions", f"Lambda functions in {account.name}",
            _scope_line("function", len(found), regions),
            self._function_roster(account, found, len(regions) > 1), unreadable,
            {region: self._function_nodes(account, members, runs, now)
             for region, members in functions.items()})

    def _subjects_node(self, account: Account, aspect: str, noun: str,
                       description: str, scope: Entry, report: str,
                       unreadable: Mapping[str, Measurement],
                       nodes: Mapping[str, tuple[CheckResult, ...]]
                       ) -> CheckResult:
        """The node of an aspect whose subjects are nodes — `lambda`,
        `codepipeline` and `batch` (ADR-0006 §9, ADR-0009 §8) — above *nodes*, its
        subjects' by the region each was read in.

        The subjects hang beneath their region's node where the account reads
        several regions, and beneath this one where it reads one (ADR-0007 §3).
        What stays this node's own is how many of them are in scope and its roster
        — and, where its regions have no nodes of their own, a region that could
        not be read."""
        regions = self.regions_for(account)
        if len(regions) > 1:
            # A node for every region the configuration names, read or not — the
            # shape is the configuration's and never what AWS answered (ADR-0007
            # §1) — and for one a reading names that the configuration no longer
            # does, so that no reading is graded away. Those children are
            # configuration, so this node never says that they are complete: a run
            # cannot find a region gone.
            named = dict.fromkeys((*regions, *sorted(unreadable), *sorted(nodes)))
            return CheckResult(
                reason=[scope], name=aspect, description=description, report=report,
                children=tuple(
                    self._region_node(region, f"{description}, {region}", noun,
                                      unreadable.get(region), nodes.get(region, ()))
                    for region in named))
        return CheckResult(
            # A region that could not be read stands before the count: worst first
            # (little-sister ADR-0042).
            reason=[*(_unreadable_entry(reading, noun)
                      for reading in unreadable.values()), scope],
            name=aspect, description=description, report=report,
            children=tuple(node for members in nodes.values() for node in members),
            # Complete where the listing was read whole, so a subject that was
            # deleted, or that the configuration now ignores, leaves with this run;
            # unsaid where it could not be read, and the subjects stay as they were
            # (little-sister ADR-0109).
            children_complete=not unreadable)

    @staticmethod
    def _region_node(region: str, description: str, noun: str,
                     unreadable: Measurement | None,
                     children: tuple[CheckResult, ...]) -> CheckResult:
        """One region's node beneath an aspect whose subjects are nodes, where the
        account reads several regions (ADR-0007 §3): named by the region, grading
        nothing of its own — unless the region could not be read, which it then
        says. It is the node that says its children are complete, so a region that
        could not be read keeps the nodes it had while its neighbors still remove
        what is gone.

        It declines the density trade, as its aspect does and for its aspect's
        reason (little-sister ADR-0063): it is the box that holds a region's
        subjects, and which of them exist is read while everything is fine. The
        aspect declares that for itself. A region is named by the configuration and
        not by this type, which it says (little-sister ADR-0118), so its flag rides
        the result and nothing declared for an aspect's name reaches it."""
        if unreadable is not None:
            return CheckResult(reason=[_unreadable_entry(unreadable, noun)],
                               name=region, description=description,
                               show_when_quiet=True, dynamic=True)
        return CheckResult(StatusCode.OK, [], name=region, description=description,
                           children=children, children_complete=True,
                           show_when_quiet=True, dynamic=True)

    def _function_nodes(self, account: Account,
                        members: Sequence[tuple[FunctionReading, Measurement]],
                        runs: Mapping[tuple[str, str], Sequence[Measurement]],
                        now: datetime) -> tuple[CheckResult, ...]:
        """One region's functions as nodes, in the order they were read — which
        is by name."""
        return tuple(
            self._function_node(account, function, reading,
                                runs.get((function.region, function.name), ()), now)
            for function, reading in members)

    def _function_node(self, account: Account, function: FunctionReading,
                       reading: Measurement, runs: Sequence[Measurement],
                       now: datetime) -> CheckResult:
        """A function's own node, named by what AWS calls the function (ADR-0006
        §9). A display-name rule gives it its title and never reaches its path, as
        it never reaches a slug. It says that a run names it (little-sister
        ADR-0118): a function its account calls ``batch`` is not the ``batch``
        aspect, and what this type declares for that aspect is not said of it.

        Its one line is the function's, written from the function's reading and
        carrying it — and **naming the function as its subject, though that reading
        names none**: that is what makes the node stand for the function, so its
        pages draw the function's runs, and what keeps the function's own reading
        out of the series (little-sister ADR-0106 decision 2). No run has a line of
        its own: how each run this poll read in full stood is said for the record
        alone (little-sister ADR-0111 decision 7).
        """
        subject = _subject(LAMBDA, account.name, function.region, function.name)
        line = replace(self._function_entry(account, function, now),
                       subject=subject, data=dict(reading.record))
        short = self.lambda_.short_name(function.name)
        return CheckResult(
            reason=[line], name=function.name,
            title="" if short == function.name else short,
            description=f"Lambda function in {account.name}, {function.region}",
            for_record=[_run_entry(run) for run in runs], dynamic=True)

    def _function_roster(self, account: Account,
                         readings: list[FunctionReading],
                         show_region: bool) -> str:
        return "\n".join(
            f"- {f'{plain(reading.region)} / ' if show_region else ''}"
            f"[{plain(reading.name)}]"
            f"({self._link(account, _function_link(reading.region, reading.name))})"
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
    def _executions(client: CodePipelineClient, name: str,
                    region: str) -> list[PipelineReading]:
        """One page of the pipeline's executions, the newest first, each narrowed
        at the seam: its status, when it started, the last change CodePipeline
        recorded of it, and the id CodePipeline gives it.

        Empty when the pipeline has never been executed — the case the original
        dropped on the floor, because it only ever built a ``Status`` inside the
        loop over executions. An execution sent without a start is none of them: it
        has no place among the others.
        """
        summaries = client.list_pipeline_executions(
            pipelineName=name, maxResults=_EXECUTIONS_PAGE,
        ).get("pipelineExecutionSummaries", [])
        dated: list[dict[str, Any]] = [
            dict(summary) for summary in summaries
            if summary.get("startTime") is not None]
        # Sorted rather than trusting the API's newest-first order: it costs one
        # sort and does not depend on a documented ordering. Two that started at
        # one instant keep the order they came in.
        dated.sort(key=lambda summary: summary["startTime"], reverse=True)
        executions: list[PipelineReading] = []
        for summary in dated:
            updated = summary.get("lastUpdateTime")
            executions.append(PipelineReading(
                name=_kept(name), region=region,
                status=_word(str(summary.get("status", ""))),
                started=summary["startTime"],
                execution_id=_identifier(
                    str(summary.get("pipelineExecutionId", "") or "")),
                updated=updated if isinstance(updated, datetime) else None))
        return executions

    def _behind(self, executions: Sequence[PipelineReading]
                ) -> list[tuple[int, PipelineReading]]:
        """The executions behind a pipeline's *newest* that its history may lack, by
        their places in *executions*, which are newest first (ADR-0009 §5): out of the
        newest of the page, as many as the series keeps beside the newest itself,
        since an older one would leave the series the moment it was kept. None where
        the check keeps no series, and none that came without an id or a status: the
        first would be a new record at every poll, and the second says nothing."""
        named = [(at, execution) for at, execution in enumerate(executions)
                 if at and execution.execution_id and execution.status]
        return named[:max(self.series_keep - 1, 0)]

    @staticmethod
    def _lacking(executions: Sequence[PipelineReading],
                 behind: Sequence[tuple[int, PipelineReading]], line_at: int,
                 records: Sequence[SeriesRecord]) -> list[int]:
        """Of *behind*, the executions this poll reads for the pipeline's history
        (ADR-0009 §5), by their places in *executions*: each one *records* lack, or
        hold in a status that ends nothing. So an execution a newer one overtook while
        it ran is read to its end, and a pipeline's series is whole from its first
        poll, as far as one page reaches.

        And the one the history holds as its line's, where the line is now written
        from another — the one at *line_at* (ADR-0014 §4). What stood for it was the
        pipeline's line, which says what no other execution is asked: how long ago it
        started, whether a success has grown stale, and what was in flight beside it.
        Read once more, it is said for the record by its own status (ADR-0009 §6);
        the poll after that finds the line where it is, and leaves it alone. Which
        execution the history holds as its line's, :func:`_carried` says — and of
        several, none is read while the line is written from one of them, which
        would be at every poll. What the check kept decides what is read and nothing
        else (little-sister ADR-0113): a record holds what CodePipeline answered."""
        if not behind:
            return []
        held = {record.identity: str(record.data.get("status") or "")
                for record in records}
        carried = _carried(records)
        if executions[line_at].execution_id in carried:
            carried = set()
        return [at for at, execution in behind
                if execution.execution_id in carried
                or held.get(execution.execution_id, "").strip().lower()
                not in _EXECUTION_ENDED]

    def _retried(self, client: CodePipelineClient, name: str,
                 executions: Sequence[PipelineReading],
                 records: Sequence[SeriesRecord]) -> list[PipelineReading]:
        """*executions*, each one in flight that the history holds ended failed or
        stopped — or holds on a retry already — with what CodePipeline answers of its
        action executions: one call for each, at every poll while it runs again
        (ADR-0014 §5). A retry of a stage runs the execution it failed in again, under
        its own id and from the start it had, so the page alone cannot tell it from a
        first run. The history can, and decides what is asked and nothing else
        (little-sister ADR-0113 decision 3): the record holds what CodePipeline
        answered. Nothing is asked where the check keeps no series."""
        held = {record.identity: record.data for record in records
                if record.identity}
        retried: list[PipelineReading] = []
        for execution in executions:
            kept = (held.get(execution.execution_id) if execution.execution_id
                    else None)
            if (kept is not None and _in_flight(execution.status)
                    and (str(kept.get("status") or "").strip().lower()
                         in _EXECUTION_RETRIED_FROM
                         or isinstance(kept.get("retry"), Mapping))):
                execution = replace(execution, retry=self._actions(
                    client, name, execution.execution_id))
            retried.append(execution)
        return retried

    @staticmethod
    def _actions(client: CodePipelineClient, name: str,
                 execution_id: str) -> Retry:
        """What one page of an execution's action executions says of its retry: how
        many failed, how many were abandoned when it was stopped, and when the first
        one that started after the last of those had ended began. A refusal is an
        answer too, and is kept as one (little-sister ADR-0085 decision 3)."""
        try:
            details = client.list_action_executions(
                pipelineName=name, filter={"pipelineExecutionId": execution_id},
                maxResults=_ACTIONS_PAGE,
            ).get("actionExecutionDetails", [])
        except (BotoCoreError, ClientError) as error:
            return Retry(error=_kept(str(error)))
        ended = [detail.get("lastUpdateTime") for detail in details
                 if detail.get("status") in ("Failed", "Abandoned")]
        last = max((at for at in ended if isinstance(at, datetime)), default=None)
        began = [detail.get("startTime") for detail in details]
        return Retry(
            failed=sum(1 for detail in details if detail.get("status") == "Failed"),
            abandoned=sum(1 for detail in details
                          if detail.get("status") == "Abandoned"),
            started=min((at for at in began if isinstance(at, datetime)
                         and last is not None and at > last), default=None))

    def _read_pipelines(self, session: Session, account: Account,
                        region: str) -> list[PipelineReading]:
        """One region's pipelines, narrowed at the seam: each pipeline's newest
        execution — or the pipeline alone, where it has never been executed — and
        beside it what the pipeline's line is written from where that is another
        (ADR-0014 §2): every execution in flight, each one the history shows on a
        retry with what its action executions say (:meth:`_retried`), and while the
        newest is in flight on no retry, the newest whose verdict the line can keep.
        Behind them, the older executions this poll reads for the pipeline's history
        (:meth:`_lacking`). Each once, newest first. One client for the region, not
        one per pipeline, and one page of executions for a pipeline, whatever is
        read out of it."""
        client = session.client("codepipeline", region_name=region)
        readings: list[PipelineReading] = []
        for name in self._list_pipeline_names(client):
            if self.codepipeline.ignored(name):
                continue
            executions = self._executions(client, name, region)
            if not executions:
                readings.append(PipelineReading(name=_kept(name), region=region))
                continue
            behind = self._behind(executions)
            # What the check kept is read where it decides something: an execution
            # its history may lack, or one in flight that may be on a retry.
            records = (self.kept(_subject(CODEPIPELINE, account.name, region,
                                          executions[0].name))
                       if self.series_keep > 0 and (behind or any(
                           _in_flight(execution.status) and execution.execution_id
                           for execution in executions))
                       else ())
            executions = self._retried(client, name, executions, records)
            line_at = _line_index([(execution.status, _ended_in(execution))
                                   for execution in executions])
            read = {0, line_at, *(at for at, execution in enumerate(executions)
                                  if _in_flight(execution.status))}
            read.update(self._lacking(executions, behind, line_at, records))
            readings.extend(executions[at] for at in sorted(read))
        return readings

    def _pipeline_entry(self, account: Account, pipeline: PipelineReading,
                        verdict: PipelineReading | None,
                        in_flight: Sequence[PipelineReading],
                        now: datetime) -> Entry:
        """A pipeline's line: what the execution whose verdict it keeps did and when
        that execution started, graded by `state_map` — and, where it succeeded, by
        how long ago that was — and beside it what is in flight (ADR-0014 §2).

        *verdict* is the newest execution whose verdict the line can keep — one that is
        not in flight, or one in flight again on a retry, which says the status it had
        ended in (ADR-0014 §5) — and none where no execution read is either: the line
        then says what is in flight alone. What is in flight
        leaves the line's verdict where that execution put it and can only make it
        worse — its status counts as `state_map` says, and so does an execution in
        flight for longer than `max_run_time` — and while there is any, the line is
        marked running: an italic, display only (little-sister ADR-0042 decision 6),
        so the words say it as well."""
        settings = self.codepipeline
        rule = settings.rule_for(pipeline.name)
        code = StatusCode.OK
        parts: list[str] = []
        if verdict is not None and not verdict.status:
            # A pipeline that has never been executed. Reporting nothing for it
            # would make a pipeline created and never triggered indistinguishable
            # from one that does not exist.
            code = StatusCode.WARN
            parts.append("never run")
        elif verdict is not None:
            # An execution on a retry is in flight, and what the line keeps of it is
            # the status it had ended in, as its action executions say.
            ended = _ended_in(verdict)
            code, phrase = self._verdict_of(
                replace(verdict, status=ended) if ended else verdict, rule, now)
            parts.append(phrase)
        for group in _by_status(in_flight):
            graded, phrase = self._in_flight_phrase(group, rule, now)
            code = _worst(code, graded)
            parts.append(phrase)
        label = plain(settings.short_name(pipeline.name))
        link = self._link(account, _pipeline_link(pipeline.region, pipeline.name))
        return Entry(
            # The region and the full name, as everywhere else: the slug is a
            # stored key, and neither a region's level coming or going nor a
            # cosmetic `shorten` rule may re-point a pin (ADR-0007 §5). The line
            # prints no region: it stands on the pipeline's own node, and the
            # level above says it where an account reads several (ADR-0007 §3).
            slug(pipeline.region, pipeline.name),
            f"[{label}]({link}): {' · '.join(parts)}",
            code, running=bool(in_flight))

    def _verdict_of(self, execution: PipelineReading, rule: Rule | None,
                    now: datetime) -> tuple[StatusCode, str]:
        """What a pipeline's line says of the execution whose verdict it keeps: its
        status and when it started, graded by `state_map` — and, where it
        succeeded, by how long ago that was."""
        settings = self.codepipeline
        age = self._elapsed(execution.started, now)
        code = settings.code_for(execution.status)
        # "started N ago" rather than "N ago": `startTime` is what was read, and of an
        # execution in flight it is the only honest thing to say.
        when = f", started {coarse_span(age)} ago" if age is not None else ""
        phrase = f"{plain(execution.status)}{when}"
        if code is StatusCode.OK and age is not None:
            # A success this old is not evidence the pipeline still works. Only a
            # success: a failure is already the finding, and telling somebody it is
            # also stale is noise on the line they act on.
            stale = settings.age_for(rule)
            aged = stale.code_for(age)
            if aged is not StatusCode.OK:
                code = aged
                phrase = (f"{plain(execution.status)}, but that run started "
                          f"{coarse_span(age)} ago")
                sentence = sentence_for(stale, rule)
                if sentence:
                    phrase += f" — {plain(sentence)}"
        return code, phrase

    def _in_flight_phrase(self, group: Sequence[PipelineReading],
                          rule: Rule | None,
                          now: datetime) -> tuple[StatusCode, str]:
        """What a pipeline's line says of its executions in flight in one status:
        the status and when the one started, or how many and when the oldest of them
        did — graded by what `state_map` says of the status, and once the oldest has
        been in flight for longer than `max_run_time`, by that as well (ADR-0014
        §3). Of executions on a retry it says when the retry began, which the bound
        counts from; of one whose retry could not be read, that, as a warning
        (ADR-0014 §5)."""
        settings = self.codepipeline
        first = group[0]
        status, retried = first.status, bool(_ended_in(first))
        code = settings.code_for(status)
        phrase = (plain(status) if len(group) == 1
                  else f"{len(group)} {plain(status)}")
        # Every execution the page holds has a start (`_executions`), so the oldest
        # has one; a retry has one once an action has started again, and an
        # execution said without one is said without when.
        age = self._elapsed(min((begun for begun in map(_begun, group)
                                 if begun is not None), default=None), now)
        limit = settings.run_time_for(rule)
        overrun = StatusCode.OK if age is None else limit.code_for(age)
        if age is not None and retried:
            phrase += (f", retried {coarse_span(age)} ago" if len(group) == 1
                       else f", retried, the oldest {coarse_span(age)} ago")
        elif age is not None:
            phrase += (f", started {coarse_span(age)} ago" if len(group) == 1
                       else f", the oldest started {coarse_span(age)} ago")
        elif retried:
            phrase += ", retried"
        if overrun is not StatusCode.OK:
            code = _worst(code, overrun)
            phrase += ", past max_run_time"
            sentence = sentence_for(limit, rule)
            if sentence:
                phrase += f" — {plain(sentence)}"
        if first.retry is not None and first.retry.error:
            # Asked because the history holds it ended failed or stopped, and not
            # answered: the failure it may be running again is not on the line, and
            # the line says why, at a warning, until the call is answered.
            code = _worst(code, StatusCode.WARN)
            phrase += f" · its retry could not be read: {plain(first.retry.error)}"
        return code, phrase

    def _measure_codepipeline(self, account: Account,
                              session: Session) -> list[Measurement]:
        """Every pipeline in this account's regions that no rule ignores — a rule's
        ``ignore`` spares the pipeline's execution list, so it is decided here
        (ADR-0005 §2) — a reading of its newest execution; of the one its line is
        written from and of every one in flight, where those are others (ADR-0014
        §2); and of each older execution the poll reads for its history (ADR-0009
        §5)."""
        settings = self.codepipeline
        readings: list[Measurement] = []
        for region in self.regions_for(account):
            try:
                pipelines = self._read_pipelines(session, account, region)
            except (BotoCoreError, ClientError) as error:
                readings.append(_unreadable(CODEPIPELINE, account, region, error))
                continue
            for pipeline in pipelines:
                self._note_rule(CODEPIPELINE, settings.rule_for(pipeline.name))
                readings.append(self._pipeline_reading(account, pipeline))
        return readings

    @staticmethod
    def _pipeline_reading(account: Account,
                          pipeline: PipelineReading) -> Measurement:
        """A pipeline's reading of one execution, of the object ADR-0005 §3 gives a
        history: the pipeline, in its account and its region.

        It names the execution by the id CodePipeline gives it, so an execution
        read in progress and again finished is one record rather than a row a poll
        repeats (ADR-0005 §5), and it names the state :data:`NEVER_RUN` where there
        is no execution to name. Its own time, `at`, is when that execution started
        — the instant the line reports of the newest, and each execution's place in
        the pipeline's series.

        `duration_s` is how long that execution took, from its start to the last
        change CodePipeline recorded of it: once the execution is over, and nothing
        while it is on its way, when its last change is no end (ADR-0008 §2, §3).
        """
        started = _iso(pipeline.started)
        identity, state = ((pipeline.execution_id, "") if pipeline.status
                           else ("", NEVER_RUN))
        over = pipeline.status.strip().lower() in _EXECUTION_ENDED
        return _reading(
            CODEPIPELINE, "pipeline", account.name, pipeline.region,
            {"name": pipeline.name, "execution": pipeline.execution_id or None,
             "status": pipeline.status or None, "started": started,
             "duration_s": (_seconds(pipeline.started, pipeline.updated)
                            if over else None),
             "at": started,
             # Only where its action executions were asked for: a record holds
             # what CodePipeline answered, and nothing it was not asked.
             **({} if pipeline.retry is None else {"retry": {
                 "failed": pipeline.retry.failed,
                 "abandoned": pipeline.retry.abandoned,
                 "started": _iso(pipeline.retry.started),
                 "error": pipeline.retry.error or None}})},
            subject=_subject(CODEPIPELINE, account.name, pipeline.region,
                             pipeline.name),
            identity=identity, state=state)

    def _grade_codepipeline(self, account: Account,
                            readings: Sequence[Measurement],
                            now: datetime) -> CheckResult:
        """The pipelines' node, from its readings: a node for every pipeline, which
        carries the pipeline's line — written from the execution whose verdict it
        keeps and carrying it, its staleness and what is in flight measured to *now*
        (ADR-0014 §2) — and says how every other execution the poll read stood, for
        the record (ADR-0009 §6).

        The pipelines hang beneath their region's node where the account reads
        several regions, and beneath this one where it reads one (ADR-0007 §3).
        What stays this node's own is how many pipelines are in scope and its
        roster — and, where its regions have no nodes of their own, a region that
        could not be read."""
        regions = self.regions_for(account)
        unreadable: dict[str, Measurement] = {}
        pipelines: dict[str, dict[str, list[Measurement]]] = {}
        for reading in readings:
            record = reading.record
            region = str(record["region"])
            if record["kind"] == "unreadable":
                unreadable[region] = reading
            elif record["kind"] == "pipeline":
                pipelines.setdefault(region, {}).setdefault(
                    str(record["name"]), []).append(reading)
        found = [(region, name) for region, members in pipelines.items()
                 for name in members]
        return self._subjects_node(
            account, CODEPIPELINE, "pipelines",
            f"CodePipeline pipelines in {account.name}",
            _scope_line("pipeline", len(found), regions),
            self._pipeline_roster(account, found, len(regions) > 1), unreadable,
            {region: tuple(self._pipeline_node(account, members[name], now)
                           for name in sorted(members))
             for region, members in pipelines.items()})

    def _pipeline_node(self, account: Account, executions: Sequence[Measurement],
                       now: datetime) -> CheckResult:
        """A pipeline's own node, named by what AWS calls the pipeline (ADR-0009
        §1). A display-name rule gives it its title and never reaches its path, as
        it never reaches a slug. It says that a run names it (little-sister
        ADR-0118): a pipeline its account calls ``batch`` is not the ``batch``
        aspect.

        Its one line is the pipeline's, written from the execution whose verdict it
        keeps and carrying it (ADR-0014 §2): the newest — the one that started last,
        whatever order the readings came in, and of two that started at one instant
        the one that was read first — unless it is in flight on no retry, and then
        the newest behind it whose verdict the line can keep, with what is in flight
        beside it. One in flight on a retry keeps the status it had ended in (§5).
        That reading names the pipeline as its subject, so the line does, which is
        what makes the node stand for the pipeline and its pages draw the pipeline's
        executions (little-sister ADR-0106 decision 2). No other execution has a
        line of its own: how each one this poll read stood is said for the record
        alone (ADR-0009 §6)."""
        # Stable, so of two that started at one instant the one read first leads.
        ordered = sorted(executions, key=_started, reverse=True)
        pipelines = [_pipeline_of(execution.record) for execution in ordered]
        at = _line_index([(pipeline.status, _ended_in(pipeline))
                          for pipeline in pipelines])
        carried, pipeline = ordered[at], pipelines[at]
        in_flight = [one for one in pipelines if _in_flight(one.status)]
        verdict = (None if _in_flight(pipeline.status) and not _ended_in(pipeline)
                   else pipeline)
        short = self.codepipeline.short_name(pipeline.name)
        said = (self._execution_entry(execution, now) for execution in executions
                if execution is not carried)
        return CheckResult(
            reason=[_carrying(self._pipeline_entry(account, pipeline, verdict,
                                                   in_flight, now), carried)],
            name=pipeline.name, title="" if short == pipeline.name else short,
            description=(f"CodePipeline pipeline in {account.name}, "
                         f"{pipeline.region}"),
            for_record=[entry for entry in said if entry is not None],
            dynamic=True)

    def _execution_entry(self, execution: Measurement,
                         now: datetime) -> Entry | None:
        """What the grading says of one execution its pipeline's line is not written
        from, for the record alone (ADR-0009 §6): the verdict its status has in
        `state_map`, as the line's has, in a sentence that is the status — and of one
        in flight for longer than `max_run_time`, the worse of that verdict and the
        overrun, in a sentence that says when it started (ADR-0014 §3). How old a
        success may get is asked of the line's own execution alone.

        Nothing of one a newer execution overtook: it neither failed nor deployed,
        so it gets no line, whatever the map says of `Superseded`, and its mark is
        the one that claims nothing (little-sister ADR-0111 decision 1). The line
        carries the execution's record and its subject, which is how the kept
        execution finds it (little-sister ADR-0111 decision 7); no node shows it,
        so its slug is no key."""
        record = execution.record
        status = str(record.get("status") or "")
        if not status or status.strip().lower() == _SUPERSEDED:
            return None
        settings = self.codepipeline
        code, said = settings.code_for(status), plain(status)
        reading = _pipeline_of(record)
        retried = bool(_ended_in(reading))
        # A retry is held to the bound from its own start (ADR-0014 §5).
        age = self._elapsed(_begun(reading), now)
        if _in_flight(status) and age is not None:
            limit = settings.run_time_for(settings.rule_for(str(record["name"])))
            overrun = limit.code_for(age)
            if overrun is not StatusCode.OK:
                code = _worst(code, overrun)
                said = (f"{plain(status)}, {'retried' if retried else 'started'} "
                        f"{coarse_span(age)} ago, past max_run_time")
        return Entry(slug(str(record["region"]), str(record["name"]),
                          str(record.get("execution") or "")),
                     said, code, subject=execution.subject, data=dict(record))

    def _pipeline_roster(self, account: Account,
                         found: Sequence[tuple[str, str]],
                         show_region: bool) -> str:
        """The pipelines in scope, each by its region and its name, as a list."""
        return "\n".join(
            f"- {f'{plain(region)} / ' if show_region else ''}"
            f"[{plain(name)}]({self._link(account, _pipeline_link(region, name))})"
            for region, name in sorted(found))

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
                    job_id=_identifier(str(row.get("jobId", ""))),
                    name=_kept(name),
                    status=_word(str(row.get("status", "")).upper()),
                    created=self._job_time(row.get("createdAt")),
                    started=self._job_time(row.get("startedAt")),
                    stopped=self._job_time(row.get("stoppedAt")),
                    reason=_kept(str(row.get("statusReason", "") or ""))))
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
            queue = JobQueue(name=_kept(name), region=region,
                             state=_word(str(row.get("state", ""))),
                             status=_word(str(row.get("status", ""))),
                             status_reason=_kept(
                                 str(row.get("statusReason", "") or "")))
            jobs: list[Job] = []
            capped = False
            for status in BATCH_STATUSES:
                found, cut = self._list_jobs(client, name, status)
                jobs.extend(found)
                capped = capped or cut
            readings.append(QueueReading(queue=queue, jobs=tuple(jobs),
                                         capped=capped))
        return readings

    def _queue_entry(self, account: Account, reading: QueueReading,
                     job_names: int) -> Entry | None:
        """A line about the *queue*, and only when the queue has something to
        say for itself.

        A healthy queue full of jobs is already described by the job names
        beneath it, and a line of its own would say nothing. What earns one: it
        takes no new work, AWS could not build it, it holds nothing at all, or the
        reading was capped. It stands on the queue's own node, so it prints no
        region (ADR-0007 §3).
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
        link = self._link(account, _queue_link(queue.region))
        return Entry(slug(queue.region, queue.name),
                     f"[{plain(queue.name)}]({link}): {' · '.join(notes)}",
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

    def _job_entry(self, account: Account, queue: JobQueue, name: str,
                   jobs: list[Job], now: datetime) -> Entry:
        """A job name's line, carrying every reading of the name at once.

        Splitting the finished and the running reading into two lines would make
        two pins for one thing an operator thinks of as one thing. They meet on
        one line, the way the lambda aspect's metric and log readings do — on the
        job name's own node, beneath its queue's, so the line prints neither the
        queue nor the region (ADR-0009 §3). Batch's seven statuses are three words
        here: finished, running — starting among it — and waiting, which is for
        capacity where every waiting job is ``RUNNABLE`` (``BATCH_STATUSES``). While
        a job of the name runs or waits, the line is marked ``running``.
        """
        settings = self.batch
        finished = [job for job in jobs if job.status in BATCH_FINISHED_STATUSES]
        running = [job for job in jobs if job.status in BATCH_RUNNING_STATUSES]
        waiting = [job for job in jobs if job.status in BATCH_WAITING_STATUSES]
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
            # Waiting is measured from submission, because a waiting job has never
            # started — that is the whole complaint. *For capacity* is said where it
            # is true of every job counted, and not of one held by another job.
            longest = self._longest(waiting, lambda job: job.created, now)
            for_how_long = f" ({coarse_span(longest)})" if longest is not None else ""
            why = (" for capacity"
                   if all(job.status == BATCH_CAPACITY_STATUS for job in waiting)
                   else "")
            parts.append(f"{len(waiting)} waiting{why}{for_how_long}")
            if longest is not None and longest > settings.max_wait_seconds:
                code = _worst(code, StatusCode.WARN)
        if not parts:
            # No run handed over is in a status this aspect knows — one Batch would
            # have to add, or a reading this check did not take — so the line has
            # nothing to count and says so.
            parts.append("no run finished, running or waiting")

        link_to = newest or self._newest_job(jobs)
        label = plain(settings.short_name(name))
        linked = (
            f"[{label}]"
            f"({self._link(account, _job_link(queue.region, link_to.job_id))})"
            if link_to is not None and link_to.job_id else label)
        return Entry(
            # Region, queue *and* name: the same job name may be submitted to two
            # queues, and those are two different things to put into maintenance —
            # and a slug keeps every part, whatever the levels above it say
            # (ADR-0007 §5).
            slug(queue.region, queue.name, name),
            f"{linked}: {' · '.join(parts)}",
            code,
            # Work in flight — a job submitted, waiting, starting or running — is
            # marked as such: an italic, display only, which leaves the code what
            # the newest finished run made it (little-sister ADR-0042 decision 6).
            # The words say it as well, which is the rule the italic rides on.
            running=bool(running or waiting))

    @staticmethod
    def _newest_job(jobs: list[Job]) -> Job | None:
        """The most recently submitted of these, or ``None``. Submission time,
        because it is the one timestamp every job has."""
        dated = [job for job in jobs if job.created is not None]
        if not dated:
            return jobs[0] if jobs else None
        return max(dated, key=lambda job: job.created
                   or datetime.min.replace(tzinfo=UTC))

    @staticmethod
    def _longest(jobs: list[Job], when: Callable[[Job], datetime | None],
                 now: datetime) -> int | None:
        """How long the oldest of these has been in its state. The oldest
        decides, so a queue that keeps starting fresh jobs cannot reset the
        clock on the one that is stuck."""
        ages = [max(0, int((now - stamp).total_seconds()))
                for stamp in (when(job) for job in jobs) if stamp is not None]
        return max(ages) if ages else None

    def _measure_batch(self, account: Account,
                       session: Session) -> list[Measurement]:
        """Every job queue no ``ignore_queue_patterns`` entry names — that list
        spares each queue's job listings, so it is decided here — then a reading
        per queue and one per run in it. Of a name ``ignore_name_patterns`` hides,
        none: listing a queue answers with its runs either way, and what the list
        spares is the keeping — a hidden name has no series (ADR-0009 §7)."""
        settings = self.batch
        readings: list[Measurement] = []
        for region in self.regions_for(account):
            try:
                queues = self._read_queues(session, region)
            except (BotoCoreError, ClientError) as error:
                readings.append(_unreadable(BATCH, account, region, error))
                continue
            for read in queues:
                queue = read.queue
                readings.append(_reading(
                    BATCH, "queue", account.name, region,
                    {"name": queue.name, "state": queue.state or None,
                     "status": queue.status or None,
                     "reason": queue.status_reason or None,
                     "capped": read.capped}))
                readings.extend(self._run_reading(account, queue, job)
                                for job in read.jobs
                                if not settings.ignored(job.name))
        return readings

    @staticmethod
    def _run_reading(account: Account, queue: JobQueue, job: Job) -> Measurement:
        """One run of a job, of the object ADR-0005 §3 gives a history: the job's
        name in its queue, in its account and its region.

        It names the run by the ``jobId`` Batch gives it, so a run seen waiting,
        then running, then finished is one record that ends in its final state, and
        several runs of one name in one poll are several records (ADR-0005 §5).
        Its own time, `at`, is when it finished — nothing while it has not.

        `wait_s` is how long it waited, from when it was created to when it
        started, and `duration_s` how long it ran, from then to when it stopped:
        each once both its instants are known, and neither counted to this poll's
        clock (ADR-0008 §1, §3).
        """
        return _reading(
            BATCH, "job", account.name, queue.region,
            {"queue": queue.name, "name": job.name, "id": job.job_id or None,
             "status": job.status, "reason": job.reason or None,
             "created": {"at": _iso(job.created)}, "started": _iso(job.started),
             "ended": _iso(job.stopped),
             "wait_s": _seconds(job.created, job.started),
             "duration_s": _seconds(job.started, job.stopped),
             "at": _iso(job.stopped)},
            subject=_subject(BATCH, account.name, queue.region, queue.name,
                             job.name),
            identity=job.job_id)

    def _grade_batch(self, account: Account, readings: Sequence[Measurement],
                     now: datetime) -> CheckResult:
        """The job queues' node, from its readings: a node for every queue, which
        says what the queue has to say of itself, and beneath it a node for every
        job name in it, which carries the name's line and says how each run the
        poll read stood, for the record (ADR-0009).

        The queues hang beneath their region's node where the account reads several
        regions, and beneath this one where it reads one (ADR-0007 §3). What stays
        this node's own is how many queues are in scope and its roster — and, where
        its regions have no nodes of their own, a region that could not be read.

        A run of a name ``ignore_name_patterns`` hides is said nothing of, and its
        name has no node: the measuring half leaves such a run out (§7), and one
        that was read before the list named it is left out here."""
        settings = self.batch
        regions = self.regions_for(account)
        unreadable: dict[str, Measurement] = {}
        queues: dict[str, list[tuple[QueueReading, Measurement]]] = {}
        runs: dict[tuple[str, str], dict[str, list[tuple[Job, Measurement]]]] = {}
        for reading in readings:
            record = reading.record
            region = str(record["region"])
            if record["kind"] == "unreadable":
                unreadable[region] = reading
            elif record["kind"] == "queue":
                queues.setdefault(region, []).append((_queue_of(record), reading))
            elif (record["kind"] == "job"
                  and not settings.ignored(str(record["name"]))):
                runs.setdefault((region, str(record["queue"])), {}).setdefault(
                    str(record["name"]), []).append((_job_of(record), reading))
        several = len(regions) > 1
        roster: list[str] = []
        nodes: dict[str, tuple[CheckResult, ...]] = {}
        for region, members in queues.items():
            members.sort(key=lambda member: member[0].queue.name)
            nodes[region] = tuple(
                self._queue_node(account, read, reading,
                                 runs.get((region, read.queue.name), {}), now)
                for read, reading in members)
            for read, _ in members:
                names = len(runs.get((region, read.queue.name), {}))
                said = "no job names" if not names else (
                    f"{names} job name{'' if names == 1 else 's'}")
                link = self._link(account, _queue_link(region))
                roster.append(f"- {f'{plain(region)} / ' if several else ''}"
                              f"[{plain(read.queue.name)}]({link}) — {said}")
        found = sum(len(members) for members in queues.values())
        return self._subjects_node(
            account, BATCH, "job queues", f"Batch job queues in {account.name}",
            _scope_line("job queue", found, regions), "\n".join(sorted(roster)),
            unreadable, nodes)

    def _queue_node(self, account: Account, read: QueueReading,
                    reading: Measurement,
                    names: Mapping[str, Sequence[tuple[Job, Measurement]]],
                    now: datetime) -> CheckResult:
        """A job queue's own node, named by what AWS calls the queue: a level in
        every Batch path, since a queue is nothing a configuration names (ADR-0009
        §2). It says that a run names it (little-sister ADR-0118).

        Its one line is what the queue has to say of itself, written from the
        queue's reading and carrying it; a queue with nothing to say grades
        nothing. Its job names stand beneath it, in name order, and it says that
        they are complete in every run that lists it — read at its cap as well,
        where a name whose runs are no longer among those read would otherwise
        stand stale and warn every node above it. Such a statement need not be
        exact: the name returns with its next run, and with everything that was
        kept of it (little-sister ADR-0109 decision 3). It declines the density
        trade as a region's node does: it is the box its job names stand in
        (little-sister ADR-0063)."""
        queue = read.queue
        line = self._queue_entry(account, read, len(names))
        return CheckResult(
            StatusCode.OK if line is None else None,
            [] if line is None else [_carrying(line, reading)],
            name=queue.name,
            description=f"Batch job queue in {account.name}, {queue.region}",
            children=tuple(self._job_node(account, queue, name, names[name], now)
                           for name in sorted(names)),
            children_complete=True, show_when_quiet=True, dynamic=True)

    def _job_node(self, account: Account, queue: JobQueue, name: str,
                  runs: Sequence[tuple[Job, Measurement]],
                  now: datetime) -> CheckResult:
        """A job name's own node, beneath its queue's and named by what AWS calls
        the job (ADR-0009 §1). A display-name rule gives it its title and never
        reaches its path, as it never reaches a slug. It says that a run names it
        (little-sister ADR-0118).

        Its one line is the job name's, written from every run of the name, so it
        carries none of them — and names, as its subject, the one object they all
        are (ADR-0005 §7), which is what makes the node stand for the job name and
        its pages draw the name's runs (little-sister ADR-0106 decision 2). No run
        has a line of its own: how each run this poll read stood is said for the
        record alone (§4)."""
        line = replace(
            self._job_entry(account, queue, name, [job for job, _ in runs], now),
            subject=runs[0][1].subject)
        short = self.batch.short_name(name)
        said = (self._job_run_entry(run, now) for _, run in runs)
        return CheckResult(
            reason=[line], name=name, title="" if short == name else short,
            description=f"Batch job name in {account.name}, {queue.region}",
            for_record=[entry for entry in said if entry is not None],
            dynamic=True)

    def _job_run_entry(self, run: Measurement, now: datetime) -> Entry | None:
        """What the grading says of one run of a job name, for the record alone
        (ADR-0009 §4): ``OK`` for one that succeeded and ``ERROR`` for one that
        failed, in a sentence that says how long it waited and how long it ran;
        and for one that still runs or waits, ``OK`` until it is past
        ``max_run_time`` or ``max_wait_time`` and ``WARN`` from then on, in a
        sentence that says for how long — the bounds its job name's line is graded
        by, held against this run alone. One that is starting has no start to count
        from, and is said as it is. A run in a status this aspect does not know is
        said nothing of.

        A span is counted from the record's instants and an age to *now*, as the
        line counts them; the record's own two numbers are not read (ADR-0008). A
        run read again is said of again, so one that warned while it ran takes its
        last verdict from the poll that reads it finished. The line carries the
        run's record and its subject, which is how the kept run finds it
        (little-sister ADR-0111 decision 7); no node shows it, so its slug is no
        key."""
        settings = self.batch
        record = run.record
        job = _job_of(record)
        if job.status in BATCH_FINISHED_STATUSES:
            code = (StatusCode.OK if job.status == "SUCCEEDED"
                    else StatusCode.ERROR)
            said = plain(job.status)
            waited = _seconds(job.created, job.started)
            if waited is not None:
                said += f", waited {coarse_span(waited)}"
            ran = _seconds(job.started, job.stopped)
            if ran is not None:
                said += f", ran {coarse_span(ran)}"
        elif job.status in BATCH_RUNNING_STATUSES:
            # A job that is starting has no start yet, so nothing to hold against
            # the bound: it is said as it is, OK, as the line counts it.
            code, said = self._in_flight(job.status, job.started, now,
                                         settings.max_run_seconds, "max_run_time")
        elif job.status in BATCH_WAITING_STATUSES:
            # Waiting is measured from submission, as the line measures it.
            code, said = self._in_flight(job.status, job.created, now,
                                         settings.max_wait_seconds,
                                         "max_wait_time")
        else:
            return None
        return Entry(slug(str(record["region"]), str(record["queue"]), job.name,
                          job.job_id),
                     said, code, subject=run.subject, data=dict(record))

    def _in_flight(self, status: str, since: datetime | None, now: datetime,
                   bound: int, key: str) -> tuple[StatusCode, str]:
        """The verdict and the sentence of a run that still runs or waits: for how
        long, and that it is past *key* where that is more than *bound* seconds —
        the comparison its job name's line makes. With no instant to count from
        there is nothing to hold against the bound."""
        age = self._elapsed(since, now)
        if age is None:
            return StatusCode.OK, plain(status)
        if age > bound:
            return (StatusCode.WARN,
                    f"{plain(status)} for {coarse_span(age)}, past {key}")
        return StatusCode.OK, f"{plain(status)} for {coarse_span(age)}"

    # --- the tree ---------------------------------------------------------

    def _credentials_for(self, account: Account) -> str:
        """Which credentials *this* account was read with, for a log line.

        Not :meth:`_credentials_summary`, which answers the same question for the
        card: that one is check-wide, and its text is escaped for Markdown
        because a card renders it. A log line wants one account's answer, and
        wants it greppable.
        """
        profile = self.profile_for(account)
        if profile:
            return f"profile {profile}"
        if self.access_key:
            return "configured keys"
        return f"the ambient credential chain{self._ambient_note()}"

    def _log_unreadable(self, base: Session, account: Account,
                        failure: list[str]) -> None:
        """Say, in the log, that this account could not be looked at.

        **A check that ran and graded badly is reporting; a check that could not
        look is a different event**, and until this it made no sound at all — the
        engine's own line says the check completed, because it did, and the
        refusal lived only on a card somebody had to go and open.

        The line carries the three facts that identify the problem together, and
        are useless apart: what was attempted, **who we actually were**, and what
        AWS said. The middle one is the one no configuration can supply and the
        one a refusal does not always contain — see
        :func:`~little_sister_aws.identity.caller_identity`, which is why this
        spends a call here and nowhere else.
        """
        target = (f"assuming {account.role_arn}" if account.role_arn
                  else f"reading account {account.name!r} directly")
        proven = caller_identity(base, sts_region=self.sts_region)
        as_whom = f" as {proven}" if proven else ""
        logger.error("%s: account %r could not be read — %s with %s%s failed: %s",
                     self.path, account.name, target,
                     self._credentials_for(account), as_whom, " ".join(failure))

    def _estate(self, *, credentials: str | None = None,
                outcomes: Sequence[tuple[str, str]] = ()) -> Measurement:
        """The run's own reading, about the object this check declares
        (ADR-0005 §6): whether the credentials opened — and what AWS answered
        where they did not — and, in configuration order, what became of each
        account. It names the state those outcomes spell (:func:`_estate_state`),
        or :data:`CREDENTIALS_UNUSABLE` where no account was tried, and never the
        text, which the record keeps."""
        state = (CREDENTIALS_UNUSABLE if credentials is not None
                 else _estate_state(outcomes))
        return _reading(None, "estate", None, None,
                        {"credentials": credentials,
                         "accounts": [{"name": name, "outcome": outcome}
                                      for name, outcome in outcomes]},
                        subject=self.subject, state=state)

    def _grade_account(self, account: Account, record: Mapping[str, Any],
                       placed: Mapping[tuple[str, str], Sequence[Measurement]],
                       now: datetime) -> CheckResult:
        """One account's node, where a check names several (ADR-0007 §1), from its
        own reading and its aspects' readings: red with what refused it, or a
        container of the aspects this configuration runs, each built from this
        account's readings of it. It is named by the configuration, which it says
        (little-sister ADR-0118): an account called ``ec2`` shows its own `title`
        and `about`, and the ``ec2`` aspect beneath it the aspect's."""
        outcome = str(record["outcome"])
        if outcome != READ:
            # This account's problem, and this account's node. The others keep
            # reporting, which is the whole reason the tree branches here.
            return CheckResult(
                StatusCode.ERROR, self._refused(account, record),
                name=account.name, title=account.title, about=account.about,
                config=self._account_config(account), dynamic=True)
        return CheckResult(StatusCode.OK, [], name=account.name,
                           children=self._grade_aspects(account, placed, now),
                           title=account.title, about=account.about,
                           config=self._account_config(account), dynamic=True)

    def _grade_alone(self, account: Account, record: Mapping[str, Any] | None,
                     placed: Mapping[tuple[str, str], Sequence[Measurement]],
                     now: datetime) -> CheckResult:
        """The check's own node where the check names one account (ADR-0007 §2).

        The account has no node there: its level would say one word in every path
        and nothing the check's own node does not. So its aspects hang here, and
        what refused the account — the reason, and the command that renews an
        expired login — is said here, on a node that is then ``ERROR``; a pin on
        this node is the pin on the account. Read, the root grades nothing, as it
        grades nothing above several accounts' nodes."""
        if record is not None and str(record["outcome"]) != READ:
            return CheckResult(StatusCode.ERROR, self._refused(account, record),
                               report=self._scope_report())
        children = (() if record is None
                    else self._grade_aspects(account, placed, now))
        return CheckResult(StatusCode.UNDEFINED, [self._scope_reason()],
                           children=children, report=self._scope_report())

    def _grade_aspects(self, account: Account,
                       placed: Mapping[tuple[str, str], Sequence[Measurement]],
                       now: datetime) -> tuple[CheckResult, ...]:
        """The aspects this configuration runs, each built from one account's
        readings of it: the children of that account's node, or of the check's own
        where the check names one account."""
        graders: dict[str, Callable[[Account, Sequence[Measurement], datetime],
                                    CheckResult]] = {
            CLOUDWATCH: self._grade_cloudwatch, EC2: self._grade_ec2,
            LAMBDA: self._grade_lambda, CODEPIPELINE: self._grade_codepipeline,
            BATCH: self._grade_batch}
        return tuple(graders[name](account,
                                   placed.get((account.name, name), ()), now)
                     for name in self.active_aspects())

    def _refused(self, account: Account, record: Mapping[str, Any]) -> list[str]:
        """What an account that could not be opened says, from its own reading."""
        return self._refusal_lines(account, _Refusal(
            str(record["outcome"]), str(record.get("error") or ""),
            str(record.get("renewal") or "")))

    def _open(self, base: Session, account: Account) -> Session | _Refusal:
        """Open *account*'s session, renewing an expired login once if it can.

        Returns the session, or why there is none — which the account's reading
        keeps and its node says. The retry is the point of the whole exercise: an
        SSO login expires roughly once a working day, and on the machine where that
        happens the fix is a command this process can run — so it runs it, once,
        and asks AWS again rather than reddening three accounts until somebody
        notices the dashboard.
        """
        try:
            return self._opened(base, account)
        except (BotoCoreError, ClientError) as error:
            if not is_credential_error(error):
                return _Refusal(UNREACHABLE, _kept(str(error)))
            problem = self._renew(account)
            if problem:
                return _Refusal(EXPIRED, _kept(str(error)), _kept(problem))
            try:
                # A *new* base session: the one above cached the credentials
                # that just expired, and the login wrote a fresh token beside it.
                return self._opened(self._base_session(), account)
            except (BotoCoreError, ClientError) as again:
                return _Refusal(EXPIRED, _kept(str(again)), RENEWED_STILL_REFUSED)

    def _refusal_lines(self, account: Account, refusal: _Refusal) -> list[str]:
        """What an account that could not be opened says: one line where AWS said
        no, two where its login had expired. Written from the refusal and the
        configuration alone, so the node the grading builds and the log line the
        measuring half writes say the same thing."""
        if refusal.outcome == EXPIRED:
            return self._expired(account, refusal.error, refusal.renewal)
        return [self._unreachable(account, refusal.error)]

    def _unreachable(self, account: Account, error: str) -> str:
        """AWS said no, and it was not about the credentials being stale."""
        if account.role_arn:
            return f"role cannot be assumed: {plain(error)}"
        return f"account cannot be read: {plain(error)}"

    def _expired(self, account: Account, error: str,
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

    @staticmethod
    def _pair_summary(threshold: Threshold,
                      render: Callable[[int], str]) -> str | None:
        """One judgment on the card: its levels, and the sentence it says.

        The sentence belongs *with* the levels rather than on a line of its own:
        two entries would read as two settings, and an entry saying what is said
        about an instance that is too old, with no threshold above it, would be a
        sentence nobody can trigger.
        """
        levels = threshold.summary(render)
        if levels is None:
            return None
        return (f"{levels} — {plain(threshold.reason)}" if threshold.reason
                else levels)

    @staticmethod
    def _rules_summary(rules: tuple[Rule, ...],
                       effect: Callable[[Rule], str]) -> str | None:
        """One aspect's rules, as a nested list under one label.

        In the order they are consulted, which is the order they decide in: a card
        that listed them any other way would be describing a different config. And
        each shown **effective** rather than as written — a rule that names one
        level inherits the rest, and what a reader needs from this card is what the
        check will actually do to those names.
        """
        if not rules:
            return None
        lines = [f"  - **{plain(rule.name)}** — {effect(rule)}" for rule in rules]
        return "checked in order, first match wins\n" + "\n".join(lines)

    def _lambda_rule_effect(self, rule: Rule) -> str:
        if rule.ignore:
            return "neither listed nor counted"
        settings = self.lambda_
        parts = [f"errors graded within "
                 f"{format_span(settings.gate_for(rule))}, held for "
                 f"{format_span(settings.hold_for(rule))}"]
        if not settings.expects_invocations(rule):
            parts.append("silence is fine")
        if not settings.reads_log(rule):
            parts.append("log status not read")
        return ", ".join(parts)

    def _pipeline_rule_effect(self, rule: Rule) -> str:
        if rule.ignore:
            return "neither listed nor counted"
        settings = self.codepipeline
        # Each judgment is labeled, as an EC2 rule's two are: two warning levels on
        # one line would read as one judgment with two of them.
        parts = [f"{label} {summary}"
                 for label, summary in (
                     ("success stales after",
                      settings.age_for(rule).summary(format_span)),
                     ("an execution overruns after",
                      settings.run_time_for(rule).summary(format_span)))
                 if summary]
        return "; ".join(parts) or "not graded"

    def _ec2_rule_effect(self, rule: Rule) -> str:
        if rule.ignore:
            return "neither listed nor counted"
        count, aged = self.ec2.thresholds_for(rule)
        # Each half is labeled: "warn above 15, warn above 2h" would read as one
        # judgment with two warning levels, which is not a thing.
        # Levels only, no sentences: a rule's sentence is shown where it is
        # useful — on the line it colors — and six rules quoting two sentences
        # each would bury the numbers this card exists to show.
        parts = [f"{label} {summary}"
                 for label, summary in (("per name:", count.summary(str)),
                                        ("age:", aged.summary(format_span)))
                 if summary]
        return "; ".join(parts) or "not graded"

    def _note_rule(self, aspect: str, rule: Rule | None) -> None:
        """Remember that this rule matched something in this run."""
        if rule is not None:
            self._matched_rules.setdefault(aspect, set()).add(rule.name)

    def _rule_lists(self) -> tuple[tuple[str, tuple[Rule, ...]], ...]:
        """The aspects that take rules, with theirs."""
        return ((EC2, self.ec2.rules), (CODEPIPELINE, self.codepipeline.rules),
                (LAMBDA, self.lambda_.rules))

    def _report_unmatched_rules(self) -> None:
        """Say, once per aspect, which rules matched no name in this whole run.

        **Only when the set changes**, this run's first included: at
        `frequency: 60s` an unconditional line is fourteen hundred identical
        records a day about a typo that was true at breakfast, where a line on
        change turns a lasting mistake into one record and its fix into one more.
        The set is the run's, not an account's — a rule may legitimately match in
        one account and not in another.
        """
        for aspect, rules in self._rule_lists():
            if not rules:
                continue
            matched = self._matched_rules.get(aspect, set())
            unmatched = frozenset(rule.name for rule in rules
                                  if rule.name not in matched)
            if unmatched == self._unmatched_rules.get(aspect):
                continue
            if unmatched:
                logger.info("%s: %d %s rule(s) matched no name: %s", self.path,
                            len(unmatched), aspect, ", ".join(sorted(unmatched)))
            elif self._unmatched_rules.get(aspect):
                logger.info("%s: every %s rule now matches a name",
                            self.path, aspect)
            self._unmatched_rules[aspect] = unmatched

    def _account_config(self, account: Account) -> str:
        return config_markdown({
            "regions": ", ".join(plain(region)
                                 for region in self.regions_for(account)),
            "credentials": self._account_credentials(account),
            "console links": self._links_summary(account),
        })

    def _account_credentials(self, account: Account) -> str:
        """Where this account's credentials come from, in one line.

        Both halves, where there are two: a profile that assumes a role is the
        normal cross-account shape, and reading only one of them off the card
        would send somebody to fix the wrong end of it.
        """
        profile = self.profile_for(account)
        if account.role_arn:
            if profile:
                return f"assumed role, from profile {plain(profile)}"
            if self.access_key:
                return "assumed role, from configured keys"
            return f"assumed role, from the ambient chain{self._ambient_note()}"
        if profile:
            return f"profile {plain(profile)}"
        if self.access_key:
            return "configured keys"
        return f"ambient credential chain{self._ambient_note()}"

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

    def measure(self) -> list[Measurement]:
        """Read every account: the estate first, then each account's own reading,
        then each aspect's readings in the order it read them (ADR-0005 §1).

        The credentials are opened once; where they cannot be, the estate is the
        only reading, and no account is tried. An account that cannot be opened is
        a reading of its own — and, because a check that could not look is a
        different event from one that looked and graded badly, a line in the log
        naming who we actually were (:meth:`_log_unreadable`). What the log says
        about the run as a whole — the accounts in scope, how many could not be
        read, the rules that matched nothing — is said here too: it is this
        process talking about this run, and the grading may keep no state.
        """
        try:
            base = self._base_session()
        except (BotoCoreError, ClientError) as error:
            # Nothing can be read at all — the whole branch goes red rather than
            # every account inventing the same excuse.
            return [self._estate(credentials=_kept(str(error)))]
        self._matched_rules = {}
        measurers: dict[str, Callable[[Account, Session], list[Measurement]]] = {
            CLOUDWATCH: self._measure_cloudwatch, EC2: self._measure_ec2,
            LAMBDA: self._measure_lambda, CODEPIPELINE: self._measure_codepipeline,
            BATCH: self._measure_batch}
        outcomes: list[tuple[str, str]] = []
        accounts: list[Measurement] = []
        readings: list[Measurement] = []
        for account in self.accounts:
            opened = self._open(base, account)
            if isinstance(opened, _Refusal):
                self._log_unreadable(base, account,
                                     self._refusal_lines(account, opened))
                outcomes.append((account.name, opened.outcome))
                accounts.append(_reading(None, "account", account.name, None,
                                         {"outcome": opened.outcome,
                                          "error": opened.error,
                                          "renewal": opened.renewal or None}))
                continue
            outcomes.append((account.name, READ))
            accounts.append(_reading(None, "account", account.name, None,
                                     {"outcome": READ, "error": None,
                                      "renewal": None}))
            # A switched-off aspect emits no node **and makes no API call** — which
            # is the half that matters to a role whose policy does not carry that
            # service's permissions at all.
            for name in self.active_aspects():
                readings.extend(measurers[name](account, opened))
        # An account that could not be looked at at all — not one whose aspects
        # graded badly, which is an ordinary reading and says so on its own node.
        # `2 of 2` is the shape of a credential problem and `1 of 3` the shape of
        # one account's policy, so the count is itself a diagnosis — which is why
        # the estate's state is spelled from it (ADR-0005 §6).
        unreadable = [name for name, outcome in outcomes if outcome != READ]
        # "in scope", not "read": this line is the roster, and directly under a
        # run where every account was refused, "read 2 account(s)" was a claim
        # the very next line contradicted.
        logger.info("%s: %d account(s) in scope: %s", self.path, len(outcomes),
                    ", ".join(account.name for account in self.accounts))
        if unreadable:
            logger.error("%s: %d of %d account(s) could not be read: %s",
                         self.path, len(unreadable), len(outcomes),
                         ", ".join(unreadable))
        self._report_unmatched_rules()
        return [self._estate(outcomes=outcomes), *accounts, *readings]

    def grade(self, measurements: Sequence[Measurement],
              now: datetime) -> CheckResult:
        """The check's tree, from the readings alone (little-sister ADR-0086
        decision 6): the estate says whether the credentials opened, each
        account's reading whether that account did, and each aspect's readings
        become that account's child — or the check's own, where the check names
        one account and the account has no node (ADR-0007). *now* is what every age
        on a line is measured to.
        """
        estate: Mapping[str, Any] | None = None
        accounts: dict[str, Mapping[str, Any]] = {}
        placed: dict[tuple[str, str], list[Measurement]] = {}
        for measurement in measurements:
            record = measurement.record
            kind = record.get("kind")
            if kind == "estate":
                estate = record
            elif kind == "account":
                accounts[str(record["account"])] = record
            elif record.get("aspect") in self.ASPECTS:
                placed.setdefault((str(record["account"]), str(record["aspect"])),
                                  []).append(measurement)
        if estate is None:
            # Only a failure record written by the engine has no estate reading,
            # and the engine grades that run itself; this is the guard for a caller
            # that hands over something no measurement of ours produced.
            return CheckResult(StatusCode.ERROR,
                               ["no estate reading to grade — nothing was read"],
                               report=self._scope_report())
        if estate.get("credentials") is not None:
            return CheckResult(
                StatusCode.ERROR,
                [f"no usable AWS credentials: {plain(str(estate['credentials']))}"],
                report=self._scope_report())
        if len(self.accounts) == 1:
            # What is counted is the configuration — the accounts this check names —
            # and never what AWS answered (ADR-0007 §1).
            alone = self.accounts[0]
            return self._grade_alone(alone, accounts.get(alone.name), placed, now)
        children = tuple(self._grade_account(account, accounts[account.name],
                                             placed, now)
                         for account in self.accounts if account.name in accounts)
        # The root grades nothing. It says only what is watched: an account that
        # failed is red on its own node and reaches this container by roll-up, so
        # repeating it here would report one fact twice. So it declares
        # `UNDEFINED` — a container that happens to carry a sentence — and what
        # stood on it for the estate's reading is what the run rolls up to
        # (little-sister ADR-0087 decision 8, ADR-0005 §6).
        return CheckResult(StatusCode.UNDEFINED, [self._scope_reason()],
                           children=children, report=self._scope_report())
