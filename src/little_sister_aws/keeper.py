"""The S3 keeper: what carries a little-sister instance's ``var/state/`` into a
bucket, so the state survives the machine.

little-sister keeps what a restart needs as files under ``var/state/`` — the
maintenance pins, the event log, and whatever joins them — and takes a **keeper**
to carry that directory somewhere durable: ``load(name)``, ``save(name, data)``,
``list()``, in bytes, restored before anything reads and mirrored back after the
writer (little-sister ADR-0071 §5), plus the two calls a keeper may answer,
``tick(interval_seconds)`` every interval and ``close()`` at a graceful end. This
module is the first one. With it, an instance redeployed onto a fresh machine —
one terminated without a stop, too — comes up as the instance that stopped on the
old one; without it, every pin is lost with the disk.

**Nothing here registers on import**, like the secret provider beside it
(ADR-0002): a deployment calls :func:`register_s3_keeper` in its own
import-before-app slot, because where an installation's state is kept is a
decision, and a decision should be readable at the place it is taken.

That call has **two routes**, and the file is only one of them. With no argument
it reads ``config/aws-keeper.yaml``; with ``config=`` it takes a
:class:`KeeperConfig` the deployment built itself and reads no file. The second is
the only route for an installation whose bucket name is not a constant — one that
carries the account id, say, where one image is deployed to several accounts — and
the two are the same keeper: :class:`KeeperConfig` normalizes its own ``prefix``,
so a config built by hand keeps its keys where the file's would.

The shape is ADR-0004's, and four things decide it.

* **One lease per prefix.** One object under the prefix, :data:`OWNER_NAME`, says
  who may write here. The holder re-writes it every interval — the heartbeat —
  and writes the state files behind it; anybody else reads it every interval and
  writes nothing. The lease is *taken* with S3's own compare-and-swap, which is
  the only place a precondition is needed: with one holder there is one writer.
* **Liveness is measured inside one S3 answer.** ``Date`` of the answer minus
  ``LastModified`` of the object it carried, against the ``ttl_seconds`` the
  holder wrote into it. Every term is S3's; no machine's clock enters.
* **Standby, never a latch.** An instance that does not hold the lease restores
  at startup — reading needs no lease — monitors normally, keeps its state on its
  own disk, and takes the lease the moment it is free. A holder whose heartbeat is
  refused demotes itself before it writes anything. Nothing here needs a restart.
* **The client is bounded in seconds** (:data:`CLIENT_CONFIG`), because both the
  save and the tick run on little-sister's scheduler tick, and there is a call on
  *every* tick now.

What this deliberately does **not** do is merge two writers' state, or keep a
history of it: the prefix is a mirror of a memory that is bounded, and a mirror
has one useful version. **Authority follows the lease** (little-sister ADR-0077):
whoever held it wrote the truth up to the moment it lapsed, so an instance that
takes it over adopts what the store changed while it stood by — this keeper
remembers the ETag of every file it loaded or saved and answers the seam's
``changed_since_sync()`` from one listing, and the library does the rest. Beside
the lease live three more objects nothing restores: a **presence file** per
standby, so the holder can say who is standing by; the **instance log**, a
bounded record of who held the prefix when; and nothing else. Two clocks meet on
these pages — the store's and the host's — and the offset between them is measured
on every answer, so a store stamp is shown in host time where it stands beside a
local one, and a drifting clock is a line.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import quote

import yaml
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from little_sister.checks import plain
from little_sister.config_dir import register_aspect, sole_aspect_file
from little_sister.instance import this_instance
from little_sister.keeper import register_keeper
from little_sister.reasons import Entry
from little_sister.self_report import register_action, register_contributor
from little_sister.spans import format_duration, format_span, local_time
from little_sister.status import StatusCode

from little_sister_aws import identities as aws_identities
from little_sister_aws.identities import NamedIdentity, load_identities
from little_sister_aws.identity import (
    Identity,
    OptionalTextError,
    is_credential_error,
    open_session,
    parse_optional_text,
)

if TYPE_CHECKING:
    # Per-service boto3 stubs are development dependencies, not runtime imports.
    from mypy_boto3_s3.client import S3Client

logger = logging.getLogger(__name__)

#: What one call against the client answers with. A type variable rather than
#: ``Any`` so the seam methods keep their own return types through the one retry
#: wrapper below (P9: narrow where the bag enters, not at the last helper).
_Answer = TypeVar("_Answer")

#: The configuration aspect this module adds: ``config/aws-keeper.yaml``.
#:
#: Its own file, rather than a block in the ``aws`` aspect beside it, because that
#: file is a flat mapping of **identity names** — a reserved top-level key there
#: would make ``keeper`` an identity nobody may declare, which is a stored key
#: changing shape (PL10) to save one file. And ``aws-keeper`` rather than
#: ``keeper``, because the next keeper somebody writes will not be this one and an
#: aspect name is claimed once.
ASPECT = "aws-keeper"

#: The one object under the prefix that is **not** state: the lease. Filtered out
#: of :meth:`S3Keeper.list` so it never reaches little-sister as a state file. The
#: name is a stored key — buckets written by this package's first shape carry it —
#: and the leading dot is only convention; the filter is what keeps it out.
OWNER_NAME = ".little-sister-owner.json"

#: Every object under the prefix that is **this module's and not state** starts
#: with this: the lease, the presence files, the instance log. Dropped from the
#: listing the library restores from and from what a takeover adopts, in one
#: rule rather than one per name — a state file never starts with it, and a new
#: object of this module's needs no new filter.
RESERVED_PREFIX = ".little-sister-"

#: A standby's presence file: ``.little-sister-standby-<key>.json``, where the key
#: is the instance's mark made safe for an object key (:func:`_presence_key`), and
#: the body carries the mark itself and since when the instance stands by. Written
#: by the standby every interval — its heartbeat — and read by the holder, so the
#: holder's child can say who is standing by (ADR-0004 decision 13).
PRESENCE_PREFIX = f"{RESERVED_PREFIX}standby-"
PRESENCE_SUFFIX = ".json"

#: The instance log: who held the prefix over which interval and how it ended,
#: and who stood by from when to when — one entry per transition, newest first,
#: bounded (ADR-0004 decision 15). Kept beside the lease and never restored.
INSTANCES_NAME = f"{RESERVED_PREFIX}instances.json"

#: How many entries the instance log keeps. A hundred transitions is months of
#: rollouts for any deployment this package knows of, and the object stays a few
#: tens of kilobytes.
INSTANCE_LOG_SIZE = 100

#: Past this many seconds between the host's clock and the store's, the offset
#: is a line (ADR-0004 decision 14). Seconds rather than minutes, since S3 refuses
#: a request more than fifteen minutes adrift and that already shows as a lost
#: lease; and not less, because the ``Date`` header is whole seconds and the
#: measurement carries half a round trip. The line clears only once the offset
#: is back under :data:`SKEW_CLEAR_SECONDS`, so a host wobbling around the
#: threshold does not flap it every interval.
SKEW_THRESHOLD_SECONDS = 5.0
SKEW_CLEAR_SECONDS = 3.0

#: How long the takeover line stays WARN after a takeover that adopted something
#: (decision 4). One interval would be a blink; the point of the line is that
#: somebody learns the ``.bak`` files exist, and ten minutes of WARN costs nothing.
TAKEOVER_WARN_SECONDS = 600.0

#: How many previous claims the lease carries beside the current one. Small on
#: purpose: it is there so a human can tell *this prefix has changed hands four
#: times lately* from *once, a long time ago*, and a longer list answers no
#: further question while every heartbeat carries it.
CLAIM_HISTORY = 4

#: The name this keeper claims in little-sister's registry — one keeper per
#: instance, and this is which one, on ``/system/installed`` and in the lines
#: the heartbeat carries when it fails.
KEEPER_NAME = "s3"

#: How many heartbeats may be missed before a lease is dead — the default for
#: ``lapse_after``. Three is a failover of three minutes at the default interval,
#: which a monitoring instance that keeps monitoring meanwhile can afford, and it
#: is one missed tick more than a single slow call could explain.
DEFAULT_LAPSE_AFTER = 3

#: What a lease written **before the first tick** says its ``ttl`` is. The start
#: takes the lease from the restore's listing, which happens before the layer has
#: told this keeper its interval; the first tick rewrites it with the real one.
#: Three minutes is the default failover — ``DEFAULT_LAPSE_AFTER`` at the layer's
#: own default interval — and it is written here rather than imported, because the
#: layer's default is not on the surface this package may import from (PL3).
START_TTL_SECONDS = 180.0

#: What the client is allowed to spend. The save and the tick run on the scheduler
#: tick, so these are the numbers that decide how much of a tick an unreachable
#: bucket can take: two attempts of at most five seconds, plus connect. boto3's
#: defaults are 60 and 60 with several retries, which is minutes. They also bound
#: what an operator's click costs the tick: *take over* does its S3 I/O under the
#: keeper's lock, so a tick can wait behind it for two attempts of connect plus
#: read — about fourteen seconds — which is fine for an action pressed once a
#: year and is the number to look at before widening these.
CLIENT_CONFIG = Config(connect_timeout=2, read_timeout=5,
                       retries={"mode": "standard", "max_attempts": 2})

#: What ``config/aws-keeper.yaml`` may carry. An unknown key is a typo worth
#: naming: a misspelled ``prefix`` would silently keep the state at the bucket's
#: root, next to — or on top of — somebody else's.
_KEYS = frozenset({"bucket", "prefix", "identity", "region", "lapse_after"})

#: The error codes S3 answers a refused precondition with. 412 is the ordinary
#: one; 409 is two writers colliding inside the service; ``NoSuchKey`` reaches
#: here only when an ``If-Match`` names a key somebody deleted underneath us,
#: which is the same discovery said differently.
_PRECONDITION_CODES = frozenset({
    "PreconditionFailed", "ConditionalRequestConflict", "NoSuchKey",
})

#: What a missing object answers with, which is not a failure: nothing has been
#: kept for that file yet.
_ABSENT_CODES = frozenset({"NoSuchKey", "404"})

#: How an instant is written into the lease: ISO 8601, UTC, to the second
#: (ADR-0004 decision 11). Read back with :func:`_parse_instant`.
_INSTANT = "%Y-%m-%dT%H:%M:%SZ"

#: What an object key may carry of an instance's mark unencoded: the characters
#: S3 names as safe. Anything else — the ``:`` between the mark's parts — is
#: percent-encoded, which is injective: two marks never share a key.
_KEY_SAFE = "-_."

#: The kinds of entry the instance log holds, and the ways a lease is taken, as
#: the log spells them.
_TOOK, _RELEASED, _STOOD_BY = "took", "released", "stood-by"

#: What one listing answers with, per object: ``(name, etag, last_modified)``.
#: Named here because inside :class:`S3Keeper` the name ``list`` is the seam's
#: method and no longer the builtin.
_Items = list[tuple[str, str, datetime | None]]
_Names = list[str]
_Entries = list[dict[str, str]]


class KeeperConfigError(Exception):
    """``config/aws-keeper.yaml`` cannot be read.

    Raised, not logged, and so a refusal to start — the same call the identities
    file makes for the same reason. Every *runtime* failure of a keeper is a line
    and never a refusal (little-sister ADR-0071 §4), but a file that cannot be
    read is not a runtime failure: it is a deployment that meant to keep its state
    somewhere and cannot say where, and starting anyway would mean discovering it
    on the day the machine is replaced.
    """


class KeeperStandby(Exception):
    """A save was asked of an instance that does not hold the lease.

    The seam never asks — :meth:`S3Keeper.tick` answered ``False`` and the layer
    sent nothing — so this reaches a caller only from outside the seam, and it is
    an error there: writing without the lease is the one thing the lease exists
    to prevent.
    """


@dataclass(frozen=True)
class Lease:
    """The lease object, as it was read: who holds it, for how long, and how old
    the read found it.

    ``instance`` is the library's mark (little-sister ADR-0074) — compared for
    equality, never parsed. ``age_seconds`` and ``served_at`` are both S3's: the age
    is the answer's ``Date`` against the object's ``LastModified``, and
    ``served_at`` the same ``Date`` as an ISO instant, which is what the next claim
    stamps this one with, so the history stays in one clock domain however many
    machines contributed.
    """

    instance: str = ""
    #: What the holder wrote: how long after its last heartbeat the lease is dead.
    #: ``0`` is a lease given up on purpose (:meth:`S3Keeper.close`).
    ttl_seconds: float = 0.0
    #: Seconds between the object being written and the answer that carried it,
    #: or ``None`` where the answer did not say.
    age_seconds: float | None = None
    #: S3's own clock at the moment this lease was read, as an ISO instant.
    served_at: str = ""
    #: The claims before this one, newest first: ``(instance, at)`` pairs, where
    #: ``at`` is the ISO instant S3 served when that claim read the lease it was
    #: taking over.
    claims: tuple[tuple[str, str], ...] = ()
    #: The object's ETag, which is what makes taking it a compare-and-swap.
    etag: str = ""
    #: How the holder came by it, as the lease says: the prefix was ``free``, the
    #: one before ``lapsed`` or was ``released``, or an ``operator`` took it over
    #: — so a holder whose heartbeat is refused can say which it was, and the
    #: page of the instance taken over from reads the same as the taker's within
    #: one interval. ``""`` where the lease was written before the field existed.
    how: str = ""

    @property
    def alive(self) -> bool:
        """Whether the holder may still be writing.

        A lease whose age could not be measured is **alive**: not knowing is not
        a lapse, and a standby that took a lease it could not read the age of
        would be the second writer this whole module exists to prevent. S3 always
        answers with both halves; the case is a fake's, or a proxy's.
        """
        if self.ttl_seconds <= 0:
            return False
        if self.age_seconds is None:
            return True
        return self.age_seconds < self.ttl_seconds

    @property
    def lapses_in(self) -> float | None:
        """Seconds until it lapses, ``None`` where the age is unknown."""
        if self.age_seconds is None:
            return None
        return max(0.0, self.ttl_seconds - self.age_seconds)

    def churn(self) -> str:
        """The claims before this one, as a phrase — the whole point of keeping
        them. *Four earlier claims, the last at …* reads differently from *no
        earlier claim*, and neither needs a threshold to be worth seeing."""
        if not self.claims:
            return "no earlier claim recorded"
        last = _shown(self.claims[0][1])
        earlier = (f"{len(self.claims)} earlier claims" if len(self.claims) > 1
                   else "1 earlier claim")
        return f"{earlier}, the most recent at {last}" if last else earlier


def _http_date(text: str) -> datetime:
    """An HTTP date as the instant it names.

    A date that says ``-0000`` names a time in UTC and says nothing of the zone it
    was written in (RFC 5322 §3.3); Python answers it without a zone, and it is
    read here as the instant it is. So no time without a zone leaves this
    function: one is right only on the machine that reads it, a subtraction from
    an instant refuses it, and so does the line that would show it.

    :raises ValueError: the text is no date, or a date that names no zone at all.
    :raises TypeError: it is no text.
    """
    moment = parsedate_to_datetime(text)
    if moment.tzinfo is None:
        if not text.rstrip().endswith("-0000"):
            raise ValueError(f"an HTTP date that names no zone: {text!r}")
        moment = moment.replace(tzinfo=UTC)
    return moment


def _measured_age(written: datetime | None, served: str) -> float | None:
    """How old an object was **inside S3's own answer**: the ``Date`` header of
    the response against the ``LastModified`` of the object it carried.

    Both come from S3, so no machine's clock enters the number and there is
    nothing to skew. ``None`` where the answer did not carry both halves.
    """
    if written is None or not served:
        return None
    try:
        return (_http_date(served) - written).total_seconds()
    except (TypeError, ValueError):
        return None


def _instant(served: str) -> str:
    """S3's ``Date`` header as the ISO instant the lease stores; ``""`` where it
    is not a date at all, or one that names no zone."""
    try:
        return _http_date(served).astimezone(UTC).strftime(_INSTANT)
    except (TypeError, ValueError):
        return ""


def _parse_instant(text: str) -> datetime | None:
    """An ISO instant back into a moment that knows its zone, or ``None`` for
    anything else — an older lease carried HTTP dates, which :func:`_http_date`
    reads, and a hand-edited one may carry anything: a time that names no zone is
    not an instant, and is shown as the text it is."""
    for reader in (lambda value: datetime.strptime(value, _INSTANT).replace(tzinfo=UTC),
                   _http_date):
        try:
            moment = reader(text)
        except (TypeError, ValueError):
            continue
        if moment is not None:
            return moment
    return None


def _shown(text: str) -> str:
    """An instant as a line shows it — through the settings' zone and format
    (ADR-0004 decision 11) — or the text as it is where it is not one."""
    moment = _parse_instant(text)
    return local_time(moment) if moment is not None else text


def _presence_key(mark: str) -> str:
    """The presence file's name for an instance: its mark percent-encoded
    between the prefix and the suffix — one key per mark, and never one key for
    two. The body carries the mark itself."""
    return f"{PRESENCE_PREFIX}{quote(mark, safe=_KEY_SAFE)}{PRESENCE_SUFFIX}"


def _served(answer: Mapping[str, Any]) -> str:
    """The ``Date`` header of an answer — S3's clock at the moment it answered —
    or ``""`` where the answer did not carry one."""
    headers = answer.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    return str(headers.get("date", ""))


@dataclass(frozen=True)
class Standby:
    """One instance standing by on this prefix, as a listing found it: the mark
    from the file's body, since when (a store instant), the ``ttl`` the writer
    wrote — its own rule for when its file is stale, whatever the reader's
    interval — and the ETag the body was read under, since the same ETag next
    interval means the same body."""

    instance: str
    since: str
    ttl_seconds: float
    etag: str


def _read_presence(data: bytes, etag: str, *, default_ttl: float) -> Standby:
    """A presence file's body, read as leniently as the lease: anything that is
    not this module's shape is an instance that left no name, judged by the
    reader's own ttl."""
    try:
        body = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        body = None
    if not isinstance(body, Mapping):
        return Standby(instance="an instance that wrote no presence", since="",
                       ttl_seconds=default_ttl, etag=etag)
    ttl = body.get("ttl_seconds")
    return Standby(instance=str(body.get("instance") or "an unnamed instance"),
                   since=str(body.get("since") or ""),
                   ttl_seconds=(float(ttl) if isinstance(ttl, (int, float))
                                and not isinstance(ttl, bool) and ttl > 0
                                else default_ttl),
                   etag=etag)


def _read_log(data: bytes) -> list[dict[str, str]]:
    """The instance log's entries, newest first, as leniently as everything
    else this module reads: an entry is any mapping, and the file is otherwise
    an empty log."""
    try:
        body = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return []
    entries = body.get("entries") if isinstance(body, Mapping) else None
    if not isinstance(entries, list):
        return []
    return [{str(key): str(value) for key, value in item.items()}
            for item in entries if isinstance(item, Mapping)][:INSTANCE_LOG_SIZE]


def _read_lease(data: bytes) -> Lease:
    """The lease body, read **leniently on purpose**. A lease this process cannot
    parse is not a refusal and not an absence: it means something wrote this key
    that was not this module, which is worth naming rather than raising over. So
    every unreadable shape collapses to a holder that reads as what it is, with a
    ``ttl`` of zero — a lease nobody wrote is nobody's to hold."""
    try:
        body = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        body = None
    if not isinstance(body, Mapping):
        return Lease(instance="something that did not write a lease")
    ttl = body.get("ttl_seconds", 0)
    return Lease(instance=str(body.get("instance") or "an unnamed instance"),
                 ttl_seconds=float(ttl) if isinstance(ttl, (int, float)) else 0.0,
                 claims=_read_claims(body.get("claims")),
                 how=str(body.get("how") or ""))


def _taken(how: str) -> str:
    """How a lease changed hands, as a line says it."""
    return {"operator": "on an operator's request",
            "lapsed": "after the lease lapsed",
            "released": "after the lease was given up",
            "free": "on a free prefix"}.get(how, "")


def _read_claims(recorded: object) -> tuple[tuple[str, str], ...]:
    """The claim history, as leniently as the lease itself: anything that is not
    a list of two-field mappings is simply no history. It is printed and never
    acted on, so a malformed one costs a phrase and not a decision."""
    if not isinstance(recorded, list):
        return ()
    claims = []
    for item in recorded[:CLAIM_HISTORY]:
        if isinstance(item, Mapping):
            claims.append((str(item.get("instance") or ""),
                           str(item.get("at") or "")))
    return tuple(claims)


@dataclass(frozen=True)
class KeeperConfig:
    """Where this instance's state is kept, who it is kept as, and how many
    heartbeats a lease survives."""

    bucket: str
    #: A key prefix inside the bucket, ``""`` for its root. Normalized to end in
    #: ``/`` when it is not empty, so the key is always ``prefix + name``.
    prefix: str = ""
    #: The name of an identity declared in ``config/aws.yaml``; ``""`` is the
    #: ambient credential chain, which is what an instance with a role wants.
    identity: str = ""
    #: The bucket's region. Empty means the one the profile or the environment
    #: implies, which is the case a single-region installation never thinks about.
    region: str = ""
    #: Missed heartbeats after which the lease is dead — the failover, in
    #: intervals. The holder writes ``lapse_after × interval`` into the lease as
    #: ``ttl_seconds``, so a reader needs nothing but the object.
    lapse_after: int = DEFAULT_LAPSE_AFTER

    def __post_init__(self) -> None:
        # Here rather than in the loader, because the loader is one of two routes:
        # ``register_s3_keeper(config=…)`` hands a config a deployment built itself
        # straight to the keeper, which builds every key by concatenation — and
        # ``prefix="state"`` would keep the lease at ``state.little-sister-owner.json``
        # in the bucket's root.
        prefix = self.prefix.lstrip("/")
        object.__setattr__(self, "prefix",
                           f"{prefix.rstrip('/')}/" if prefix else "")


class S3Keeper:
    """One bucket and prefix, as little-sister's keeper seam sees it.

    The lease is the whole of the coordination: :meth:`tick` renews it or reads it,
    :meth:`save` writes unconditionally behind a heartbeat that landed, and
    :meth:`close` gives it up. Every fact a line reports is something a call
    already made has learned; :meth:`lines` touches nothing.
    """

    def __init__(self, config: KeeperConfig, *,
                 client_factory: Callable[[], S3Client],
                 instance: str = "",
                 now: Callable[[], datetime] | None = None) -> None:
        self._config = config
        self._client_factory = client_factory
        self._client: S3Client | None = None
        #: The host's clock, as an aware UTC moment — the other clock of decision
        #: 14, read wherever a store stamp meets a local one. An argument so a
        #: test can hold the two clocks apart on purpose.
        self._now = now or (lambda: datetime.now(UTC))
        #: What this process calls itself on the lease — the library's mark
        #: (little-sister ADR-0074). An argument so a test can name two instances
        #: without the machine's own mark deciding what the test proves.
        self._instance = instance or this_instance().mark
        #: Whether this instance holds the lease, and the ETag of the lease as it
        #: last read or wrote it — what makes the next heartbeat conditional.
        self._holding = False
        self._lease_etag = ""
        #: The interval the layer last gave :meth:`tick`, and the ``ttl`` this
        #: instance writes from it.
        self._interval = 0.0
        #: Consecutive heartbeats the bucket did not answer while holding.
        self._missed = 0
        #: The one-time start: the versioning check and the first attempt on the
        #: lease, made on the first call rather than at registration.
        self._started = False
        #: What the last read found while not holding — who, for how long.
        self._standing_by: Lease | None = None
        #: Why this instance stopped writing, while it is not holding again.
        self._demoted = ""
        #: Why the lease could not be read at all, while that lasts.
        self._unreachable = ""
        #: What this instance took the lease over from, how, and the claims
        #: before — permanent facts about this tenure, reported uncoded.
        self._predecessor: Lease | None = None
        self._how = ""
        self._claims: tuple[tuple[str, str], ...] = ()
        #: Who the lease named when this instance last looked while not holding
        #: — a holder it did not know is the signal to read the instance log
        #: again, since a standby does not list (decision 15).
        self._seen_holder = ""
        #: What the bucket said about versioning: ``""`` (off or suspended),
        #: ``"enabled"``, or ``"unchecked: <why>"``.
        self._versioning = ""
        # The actions run on a web thread against the tick on the scheduler's:
        # everything that reads or moves the lease's state does so under this.
        self._lock = threading.RLock()
        #: Per state file, the ETag the store answered when this instance last
        #: loaded or saved it — what a takeover compares the listing against
        #: (little-sister ADR-0077) — beside a digest of the bytes, because an
        #: ETag can move without the bytes moving (a ``PUT`` under SSE-KMS gets a
        #: new one every time) and the question is the bytes; and the host's
        #: clock at the last of them.
        self._synced: dict[str, tuple[str, str]] = {}
        self._synced_at: datetime | None = None
        #: What the last takeover adopted, and when on the host's clock — the
        #: line is WARN for :data:`TAKEOVER_WARN_SECONDS` after it and a fact after.
        self._takeover_at: datetime | None = None
        self._takeover_changed: tuple[str, ...] = ()
        self._takeover_latest = ""
        #: Whether an operator released the lease from here: a released instance
        #: stands by and does not take the lease back on its own — until another
        #: instance has held it, after which it is an ordinary standby again.
        self._released = ""
        #: Since when this instance stands by (an S3 instant), and whether it
        #: has a presence file in the bucket to delete when it stops.
        self._standby_since = ""
        self._presence_written = False
        #: Who the holder's last listing found standing by, by presence key.
        self._standbys: dict[str, Standby] = {}
        #: The store's clock minus the host's, in seconds, from the last answer
        #: that carried a ``Date``; ``None`` until one has. And whether the
        #: offset is past the threshold — in at 5 s, out at 3 s.
        self._offset: float | None = None
        self._skewed = False
        #: The instance log's newest entries, as last read or written, and the
        #: ETag they were read under — a listing that shows another one is the
        #: signal to read it again.
        self._log: tuple[dict[str, str], ...] = ()
        self._log_etag = ""

    @property
    def config(self) -> KeeperConfig:
        return self._config

    @property
    def holding(self) -> bool:
        """Whether this instance holds the lease now."""
        return self._holding

    def key(self, name: str) -> str:
        """The object key state file ``name`` lives under."""
        return f"{self._config.prefix}{name}"

    # --- the seam ---

    def load(self, name: str) -> bytes | None:
        """The bytes kept for ``name``, or ``None`` where nothing is kept yet.

        Reading needs no lease, ever: a standby restores at startup like any other
        instance, which is what lets a successor come up with its predecessor's
        state before the predecessor's lease has lapsed. Absence is not a failure;
        anything else raises, and little-sister turns that into the ERROR line
        that says the state was not restored.
        """
        self._ensure_started()
        key = self.key(name)

        def read(client: S3Client) -> bytes | None:
            try:
                answer = client.get_object(Bucket=self._config.bucket, Key=key)
            except ClientError as error:
                if _code(error) in _ABSENT_CODES:
                    return None
                raise
            data = bytes(answer["Body"].read())
            self._synced_with(name, answer, data)
            return data

        return self._calling(read)

    def save(self, name: str, data: bytes) -> None:
        """Put ``data`` there as ``name`` — **unconditionally**, behind the lease.

        The heartbeat that :meth:`tick` sent before this interval's saves is the
        condition: it landed with ``If-Match`` on the lease this instance last
        wrote, so nothing else has held the prefix since, and a second guard on
        the same guarantee would only add a failure mode (ADR-0004, alternatives).
        Asked of an instance that does not hold the lease, this raises rather than
        writes; the seam never asks, because the tick said not to.
        """
        if not self._holding:
            raise KeeperStandby(
                f"{self._instance} does not hold the lease on {self._address()} "
                f"and may not write {name} there")
        key = self.key(name)

        def write(client: S3Client) -> None:
            answer = client.put_object(Bucket=self._config.bucket, Key=key,
                                       Body=data)
            self._synced_with(name, answer, data)

        self._calling(write)

    def _synced_with(self, name: str, answer: Mapping[str, Any],
                     data: bytes) -> None:
        """Remember what the store answered for ``name``: the ETag a takeover
        compares the listing against, the digest of the bytes it decides by, and
        when, on the host's clock."""
        self._note_clock(answer)
        with self._lock:
            self._synced[name] = (str(answer.get("ETag", "")), _digest(data))
            self._synced_at = self._now()

    def list(self) -> list[str]:
        """Every state file the bucket holds under this prefix, in key order.

        ``Delimiter="/"`` so a key with a further slash in it does not arrive at
        all: the seam takes plain file names, and something under a deeper prefix
        is not this instance's state — it is somebody else's, or a mistake, and
        either way it is not ours to restore.

        Everything under :data:`RESERVED_PREFIX` is dropped here — the lease, the
        presence files, the instance log — and this is the only place it could
        be: they live under the prefix like the state does, and little-sister
        would otherwise restore this module's own objects into ``var/state/`` as
        files nothing reads.

        This is also the first call little-sister makes — the restore's listing —
        which is why the one-time start hangs off it: the versioning check, and
        the first look at the lease, so the lines are right from the first tick.
        And a listing is where a stale presence file is deleted, by whoever
        lists (decision 13), so this one sweeps too.
        """
        self._ensure_started()

        def enumerate_keys(client: S3Client) -> _Names:
            items, served = self._listing(client)
            self._after_listing(client, items, served)
            return [name for name, _etag, _written in items
                    if not name.startswith(RESERVED_PREFIX)]

        return self._calling(enumerate_keys)

    def _same_bytes(self, client: S3Client, name: str, digest: str) -> bool:
        """Whether the store's copy of ``name`` is, byte for byte, what this
        instance last synced — fetched once for the question. A match refreshes
        the token, so the next listing does not ask again; anything but a clean
        answer is *not the same*, and the library fetches and decides."""
        try:
            answer = client.get_object(Bucket=self._config.bucket, Key=self.key(name))
        except ClientError as error:
            if _code(error) in _ABSENT_CODES:
                return False
            raise
        data = bytes(answer["Body"].read())
        if _digest(data) != digest:
            return False
        self._synced_with(name, answer, data)
        return True

    def _listing(self, client: S3Client) -> tuple[_Items, str]:
        """Every object under the prefix — ``(name, etag, last_modified)``, in key
        order — and S3's clock at the answer. ``Delimiter="/"`` so a key with a
        further slash in it does not arrive at all: something under a deeper
        prefix is not this instance's state."""
        prefix = self._config.prefix
        items: _Items = []
        served = ""
        token = ""
        while True:
            page = (
                client.list_objects_v2(
                    Bucket=self._config.bucket, Prefix=prefix,
                    Delimiter="/", ContinuationToken=token)
                if token else
                client.list_objects_v2(
                    Bucket=self._config.bucket, Prefix=prefix,
                    Delimiter="/"))
            served = served or _served(page)
            for item in page.get("Contents", ()):
                key = str(item.get("Key", ""))
                name = key[len(prefix):]
                if name:
                    written = item.get("LastModified")
                    items.append((name, str(item.get("ETag", "")),
                                  written if isinstance(written, datetime) else None))
            token = str(page.get("NextContinuationToken", "") or "")
            if not page.get("IsTruncated") or not token:
                break
        self._note_clock(page)
        return items, served

    def changed_since_sync(self) -> _Names:
        """The seam's question at a takeover (little-sister ADR-0077): which state
        files the store holds a different copy of than this instance last loaded
        or saved — including a file this instance has never seen. The listing's
        ETags say which files *may* have changed; each of those is fetched once
        and decided by its bytes against the digest of the last sync, because an
        ETag moves without the bytes moving under SSE-KMS, and a takeover that
        set a file aside for its own copy would be a ``.bak`` and a line for
        nothing. A candidate whose bytes match refreshes the token and is not
        named. The library adopts every name answered before its first save.

        The answer is also this keeper's own line: *took over; the store had
        changed for N files since this instance last synced with it* — WARN for
        ten minutes, a fact after — and nothing at all where nothing changed,
        which is the successor of a holder that died before anybody wrote again;
        an ask that finds nothing leaves a takeover line that is still standing
        alone. Only a holder is asked, and only a holder answers; the listing
        reviews the presence files on the way like every listing does.
        """
        with self._lock:
            if not self._holding:
                return []

            def compare(client: S3Client) -> _Names:
                items, served = self._listing(client)
                self._after_listing(client, items, served)
                changed: _Names = []
                latest: datetime | None = None
                for name, etag, written in items:
                    if name.startswith(RESERVED_PREFIX):
                        continue
                    known = self._synced.get(name)
                    if known is not None and known[0] == etag:
                        continue
                    if known is not None and self._same_bytes(client, name, known[1]):
                        continue
                    changed.append(name)
                    if written is not None and (latest is None or written > latest):
                        latest = written
                if changed:
                    self._takeover_at = self._now()
                    self._takeover_changed = tuple(changed)
                    self._takeover_latest = (
                        latest.astimezone(UTC).strftime(_INSTANT)
                        if latest is not None else "")
                return changed

            changed = self._calling(compare)
        if changed:
            logger.info("aws: the store at %s changed for %d file(s) since this "
                        "instance last synced with it — %s — adopting them before "
                        "the first save", self._address(), len(changed),
                        ", ".join(changed))
        return changed

    def tick(self, interval_seconds: float) -> bool:
        """Once per interval, before any save: renew the lease or look at it.

        Holding: one heartbeat, conditional on the lease this instance last wrote.
        Landed, and this interval's saves are wanted. Refused, and the lease was
        taken while this instance was away — it demotes itself *before* it writes
        anything, which is the whole of what the condition is for. Not answered at
        all, and that is one missed heartbeat; ``lapse_after`` of them in a row and
        from the outside the lease has lapsed, so it demotes itself for the same
        reason.

        Not holding: one read. Absent, lapsed or given up, and this instance takes
        it — compare-and-swap on what it just read, so two standbys racing for one
        lapsed lease cannot both win — and takes this interval's saves with it.
        Alive, and it stands by, remembering who holds it for the line.

        The interval is what the layer says it is, and it is what the ``ttl`` this
        instance writes is computed from: ``lapse_after × interval``.

        An instance an operator **released** from (:meth:`release`) reads like a
        standby and takes nothing back on its own: the lease is somebody else's
        to take, or *take over*'s.
        """
        with self._lock:
            self._interval = max(0.0, float(interval_seconds))
            started = self._ensure_started()
            if started is not None:
                return started  # the start was this tick's look; one call, not two
            try:
                return self._calling(self._heartbeat if self._holding else self._take)
            except (BotoCoreError, ClientError) as error:
                return self._not_answered(error)

    def close(self) -> None:
        """The graceful end: give the lease up, so the next standby takes it on
        its next read instead of waiting ``lapse_after`` intervals. A heartbeat
        with a ``ttl`` of zero — a ``PUT`` like every other, needing no permission
        a heartbeat does not have. A standby leaves no presence file behind and
        writes how long it stood by into the instance log. Nothing raised: a
        process that is ending has nobody to tell."""
        with self._lock:
            if not self._holding:
                self._stop_standing_by(why="stopped")
                return
            try:
                landed = self._calling(lambda client: self._put_lease(
                    client, ttl=0.0, if_match=self._lease_etag))
            except (BotoCoreError, ClientError) as error:
                logger.warning("aws: the s3 keeper could not give up its lease on %s "
                               "at shutdown (%r); it lapses on its own",
                               self._address(), error)
                return
            self._holding = False
            if landed is None:
                logger.info("aws: the lease on %s was no longer this instance's to "
                            "give up", self._address())
                return
            logger.info("aws: the lease on %s given up", self._address())
            self._record({"kind": _RELEASED, "instance": self._instance,
                          "how": "close"})

    # --- the two actions (decision 9) ---

    def take_over(self) -> str:
        """*Take over*: write the lease onto this instance now, regardless of who
        holds it — for an operator who knows what they are doing, on the keeper's
        child of ``/little-sister`` (little-sister ADR-0076). The holder's next
        heartbeat is refused and it demotes itself. The seam flushes the state
        layer right after the handler, so the layer adopts what the store changed
        and saves in the same click (little-sister ADR-0077) — the order is *the
        lease, then adopt, then save* here too, without the wait for an interval.
        Pressed on the instance that holds the lease already, that flush is the
        whole of it: the state written to the store now. Answers the sentence the
        page shows."""
        with self._lock:
            if self._holding:
                return (f"this instance holds the lease on {self._address()} already; "
                        f"its state is written to the store now")

            def force(client: S3Client) -> Lease | None:
                found = self._get_lease(client)
                claims = (((found.instance, found.served_at), *found.claims)
                          [:CLAIM_HISTORY] if found is not None else ())
                landed = self._put_lease(client, ttl=self._ttl(), claims=claims,
                                         how="operator")
                self._hold(landed or "", claims, found, how="operator")
                return found

            found = self._calling(force)
        if found is None or found.instance == self._instance:
            return (f"took the lease on {self._address()}; the prefix was free, and "
                    f"the state is written to the store now")
        return (f"took the lease on {self._address()} over from {found.instance}; "
                f"what the store changed since this instance last synced with it is "
                f"adopted now, before anything is saved")

    def release(self) -> str:
        """*Release*: give the lease up now — :meth:`close` without the stop —
        and stand by; the flush the seam runs after the handler finds this
        instance not holding and sends nothing, which is what a release means.
        Not taken back on this instance's own next tick, on purpose: a release
        that this instance's own tick could undo a second later would be a race
        with the standby it was pressed for. *Take over* takes it back; and once
        another instance has held the lease, this one is an ordinary standby
        again and takes a lapsed lease by the normal rule.
        While it stands, the line is WARN: nothing of this instance's state
        reaches the store, and a pin set here is lost at termination."""
        with self._lock:
            if not self._holding:
                return f"this instance does not hold the lease on {self._address()}"
            landed = self._calling(lambda client: self._put_lease(
                client, ttl=0.0, if_match=self._lease_etag))
            self._holding = False
            self._lease_etag = ""
            self._released = "an operator released it"
            self._record({"kind": _RELEASED, "instance": self._instance,
                          "how": "operator"})
            logger.info("aws: the lease on %s released by an operator",
                        self._address())
        if landed is None:
            return (f"the lease on {self._address()} was no longer this instance's "
                    f"to give up")
        return (f"released the lease on {self._address()} on request; this instance "
                f"stands by, and nothing of its state reaches the store until an "
                f"instance takes the lease — *take over* takes it back")

    # --- the session, and the one retry ---

    def _calling(self, call: Callable[[S3Client], _Answer]) -> _Answer:
        """Run ``call`` against the client, re-opening the session **once** if it
        fails a credential check.

        The keeper outlives its credentials: an assumed role's are good for an
        hour and this process runs for weeks, and on a laptop an SSO login expires
        about once a working day. Both look the same from here — a credential
        error rather than a refusal — and both are fixed by opening the session
        again, which is why this is one narrow retry and not a general one. An
        ``AccessDenied`` is *not* a credential error and is reported unchanged.
        """
        client = self._client
        if client is None:
            client = self._client = self._client_factory()
        try:
            return call(client)
        except (BotoCoreError, ClientError) as error:
            if not is_credential_error(error):
                raise
            logger.info("aws: the s3 keeper's credentials went stale; opening its "
                        "session again")
            client = self._client = self._client_factory()
            return call(client)

    # --- the lease ---

    def _address(self) -> str:
        """The prefix as somebody would type it, for a line and for the log."""
        return f"s3://{self._config.bucket}/{self._config.prefix}"

    def _ttl(self) -> float:
        """What this instance writes as the lease's ``ttl``: ``lapse_after`` times
        the interval the layer gave it, or :data:`START_TTL_SECONDS` before it has
        been given one."""
        if self._interval > 0:
            return self._config.lapse_after * self._interval
        return START_TTL_SECONDS

    def _ensure_started(self) -> bool | None:
        """The one-time start, on the first call rather than at registration —
        the session is opened lazily on purpose, so a bucket that cannot be reached
        is a line and not an import that fails. Two things: the versioning check
        (decision 10), and a first look at the lease, so a successor of a dead
        instance says *standby, lapsing in …* from its first tick rather than
        *nothing yet*. Neither may raise: a start that cannot reach the bucket is
        the ``unreachable`` line, retried on every tick.

        Answers what the look answered when it ran now, and ``None`` when the
        start had already happened — so a tick that *is* the start does not look
        twice.
        """
        if self._started:
            return None
        self._started = True
        try:
            self._calling(self._check_versioning)
        except (BotoCoreError, ClientError) as error:
            self._versioning = f"unchecked: {error!r}"
        try:
            self._calling(self._read_log)
        except (BotoCoreError, ClientError) as error:
            logger.info("aws: the instance log on %s could not be read at start "
                        "(%r); it is read again when this instance writes it",
                        self._address(), error)
        try:
            return self._calling(self._take)
        except (BotoCoreError, ClientError) as error:
            return self._not_answered(error)

    def _heartbeat(self, client: S3Client) -> bool:
        """Renew, or find out that somebody else holds it now. Renewed, the
        holder lists the prefix once — about the price of the heartbeat — to see
        who is standing by and to delete a presence file that went stale
        (decision 13)."""
        landed = self._put_lease(client, ttl=self._ttl(), if_match=self._lease_etag)
        if landed is not None:
            self._lease_etag = landed
            self._missed = 0
            self._unreachable = ""
            items, served = self._listing(client)
            self._after_listing(client, items, served)
            return True
        # Refused: read before it is believed — the client is allowed two
        # attempts, so a re-sent heartbeat can be refused for one that landed.
        found = self._get_lease(client)
        if found is not None and found.instance == self._instance:
            self._lease_etag = found.etag
            self._missed = 0
            return True
        who = found.instance if found is not None else "an instance that left no lease"
        taken = _taken(found.how) if found is not None else ""
        self._demote(f"the lease was taken by {who}{' ' + taken if taken else ''} "
                     f"while this instance was writing")
        self._stand_by(client, found)
        return False

    def _take(self, client: S3Client) -> bool:
        """Look, and take the lease if it is nobody's — or stand by, saying so
        with a presence file the holder can see (decision 13). An instance an
        operator released from only looks."""
        found = self._get_lease(client)
        self._unreachable = ""
        if found is not None and found.instance != self._instance and self._released:
            # Another instance has held the lease since the release: the
            # suppression has done its work, and this is an ordinary standby
            # again, taking a lapsed lease by the normal rule.
            self._released = ""
        if found is not None and found.alive and found.instance != self._instance:
            self._stand_by(client, found)
            return False
        if self._released:
            self._stand_by(client, found)
            return False
        # A lease naming this instance is this instance's to take back however
        # fresh it is — nobody else can carry this mark — which is what a holder
        # that demoted itself over an unanswered bucket needs once it answers.
        claims = (((found.instance, found.served_at), *found.claims)[:CLAIM_HISTORY]
                  if found is not None else ())
        how = ("free" if found is None else "released" if found.ttl_seconds <= 0
               else "lapsed" if found.instance != self._instance else "own")
        landed = self._put_lease(client, ttl=self._ttl(), claims=claims,
                                 how=self._how if how == "own" else how,
                                 if_match=found.etag if found is not None else "",
                                 if_none_match=found is None)
        if landed is None:
            # Somebody else took it between the read and the write; the next
            # tick reads who.
            self._stand_by(client, self._get_lease(client))
            return False
        self._hold(landed, claims, found, how=how)
        return True

    def _hold(self, etag: str, claims: tuple[tuple[str, str], ...],
              found: Lease | None, *, how: str) -> None:
        """This instance holds the lease from now: the bookkeeping of a takeover,
        the presence file it leaves behind gone, and the instance log told how it
        came about and how long this instance stood by before."""
        self._holding = True
        self._lease_etag = etag
        self._claims = claims
        self._predecessor = found
        if how != "own":
            self._how = how
        self._seen_holder = self._instance
        self._standing_by = None
        self._demoted = ""
        self._released = ""
        self._missed = 0
        entries: _Entries = []
        if self._standby_since:
            entries.append({"kind": _STOOD_BY, "instance": self._instance,
                            "since": self._standby_since})
        self._standby_since = ""
        if how != "own":
            entries.append({"kind": _TOOK, "instance": self._instance,
                            "from": found.instance if found is not None else "",
                            "how": how})
        if found is not None:
            logger.info("aws: took the lease on %s over from %s (%s)", self._address(),
                        found.instance, found.churn())
        else:
            logger.info("aws: took the lease on %s; the prefix was free",
                        self._address())
        self._delete_presence()
        if entries:
            self._record(*entries)

    def _stand_by(self, client: S3Client, found: Lease | None) -> None:
        """Remember who holds the lease, and say that this instance is here: the
        presence file, written every interval this instance stands by."""
        self._standing_by = found
        holder = found.instance if found is not None else ""
        if holder != self._seen_holder:
            # A holder this instance did not know wrote the log: read it again,
            # once — a standby does not list, so this is its only signal.
            self._seen_holder = holder
            try:
                self._read_log(client)
            except (BotoCoreError, ClientError) as error:
                logger.info("aws: the instance log on %s could not be read after "
                            "the lease changed hands (%r)", self._address(), error)
        served = found.served_at if found is not None else ""
        if not self._standby_since:
            # S3's clock where the answer carried it; the host's where it did
            # not, which is a fake's or a proxy's and not S3's.
            self._standby_since = served or self._now().strftime(_INSTANT)
        try:
            self._write_presence(client)
        except (BotoCoreError, ClientError) as error:
            # The lease was read; a presence file that could not be written costs
            # the holder a line, not this instance its standby. Tried again next
            # interval, like the heartbeat it is.
            logger.warning("aws: the presence file on %s could not be written: %r",
                           self._address(), error)

    def _stop_standing_by(self, *, why: str) -> None:
        """A standby that stops — a close — leaves no presence file and tells the
        log how long it stood by. Nothing raised."""
        if not self._standby_since and not self._presence_written:
            return
        try:
            self._delete_presence()
            if self._standby_since:
                self._record({"kind": _STOOD_BY, "instance": self._instance,
                              "since": self._standby_since, "how": why})
        finally:
            self._standby_since = ""

    def _not_answered(self, error: Exception) -> bool:
        """The bucket did not answer a tick. Holding, that is one missed heartbeat,
        and ``lapse_after`` of them is a lapse seen from outside; standing by, it is
        a read that will be tried again."""
        if self._holding:
            self._missed += 1
            if self._missed >= self._config.lapse_after:
                self._demote(f"the bucket did not answer {self._missed} heartbeats "
                             f"in a row ({error!r}), so the lease has lapsed as far "
                             f"as anybody else can tell")
            else:
                logger.warning("aws: the s3 keeper's heartbeat on %s was not "
                               "answered (%d of %d): %r", self._address(),
                               self._missed, self._config.lapse_after, error)
            return False
        self._unreachable = repr(error)
        logger.warning("aws: the lease on %s could not be read: %r", self._address(),
                       error)
        return False

    def _demote(self, why: str) -> None:
        self._holding = False
        self._lease_etag = ""
        self._demoted = why
        logger.warning("aws: %s stopped writing to %s: %s", self._instance,
                       self._address(), why)

    # --- the presence file (decision 13) ---

    def _write_presence(self, client: S3Client) -> None:
        """This instance's presence file, written every interval it stands by:
        the mark, since when, and the ``ttl`` after which — its ``LastModified``
        against a listing's ``Date``, the lease's own rule — it is stale."""
        body = json.dumps({"instance": self._instance,
                           "since": self._standby_since,
                           "ttl_seconds": self._ttl(),
                           "clock": "store"}, sort_keys=True).encode("utf-8")
        answer = client.put_object(Bucket=self._config.bucket,
                                   Key=self.key(_presence_key(self._instance)),
                                   Body=body)
        self._note_clock(answer)
        self._presence_written = True

    def _delete_presence(self) -> None:
        """Delete this instance's presence file, where it wrote one: an instance
        that takes the lease, or stops standing by, leaves none behind. A delete
        that fails is a warning and a stale file the next listing sweeps."""
        if not self._presence_written:
            return
        key = self.key(_presence_key(self._instance))
        try:
            self._calling(lambda client: client.delete_object(
                Bucket=self._config.bucket, Key=key))
        except (BotoCoreError, ClientError) as error:
            logger.warning("aws: the presence file %s could not be deleted (%r); "
                           "it is swept when it goes stale", key, error)
        self._presence_written = False

    def _after_listing(self, client: S3Client, items: _Items, served: str) -> None:
        """What every listing does with what it saw, whoever made it: the presence
        files reviewed — the live ones remembered as who stands by, a body fetched
        once per new ETag since an unchanged heartbeat rewrites the same bytes;
        the stale ones deleted, each judged by the ``ttl`` its writer put in it
        against ``LastModified`` and the listing's ``Date``, and each written
        into the instance log as *stood by from … to …* by the deleter, because a
        killed standby cannot write its own and is the case the log exists for
        (decision 13) — and the instance log read again where the listing shows
        an ETag other than the one last read (decision 15)."""
        found: dict[str, Standby] = {}
        dead: _Entries = []
        for name, etag, written in items:
            if name == INSTANCES_NAME:
                if etag != self._log_etag:
                    self._read_log(client)
                continue
            if not name.startswith(PRESENCE_PREFIX):
                continue
            known = self._standbys.get(name)
            if known is None or known.etag != etag:
                try:
                    answer = client.get_object(Bucket=self._config.bucket,
                                               Key=self.key(name))
                except ClientError as error:
                    if _code(error) in _ABSENT_CODES:
                        continue    # swept by somebody else, or its instance took over
                    raise
                self._note_clock(answer)
                known = _read_presence(bytes(answer["Body"].read()),
                                       str(answer.get("ETag", "")),
                                       default_ttl=self._ttl())
            age = _measured_age(written, served)
            if age is not None and age >= known.ttl_seconds:
                try:
                    client.delete_object(Bucket=self._config.bucket, Key=self.key(name))
                except (BotoCoreError, ClientError) as error:
                    logger.warning("aws: the stale presence file %s could not be "
                                   "deleted: %r", name, error)
                    continue
                logger.info("aws: deleted the presence file %s of %s, %s old against "
                            "its ttl of %s", name, known.instance, format_span(age),
                            format_span(known.ttl_seconds))
                if written is not None:
                    dead.append({"kind": _STOOD_BY, "instance": known.instance,
                                 "since": known.since, "how": "died",
                                 "at": written.astimezone(UTC).strftime(_INSTANT)})
                continue
            found[name] = known
        self._standbys = found
        if dead:
            self._record(*dead)

    # --- two clocks (decision 14) ---

    def _note_clock(self, answer: Mapping[str, Any]) -> None:
        """The store's clock against the host's, from the ``Date`` header of an
        answer just received: kept as the latest reading, refreshed by every call
        for nothing. Good to about a second — the header is whole seconds, plus
        half a round trip."""
        served = _served(answer)
        if not served:
            return
        try:
            moment = _http_date(served)
        except (TypeError, ValueError):
            return
        with self._lock:
            self._offset = (moment - self._now()).total_seconds()
            if abs(self._offset) > SKEW_THRESHOLD_SECONDS:
                self._skewed = True
            elif abs(self._offset) < SKEW_CLEAR_SECONDS:
                self._skewed = False

    def _in_host_time(self, instant: str) -> datetime | None:
        """A store instant moved onto the host's clock — what a store stamp is
        converted to before it meets a local one on a page — or ``None`` where
        the text is not an instant."""
        moment = _parse_instant(instant)
        if moment is None:
            return None
        return moment - timedelta(seconds=self._offset or 0.0)

    def _shown_host(self, instant: str) -> str:
        """A store instant as a line shows it beside a local one: in host time,
        through the settings' zone and format."""
        moment = self._in_host_time(instant)
        return local_time(moment) if moment is not None else instant

    # --- the instance log (decision 15) ---

    def _read_log(self, client: S3Client) -> tuple[_Entries, str]:
        """The instance log as the bucket holds it — its entries, newest first,
        and its ETag — an empty log where there is none. Remembers the newest
        few for the line."""
        key = self.key(INSTANCES_NAME)
        try:
            answer = client.get_object(Bucket=self._config.bucket, Key=key)
        except ClientError as error:
            if _code(error) in _ABSENT_CODES:
                self._log = ()
                self._log_etag = ""
                return [], ""
            raise
        self._note_clock(answer)
        entries = _read_log(bytes(answer["Body"].read()))
        self._log = tuple(entries[:3])
        self._log_etag = str(answer.get("ETag", ""))
        return entries, self._log_etag

    def _record(self, *entries: dict[str, str]) -> None:
        """Append ``entries`` to the instance log — read, prepend, write with
        ``If-Match`` on what was read, once more from a fresh read if that was
        refused — each stamped with the store's clock at the write, unless it
        brings its own stamp, and with who wrote it, since a lapse's end is the
        taker's observation and not the dead holder's last breath. Bounded to the
        newest :data:`INSTANCE_LOG_SIZE`. The one conditional write of a
        non-holder: the log is the one object every instance writes. Nothing
        raised: a transition that could not be logged is a warning, not a tick
        that failed."""

        def write(client: S3Client) -> None:
            for attempt in (1, 2):
                held, etag = self._read_log(client)
                # Stamped on the store's clock — the host's, moved by the offset
                # just measured — so every entry is in one clock domain.
                now = (self._now() + timedelta(seconds=self._offset or 0.0)
                       ).strftime(_INSTANT)
                # Newest first: of several entries written together — stood by,
                # then took — the later one leads.
                stamped = [{"at": now, "by": self._instance, **entry}
                           for entry in reversed(entries)]
                merged = (stamped + held)[:INSTANCE_LOG_SIZE]
                body = json.dumps({"clock": "store", "entries": merged},
                                  sort_keys=True).encode("utf-8")
                key = self.key(INSTANCES_NAME)
                try:
                    if etag:
                        answer = client.put_object(Bucket=self._config.bucket,
                                                   Key=key, Body=body, IfMatch=etag)
                    else:
                        answer = client.put_object(Bucket=self._config.bucket,
                                                   Key=key, Body=body,
                                                   IfNoneMatch="*")
                except ClientError as error:
                    if _code(error) in _PRECONDITION_CODES and attempt == 1:
                        continue    # somebody else logged a transition; read again
                    raise
                self._note_clock(answer)
                self._log = tuple(merged[:3])
                self._log_etag = str(answer.get("ETag", ""))
                return

        try:
            self._calling(write)
        except (BotoCoreError, ClientError) as error:
            logger.warning("aws: the instance log on %s could not be written: %r",
                           self._address(), error)

    def _get_lease(self, client: S3Client) -> Lease | None:
        """The lease as it is, or ``None`` where there is none. Absence is a fact
        rather than a failure; anything else travels."""
        key = self.key(OWNER_NAME)
        try:
            answer = client.get_object(Bucket=self._config.bucket, Key=key)
        except ClientError as error:
            if _code(error) in _ABSENT_CODES:
                return None
            raise
        data = bytes(answer["Body"].read())
        served = _served(answer)
        self._note_clock(answer)
        return replace(_read_lease(data),
                       served_at=_instant(served),
                       age_seconds=_measured_age(answer.get("LastModified"), served),
                       etag=str(answer.get("ETag", "")))

    def _put_lease(self, client: S3Client, *, ttl: float,
                   claims: tuple[tuple[str, str], ...] | None = None,
                   how: str | None = None,
                   if_match: str = "", if_none_match: bool = False) -> str | None:
        """Write the lease, conditionally; the new ETag, or ``None`` where the
        precondition was refused. Every other error travels. ``how`` is how this
        tenure came about, written into every heartbeat of it, so the instance
        taken over from reads it whichever of the two ticks comes first."""
        body = json.dumps(
            {"instance": self._instance,
             "ttl_seconds": ttl,
             "how": self._how if how is None else how,
             "claims": [{"instance": who, "at": when}
                        for who, when in (self._claims if claims is None else claims)]},
            sort_keys=True).encode("utf-8")
        key = self.key(OWNER_NAME)
        try:
            if if_none_match:
                answer = client.put_object(Bucket=self._config.bucket, Key=key,
                                           Body=body, IfNoneMatch="*")
            elif if_match:
                answer = client.put_object(Bucket=self._config.bucket, Key=key,
                                           Body=body, IfMatch=if_match)
            else:
                answer = client.put_object(Bucket=self._config.bucket, Key=key,
                                           Body=body)
        except ClientError as error:
            if _code(error) not in _PRECONDITION_CODES:
                raise
            return None
        self._note_clock(answer)
        return str(answer.get("ETag", "")) or if_match

    def _check_versioning(self, client: S3Client) -> None:
        """Once, at start: whether the bucket versions every heartbeat (decision
        10). ``Enabled`` is the line; ``Suspended`` and absent are fine."""
        try:
            answer = client.get_bucket_versioning(Bucket=self._config.bucket)
        except ClientError as error:
            if is_credential_error(error):
                raise
            self._versioning = f"unchecked: {_code(error) or error!r}"
            return
        status = str(answer.get("Status", ""))
        self._versioning = "enabled" if status == "Enabled" else ""

    # --- what this keeper says about itself ---

    def lines(self) -> tuple[Entry, ...]:
        """This keeper's own report, read on every tick — the self-report
        contributor (little-sister ADR-0072), registered under :data:`ASPECT`, so
        each slug below is its own on the child ``/little-sister/aws-keeper``
        (the flat ``aws-keeper.<slug>`` form exists only in ``current_lines()``).

        **Recorded state, read.** Nothing here touches the bucket: every line is
        something a call already made has learned.

        Graded by the library's own loss principle (ADR-0004 decision 9): what is
        already lost is ERROR and is the library's line; what *would* be lost at a
        restart is WARN. Nothing here is ERROR — a second instance is no longer a
        way to lose state, it is a standby. **Every line is a claim and carries a
        code**; what this keeper merely knows — who holds the lease, whom it took
        it from, the last transitions — is :meth:`report` (little-sister ADR-0076
        decision 1, little-sister ADR-0044 decision 6).
        """
        with self._lock:
            return self._lines()

    def report(self) -> str:
        """This keeper's facts, as Markdown — the ``report`` of its child, shown on
        the child's page and never on a card (little-sister ADR-0044 decision 6):
        who holds the lease and on what terms, whom this instance took it from and
        how, a takeover that changed the store once its ten minutes at WARN are
        over, the last transitions in the instance log, and a versioning check
        that could not be made. Recorded state, read, like the lines."""
        with self._lock:
            return self._report()

    def _lines(self) -> tuple[Entry, ...]:
        # Call only while holding the lock.
        lines: list[Entry] = []
        address = self._address()
        if self._holding:
            if self._standbys:
                who = ", ".join(
                    f"{standby.instance} since {self._shown_host(standby.since)}"
                    if standby.since else standby.instance
                    for standby in self._standbys.values())
                count = len(self._standbys)
                lines.append(Entry("standbys", plain(
                    f"{count} instance{'s are' if count > 1 else ' is'} standing by "
                    f"on {address}: {who}. In a rollout this clears within minutes; "
                    f"a second instance that stays is a misconfiguration"),
                    code=StatusCode.WARN))
        else:
            if self._released:
                lines.append(Entry("released", plain(
                    f"this instance ({self._instance}) released the lease on "
                    f"{address} on request and stands by; nothing of its state "
                    f"reaches the store until an instance takes the lease — a pin "
                    f"set here is lost at termination — and *take over* takes it "
                    f"back"), code=StatusCode.WARN))
            if self._demoted:
                lines.append(Entry("demoted", plain(
                    f"this instance ({self._instance}) has stopped writing to "
                    f"{address}: {self._demoted}. It takes the lease back when it "
                    f"is free; a pin set here meanwhile does not survive it"),
                    code=StatusCode.WARN))
            if self._standing_by is not None:
                held = self._standing_by
                lapse = ("at an unknown time" if held.lapses_in is None
                         else f"in {format_span(held.lapses_in)}")
                age = ("an unknown time" if held.age_seconds is None
                       else format_span(held.age_seconds))
                lines.append(Entry("standby", plain(
                    f"the lease on {address} is held by {held.instance}, last "
                    f"heartbeat {age} ago and lapsing {lapse}; this instance keeps "
                    f"its state locally only, and a pin set here does not survive "
                    f"it"), code=StatusCode.WARN))
            if self._unreachable:
                lines.append(Entry("unreachable", plain(
                    f"the lease on {address} could not be read "
                    f"({self._unreachable}); this instance keeps its state locally "
                    f"until it can"), code=StatusCode.WARN))
        if self._takeover_changed and self._takeover_is_fresh():
            # WARN for ten minutes — long enough to be noticed — and a fact in the
            # report after (decision 4).
            lines.append(Entry("takeover", self._takeover_text(),
                               code=StatusCode.WARN))
        if self._skewed and self._offset is not None:
            behind = "behind" if self._offset > 0 else "ahead of"
            lines.append(Entry("clock", plain(
                f"this host's clock is {format_span(abs(self._offset))} {behind} "
                f"the store's; the ages on this page are the store's clock, the "
                f"times beside them the host's, and past fifteen minutes S3 "
                f"refuses every request"), code=StatusCode.WARN))
        if self._versioning == "enabled":
            lines.append(Entry("versioning", plain(
                f"versioning is enabled on bucket {self._config.bucket}: every "
                f"heartbeat and every save is a new version — about 43,000 a month "
                f"of the lease alone — for a history nobody reads. Suspend it, or "
                f"bound it with a lifecycle rule"), code=StatusCode.WARN))
        return tuple(lines)

    def _takeover_is_fresh(self) -> bool:
        return (self._takeover_at is not None
                and (self._now() - self._takeover_at).total_seconds()
                < TAKEOVER_WARN_SECONDS)

    def _takeover_text(self) -> str:
        count = len(self._takeover_changed)
        synced = (local_time(self._synced_at) if self._synced_at is not None
                  else "an unknown time")
        latest = (f", the latest at {self._shown_host(self._takeover_latest)}"
                  if self._takeover_latest else "")
        return plain(
            f"took over {self._address()}: the store had changed for {count} file"
            f"{'s' if count > 1 else ''} ({', '.join(self._takeover_changed)}) "
            f"since this instance last synced with it at {synced}{latest}; "
            f"what they replaced is on /little-sister/state")

    def _report(self) -> str:
        # Call only while holding the lock. One paragraph per fact; a fact the
        # keeper no longer has is not written, so the report clears with it.
        facts: list[str] = []
        address = self._address()
        if self._holding:
            every = format_duration(int(self._interval)) if self._interval else "—"
            facts.append(plain(
                f"This instance ({self._instance}) holds the lease on {address}: a "
                f"heartbeat every {every}, lapsing after "
                f"{self._config.lapse_after} missed."))
        if self._predecessor is not None:
            was = self._predecessor
            if self._how == "operator":
                beat = (f"its last heartbeat was {format_span(was.age_seconds)} ago"
                        if was.age_seconds is not None
                        else "its last heartbeat is of unknown age")
                within = (f"within {format_duration(int(self._interval))}"
                          if self._interval else "at its next heartbeat")
                facts.append(plain(
                    f"Took over {address} from {was.instance} on an operator's "
                    f"request; {beat}, and it learns of this at its next "
                    f"heartbeat, {within} ({was.churn()})."))
            else:
                lapsed = ""
                if was.ttl_seconds > 0 and was.age_seconds is not None:
                    over = max(0.0, was.age_seconds - was.ttl_seconds)
                    lapsed = f", lapsed {format_span(over)} before"
                given = " (given up)" if was.ttl_seconds <= 0 else ""
                facts.append(plain(
                    f"Took over {address} from {was.instance}{given}{lapsed} "
                    f"({was.churn()})."))
        if self._takeover_changed and not self._takeover_is_fresh():
            facts.append(self._takeover_text())
        if self._log:
            facts.append(plain(f"The last transitions on {address}:") + "\n\n"
                         + "\n".join(f"- {plain(self._entry_line(entry))}"
                                     for entry in self._log))
        if self._versioning.startswith("unchecked"):
            facts.append(plain(
                f"Could not check whether versioning is on for bucket "
                f"{self._config.bucket} ({self._versioning[len('unchecked: '):]})."))
        return "\n\n".join(facts)


    def _entry_line(self, entry: Mapping[str, str]) -> str:
        """One instance-log entry as the line reads it, its instants in host
        time."""
        kind = entry.get("kind", "")
        who = entry.get("instance", "an unnamed instance")
        at = self._shown_host(entry.get("at", "")) or "an unknown time"
        if kind == _TOOK:
            source = entry.get("from") or "nobody"
            how = entry.get("how", "?")
            return f"{who} took the lease from {source} ({how}) at {at}"
        if kind == _RELEASED:
            return f"{who} released the lease ({entry.get('how', '?')}) at {at}"
        if kind == _STOOD_BY:
            since = self._shown_host(entry.get("since", "")) or "an unknown time"
            return f"{who} stood by from {since} to {at}"
        return f"{who}: {kind or 'an entry this version cannot read'} at {at}"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _code(error: ClientError) -> str:
    """The error code S3 answered with, or ``""``."""
    code = error.response.get("Error", {}).get("Code", "")
    return str(code)


# --- the configuration aspect ---


def _text(entry: Mapping[str, Any], key: str, *, path: Path) -> str:
    """One optional string, read by the seam's own reader and refused in this
    file's words — the same split ``identities.py`` makes.

    ``key in entry`` rather than a ``None`` test, because a key **written and
    left empty is a typo, not a value**: read as unset, ``prefix:`` with nothing
    after it would quietly keep this instance's state at the bucket's root, on
    top of whatever else is there.
    """
    try:
        return parse_optional_text(entry, key, where=f"{path}: {key!r}").strip()
    except OptionalTextError as error:
        if error.kind == "left-empty":
            raise KeeperConfigError(
                f"{path}: {key!r} was written and left empty") from error
        raise KeeperConfigError(
            f"{path}: {key!r} must be a non-empty string") from error


def _lapse_after(entry: Mapping[str, Any], *, path: Path) -> int:
    """``lapse_after``: a positive integer, or the default where it is not
    written. A key written and left empty is refused like any other."""
    if "lapse_after" not in entry:
        return DEFAULT_LAPSE_AFTER
    value = entry["lapse_after"]
    if value is None:
        raise KeeperConfigError(f"{path}: 'lapse_after' was written and left empty")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise KeeperConfigError(
            f"{path}: 'lapse_after' must be a positive integer — how many "
            f"heartbeats may be missed before the lease is dead — not {value!r}")
    return value


def load_keeper_config(spec: str | Path | None = None) -> KeeperConfig | None:
    """What ``config/aws-keeper.yaml`` says, or ``None`` where there is no file.

    No file and an empty file both mean **no keeper**, which is deliberate rather
    than lenient: a deployment with two complete configuration roots — one for a
    laptop, one for the cloud — registers the keeper from one ``wsgi.py`` and
    wants the local root to be the instance that keeps its state on its own disk.
    A file that exists and cannot be read is the other case entirely, and refuses.
    """
    path = sole_aspect_file(ASPECT, spec)
    if path is None:
        logger.info("aws: no %s.yaml in the configuration — this instance keeps "
                    "its state on its own disk", ASPECT)
        return None
    try:
        body = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise KeeperConfigError(f"{path} could not be read: {error}") from error
    if body is None:
        logger.info("aws: %s is empty — this instance keeps its state on its own "
                    "disk", path)
        return None
    if not isinstance(body, Mapping):
        raise KeeperConfigError(
            f"{path} must be a mapping of settings, got {type(body).__name__}")
    unknown = sorted(set(body) - _KEYS)
    if unknown:
        raise KeeperConfigError(
            f"{path}: unknown key(s) {', '.join(repr(key) for key in unknown)} "
            f"— known: {', '.join(sorted(_KEYS))}")
    bucket = _text(body, "bucket", path=path)
    if not bucket:
        raise KeeperConfigError(
            f"{path}: 'bucket' is required — a keeper with no bucket is a file "
            f"that says the state is kept somewhere and does not say where")
    return KeeperConfig(
        bucket=bucket,
        prefix=_text(body, "prefix", path=path),
        identity=_text(body, "identity", path=path),
        region=_text(body, "region", path=path),
        lapse_after=_lapse_after(body, path=path))


def declare_aspect() -> None:
    """Claim ``config/aws-keeper.yaml`` before anything reads it (little-sister
    ADR-0035): an undeclared aspect raises rather than reporting no file."""
    register_aspect(ASPECT)


def _named_identity(name: str,
                    identities: Mapping[str, NamedIdentity]) -> NamedIdentity:
    """The identity the keeper opens its session as.

    An identity nobody declared is a refusal here rather than a fall back to the
    ambient chain: the two read different accounts, and a keeper quietly writing
    the state of one account into the bucket of another is the failure named
    identities exist to prevent.
    """
    if not name:
        return NamedIdentity(name="", identity=Identity())
    declared = identities.get(name)
    if declared is None:
        raise KeeperConfigError(
            f"the keeper names identity {name!r}, which config/aws.yaml does not "
            f"declare — known: {', '.join(sorted(identities)) or 'none'}")
    return declared


def _new_client(identity: NamedIdentity, config: KeeperConfig) -> S3Client:
    """An S3 client for the keeper — the one seam a test replaces.

    The region is the **bucket's**, from the keeper's own file rather than the
    identity's: an identity's ``region:`` says where its *secrets* are read, and a
    deployment reading its secrets in one region may well keep its state in
    another.
    """
    return open_session(identity.identity).client(
        "s3", region_name=config.region or None, config=CLIENT_CONFIG)


def register_s3_keeper(config: KeeperConfig | None = None,
                       identities: Mapping[str, NamedIdentity] | None = None
                       ) -> S3Keeper | None:
    """Install the S3 keeper before ``little_sister.app`` is imported.

    Returns the keeper, or ``None`` where the configuration declares none — which
    is an instance that keeps its state on its own disk, and a supported shape.

    ``config`` is the route that reads no file: a :class:`KeeperConfig` the
    deployment built — a bucket name derived at startup rather than written down.
    Without it, ``config/aws-keeper.yaml`` is read. ``identities`` is the same
    choice for ``config/aws.yaml``.

    The session is opened **lazily**, at the first call little-sister makes, not
    here: registration happens in the import-before-app slot, and a bucket that
    cannot be reached must be a line on ``/little-sister/aws-keeper`` rather than
    an import that fails. What *is* refused here is a file that cannot be read or
    an identity that was never declared — configuration, not weather.
    """
    if config is None:
        # The aspects have to be declared before anything asks for their files —
        # this call *is* the import-before-app slot little-sister ADR-0035 means.
        # **Both** of them: a deployment may register a keeper without registering
        # the secret provider, and the identity this keeper opens its session as
        # is declared in that provider's file. Declaring an aspect twice is a
        # no-op, so the ordinary deployment that registers both pays nothing.
        declare_aspect()
        aws_identities.declare_aspect()
        config = load_keeper_config()
    if config is None:
        return None
    if identities is None:
        identities = load_identities()
    identity = _named_identity(config.identity, identities)
    keeper = S3Keeper(config, client_factory=lambda: _new_client(identity, config))
    register_keeper(KEEPER_NAME, keeper)
    # Three seams, one call: the keeper seam carries loads and saves, what this
    # keeper knows about its lease is not a refusal and goes through the
    # self-report seam — the contributor is named for the aspect, so its child is
    # `/little-sister/aws-keeper` and its slugs are its own there — and the two
    # actions an operator may take on that child (decision 9) go through the
    # action seam beside it.
    register_contributor(ASPECT, keeper.lines, title="S3 keeper",
                         report=keeper.report,
                         about="The lease on the bucket prefix this instance's state "
                               "is kept under: who holds it, who stands by, and "
                               "the two things an operator may do about it.")
    register_action(ASPECT, "take-over", "Take over", keeper.take_over)
    register_action(ASPECT, "release", "Release", keeper.release)
    logger.info("aws: the state is kept in s3://%s/%s, as %s", config.bucket,
                config.prefix, identity.name or "the ambient chain")
    return keeper


__all__ = ["ASPECT", "CLIENT_CONFIG", "DEFAULT_LAPSE_AFTER", "INSTANCES_NAME",
           "INSTANCE_LOG_SIZE", "KEEPER_NAME", "OWNER_NAME", "PRESENCE_PREFIX",
           "RESERVED_PREFIX", "SKEW_CLEAR_SECONDS", "SKEW_THRESHOLD_SECONDS",
           "START_TTL_SECONDS", "TAKEOVER_WARN_SECONDS",
           "KeeperConfig", "KeeperConfigError", "KeeperStandby", "Lease",
           "S3Keeper", "Standby", "declare_aspect", "load_keeper_config",
           "register_s3_keeper"]
