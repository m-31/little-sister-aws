"""The S3 keeper: one lease per prefix, the heartbeat that holds it, standby for
everybody else, and the file that says where the state is kept.

No live AWS anywhere (PL6): the client is a fake, injected at the one seam
``_new_client``, and a session is never opened. What is asserted about S3 itself is
what this package sends and what it does with what comes back — the parameters were
checked against the installed botocore's own `PutObject` model, which is the only
honest way to pin them without a bucket. The fake keeps S3's own clock: every
object remembers when it was put, every answer says what time it is, and a test
advances that clock rather than sleeping.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from little_sister import config_dir, self_report
from little_sister import keeper as ls_keeper
from little_sister.state import StateLayer
from little_sister.status import StatusCode

from little_sister_aws import keeper as aws_keeper
from little_sister_aws.identities import NamedIdentity
from little_sister_aws.identity import Identity
from little_sister_aws.keeper import (
    INSTANCE_LOG_SIZE,
    INSTANCES_NAME,
    OWNER_NAME,
    PRESENCE_PREFIX,
    RESERVED_PREFIX,
    KeeperConfig,
    KeeperConfigError,
    KeeperStandby,
    S3Keeper,
    load_keeper_config,
    register_s3_keeper,
)

BUCKET = "example-state"
ROLE = "arn:aws:iam::000000000000:role/monitoring-role"
INTERVAL = 60.0
EPOCH = datetime(2026, 9, 5, 8, 15, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _forget_registrations():
    """A keeper or an aspect one test registers must not be another's premise."""
    with mock.patch.dict(config_dir._ASPECTS if hasattr(config_dir, "_ASPECTS")
                         else {}, clear=False):
        yield
    ls_keeper.forget_keeper()
    self_report.forget_contributors()
    self_report.forget_actions()


@pytest.fixture(autouse=True)
def _instants_shown_plainly():
    """Every instant a line shows goes through the settings' zone and format
    (ADR-0004 decision 11), which needs a configuration root this suite does not
    have: the renderer is replaced by one that shows the instant as ISO in angle
    brackets, so a test can read the moment back. A test about the rendering
    itself patches it again."""
    with mock.patch("little_sister_aws.keeper.local_time",
                    lambda moment, fmt=None: f"<{moment.isoformat()}>"):
        yield


@pytest.fixture
def config_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A configuration root of this test's own — borrowing the working
    directory's would be a test that passes only where it happens to run."""
    root = tmp_path / "config"
    root.mkdir()
    monkeypatch.setenv("LITTLE_SISTER_CONFIG_DIR", str(root))
    return root


def _client_error(code: str, operation: str = "PutObject") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class _Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3:
    """One bucket, in a dict, with S3's conditional semantics as far as this
    keeper uses them — and S3's clock, which the lease is measured against."""

    def __init__(self) -> None:
        #: key -> (data, etag, written_at)
        self.objects: dict[str, tuple[bytes, str, datetime]] = {}
        self.puts: list[dict[str, Any]] = []
        self.gets: list[str] = []
        self.deletes: list[str] = []
        self.listings = 0
        #: Fails the next delete.
        self.fail_delete: Exception | None = None
        self.versioning_asked = 0
        self.versioning = ""                 # what GetBucketVersioning says
        self.now = EPOCH
        self._next_etag = 0
        #: Fails the next call that is **not** about the lease.
        self.fail_next: Exception | None = None
        #: Fails the next call that *is* about the lease.
        self.fail_lease: Exception | None = None
        #: Fails every call about the lease, until cleared.
        self.fail_lease_always: Exception | None = None
        #: Answer gets without S3's clock — the case the keeper must read as alive.
        self.silent_clock = False

    def _etag(self) -> str:
        self._next_etag += 1
        return f'"etag-{self._next_etag}"'

    def _maybe_fail(self, key: str = "") -> None:
        if key.endswith(OWNER_NAME):
            if self.fail_lease_always is not None:
                raise self.fail_lease_always
            if self.fail_lease is not None:
                error, self.fail_lease = self.fail_lease, None
                raise error
            return
        if self.fail_next is not None:
            error, self.fail_next = self.fail_next, None
            raise error

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        self._maybe_fail(Key)
        self.gets.append(Key)
        held = self.objects.get(Key)
        if held is None:
            raise _client_error("NoSuchKey", "GetObject")
        data, etag, written_at = held
        answer: dict[str, Any] = {"Body": _Body(data), "ETag": etag}
        if not self.silent_clock:
            answer["LastModified"] = written_at
            answer["ResponseMetadata"] = {
                "HTTPHeaders": {"date": format_datetime(self.now, usegmt=True)}}
        return answer

    def put_object(self, *, Bucket: str, Key: str, Body: bytes,
                   IfMatch: str | None = None,
                   IfNoneMatch: str | None = None) -> dict[str, Any]:
        self._maybe_fail(Key)
        self.puts.append({"Key": Key, "Body": Body, "IfMatch": IfMatch,
                          "IfNoneMatch": IfNoneMatch})
        held = self.objects.get(Key)
        if IfNoneMatch == "*" and held is not None:
            raise _client_error("PreconditionFailed")
        if IfMatch is not None and (held is None or held[1] != IfMatch):
            raise _client_error("PreconditionFailed")
        # S3's ETag of a plain PUT is the body's MD5: the same bytes, the same
        # tag, which is what a standby's unchanged presence file relies on.
        etag = held[1] if held is not None and held[0] == Body else self._etag()
        self.objects[Key] = (Body, etag, self.now)
        answer: dict[str, Any] = {"ETag": etag}
        if not self.silent_clock:
            answer["ResponseMetadata"] = {
                "HTTPHeaders": {"date": format_datetime(self.now, usegmt=True)}}
        return answer

    def list_objects_v2(self, *, Bucket: str, Prefix: str, Delimiter: str,
                        ContinuationToken: str | None = None) -> dict[str, Any]:
        self._maybe_fail()
        self.listings += 1
        keys = sorted(key for key in self.objects
                      if key.startswith(Prefix) and "/" not in key[len(Prefix):])
        page, rest = keys[:2], keys[2:]      # two per page, so paging is exercised
        if ContinuationToken:
            page, rest = keys[2:], []
        answer: dict[str, Any] = {
            "Contents": [{"Key": key, "ETag": self.objects[key][1],
                          "LastModified": self.objects[key][2]} for key in page],
            "IsTruncated": bool(rest),
            "NextContinuationToken": "more" if rest else ""}
        if not self.silent_clock:
            answer["ResponseMetadata"] = {
                "HTTPHeaders": {"date": format_datetime(self.now, usegmt=True)}}
        return answer

    def delete_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        if self.fail_delete is not None:
            error, self.fail_delete = self.fail_delete, None
            raise error
        self.deletes.append(Key)
        self.objects.pop(Key, None)      # S3 answers 204 for a key that is not there
        return {}

    def get_bucket_versioning(self, *, Bucket: str) -> dict[str, Any]:
        self.versioning_asked += 1
        if self.fail_next is not None:
            error, self.fail_next = self.fail_next, None
            raise error
        return {"Status": self.versioning} if self.versioning else {}

    # --- what a test does to the world ---

    #: How far the host's clock runs from the store's, in seconds: zero unless a
    #: test about the two clocks says otherwise.
    host_offset = 0.0

    def host_clock(self) -> datetime:
        """The host's clock, following the store's — the ordinary case, where
        both machines are on time."""
        return self.now + timedelta(seconds=self.host_offset)

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)

    def lease(self, prefix: str = "") -> dict[str, Any]:
        """What the lease object holds, as a mapping."""
        return dict(json.loads(self.objects[f"{prefix}{OWNER_NAME}"][0].decode()))

    def lease_puts(self) -> list[dict[str, Any]]:
        return [put for put in self.puts if put["Key"].endswith(OWNER_NAME)]

    def file_puts(self) -> list[dict[str, Any]]:
        """The state files this keeper sent — nothing of its own."""
        return [put for put in self.puts
                if not put["Key"].rsplit("/", 1)[-1].startswith(RESERVED_PREFIX)]

    def presence_keys(self, prefix: str = "") -> list[str]:
        return sorted(key for key in self.objects
                      if key.startswith(f"{prefix}{PRESENCE_PREFIX}"))

    def log(self, prefix: str = "") -> list[dict[str, str]]:
        """The instance log's entries, newest first, or none."""
        held = self.objects.get(f"{prefix}{INSTANCES_NAME}")
        if held is None:
            return []
        return list(json.loads(held[0].decode())["entries"])


INSTANCE = "host-a:1"
OTHER = "host-b:2"


def _keeper(config: KeeperConfig | None = None, *, instance: str = INSTANCE,
            holding: bool = True) -> tuple[S3Keeper, _FakeS3]:
    """A keeper over one fake bucket.

    ``holding`` runs the start — the first call little-sister makes — so the keeper
    holds the lease on a fresh prefix, and then forgets that it happened, so a
    test about a save asserts on the save. Taking the lease has its own tests.
    """
    fake = _FakeS3()
    keeper = S3Keeper(config or KeeperConfig(bucket=BUCKET),
                      client_factory=lambda: fake, instance=instance,
                      now=fake.host_clock)
    if holding:
        assert keeper.tick(INTERVAL) is True
        fake.puts.clear()
        fake.gets.clear()
        fake.listings = 0
    return keeper, fake


def _held_by(fake: _FakeS3, who: str, *, ttl: float = 180.0,
             claims: list[dict[str, str]] | None = None, prefix: str = "") -> None:
    """Somebody else's lease, written now."""
    body = json.dumps({"instance": who, "ttl_seconds": ttl,
                       "claims": claims or []}).encode()
    fake.objects[f"{prefix}{OWNER_NAME}"] = (body, fake._etag(), fake.now)


def _graded(keeper: S3Keeper) -> tuple[Any, ...]:
    """Only the lines that grade — the keeper reports facts uncoded beside them."""
    return tuple(line for line in keeper.lines() if line.code is not None)


def _slugs(keeper: S3Keeper) -> list[str]:
    return [line.slug for line in keeper.lines()]


def _line(keeper: S3Keeper, slug: str) -> Any:
    found = [line for line in keeper.lines() if line.slug == slug]
    assert len(found) == 1, f"{slug!r} not exactly once in {_slugs(keeper)}"
    return found[0]


def _logged(call: Any) -> str:
    """What the log record would actually read as — the format string applied to
    its arguments, rather than the arguments alone."""
    message, *args = call.call_args.args
    return str(message) % tuple(args)


class TestTakingTheLease:
    """ADR-0004 decision 3: taken by a conditional write, on a free prefix."""

    def test_a_fresh_prefix_is_taken_with_if_none_match(self) -> None:
        keeper, fake = _keeper(holding=False)

        assert keeper.tick(INTERVAL) is True
        (put,) = fake.lease_puts()
        assert put["IfNoneMatch"] == "*" and put["IfMatch"] is None
        assert keeper.holding

    def test_the_lease_names_this_instance_and_its_ttl(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, lapse_after=3),
                               holding=False)
        keeper.tick(INTERVAL)

        lease = fake.lease()
        assert lease["instance"] == INSTANCE
        assert lease["ttl_seconds"] == 3 * INTERVAL, "lapse_after × interval"
        assert lease["claims"] == []

    def test_a_live_lease_is_somebody_elses_and_this_instance_stands_by(
            self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        fake.advance(40)

        assert keeper.tick(INTERVAL) is False
        assert not keeper.holding
        assert fake.lease_puts() == [], "nothing written while standing by"
        line = _line(keeper, "standby")
        assert line.code == StatusCode.WARN
        assert OTHER in line.text
        assert "40 s ago" in line.text and "in 2m 20s" in line.text
        assert "does not survive" in line.text

    def test_a_lapsed_lease_is_taken_with_if_match_on_what_was_read(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        old_etag = fake.objects[OWNER_NAME][1]
        fake.advance(181)

        assert keeper.tick(INTERVAL) is True
        (put,) = fake.lease_puts()
        assert put["IfMatch"] == old_etag
        assert keeper.holding

    def test_a_lease_given_up_is_taken_at_once(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=0)

        assert keeper.tick(INTERVAL) is True
        assert "(given up)" in keeper.report()

    def test_two_standbys_racing_for_one_lapsed_lease_cannot_both_win(
            self) -> None:
        fake = _FakeS3()
        _held_by(fake, "host-c:3", ttl=180)
        fake.advance(200)
        a = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                     instance=INSTANCE)
        b = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                     instance=OTHER)

        assert a.tick(INTERVAL) is True
        assert b.tick(INTERVAL) is False, "B read the dead lease, then A's landed"
        assert a.holding and not b.holding
        assert INSTANCE in _line(b, "standby").text

    def test_the_takeover_records_who_held_it_and_the_claims_before(
            self, config_root: Path) -> None:
        # `config_root`: the claim's instant is shown through the settings, which
        # are read from a configuration root — an empty one answers with defaults.
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180,
                 claims=[{"instance": "host-c:3", "at": "2026-09-01T00:00:00Z"}])
        fake.advance(400)
        keeper.tick(INTERVAL)

        lease = fake.lease()
        assert [claim["instance"] for claim in lease["claims"]] == [OTHER, "host-c:3"]
        assert lease["claims"][0]["at"] == "2026-09-05T08:21:40Z", \
            "S3's clock at the read, as an ISO instant"
        # whom the lease was taken from is a fact: the report, no line (ADR-0076)
        assert "predecessor" not in _slugs(keeper)
        report = keeper.report()
        assert OTHER in report and "lapsed 3m 40s before" in report
        assert "1 earlier claim" in report

    def test_the_history_is_capped_and_the_oldest_falls_off(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=0,
                 claims=[{"instance": f"host-{n}", "at": ""} for n in range(4)])
        keeper.tick(INTERVAL)

        claims = [claim["instance"] for claim in fake.lease()["claims"]]
        assert claims == [OTHER, "host-0", "host-1", "host-2"]

    def test_a_lease_whose_age_cannot_be_measured_is_alive(self) -> None:
        """Not knowing is not a lapse: a standby that took a lease it could not
        read the age of would be the second writer this exists to prevent."""
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        fake.silent_clock = True
        fake.advance(10_000)

        assert keeper.tick(INTERVAL) is False
        assert "unknown time" in _line(keeper, "standby").text

    def test_a_lease_nothing_of_ours_wrote_is_nobodys(self) -> None:
        keeper, fake = _keeper(holding=False)
        fake.objects[OWNER_NAME] = (b"not json at all", '"e"', fake.now)

        assert keeper.tick(INTERVAL) is True
        assert "did not write a lease" in keeper.report()

    def test_a_first_look_happens_on_the_first_call_not_at_construction(
            self) -> None:
        fake = _FakeS3()
        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                          instance=INSTANCE)
        assert fake.gets == [] and fake.puts == []

        keeper.list()

        assert keeper.holding, "the restore's listing is the first call, and the " \
                               "lines are right from the first tick"

    def test_a_bucket_that_cannot_be_reached_is_a_line_and_is_tried_again(
            self) -> None:
        keeper, fake = _keeper(holding=False)
        fake.fail_lease = EndpointConnectionError(endpoint_url="https://s3")

        assert keeper.tick(INTERVAL) is False
        line = _line(keeper, "unreachable")
        assert line.code == StatusCode.WARN and "locally until it can" in line.text

        assert keeper.tick(INTERVAL) is True
        assert "unreachable" not in _slugs(keeper)


class TestTheHeartbeat:
    """ADR-0004 decisions 3 and 4: renewed every interval, and a refused renewal
    is the holder demoting itself *before* it writes."""

    def test_it_renews_with_if_match_on_the_lease_it_last_wrote(self) -> None:
        keeper, fake = _keeper()
        etag = fake.objects[OWNER_NAME][1]

        assert keeper.tick(INTERVAL) is True
        (put,) = fake.lease_puts()
        assert put["IfMatch"] == etag
        assert fake.lease()["instance"] == INSTANCE

    def test_the_ttl_follows_the_interval_the_layer_gives(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, lapse_after=2))

        keeper.tick(15)

        assert fake.lease()["ttl_seconds"] == 30

    def test_a_refused_heartbeat_demotes_before_any_save(self) -> None:
        keeper, fake = _keeper()
        _held_by(fake, OTHER, ttl=180)          # taken while this one was away

        assert keeper.tick(INTERVAL) is False
        assert not keeper.holding
        demoted = _line(keeper, "demoted")
        assert demoted.code == StatusCode.WARN
        assert OTHER in demoted.text and "stopped writing" in demoted.text
        assert OTHER in _line(keeper, "standby").text
        with pytest.raises(KeeperStandby):
            keeper.save("a.json", b"x")

    def test_our_own_re_sent_heartbeat_is_no_demotion(self) -> None:
        """The client is allowed two attempts, so a heartbeat whose answer was
        lost is re-sent against an ETag it has itself replaced."""
        keeper, _fake = _keeper()
        keeper.tick(INTERVAL)
        # the answer to that one was lost: the keeper still holds the old ETag
        keeper._lease_etag = "stale"

        assert keeper.tick(INTERVAL) is True
        assert keeper.holding
        assert "demoted" not in _slugs(keeper)

    def test_a_demoted_holder_takes_the_lease_back_when_it_is_free(self) -> None:
        keeper, fake = _keeper()
        _held_by(fake, OTHER, ttl=180)
        keeper.tick(INTERVAL)
        fake.advance(181)

        assert keeper.tick(INTERVAL) is True
        assert keeper.holding
        assert "demoted" not in _slugs(keeper)
        assert OTHER in keeper.report()

    def test_a_missed_heartbeat_is_counted_and_no_save_follows(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, lapse_after=3))
        fake.fail_lease = EndpointConnectionError(endpoint_url="https://s3")

        with mock.patch.object(aws_keeper, "logger") as log:
            assert keeper.tick(INTERVAL) is False
        assert keeper.holding, "one missed heartbeat is not a lapse"
        assert "(1 of 3)" in _logged(log.warning)
        assert keeper.tick(INTERVAL) is True, "and the next one lands"

    def test_lapse_after_missed_heartbeats_is_a_demotion(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, lapse_after=2))
        fake.fail_lease_always = EndpointConnectionError(endpoint_url="https://s3")

        assert keeper.tick(INTERVAL) is False
        assert keeper.tick(INTERVAL) is False
        assert not keeper.holding
        assert "2 heartbeats in a row" in _line(keeper, "demoted").text

        fake.fail_lease_always = None
        assert keeper.tick(INTERVAL) is True, "free again, so taken back"


class TestSaves:
    """ADR-0004 decision 3: unconditional behind a heartbeat that landed."""

    def test_a_save_carries_no_condition(self) -> None:
        keeper, fake = _keeper()

        keeper.save("events.json", b"[]")

        (put,) = fake.file_puts()
        assert put["IfMatch"] is None and put["IfNoneMatch"] is None
        assert fake.objects["events.json"][0] == b"[]"

    def test_a_save_lands_on_whatever_is_there(self) -> None:
        keeper, fake = _keeper()
        fake.objects["events.json"] = (b"theirs", '"x"', fake.now)

        keeper.save("events.json", b"ours")

        assert fake.objects["events.json"][0] == b"ours"

    def test_a_save_without_the_lease_is_refused_here_not_in_the_bucket(
            self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER)
        keeper.tick(INTERVAL)

        with pytest.raises(KeeperStandby, match="does not hold the lease"):
            keeper.save("events.json", b"x")
        assert fake.file_puts() == []

    def test_a_prefix_is_where_the_keys_live(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, prefix="state/"))

        keeper.save("events.json", b"x")

        assert "state/events.json" in fake.objects
        assert "state/" + OWNER_NAME in fake.objects


class TestClose:
    """ADR-0004 decision 8: release is a heartbeat of zero."""

    def test_it_gives_the_lease_up_with_a_ttl_of_zero(self) -> None:
        keeper, fake = _keeper()

        keeper.close()

        assert fake.lease()["ttl_seconds"] == 0
        assert not keeper.holding
        (put,) = fake.lease_puts()
        assert put["IfMatch"] is not None, "still this instance's to give up"

    def test_a_standby_has_nothing_to_give_up(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER)
        keeper.tick(INTERVAL)

        keeper.close()

        assert fake.lease_puts() == []

    def test_a_close_that_cannot_reach_the_bucket_raises_nothing(self) -> None:
        keeper, fake = _keeper()
        fake.fail_lease = EndpointConnectionError(endpoint_url="https://s3")

        keeper.close()

        assert keeper.holding, "it lapses on its own"

    def test_the_next_standby_takes_a_given_up_lease_on_its_next_read(
            self) -> None:
        keeper, fake = _keeper()
        other = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=OTHER)
        assert other.tick(INTERVAL) is False

        keeper.close()

        assert other.tick(INTERVAL) is True


class TestTheLines:
    """ADR-0004 decision 9: by the loss principle — nothing here is ERROR."""

    def test_a_holder_says_so_in_its_report_and_writes_no_line(self) -> None:
        keeper, _fake = _keeper()

        assert keeper.lines() == ()
        report = keeper.report()
        assert INSTANCE in report and "every 1m" in report
        assert "after 3 missed" in report

    def test_nothing_this_keeper_says_is_error(self) -> None:
        keeper, fake = _keeper()
        _held_by(fake, OTHER)
        keeper.tick(INTERVAL)
        fake.fail_lease_always = EndpointConnectionError(endpoint_url="https://s3")
        keeper.tick(INTERVAL)

        assert {line.code for line in _graded(keeper)} == {StatusCode.WARN}

    def test_instants_in_a_line_are_shown_through_the_settings(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=0,
                 claims=[{"instance": "host-c:3", "at": "2026-09-04T20:32:39Z"}])
        with mock.patch("little_sister_aws.keeper.local_time",
                        lambda moment, fmt=None: f"<{moment.isoformat()}>"):
            keeper.tick(INTERVAL)
            report = keeper.report()

        assert "<2026-09-04T20:32:39+00:00>" in report
        assert "GMT" not in report

    def test_a_lease_written_by_the_first_shape_is_still_read(self) -> None:
        """Buckets exist with the earlier claim format — HTTP dates — and one of
        them must not become unreadable."""
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=0,
                 claims=[{"instance": "host-c:3",
                          "at": "Fri, 04 Sep 2026 20:32:39 GMT"}])
        with mock.patch("little_sister_aws.keeper.local_time",
                        lambda moment, fmt=None: "shown"):
            keeper.tick(INTERVAL)
            assert "the most recent at shown" in keeper.report()


class TestVersioning:
    """ADR-0004 decision 10: checked once at startup, off is what is wanted."""

    def test_enabled_is_a_warn_line_naming_the_cost(self) -> None:
        fake = _FakeS3()
        fake.versioning = "Enabled"
        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                          instance=INSTANCE)

        keeper.tick(INTERVAL)

        line = _line(keeper, "versioning")
        assert line.code == StatusCode.WARN
        assert BUCKET in line.text and "43,000" in line.text

    @pytest.mark.parametrize("status", ["", "Suspended"])
    def test_off_and_suspended_are_no_line(self, status: str) -> None:
        fake = _FakeS3()
        fake.versioning = status
        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                          instance=INSTANCE)

        keeper.tick(INTERVAL)

        assert "versioning" not in _slugs(keeper)

    def test_no_permission_to_ask_is_a_fact_in_the_report_that_says_so(self) -> None:
        fake = _FakeS3()
        fake.fail_next = _client_error("AccessDenied", "GetBucketVersioning")
        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                          instance=INSTANCE)

        keeper.tick(INTERVAL)

        assert "versioning" not in _slugs(keeper)
        report = keeper.report()
        assert "Could not check" in report and "AccessDenied" in report

    def test_it_is_asked_once_for_the_life_of_the_process(self) -> None:
        keeper, fake = _keeper()
        for _ in range(5):
            keeper.tick(INTERVAL)

        assert fake.versioning_asked == 1


class TestReadingAndListing:
    def test_a_key_that_is_not_there_is_nothing_kept_yet(self) -> None:
        keeper, _fake = _keeper()

        assert keeper.load("events.json") is None

    def test_reading_needs_no_lease(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER)
        fake.objects["events.json"] = (b"theirs", '"x"', fake.now)

        assert keeper.load("events.json") == b"theirs"
        assert not keeper.holding

    def test_a_read_that_is_refused_is_not_an_absent_file(self) -> None:
        """Absence is a first start; anything else is the ERROR line saying the
        state was not restored, and the two must not be confused."""
        keeper, fake = _keeper()
        fake.fail_next = _client_error("AccessDenied", "GetObject")

        with pytest.raises(ClientError):
            keeper.load("events.json")

    def test_listing_pages_and_strips_the_prefix(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, prefix="state/"))
        for name in ("a.json", "b.json", "c.json"):
            fake.objects[f"state/{name}"] = (b"x", '"e"', fake.now)

        assert keeper.list() == ["a.json", "b.json", "c.json"]
        assert fake.listings == 2, "the second page has to be asked for"

    def test_the_lease_is_never_offered_as_a_state_file(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, prefix="state/"))
        fake.objects["state/a.json"] = (b"x", '"e"', fake.now)

        assert keeper.list() == ["a.json"]

    def test_a_key_under_a_deeper_prefix_is_not_this_instances_state(self) -> None:
        keeper, fake = _keeper(KeeperConfig(bucket=BUCKET, prefix="state/"))
        fake.objects["state/a.json"] = (b"x", '"e"', fake.now)
        fake.objects["state/other-instance/a.json"] = (b"x", '"e"', fake.now)

        assert keeper.list() == ["a.json"]


class TestTheCredentialRetry:
    """The keeper outlives its credentials, which every other caller of the
    identity seam does not."""

    def test_a_stale_credential_re_opens_the_session_once_and_retries(self) -> None:
        fake = _FakeS3()
        opened: list[int] = []

        def factory() -> Any:
            opened.append(1)
            return fake

        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=factory,
                          instance=INSTANCE)
        keeper.tick(INTERVAL)                            # opens the client, holds
        keeper.save("a.json", b"first")
        fake.fail_next = _client_error("ExpiredToken")

        with mock.patch.object(aws_keeper, "logger"):
            keeper.save("a.json", b"second")

        assert len(opened) == 2, "the session is opened again, once"
        assert fake.objects["a.json"][0] == b"second"

    def test_a_refusal_is_not_a_credential_error_and_is_not_retried(self) -> None:
        fake = _FakeS3()
        opened: list[int] = []

        def factory() -> Any:
            opened.append(1)
            return fake

        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=factory,
                          instance=INSTANCE)
        keeper.tick(INTERVAL)
        fake.fail_next = _client_error("AccessDenied")

        with pytest.raises(ClientError):
            keeper.save("a.json", b"x")
        assert len(opened) == 1

    def test_a_transport_failure_is_not_retried_either(self) -> None:
        fake = _FakeS3()
        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                          instance=INSTANCE)
        keeper.tick(INTERVAL)
        fake.fail_next = EndpointConnectionError(endpoint_url="https://s3")

        with pytest.raises(EndpointConnectionError):
            keeper.load("a.json")

    def test_a_stale_credential_on_the_heartbeat_is_the_same_one_retry(
            self) -> None:
        fake = _FakeS3()
        opened: list[int] = []

        def factory() -> Any:
            opened.append(1)
            return fake

        keeper = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=factory,
                          instance=INSTANCE)
        keeper.tick(INTERVAL)
        fake.fail_lease = _client_error("ExpiredToken")

        with mock.patch.object(aws_keeper, "logger"):
            assert keeper.tick(INTERVAL) is True

        assert len(opened) == 2
        assert keeper.holding


class TestTheConfiguration:
    def _write(self, root: Path, body: str) -> None:
        (root / "aws-keeper.yaml").write_text(body, encoding="utf-8")

    def test_a_file_that_is_not_a_mapping_is_refused_by_what_it_is(
            self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, "- bucket\n- prefix\n")

        with pytest.raises(KeeperConfigError, match="mapping of settings, got list"):
            load_keeper_config()

    def test_a_file_that_is_not_yaml_at_all_is_refused(
            self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, "bucket: [unclosed\n")

        with pytest.raises(KeeperConfigError, match="could not be read"):
            load_keeper_config()

    def test_a_value_that_is_not_a_string_is_refused_by_name(
            self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, "bucket: 3\n")

        with pytest.raises(KeeperConfigError, match="must be a non-empty string"):
            load_keeper_config()

    def test_no_file_means_no_keeper_which_is_a_shape_not_a_gap(
            self, config_root: Path) -> None:
        aws_keeper.declare_aspect()

        assert load_keeper_config() is None

    def test_an_empty_file_means_the_same(self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, "")

        assert load_keeper_config() is None

    def test_a_bucket_is_the_whole_of_what_is_required(
            self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"bucket: {BUCKET}\n")

        config = load_keeper_config()

        assert config == KeeperConfig(bucket=BUCKET)

    def test_every_key_it_takes(self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"""
bucket: {BUCKET}
prefix: /instances/one/
identity: live
region: eu-central-1
lapse_after: 5
""")

        config = load_keeper_config()

        assert config == KeeperConfig(bucket=BUCKET, prefix="instances/one/",
                                      identity="live", region="eu-central-1",
                                      lapse_after=5)

    @pytest.mark.parametrize("written", ["0", "-1", "two", "1.5", "true"])
    def test_lapse_after_is_a_positive_integer_or_refused(
            self, config_root: Path, written: str) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"bucket: {BUCKET}\nlapse_after: {written}\n")

        with pytest.raises(KeeperConfigError, match="'lapse_after'"):
            load_keeper_config()

    def test_lapse_after_left_empty_is_a_typo(self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"bucket: {BUCKET}\nlapse_after:\n")

        with pytest.raises(KeeperConfigError, match="left empty"):
            load_keeper_config()

    def test_lapse_after_defaults_to_three(self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"bucket: {BUCKET}\n")

        config = load_keeper_config()

        assert config is not None and config.lapse_after == 3

    @pytest.mark.parametrize("written,key", [
        ("state", "state/"),          # a prefix is a place, so it ends in a
        ("state/", "state/"),         # separator whether or not somebody wrote one
        ("/state", "state/"),         # and a leading one is the bucket's root,
        ("/a/b/", "a/b/"),            # which is where every key already starts
    ])
    def test_a_prefix_is_normalized_to_end_in_one_separator(
            self, config_root: Path, written: str, key: str) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"bucket: {BUCKET}\nprefix: {written}\n")

        config = load_keeper_config()

        assert config is not None
        assert config.prefix == key
        assert S3Keeper(config, client_factory=lambda: None  # type: ignore[arg-type,return-value]
                        ).key("events.json") == f"{key}events.json"

    def test_a_file_without_a_bucket_is_refused(self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, "prefix: state/\n")

        with pytest.raises(KeeperConfigError, match="'bucket' is required"):
            load_keeper_config()

    def test_an_unknown_key_is_refused_and_the_known_ones_named(
            self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"bucket: {BUCKET}\nprefx: state/\n")

        with pytest.raises(KeeperConfigError) as caught:
            load_keeper_config()
        assert "'prefx'" in str(caught.value)
        assert "bucket" in str(caught.value)

    def test_a_key_left_empty_is_a_typo_not_a_value(
            self, config_root: Path) -> None:
        aws_keeper.declare_aspect()
        self._write(config_root, f"bucket: {BUCKET}\nprefix:   \n")

        with pytest.raises(KeeperConfigError, match="'prefix'"):
            load_keeper_config()


class TestRegistration:
    def test_it_registers_the_keeper_little_sister_will_call(
            self, config_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeS3()
        monkeypatch.setattr(aws_keeper, "_new_client",
                            lambda identity, config: fake)
        (config_root / "aws-keeper.yaml").write_text(
            f"bucket: {BUCKET}\nprefix: state\n", encoding="utf-8")

        keeper = register_s3_keeper()

        registered = ls_keeper.registered_keeper()
        assert registered is not None
        assert registered.name == "s3"
        assert registered.keeper is keeper
        assert registered.package == "little_sister_aws"

    def test_no_file_registers_nothing_at_all(
            self, config_root: Path) -> None:
        assert register_s3_keeper() is None
        assert ls_keeper.registered_keeper() is None

    def test_the_session_is_not_opened_at_registration(
            self, config_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # A bucket that cannot be reached must be a line on /little-sister, not an
        # import that fails — so nothing here touches AWS.
        opened: list[int] = []
        monkeypatch.setattr(aws_keeper, "_new_client",
                            lambda identity, config: opened.append(1))
        (config_root / "aws-keeper.yaml").write_text(
            f"bucket: {BUCKET}\n", encoding="utf-8")

        register_s3_keeper()

        assert opened == []

    def test_an_identity_nobody_declared_is_refused(
            self, config_root: Path) -> None:
        (config_root / "aws-keeper.yaml").write_text(
            f"bucket: {BUCKET}\nidentity: live\n", encoding="utf-8")

        with pytest.raises(KeeperConfigError, match=r"config/aws\.yaml does not"):
            register_s3_keeper()

    def test_a_declared_identity_is_the_one_the_client_is_built_from(
            self, config_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[NamedIdentity] = []
        monkeypatch.setattr(
            aws_keeper, "_new_client",
            lambda identity, config: seen.append(identity) or _FakeS3())
        live = NamedIdentity(name="live", identity=Identity(role_arn=ROLE))
        keeper = register_s3_keeper(KeeperConfig(bucket=BUCKET, identity="live"),
                                    {"live": live})
        assert keeper is not None

        keeper.load("a.json")

        assert seen == [live]

    def test_no_identity_named_is_the_ambient_chain(
            self, config_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[NamedIdentity] = []
        monkeypatch.setattr(
            aws_keeper, "_new_client",
            lambda identity, config: seen.append(identity) or _FakeS3())
        keeper = register_s3_keeper(KeeperConfig(bucket=BUCKET), {})
        assert keeper is not None

        keeper.load("a.json")

        assert seen[0].name == ""
        assert seen[0].identity == Identity()


class TestTheClientBudget:
    """The save runs on little-sister's scheduler tick, so boto3's defaults would
    be minutes of checks nobody ran."""

    def test_the_client_is_bounded_in_seconds(self) -> None:
        config = aws_keeper.CLIENT_CONFIG

        assert config.connect_timeout == 2
        assert config.read_timeout == 5
        assert config.retries == {"mode": "standard", "max_attempts": 2}

    def test_the_bucket_region_is_the_keepers_own_not_the_identitys(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        # An identity's `region:` says where its *secrets* are read; a deployment
        # may keep its state somewhere else entirely.
        built: dict[str, Any] = {}

        class _Session:
            def client(self, service: str, **kwargs: Any) -> str:
                built.update({"service": service, **kwargs})
                return "client"

        monkeypatch.setattr(aws_keeper, "open_session", lambda identity: _Session())
        identity = NamedIdentity(name="live", identity=Identity(role_arn=ROLE),
                                 region="us-east-1")

        aws_keeper._new_client(identity, KeeperConfig(bucket=BUCKET,
                                                      region="eu-central-1"))

        assert built["service"] == "s3"
        assert built["region_name"] == "eu-central-1"
        assert built["config"] is aws_keeper.CLIENT_CONFIG


class TestTwoInstancesOnePrefix:
    """The whole seam from little-sister's side, because what the lease exists
    for is a sequence rather than a call: a second instance on one prefix stands
    by and says so, takes over when the first one is gone — and, since authority
    follows the lease (little-sister ADR-0077), takes over with the store's state
    and not its own."""

    def _instance(self, tmp: Path, where: str, name: str, fake: _FakeS3
                  ) -> tuple[StateLayer, S3Keeper, dict[str, Any]]:
        """An instance: its state layer over its own directory, its keeper on
        the shared fake, and the one dict its ``maintenance.json`` is the
        serialization of — kept, and adopted back into it."""
        directory = tmp / where
        directory.mkdir()
        pins: dict[str, Any] = {"pins": []}
        state = StateLayer(directory, interval_seconds=int(INTERVAL))
        state.keep("maintenance.json", lambda: pins,
                   restore=lambda payload: pins.update(payload))
        keeper = S3Keeper(KeeperConfig(bucket=BUCKET, prefix="prod/"),
                          client_factory=lambda: fake, instance=name,
                          now=fake.host_clock)
        return state, keeper, pins

    @staticmethod
    def _as(keeper: S3Keeper) -> None:
        """The registry names one keeper per process; two instances in one test
        take turns being it."""
        ls_keeper.register_keeper("s3", keeper, replace=True)

    def test_the_second_stands_by_and_takes_over_with_the_stores_state(
            self, tmp_path: Path) -> None:
        """The *done when*: started while the first still writes, the second ends
        holding the first's last state, with its own beside it as ``.bak``."""
        fake = _FakeS3()
        a_state, a_keeper, a_pins = self._instance(tmp_path, "a", INSTANCE, fake)
        b_state, b_keeper, b_pins = self._instance(tmp_path, "b", OTHER, fake)

        # A is alone: it takes the lease at its first call and writes.
        self._as(a_keeper)
        a_state.restore_from_keeper()
        a_pins["pins"] = ["/db"]
        a_state.flush()
        assert a_keeper.holding
        assert _graded(a_keeper) == ()
        assert b"/db" in fake.objects["prod/maintenance.json"][0]

        # B starts on the same prefix: it restores A's state — reading needs no
        # lease — and stands by, saying so at WARN. Nothing of B's reaches the
        # bucket, and the state layer says nothing either: a declined tick is
        # not a failed save.
        fake.advance(20)
        self._as(b_keeper)
        b_state.restore_from_keeper()
        assert json.loads((tmp_path / "b" / "maintenance.json").read_text()) \
            == {"pins": ["/db"]}
        b_pins["pins"] = ["/db", "/queue"]
        b_state.flush()
        assert not b_keeper.holding
        standby = _line(b_keeper, "standby")
        assert standby.code == StatusCode.WARN and INSTANCE in standby.text
        assert b_state.lines() == ()
        assert b"/queue" not in fake.objects["prod/maintenance.json"][0]

        # A keeps writing, and now sees B standing by — a WARN on its child that
        # clears when B is gone, since a second instance that stays is a
        # misconfiguration.
        fake.advance(40)
        self._as(a_keeper)
        a_pins["pins"] = ["/db", "/cache"]
        a_state.flush()
        assert a_keeper.holding
        standbys = _line(a_keeper, "standbys")
        assert standbys.code == StatusCode.WARN and OTHER in standbys.text
        assert b"/cache" in fake.objects["prod/maintenance.json"][0]

        # A is killed — no close. B reads a lease that is still alive …
        fake.advance(100)
        self._as(b_keeper)
        b_state.flush()
        assert not b_keeper.holding

        # … and then one that has lapsed, and takes it. Authority follows the
        # lease: A wrote the truth up to the moment it lapsed, so B adopts what
        # the store changed since B read it — the process holds A's last pins,
        # B's own are beside the file as .bak, and the store keeps A's copy.
        fake.advance(100)
        b_state.flush()
        assert b_keeper.holding
        assert b_pins == {"pins": ["/db", "/cache"]}
        assert json.loads((tmp_path / "b" / "maintenance.json").read_text()) \
            == {"pins": ["/db", "/cache"]}
        assert json.loads((tmp_path / "b" / "maintenance.json.bak").read_text()) \
            == {"pins": ["/db", "/queue"]}
        assert b"/queue" not in fake.objects["prod/maintenance.json"][0]
        assert fake.lease("prod/")["instance"] == OTHER
        assert INSTANCE in b_keeper.report()
        takeover = _line(b_keeper, "takeover")
        assert takeover.code == StatusCode.WARN
        assert "1 file (maintenance.json)" in takeover.text
        assert "/little-sister/state" in takeover.text
        assert b_state.lines() == () and "maintenance.json.bak" in b_state.report()
        # saving resumes from the store's state; the line is WARN for ten
        # minutes — long enough to be noticed — and a fact after
        fake.advance(60)
        b_pins["pins"] = ["/db", "/cache", "/web"]
        b_state.flush()
        assert _line(b_keeper, "takeover").code == StatusCode.WARN
        assert b"/web" in fake.objects["prod/maintenance.json"][0]
        fake.advance(600)
        b_state.flush()
        assert "takeover" not in _slugs(b_keeper)
        assert "1 file (maintenance.json)" in b_keeper.report()

    def test_the_successor_of_a_dead_holder_continues_with_its_own_state(
            self, tmp_path: Path) -> None:
        """The other half of the *done when*: a second started after the first
        is gone — nobody wrote since it read the store — ends with its own."""
        fake = _FakeS3()
        a_state, a_keeper, a_pins = self._instance(tmp_path, "a", INSTANCE, fake)
        self._as(a_keeper)
        a_state.restore_from_keeper()
        a_pins["pins"] = ["/db"]
        a_state.flush()
        fake.advance(400)          # A is dead; its lease lapsed a while ago

        b_state, b_keeper, b_pins = self._instance(tmp_path, "b", OTHER, fake)
        self._as(b_keeper)
        b_state.restore_from_keeper()
        assert b_keeper.holding, "taken at the restore's listing"
        assert b_pins == {"pins": []}
        b_state.read("maintenance.json")
        b_pins["pins"] = ["/db", "/queue"]
        b_state.flush()
        assert b_pins == {"pins": ["/db", "/queue"]}
        assert not (tmp_path / "b" / "maintenance.json.bak").exists()
        assert b"/queue" in fake.objects["prod/maintenance.json"][0]
        assert "takeover" not in _slugs(b_keeper)
        assert _graded(b_keeper) == ()

    def test_a_graceful_stop_hands_over_without_the_wait(
            self, tmp_path: Path) -> None:
        fake = _FakeS3()
        a_state, a_keeper, _a_pins = self._instance(tmp_path, "a", INSTANCE, fake)
        b_state, b_keeper, _b_pins = self._instance(tmp_path, "b", OTHER, fake)
        a_state.keep("events.json", lambda: {"events": [1]})

        self._as(a_keeper)
        a_state.restore_from_keeper()
        a_state.flush()
        self._as(b_keeper)
        b_state.restore_from_keeper()
        b_state.flush()
        assert not b_keeper.holding

        self._as(a_keeper)
        a_state.shutdown()
        assert fake.lease("prod/")["ttl_seconds"] == 0

        fake.advance(1)
        self._as(b_keeper)
        b_state.flush()
        assert b_keeper.holding, "one second later, not three minutes"


class TestTheTwoActions:
    """ADR-0004 decision 9: *take over* and *release* on the keeper's child,
    through little-sister's action seam, for an operator who knows what they
    are doing."""

    def test_take_over_writes_the_lease_over_the_holders(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        assert keeper.tick(INTERVAL) is False

        said = keeper.take_over()

        assert keeper.holding
        assert OTHER in said and "adopted now" in said
        (put,) = fake.lease_puts()[-1:]
        assert put["IfMatch"] is None and put["IfNoneMatch"] is None, "regardless"
        assert fake.lease()["instance"] == INSTANCE
        assert fake.lease()["claims"][0]["instance"] == OTHER
        assert INSTANCE in keeper.report()
        assert fake.log()[0]["kind"] == "took" and fake.log()[0]["how"] == "operator"

    def test_the_holder_taken_over_from_is_demoted_at_its_next_heartbeat(
            self) -> None:
        holder, fake = _keeper()
        other = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=OTHER, now=fake.host_clock)
        assert other.tick(INTERVAL) is False
        other.take_over()

        assert holder.tick(INTERVAL) is False
        assert not holder.holding
        assert OTHER in _line(holder, "demoted").text

    def test_an_operators_take_over_reads_as_one_on_both_pages_within_an_interval(
            self) -> None:
        """What the first two-instance run showed: the taker's `predecessor` said
        *lapsed 0 s before* of a lease that never lapsed, and the holder's page
        said *holds* until its next heartbeat. Now the taker says it was an
        operator's and how fresh the holder's last heartbeat was, the lease
        carries how it was taken, and the refused heartbeat says the same."""
        holder, fake = _keeper()
        fake.advance(12)
        taker = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=OTHER, now=fake.host_clock)
        assert taker.tick(INTERVAL) is False
        taker.take_over()

        report = taker.report()
        assert "on an operator's request" in report
        assert "its last heartbeat was 12 s ago" in report
        assert "learns of this at its next heartbeat, within 1m" in report
        assert "lapsed" not in report
        assert fake.lease()["how"] == "operator"
        # the holder's next heartbeat, within one interval, is refused and says so
        fake.advance(30)
        assert holder.tick(INTERVAL) is False
        demoted = _line(holder, "demoted")
        assert f"taken by {OTHER} on an operator's request" in demoted.text
        # and the taker's own heartbeats keep saying how it came by the lease
        fake.advance(30)
        assert taker.tick(INTERVAL) is True
        assert fake.lease()["how"] == "operator"

    def test_a_lapsed_and_a_given_up_lease_still_read_as_such(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=60)
        fake.advance(72)
        assert keeper.tick(INTERVAL) is True
        report = keeper.report()
        assert "lapsed 12 s before" in report and "operator" not in report
        assert fake.lease()["how"] == "lapsed"
        other, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=0)
        assert other.tick(INTERVAL) is True
        assert "(given up)" in other.report()
        assert fake.lease()["how"] == "released"

    def test_the_demoted_holders_log_line_carries_the_take_over(self) -> None:
        """A standby does not list, so its `instances` line would go stale; the
        lease naming a holder it did not know is its signal to read the log."""
        holder, fake = _keeper()
        taker = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=OTHER, now=fake.host_clock)
        taker.tick(INTERVAL)
        taker.take_over()
        fake.advance(30)
        assert holder.tick(INTERVAL) is False
        assert f"{OTHER} took the lease from {INSTANCE} (operator)" in holder.report()
        # the same holder next interval: no read; a new one: one read
        log_gets = len([key for key in fake.gets if key == INSTANCES_NAME])
        fake.advance(60)
        holder.tick(INTERVAL)
        assert len([key for key in fake.gets if key == INSTANCES_NAME]) == log_gets
        third = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance="host-c:3", now=fake.host_clock)
        third.take_over()
        log_gets = len([key for key in fake.gets if key == INSTANCES_NAME])
        fake.advance(60)
        holder.tick(INTERVAL)
        assert len([key for key in fake.gets if key == INSTANCES_NAME]) == log_gets + 1
        assert f"host-c:3 took the lease from {OTHER} (operator)" in holder.report()

    def test_take_over_on_a_free_prefix_and_on_the_holder_itself(self) -> None:
        keeper, fake = _keeper(holding=False)
        assert "the prefix was free" in keeper.take_over()
        assert keeper.holding
        puts = len(fake.lease_puts())
        # on the holder the action is the flush the seam runs after it: the
        # sentence says so, and the keeper itself touches nothing
        said = keeper.take_over()
        assert "holds the lease" in said and "written to the store now" in said
        assert len(fake.lease_puts()) == puts

    def test_the_seams_flush_after_take_over_adopts_and_saves_in_the_click(
            self, tmp_path: Path) -> None:
        """What the library's route does after the handler: the layer's flush —
        the keeper's tick, the adoption, the save — so a take-over needs no wait
        for an interval. Modelled here as the handler followed by ``flush()``."""
        fake = _FakeS3()
        holder = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                          instance=INSTANCE, now=fake.host_clock)
        ls_keeper.register_keeper("s3", holder, replace=True)
        holder_state = StateLayer(tmp_path / "a", interval_seconds=int(INTERVAL))
        holder_state.keep("maintenance.json", lambda: {"pins": ["/db"]})
        holder_state.restore_from_keeper()
        holder_state.flush()
        assert b"/db" in fake.objects["maintenance.json"][0]

        taker = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=OTHER, now=fake.host_clock)
        ls_keeper.register_keeper("s3", taker, replace=True)
        pins: dict[str, Any] = {"pins": []}
        taker_state = StateLayer(tmp_path / "b", interval_seconds=int(INTERVAL))
        taker_state.keep("maintenance.json", lambda: pins,
                         restore=lambda payload: pins.update(payload))
        taker_state.tick()                       # standing by: nothing flushed yet
        fake.advance(30)

        taker.take_over()
        taker_state.flush()                      # what the route does next

        assert taker.holding
        assert pins == {"pins": ["/db"]}, "adopted in the click"
        assert (tmp_path / "b" / "maintenance.json").exists()
        assert _line(taker, "takeover").code == StatusCode.WARN

    def test_release_gives_the_lease_up_and_does_not_take_it_back_alone(
            self) -> None:
        keeper, fake = _keeper()

        said = keeper.release()

        assert not keeper.holding
        assert "released the lease" in said and "take over" in said
        (put,) = fake.lease_puts()
        assert json.loads(put["Body"])["ttl_seconds"] == 0
        assert put["IfMatch"] is not None
        released = _line(keeper, "released")
        assert released.code == StatusCode.WARN, "pins set here are lost"
        assert "nothing of its state reaches the store" in released.text
        assert "take over" in released.text
        assert fake.log()[0] == {**fake.log()[0], "kind": "released", "how": "operator"}
        # the next tick reads a free lease and leaves it free — the release was
        # pressed for somebody else
        fake.advance(60)
        assert keeper.tick(INTERVAL) is False
        assert not keeper.holding
        assert fake.lease()["ttl_seconds"] == 0
        assert fake.presence_keys(), "standing by, and saying so"

    def test_a_released_instance_is_an_ordinary_standby_once_another_has_held(
            self) -> None:
        """The suppression has a natural end: once another instance has held
        the lease, the released one takes a lapsed lease by the normal rule."""
        keeper, fake = _keeper()
        keeper.release()
        fake.advance(60)
        assert keeper.tick(INTERVAL) is False, "not taken back alone"
        other = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=OTHER, now=fake.host_clock)
        assert other.tick(INTERVAL) is True
        fake.advance(60)
        assert keeper.tick(INTERVAL) is False
        assert OTHER in _line(keeper, "standby").text
        assert "released" not in _slugs(keeper)
        fake.advance(200)                      # the other dies; its lease lapses
        assert keeper.tick(INTERVAL) is True
        assert keeper.holding

    def test_take_over_takes_a_released_lease_back(self) -> None:
        keeper, fake = _keeper()
        keeper.release()
        assert "released" in _slugs(keeper)
        assert "took the lease" in keeper.take_over()
        assert keeper.holding
        assert "released" not in _slugs(keeper)
        assert fake.log()[0]["how"] == "operator"

    def test_release_on_a_standby_does_nothing(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        keeper.tick(INTERVAL)
        assert "does not hold" in keeper.release()
        assert fake.lease()["instance"] == OTHER

    def test_registration_offers_both_on_the_keepers_child(
            self, config_root: Path) -> None:
        (config_root / "aws-keeper.yaml").write_text("bucket: b\n")
        with mock.patch("little_sister_aws.keeper.this_instance") as mark:
            mark.return_value.mark = INSTANCE
            keeper = register_s3_keeper()
        assert keeper is not None
        actions = self_report.actions_for(aws_keeper.ASPECT)
        assert [(action.slug, action.label) for action in actions] == [
            ("take-over", "Take over"), ("release", "Release")]
        assert actions[0].handler == keeper.take_over
        assert actions[1].handler == keeper.release
        (registration,) = self_report.registered_contributors()
        assert registration.title == "S3 keeper"


class TestTheTakeoverThatAdopts:
    """ADR-0004 decision 4 as rewritten: the keeper remembers the ETag of every
    file it loaded or saved, answers ``changed_since_sync()`` from one listing,
    and says what a takeover adopted."""

    def test_the_etag_of_every_load_and_save_is_remembered(self) -> None:
        keeper, fake = _keeper()
        fake.objects["a.json"] = (b"a", '"etag-a"', fake.now)
        fake.objects["b.json"] = (b"b", '"etag-b"', fake.now)
        keeper.load("a.json")
        keeper.save("c.json", b"c")
        # b.json was never seen; a.json is as loaded; c.json as saved
        assert keeper.changed_since_sync() == ["b.json"]
        fake.objects["a.json"] = (b"a2", '"etag-a2"', fake.now)
        assert keeper.changed_since_sync() == ["a.json", "b.json"]

    def test_a_token_that_moved_without_its_bytes_is_not_named(self) -> None:
        """Under SSE-KMS every PUT gets a new ETag: the same bytes under a new
        token are fetched once, found the same, and neither named nor set aside
        — and the token is refreshed, so the next listing does not ask again."""
        keeper, fake = _keeper()
        fake.objects["a.json"] = (b"same", '"etag-1"', fake.now)
        keeper.load("a.json")
        fake.objects["a.json"] = (b"same", '"etag-2"', fake.now)   # a KMS re-PUT
        fake.gets.clear()

        assert keeper.changed_since_sync() == []

        assert fake.gets == ["a.json"], "fetched once, to decide by the bytes"
        assert "takeover" not in _slugs(keeper)
        fake.gets.clear()
        assert keeper.changed_since_sync() == []
        assert fake.gets == [], "the token was refreshed"
        fake.objects["a.json"] = (b"other", '"etag-3"', fake.now)
        assert keeper.changed_since_sync() == ["a.json"]

    def test_an_ask_that_finds_nothing_leaves_a_standing_takeover_line(self) -> None:
        """A transient tick failure flips the layer's taking state and back, and
        it asks again: nothing changed, and the line from the takeover a minute
        ago still has its minutes to stand."""
        keeper, fake = _keeper()
        fake.objects["a.json"] = (b"a", '"etag-a"', fake.now)
        assert keeper.changed_since_sync() == ["a.json"]
        keeper.load("a.json")
        fake.advance(60)
        assert keeper.changed_since_sync() == []
        line = _line(keeper, "takeover")
        assert line.code == StatusCode.WARN and "1 file (a.json)" in line.text

    def test_only_state_files_are_named_and_only_by_a_holder(self) -> None:
        keeper, fake = _keeper()
        fake.objects[f"{PRESENCE_PREFIX}x.json"] = (b"{}", '"p"', fake.now)
        fake.objects[INSTANCES_NAME] = (b"{}", '"i"', fake.now)
        fake.objects["deeper/state.json"] = (b"{}", '"d"', fake.now)
        assert keeper.changed_since_sync() == []
        keeper.release()
        fake.objects["a.json"] = (b"a", '"etag-a"', fake.now)
        assert keeper.changed_since_sync() == []

    def test_the_takeover_line_is_warn_for_ten_minutes_and_a_fact_after(
            self) -> None:
        keeper, fake = _keeper()
        fake.objects["a.json"] = (b"a", '"etag-a"', fake.now)
        assert keeper.changed_since_sync() == ["a.json"]
        line = _line(keeper, "takeover")
        assert line.code == StatusCode.WARN
        assert "1 file (a.json)" in line.text and "/little-sister/state" in line.text
        fake.advance(599)
        keeper.tick(INTERVAL)
        assert _line(keeper, "takeover").code == StatusCode.WARN
        fake.advance(1)
        assert "takeover" not in _slugs(keeper)
        assert "1 file (a.json)" in keeper.report()

    def test_a_silent_takeover_is_no_line(self) -> None:
        keeper, _fake = _keeper()
        assert keeper.changed_since_sync() == []
        assert "takeover" not in _slugs(keeper)


class TestThePresenceFile:
    """ADR-0004 decision 13: a standby says it is here, the holder says who is
    standing by, and whoever lists cleans up."""

    def test_a_standby_writes_its_presence_file_every_interval(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        keeper.tick(INTERVAL)
        fake.advance(60)
        keeper.tick(INTERVAL)

        (key,) = fake.presence_keys()
        assert key == f"{PRESENCE_PREFIX}host-a%3A1.json", "the mark, encoded"
        body = json.loads(fake.objects[key][0])
        assert body["instance"] == INSTANCE
        assert body["since"] == "2026-09-05T08:15:00Z"
        assert body["ttl_seconds"] == 3 * INTERVAL
        assert body["clock"] == "store", "every stamp in the store is its clock"
        assert len([put for put in fake.puts if put["Key"] == key]) == 2
        assert fake.objects[key][2] == fake.now, "a heartbeat: written this interval"

    def test_the_key_is_one_per_mark_and_never_one_for_two(self) -> None:
        # `:` → `_` would give `host-a:1` and `host-a_1` one file between them.
        keys = {aws_keeper._presence_key(mark) for mark in ("host-a:1", "host-a_1",
                                                             "host-a%3A1")}
        assert len(keys) == 3

    def test_the_presence_file_is_never_offered_as_a_state_file(self) -> None:
        keeper, fake = _keeper()
        fake.objects[f"{PRESENCE_PREFIX}x.json"] = (b"{}", '"p"', fake.now)
        fake.objects[INSTANCES_NAME] = (b"{}", '"i"', fake.now)
        fake.objects["events.json"] = (b"{}", '"e"', fake.now)
        assert keeper.list() == ["events.json"]

    def test_the_holder_says_who_stands_by_within_one_interval(self) -> None:
        holder, fake = _keeper()
        standby = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                           instance=OTHER, now=fake.host_clock)
        assert "standbys" not in _slugs(holder)
        assert standby.tick(INTERVAL) is False
        fake.advance(30)

        holder.tick(INTERVAL)

        line = _line(holder, "standbys")
        assert line.code == StatusCode.WARN
        assert "1 instance is standing by" in line.text
        assert OTHER in line.text and "since <2026-09-05T08:15:00+00:00>" in line.text
        assert "misconfiguration" in line.text

    def test_the_body_is_fetched_once_per_etag_not_per_interval(self) -> None:
        holder, fake = _keeper()
        standby = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                           instance=OTHER, now=fake.host_clock)
        standby.tick(INTERVAL)
        for _ in range(3):
            fake.advance(60)
            standby.tick(INTERVAL)
            holder.tick(INTERVAL)
        presence_gets = [key for key in fake.gets if key.startswith(PRESENCE_PREFIX)]
        assert len(presence_gets) == 1
        assert OTHER in _line(holder, "standbys").text

    def test_a_killed_standbys_file_is_gone_within_one_ttl(self) -> None:
        holder, fake = _keeper()
        standby = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                           instance=OTHER, now=fake.host_clock)
        standby.tick(INTERVAL)
        fake.advance(60)
        holder.tick(INTERVAL)
        assert "standbys" in _slugs(holder)
        # the standby is killed; its last heartbeat ages past the ttl of 3 × 60 s
        fake.advance(119)
        holder.tick(INTERVAL)
        assert "standbys" in _slugs(holder), "one second short of the ttl"
        fake.advance(1)
        holder.tick(INTERVAL)
        assert "standbys" not in _slugs(holder)
        assert fake.presence_keys() == []
        assert any(key.startswith(PRESENCE_PREFIX) for key in fake.deletes)
        # the killed standby cannot write its own entry: the deleter does, from
        # the body's `since` to the file's last heartbeat, in its own name
        entry = fake.log()[0]
        assert entry["kind"] == "stood-by" and entry["instance"] == OTHER
        assert entry["how"] == "died" and entry["by"] == INSTANCE
        assert entry["since"] == "2026-09-05T08:15:00Z"
        assert entry["at"] == "2026-09-05T08:15:00Z", "its last heartbeat"

    def test_a_stale_file_is_judged_by_the_ttl_its_writer_wrote(self) -> None:
        """A standby on a longer interval wrote a longer ttl; the holder judges
        the file by that, not by its own."""
        holder, fake = _keeper()
        standby = S3Keeper(KeeperConfig(bucket=BUCKET, lapse_after=3),
                           client_factory=lambda: fake, instance=OTHER,
                           now=fake.host_clock)
        standby.tick(300.0)                     # a five-minute interval: ttl 900
        fake.advance(400)                       # past the holder's own ttl of 180
        holder.tick(INTERVAL)
        assert fake.presence_keys(), "alive by its writer's rule"
        assert OTHER in _line(holder, "standbys").text
        fake.advance(500)                       # 900 s: stale by the same rule
        holder.tick(INTERVAL)
        assert fake.presence_keys() == []

    def test_a_stopped_standby_leaves_no_file_and_logs_how_long_it_stood_by(
            self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        keeper.tick(INTERVAL)
        assert fake.presence_keys()
        fake.advance(90)

        keeper.close()

        assert fake.presence_keys() == []
        (entry,) = fake.log()
        assert entry["kind"] == "stood-by" and entry["instance"] == INSTANCE
        assert entry["since"] == "2026-09-05T08:15:00Z"
        assert entry["at"] == "2026-09-05T08:16:30Z"
        assert fake.lease()["instance"] == OTHER, "nothing of the holder's touched"

    def test_a_standby_that_takes_the_lease_deletes_its_own_file(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=60)
        keeper.tick(INTERVAL)
        assert fake.presence_keys()
        fake.advance(61)
        assert keeper.tick(INTERVAL) is True
        assert fake.presence_keys() == []

    def test_the_startup_listing_sweeps_a_stale_file_too(self) -> None:
        keeper, fake = _keeper(holding=False)
        stale = f"{PRESENCE_PREFIX}gone.json"
        fake.objects[stale] = (b"{}", '"p"', fake.now)
        fake.advance(400)
        assert keeper.list() == []
        assert stale not in fake.objects
        assert stale in fake.deletes

    def test_a_presence_file_that_cannot_be_written_costs_no_standby(self) -> None:
        keeper, fake = _keeper(holding=False)
        _held_by(fake, OTHER, ttl=180)
        keeper.tick(INTERVAL)
        (key,) = fake.presence_keys()
        written = fake.objects[key][2]
        fake.advance(60)
        fake.fail_next = EndpointConnectionError(endpoint_url="https://s3")
        assert keeper.tick(INTERVAL) is False
        assert OTHER in _line(keeper, "standby").text, "the lease was read"
        assert fake.objects[key][2] == written, "this heartbeat did not land"
        fake.advance(60)
        keeper.tick(INTERVAL)
        assert fake.objects[key][2] == fake.now, "tried again next interval"


class TestTwoClocks:
    """ADR-0004 decision 14: the offset between the host and the store, from the
    ``Date`` of every answer, and a store stamp moved onto the host's clock before
    it meets a local one."""

    def test_a_store_on_time_shows_neither_a_skew_line_nor_a_moved_stamp(
            self) -> None:
        holder, fake = _keeper()
        standby = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                           instance=OTHER, now=fake.host_clock)
        standby.tick(INTERVAL)
        holder.tick(INTERVAL)
        assert "clock" not in _slugs(holder)
        assert "since <2026-09-05T08:15:00+00:00>" in _line(holder, "standbys").text

    def test_a_store_a_minute_ahead_shows_since_in_host_time_and_the_skew(
            self) -> None:
        holder, fake = _keeper()
        fake.host_offset = -60.0             # the store's Date runs a minute ahead
        standby = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                           instance=OTHER, now=fake.host_clock)
        standby.tick(INTERVAL)
        holder.tick(INTERVAL)

        line = _line(holder, "clock")
        assert line.code == StatusCode.WARN
        assert "1m behind the store" in line.text
        # the standby stood by at 08:15:00 on the store's clock: 08:14:00 here
        assert "since <2026-09-05T08:14:00+00:00>" in _line(holder, "standbys").text

    def test_a_host_ahead_of_the_store_says_so_the_other_way(self) -> None:
        keeper, fake = _keeper(holding=False)
        fake.host_offset = 12.0
        keeper.tick(INTERVAL)
        assert "12 s ahead of the store" in _line(keeper, "clock").text

    def test_below_the_threshold_there_is_no_line(self) -> None:
        keeper, fake = _keeper(holding=False)
        fake.host_offset = 4.0
        keeper.tick(INTERVAL)
        assert "clock" not in _slugs(keeper)

    def test_the_line_has_hysteresis_in_at_five_out_under_three(self) -> None:
        keeper, fake = _keeper(holding=False)
        fake.host_offset = 6.0
        keeper.tick(INTERVAL)
        assert "clock" in _slugs(keeper)
        fake.host_offset = 4.0                  # wobbling under the threshold
        fake.advance(60)
        keeper.tick(INTERVAL)
        assert "clock" in _slugs(keeper), "not cleared until it is back under 3 s"
        fake.host_offset = 2.0
        fake.advance(60)
        keeper.tick(INTERVAL)
        assert "clock" not in _slugs(keeper)

    def test_the_takeovers_latest_change_is_shown_in_host_time(self) -> None:
        keeper, fake = _keeper()
        fake.host_offset = -60.0
        fake.objects["a.json"] = (b"a", '"etag-a"', fake.now)
        keeper.changed_since_sync()
        assert "the latest at <2026-09-05T08:14:00+00:00>" in _line(
            keeper, "takeover").text


class TestTheInstanceLog:
    """ADR-0004 decision 15: who held the prefix when, one entry per transition,
    bounded, never restored, the last few on the keeper's child."""

    def _two(self, fake: _FakeS3) -> tuple[S3Keeper, S3Keeper]:
        return (S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=INSTANCE, now=fake.host_clock),
                S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                         instance=OTHER, now=fake.host_clock))

    def test_two_instances_handing_the_lease_back_and_forth_leave_the_sequence(
            self) -> None:
        fake = _FakeS3()
        a, b = self._two(fake)
        assert a.tick(INTERVAL) is True            # A: the prefix was free
        fake.advance(30)
        assert b.tick(INTERVAL) is False           # B stands by
        fake.advance(30)
        a.close()                                  # A stops cleanly
        fake.advance(30)
        assert b.tick(INTERVAL) is True            # B takes the released lease
        fake.advance(60)
        assert a.tick(INTERVAL) is False           # A is back, standing by
        fake.advance(200)                          # B dies; its lease lapses
        assert a.tick(INTERVAL) is True            # A takes the lapsed lease

        sequence = [(entry["kind"], entry["instance"], entry.get("from", ""),
                     entry.get("how", ""), entry["by"]) for entry in fake.log()]
        assert sequence == [
            ("took", INSTANCE, OTHER, "lapsed", INSTANCE),
            ("stood-by", INSTANCE, "", "", INSTANCE),
            ("took", OTHER, INSTANCE, "released", OTHER),
            ("stood-by", OTHER, "", "", OTHER),
            ("released", INSTANCE, "", "close", INSTANCE),
            ("took", INSTANCE, "", "free", INSTANCE),
        ]
        # every stamp is the store's clock, and the lapse's end is the taker's
        # observation
        assert fake.log()[0]["at"] == "2026-09-05T08:20:50Z"
        assert fake.log()[1]["since"] == "2026-09-05T08:17:30Z"

    def test_the_hundred_and_first_entry_pushes_the_first_out(self) -> None:
        fake = _FakeS3()
        a, b = self._two(fake)
        a.tick(INTERVAL)                           # the first entry: free
        for _ in range(25):                        # four transitions a round
            fake.advance(1)
            a.release()
            fake.advance(1)
            b.take_over()
            fake.advance(1)
            b.release()
            fake.advance(1)
            a.take_over()
        entries = fake.log()
        assert len(entries) == INSTANCE_LOG_SIZE
        assert entries[0]["kind"] == "took" and entries[0]["instance"] == INSTANCE
        # the first entry ever — A taking the free prefix — is the one gone
        assert not any(entry["how"] == "free" for entry in entries)

    def test_the_log_is_never_restored_and_the_line_shows_the_last_three(
            self) -> None:
        fake = _FakeS3()
        a, b = self._two(fake)
        a.tick(INTERVAL)
        a.release()
        fake.advance(1)
        b.tick(INTERVAL)
        fake.advance(1)
        assert INSTANCES_NAME not in b.list()
        # the log is a fact: the report, no line (ADR-0076)
        assert "instances" not in _slugs(b)
        report = b.report()
        assert f"{OTHER} took the lease from {INSTANCE} (released)" in report
        assert f"{INSTANCE} released the lease (operator)" in report
        assert f"{INSTANCE} took the lease from nobody (free)" in report
        # a standby reads the log once at its start, for the line
        c = S3Keeper(KeeperConfig(bucket=BUCKET), client_factory=lambda: fake,
                     instance="host-c:3", now=fake.host_clock)
        c.tick(INTERVAL)
        assert "took the lease" in c.report()

    def test_the_holder_reads_the_log_again_when_its_listing_shows_it_changed(
            self) -> None:
        fake = _FakeS3()
        a, b = self._two(fake)
        a.tick(INTERVAL)
        fake.advance(30)
        b.tick(INTERVAL)                         # B stands by, writes nothing
        fake.advance(30)
        a.tick(INTERVAL)
        fake.advance(30)
        b.close()                                # B writes `stood-by`
        log_gets = len([key for key in fake.gets if key == INSTANCES_NAME])
        fake.advance(30)
        a.tick(INTERVAL)                         # the listing shows a new ETag
        assert len([key for key in fake.gets if key == INSTANCES_NAME]) == log_gets + 1
        assert f"{OTHER} stood by from" in a.report()
        fake.advance(60)
        a.tick(INTERVAL)                         # unchanged: nothing fetched
        assert len([key for key in fake.gets if key == INSTANCES_NAME]) == log_gets + 1
        assert json.loads(fake.objects[INSTANCES_NAME][0])["clock"] == "store"

    def test_a_refused_write_is_read_again_once(self) -> None:
        fake = _FakeS3()
        a, _b = self._two(fake)
        a.tick(INTERVAL)
        original = fake.put_object

        def racing(**kwargs: Any) -> dict[str, Any]:
            if kwargs["Key"] == INSTANCES_NAME and kwargs.get("IfMatch"):
                fake.put_object = original
                # somebody else appended between the read and the write
                original(Bucket=BUCKET, Key=INSTANCES_NAME,
                         Body=json.dumps({"entries": [{"kind": "released",
                                                       "instance": OTHER,
                                                       "at": "x", "by": OTHER}]}
                                         ).encode())
            return original(**kwargs)
        fake.put_object = racing  # type: ignore[method-assign]
        a.release()
        assert [entry["instance"] for entry in fake.log()] == [INSTANCE, OTHER]

    def test_a_log_that_cannot_be_written_is_a_warning_not_a_failed_tick(
            self, caplog: pytest.LogCaptureFixture) -> None:
        fake = _FakeS3()
        a, _b = self._two(fake)
        a.tick(INTERVAL)
        fake.fail_next = EndpointConnectionError(endpoint_url="https://s3")
        assert "released the lease" in a.release()
        assert "instance log" in caplog.text
