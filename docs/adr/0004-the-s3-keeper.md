# ADR-0004 — The S3 keeper: one prefix, one lease, a heartbeat at S3's clock

- **Status:** Accepted
- **Date:** 2026-09-05 (rewritten in place the same day, before any release, as a
  record that never shipped is — twice: the lease first, then, after the first run
  with two instances on one prefix, what the lease alone did not settle; the first
  shape is kept under *Alternatives considered*)
- **Related:** [ADR-0001](0001-the-aws-check-type.md) §3 (why boto3 is this
  package's one dependency beyond the library) and §5 (what may live in the
  identity seam), [ADR-0002](0002-aws-secret-references.md) (the provider that
  registers nothing on import, and the `aws` aspect this one reads an identity
  from), little-sister **ADR-0071** §5 (the keeper seam this fills, and the two
  lines a failure becomes), little-sister **ADR-0072** (the self-report seam this
  package says the rest on), little-sister **ADR-0074** (the instance mark the
  lease is written in), little-sister **ADR-0076** (the action seam the two
  actions go through), little-sister **ADR-0077** (authority follows the lease —
  the adoption this keeper's takeover triggers, and the `.bak` it leaves behind),
  little-sister **ADR-0001** (one process)

## Context

little-sister keeps what a restart needs as files under `var/state/`: the
maintenance pins an operator set, and the event log every node's history is derived
from. Those files live on whichever disk the process is running on, so a deployment
that is redeployed — the ordinary case for a cloud instance, and the *only* case for
one in an auto-scaling group, which is terminated without a stop — comes up having
lost the windows somebody opened and the history behind every node.

The library answered that with a **keeper**: one seam, one keeper per instance,
registered before the app is imported, mirroring the whole directory in bytes
without knowing what any file in it means. It ships no implementation, because a
store is a package's business. This is the first one.

**What the state is, decides what a copy of it is worth.** Every file the keeper
carries is the serialization of something *bounded in memory*: the event log is a
`deque(maxlen=…)`, the pins are the ones in force. The prefix therefore never grows;
it changes. It is a mirror of a bounded memory, not a data set, and a mirror has
exactly one useful version — the current one. Decisions 10 and 12 follow from that
sentence, and it is the one to reread when a feature here looks like it wants a
history.

**What this record replaces, and why.** Its first shape — a conditional `PUT` per
state file, an advisory marker that gated nothing, a file that *latched* once a
write was refused — was run for real the day before this rewrite, two instances
against one prefix on purpose, and behaved exactly as written. What the run showed was not a
defect but a price paid in the wrong currency. That shape defended two costs: no
call on a tick with nothing to save, and no timestamp anywhere, because a clock
proves nothing. Priced, the first is about **$0.23 a month** (one small `PUT` a
minute, eu-central-1) and the second is wrong for a *heartbeat*, which is the one
kind of write whose recency does mean liveness. What it bought for that: a
collision discovered only when the loser next happened to write (five and a half
minutes, that day); a winner chosen by who wrote first; two red pages telling
apart only by the *absence* of a line on one of them; state files locked until a
restart; and no way to resolve any of it from the application. A monitoring
instance is not time-critical in the way that shape assumed, and an operator's
minute is worth more than a bucket's cent.

**What the lease alone did not settle.** The first real run with two instances on
one prefix showed the next thing: a standby restores the store at startup and then
keeps its own state for as long as it stands by — pins set on it, the events it
observes — while the holder keeps writing the store. When the holder's lease lapses
and the standby takes it, *its own state is what it writes* put hours-old pins over
what the holder had written. A rollout produces exactly that overlap. The rule that
settles it is little-sister's (ADR-0077): **authority follows the lease** — whoever
held it wrote the truth up to the moment it lapsed, and a standby's own state is a
shadow of the store. The library adopts; this record is what the keeper owes that
rule, and three things beside it that the same run asked for: the holder cannot see a
standby, a killed instance leaves no record of having held the prefix, and two clocks
meet on every page that shows a store stamp beside a local one.

## Decision

1. **Its own configuration aspect, `config/aws-keeper.yaml`.** Five keys —
   `bucket` (the only required one), `prefix`, `identity`, `region`, and
   `lapse_after`, the number of missed heartbeats after which a lease is dead
   (default 3). Not a block in `config/aws.yaml`: that file is a flat mapping of
   identity *names*, so a reserved top-level key would make `keeper` a name nobody
   may declare, which is a stored key changing shape to save one file. The name is
   `aws-keeper` rather than `keeper` because an aspect name is claimed once and the
   next keeper somebody writes will not be this one.

2. **No file means no keeper.** A deployment with one `wsgi.py` and two complete
   configuration roots — a laptop's and a cloud account's — puts the file in one of
   them, and the other keeps its state on its own disk. A file that *exists* and
   cannot be read is the opposite case and **refuses the start**: an unknown key, a
   key written and left empty, no `bucket:`, a `lapse_after` that is not a positive
   integer, or an `identity:` the `aws` aspect never declared. Runtime failures are
   lines and never refusals (little-sister ADR-0071 §4); a file nobody can read is
   not a runtime failure, it is a deployment that meant to keep its state somewhere
   and cannot say where.

3. **One lease per prefix, held by heartbeat, taken by a conditional write.** A
   single object under the prefix — `.little-sister-owner.json`, dropped from the
   listing so the library never restores it as a state file — is the lease:

   ```json
   {"instance": "web-1:4711:20260905T081500Z:2b7de044",
    "ttl_seconds": 180,
    "how": "lapsed",
    "claims": [{"instance": "…", "at": "2026-09-05T08:12:16Z"}, …]}
   ```

   `how` says how the holder came by it — `free`, `lapsed`, `released`, or an
   `operator`'s take-over — and is written into every heartbeat of the tenure, so an
   instance whose heartbeat is refused reads it whichever of the two ticks came
   first; a lease written before the field existed reads as none.

   **The holder writes it every interval** — the heartbeat — and writes the state
   files behind it. **Anybody else reads it every interval** and writes nothing.
   The lease is *taken* with S3's own compare-and-swap: `If-None-Match: "*"` where
   nothing is there, `If-Match` on the version just read where a dead one is — so
   two instances racing for a lapsed lease cannot both believe they won. That is
   the only place a precondition is needed: with one holder there is one writer,
   and the state files are written **unconditionally** behind a heartbeat that
   landed. Whether it landed is what the heartbeat's own `If-Match` answers, every
   interval, before any state file is sent; a refused heartbeat means the lease was
   taken while this instance was away, and this instance stops writing *before* it
   writes (decision 4).

   `ttl_seconds` is written by the holder — `lapse_after` times its own interval —
   so a reader needs nothing but the object to know when it lapses, and two
   instances with different intervals still agree.

4. **Standby, never a latch — and authority follows the lease.** An instance that
   is not the holder is in standby: it restores the prefix at startup like any other
   — reading needs no lease, ever — monitors normally, keeps its state on its own
   disk, sends nothing to the bucket, and reads the lease once per interval. When
   the lease lapses, or is released, it takes it and writes from then on. A holder
   whose heartbeat is refused **demotes itself** to standby in the same call and
   says so; a holder that cannot reach the bucket for `lapse_after` intervals does
   the same, since from the outside its lease has lapsed and somebody may hold it
   now. Nothing here needs a restart to recover: a standby becomes the holder by the
   same rule that made anybody the holder, and a demoted holder is a standby that
   may take the lease back the moment it is free — with one exception, the holder an
   operator released from (decision 9), which stands by until another instance has
   held the lease and is an ordinary standby from then on.

   A standby's pins are local and its line says so. **When a standby takes over, the
   store's state is what it continues with**, not its own (little-sister ADR-0077):
   whoever held the lease wrote the truth up to the moment it lapsed. The keeper
   remembers, per state file, the ETag the store answered when this instance last
   loaded or saved it and a digest of the bytes, and answers the seam's
   `changed_since_sync()` from one listing — the files whose current ETag differs,
   and any it has never seen — each candidate fetched once and decided by its bytes,
   because an ETag moves without the bytes moving under SSE-KMS and a file set aside
   for its own copy would be a `.bak` and a line for nothing; a match refreshes the
   token. The library adopts every name answered before the first save and keeps
   what they replaced beside them as `.bak`, on `/little-sister/state`. The order at the moment a tick makes this
   instance the holder is therefore *take the lease, then let the layer adopt, then
   save*: the lease first, so the store is frozen while it is read. A takeover that
   adopted something is a line on the keeper's child, `takeover` — *took over; the
   store had changed for N files since this instance last synced with it; what they
   replaced is on `/little-sister/state`* — WARN for ten minutes, long enough to be
   noticed, and a fact in the child's report after; an ask that finds nothing, as the one after a
   transient tick failure does, leaves a standing line its minutes. The successor of
   a holder that died before anybody wrote again answers nothing and takes over
   silently, which is the case that must work out of the box. What the overlap loses is the standby's own observations
   between the holder's last heartbeat and the takeover; merging them into the
   store's log is the merge this record refuses, and they are in the `.bak`.

5. **The client is bounded in seconds**: `connect_timeout=2`, `read_timeout=5`,
   two attempts. boto3's defaults are sixty and sixty with several retries, which
   on the scheduler tick is minutes of monitoring lost to an unreachable bucket —
   and there is now a call on *every* tick, so the bound matters more, not less.

6. **The session is re-opened once on a credential error, at call time.**
   `assumed_session` freezes what `sts:AssumeRole` returned and those credentials
   expire while the process runs on; an SSO login expires about once a working day.
   Both look the same from here and both are fixed by opening the session again, so
   a call that fails a credential check — `is_credential_error`, the same reader
   the secret provider uses — is retried exactly once against a new client. An
   `AccessDenied` is not a credential error and is reported unchanged.

7. **The session is opened lazily**, at the first call the library makes, never at
   registration: a bucket that cannot be reached has to be a line on
   `/little-sister`, not an import that fails.

8. **Liveness is measured inside one S3 answer, and release is a heartbeat of
   zero.** Whether a lease is alive is `Date` (the header of the answer) minus
   `LastModified` (the object it carried) against `ttl_seconds` (in the object).
   Every term is S3's; no machine's clock enters, nothing skews, and the reading
   is the same from every instance. This is the measurement the first shape made
   and then refused to act on, because a timestamp on an *arbitrary* write says
   nothing about liveness. On a **heartbeat** it says exactly that, and that is the
   whole difference between this record and its first draft.

   A graceful stop — the shutdown flush the state layer already runs — writes the
   lease once more with `ttl_seconds: 0`: lapsed on arrival, so the next standby
   takes it on its next read instead of waiting `lapse_after` intervals. It is a
   `PUT` like every other, so release needs no `s3:DeleteObject`. It is a bonus,
   not the mechanism: an instance terminated by its auto-scaling group gets no
   flush, and the design assumes that case. The failover time is therefore
   `lapse_after × state_interval` — three minutes at the defaults — and the
   heartbeat interval is the knob that trades cost for it, linearly.

   The mark is little-sister's (ADR-0074): no two processes share one, one
   process's does not change while it runs, and nothing here parses it. The
   object keeps the last four claims beside the current one, newest first, each
   stamped with the moment it was taken — a pattern rather than a fact, and four
   claims in ten minutes reads differently from one nine days ago.

9. **The keeper reports by the loss principle, and offers two actions.** The
   library grades the same event by whether anything is *already* lost — a keeper
   that could not be read at startup is ERROR, a save that failed is WARN because
   *nothing is lost yet, the next machine is* — and this package grades the same
   way rather than louder. Through its own self-report contributor (little-sister
   ADR-0072), on its child `/little-sister/aws-keeper`. **Every line is a claim and
   carries a code; what the keeper merely knows is the child's `report`**
   (little-sister ADR-0076 decision 1, ADR-0044 decision 6): shown on the child's
   page, never on a card, never a grade — so the card says something only when
   something is wrong, and pinning the one warning quiets the child.

   The report: *this instance holds the lease on `s3://…`, heartbeat every n, lapse
   after m* — for the life of the tenure; whose lease this replaced and how (a
   lapse, a release, an operator's request and how fresh the holder's heartbeat was,
   with the claim history); a takeover that changed the store, once its ten minutes
   at WARN are over; the last transitions of the instance log (decision 15); and a
   versioning check that could not be made (decision 10).

   The lines:

   - `standbys` — **WARN**, on the holder: *N instances are standing by on this
     prefix: Y since t* (decision 13). In a rollout it clears within minutes; a
     second instance that stays is a misconfiguration somebody should look at.
   - `standby` — **WARN**: the lease is held by *X*, last heartbeat *t* ago, lapses
     in *u*; this instance keeps its state locally only, and a pin set here does not
     survive it. WARN because nothing is lost while it stands, and because a
     monitoring instance in standby is monitoring.
   - `demoted` — **WARN**: this instance could not renew its lease (refused by *X*,
     or unreachable for *n* intervals) and has stopped writing; it takes the lease
     back when it is free. Same principle, same grade.
   - `released` — **WARN**: this instance released the lease on request and stands
     by; nothing of its state reaches the store until an instance takes the lease,
     and a pin set here is lost at termination. WARN and not a fact for that reason.
   - `takeover` — decision 4, WARN for ten minutes; `clock` — decision 14;
     `versioning` — decision 10, WARN where the bucket versions.

   Nothing here is ERROR, on purpose: a second instance is no longer a way to lose
   state, so the loud grade the first shape argued from has nothing left to argue
   from. ERROR stays the library's, for what was actually lost.

   **Two actions**, for an operator who knows what they are doing, on this keeper's
   child of `/little-sister`, admin-only, through the seam little-sister's ADR-0076
   offers — a package contributing an **action** to its child, not only a line:

   - *Take over* writes the lease onto this instance now, regardless of who holds it
     — an unconditional `PUT` carrying the holder as the newest claim and `how:
     operator`. The holder's next heartbeat is refused and it demotes itself; the
     seam flushes the state layer right after the handler (little-sister ADR-0076),
     so the layer adopts what the store changed since this instance last synced
     with it and saves in the same click, before anything else is written — the
     order is *the lease, then adopt, then save* here too, without the wait for an
     interval. Pressed on the instance that holds the lease already, that flush is
     the whole of the action: the state written to the store now, which is why the
     button is offered in every state rather than greyed by a state read before the
     click. The action's sentence says so, and so
     do both pages within one interval: the taker's `predecessor` says it was an
     operator's, how fresh the holder's last heartbeat was, and that the holder
     learns of it at its next heartbeat, within the interval — a lease taken live
     never *lapsed*, and the line does not say so; the holder's refused heartbeat
     reads `how` from the lease and its `demoted` line says the same. Until that
     heartbeat both pages say *holds*, which is safe — no save runs behind a
     heartbeat that is refused — and now says why.
   - *Release* is `close` without the stop: a heartbeat of zero from the holder. It
     is **not taken back on this instance's own next tick**, on purpose — a release
     that this instance's own tick could undo a second later would be a 50/50 race
     with the standby it was pressed for. The released instance stands by with the
     `released` line; *take over* takes the lease back, and once another instance has
     held it the released one is an ordinary standby again and takes a lapsed lease
     by the normal rule.

   Both run on a web thread against the tick on the scheduler's, so the keeper holds
   a lock around everything that reads or moves the lease's state. What it costs is
   bounded by decision 5: *take over* does its S3 I/O under the lock, so a tick can
   wait behind an operator's click for two attempts of connect plus read — about
   fourteen seconds — which is fine for an action pressed once a year, and is the
   number to look at before widening the client's timeouts.

10. **Versioning off, and checked once at startup.** The first shape recommended
    versioning on, for putting a pin back; that advice was written for writes on
    change only. With a heartbeat every interval, versioning is 43,000 versions a
    month of a 463-byte object plus every version of the event log, bounded by a
    lifecycle rule and never prevented by one — a cost for a history nobody wants
    of a file nobody reads. So the recommendation flips, and because a
    recommendation nobody checks is a surprise on the bill, the keeper reads
    `GetBucketVersioning` **once at startup** — not on the report path — and says
    what it found: `Enabled` is a WARN line naming the cost; `Suspended` or absent
    is fine, since once-enabled versioning can only be suspended; no permission to
    ask is a fact in the child's report that says so. The restore procedure the first shape
    carried is gone with the reason for it.

11. **Stored in ISO 8601 UTC, shown through the settings.** Every timestamp the
    lease carries is `2026-09-05T08:15:00Z`, never an HTTP date; every line this
    package reports renders a time through `timezone` and `time_format` from
    `settings.yaml`, as the rest of the application does — a `GMT` in a dashboard
    line beside a `Europe/Berlin` in the next was the first shape's, and it was
    wrong.

12. **The bucket is a mirror of bounded memory, and this record never grows it
    into more.** No history, no series, no per-instance directories: the prefix
    holds the current state of one instance and one lease, at most a few hundred
    kilobytes, and its cost is the requests, not the bytes. A store that keeps a
    history is the *series* seam of little-sister's own roadmap, a different seam
    with its own record, and a package behind it may well be this one — but not
    this keeper.

13. **A standby says it is here: the presence file.** A standby writes
    `.little-sister-standby-<key>.json` beside the lease every interval — its
    heartbeat — where the key is its mark percent-encoded (one key per mark, never
    one key for two) and the body carries the mark, since when it stands by, and a
    `ttl_seconds` of its own, `lapse_after × interval`, so a reader with another
    interval judges the file by the writer's rule and not its own. The holder lists
    the prefix once per interval — about the price of its own heartbeat — and its
    child says who is standing by (`standbys`, WARN); the body is fetched once per
    new ETag, since a heartbeat that rewrites the same bytes gets the same ETag from
    S3 and costs the holder a listing and nothing else. **Cleanup is whoever lists**:
    an instance that takes the lease deletes its own file, a standby that stops
    cleanly deletes it, and every listing — the holder's each interval, any
    instance's at startup — deletes a presence file older than its own ttl,
    `LastModified` against the listing's `Date`, the lease's own rule. A killed
    standby's file is therefore gone within one ttl of its death and never a ghost
    on the holder's child; and because a killed standby never writes its own entry
    into the instance log, **the deleter writes it** — *stood by from* the body's
    `since` *to* the stale file's `LastModified`, in the deleter's name — or the
    killed instances would be exactly the ones missing from the record.

14. **Two clocks, and every stamp in the store is the store's.** Every stamp this
    package writes into the bucket — the lease's claims, a presence file's `since`,
    the instance log's intervals — is on S3's clock: an instant S3 served, or the
    host's clock moved by the offset measured on the answer just received. Every
    reader converts with its own offset and never with somebody else's, which is how
    the holder shows a standby's *since* correctly with three clocks in the room —
    the standby's host, S3, the holder's host — and each body says `"clock":
    "store"` so a reader knows which it used. The offset is the `Date` header of
    every answer against the host's clock at receipt, good to about a second (the
    header is whole seconds, plus half a round trip), kept as the latest reading and
    refreshed by every call for nothing. A store stamp is moved onto the host's clock
    before it meets a local one on a page — a standby's *since*, the takeover's
    *latest change*, the instance log's intervals — and shown through
    `little_sister.spans.local_time` in the settings' zone. Liveness never depends on
    it: the lease is measured inside one S3 answer, as before. An offset past **5 s**
    is the `clock` line at WARN — *this host's clock is 38 s behind the store's* — a
    broken time sync worth a warning, and one that bites on a laptop long before it
    bites an instance under Amazon's time sync; it clears only once the offset is
    back under 3 s, so a host wobbling around the threshold does not flap it. S3
    refuses a request more than fifteen minutes adrift, and that already shows as a
    lost lease, which is why the threshold is seconds and not minutes.

15. **The instance log.** `.little-sister-instances.json` beside the lease, never
    restored: one entry per transition, newest first, bounded to the last hundred —
    *took the lease* (from whom, and how: the prefix was free, lapsed, released, an
    operator's *take over*), *released it* (a clean stop, or an operator), *stood by
    from t to t* — each stamped on the store's clock and naming who wrote it, since a
    lapse's end is the taker's observation and not the dead holder's last breath.
    Written by whoever makes the transition, on transitions only, so it costs
    nothing per interval; it is the only record of the deployment that outlives
    every instance in it, and it answers *who was holding when this pin was set*. It
    is also the **one object a non-holder writes**, so it is the one object with a
    conditional `PUT`: read, prepend, write with `If-Match` on what was read, once
    more from a fresh read where that was refused — and a lost entry after two
    collisions is acceptable for a log nobody decides from. Read once at start, and
    read again when the holder's listing shows an ETag other than the one last read,
    so a fresh view costs one `GET` when something happened and nothing otherwise;
    a standby does not list, so its signal is the lease naming a holder it did not
    know — a demoted holder reads the take-over that demoted it on its next tick.
    The keeper's child shows the last three in its report; a page of its own waits
    for a second deployment to have read the record.

## Consequences

- A deployment that names a bucket survives its machine, **including a machine
  that is terminated without a stop**: the successor restores at startup, waits
  out the dead lease, and writes on. One that names none is unaffected, and the
  library needs neither to work.
- **The floor rises to the little-sister release that carries the seam**, and this
  record asked the seam for two things more, which it grew: `tick(interval_seconds)
  -> bool`, called by the state layer every interval whether or not there is
  anything to save, where the heartbeat and the standby's read live and whose
  answer says whether this interval's saves are wanted; and `close()`, once at a
  graceful end, where the lease is given up. The keeper seam called nothing on a
  tick with nothing to save, deliberately, and a heartbeat is precisely the call it
  did not have; a thread of the package's own was the alternative, and one process
  with one scheduler is little-sister ADR-0001. Decision 11 asked for a third,
  `little_sister.spans.local_time`, on the surface a plugin may import; and the
  seam's `changed_since_sync()` — the question the library asks at the moment
  `tick` turns from declining to taking — is little-sister's own ADR-0077, which
  this keeper answers (decision 4).
- **What one instance costs**, eu-central-1, `state_interval: 60`: 43,200
  heartbeats a month at $0.0054 per thousand `PUT`s is **$0.23**, and the holder's
  listing beside each heartbeat, 43,200 `LIST`s at the same price, another **$0.23**;
  a standby beside it, 43,200 `GET`s at $0.00043 per thousand, **$0.02**, and its
  presence heartbeat, 43,200 `PUT`s, **$0.23**; the state files only on change, the
  instance log only on transitions, and the bytes nothing. A shorter interval buys
  a shorter failover at the same rate.
- **The identity needs** `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject`
  under the prefix — the delete for a stale presence file, since release is still
  a `PUT` — and `s3:ListBucket` on the bucket, plus, optionally,
  `s3:GetBucketVersioning` for decision 10's check.
- **Everything under the prefix that starts with `.little-sister-` is this
  keeper's and not state**: the lease, the presence files, the instance log. One
  rule drops them from the listing the library restores from and from what a
  takeover adopts, so a new object of this keeper's needs no new filter, and a state
  file never starts with it.
- **One prefix is one instance, and a second one is now harmless**: it runs in
  standby and says so at WARN, the holder says who is standing by, and when it takes
  over it continues with the store's state and keeps its own as `.bak`. The private
  deployment that ran two on purpose to see the first shape's report will see this
  one instead; its own record of the consequences is rewritten when this lands.
- **A lease written before the first tick** says its `ttl` is 180 s: the start
  takes the lease from the restore's listing, before the layer has told the keeper
  its interval, and the first tick rewrites it with the real one.
- A key under a *deeper* prefix is not restored: listing uses a delimiter, so a
  nested key does not arrive at all. That is what keeps one bucket usable by two
  instances under two prefixes.

## Alternatives considered

- **The first shape: a conditional `PUT` per state file, an advisory marker, a
  latch.** Every write carried `If-Match`; a refused one was read before it was
  believed, then that file was recorded as one this process had stopped keeping,
  until a restart; the marker was re-written on the write path and taken back
  exactly once, so both instances learned once and neither refreshed again. It was
  correct and it was built, and it is replaced for the reasons the context gives:
  it defended a cost of cents with an operator's minutes. Two of its arguments
  survive unchanged — a 412 *is* a discovery and not a race in a one-process
  application, and the marker had to live under the prefix so it needed no policy
  change — and both are carried into decision 3.
- **Keeping `If-Match` on the state files as well, belt and braces.** Rejected: a
  second guard on the one guarantee the lease already gives adds the latch's whole
  failure mode back for no protection the heartbeat does not already provide, and
  the instruction was *simpler*.
- **A probe per tick on the first shape** — `HeadObject` on the marker each
  interval, the cheapest of the three shapes an open question had costed. It would
  have shortened
  detection and changed nothing else: the arbitrary winner, the latch, the two red
  pages. Answered by this record instead, and gone.
- **Per-instance prefixes with a pointer to the current one.** No instance ever
  overwrites another's files, and every instance's last state is kept. But the
  pointer is the lease in disguise, and the prefix doubles for every instance that
  ever ran; decision 12 says why the second half is the wrong direction.
- **No coordination, versioning as the safety net.** Two writers interleave whole
  files and a pin is silently gone; a version somebody could put back is not a
  design, it is a shift nobody is on.
- **`DeleteObject` for release.** Cleaner in the bucket, and one more action in
  every deployment's policy, in a different team's week; a heartbeat of zero
  releases with the permission a heartbeat already has.
- **A thread of the package's own for the heartbeat.** Rejected in favour of the
  seam's `tick`: one scheduler is the library's ADR-0001, and a thread in a plugin
  is the first exception to it.
- **Making the identity seam refresh its own credentials.** Rejected *for now*, as
  before: this is the first long-lived caller, the seam is released, and the narrow
  retry of decision 6 answers the same need. The shape it would take is known —
  `AssumeRoleCredentialFetcher` with `DeferredRefreshableCredentials` through
  `botocore_session` — additive and opt-in, and it moves into the seam the day a
  second long-lived caller appears.
- **A `region` on the identity, instead of on the keeper.** Rejected, and this
  record is where the question got its answer: the region the keeper wanted was the
  **bucket's**, and an identity's `region:` says where its *secrets* are read; one
  field would have had to answer two questions. Decision 1 puts `region` in this
  aspect's own file.
- **Writing through on every pin, as the deployment's own design had it.** Not
  ours to choose any more: the seam saves periodically, after the writer, and a
  keeper is called when the library calls it.
- **A released holder that takes the lease back on its own next tick** — *close*
  without the stop, literally. The releaser's tick and the standby's read come once
  per interval each, so whoever ticks first after the release wins: a coin toss, on
  the one action pressed in order to hand the lease to somebody in particular.
- **A presence key with `:` replaced by `_`.** Readable and lossy: two marks that
  differ only there share one file. Percent-encoding is injective.
- **Judging a presence file by the reader's own ttl.** Wrong the day two instances
  run on different intervals: the holder on a minute would sweep a standby on five as
  dead four minutes early. The file carries its ttl, like the lease.
- **The takeover line WARN for one interval.** A blink; the point of the line is
  that somebody learns the `.bak` files exist. Ten minutes costs nothing.
- **The skew line cleared at the threshold it fires at.** A host wobbling around
  five seconds would flap it every interval; in at five, out under three.
- **Deleting the dead standby's presence file without writing its entry.** Then the
  killed instances — the case the log exists for under an autoscaling group — would
  be exactly the ones missing from the record.
