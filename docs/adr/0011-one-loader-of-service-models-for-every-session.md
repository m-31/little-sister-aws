# ADR-0011 — One loader of service models for every session

- **Status:** Accepted
- **Date:** 2026-10-10
- **Related:** [ADR-0001](0001-the-aws-check-type.md) (§3, boto3 as this package's one
  dependency beyond the library; §5, the identity seam every surface opens its sessions
  through, and `open_session`, which proves a session's credentials when it opens it),
  [ADR-0002](0002-aws-secret-references.md) (the secret provider, one session per
  identity for a boot), [ADR-0004](0004-the-s3-keeper.md) (the keeper's one client),
  [ADR-0010](0010-the-package-declares-what-its-sdk-writes.md) (the SDK's lines at
  every new session, which this record does not change)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

The check opens every session anew at each run: a base session, and for every account a
session of that account's own on what `sts:AssumeRole` returned, from which each aspect
takes a client for each region ([ADR-0001](0001-the-aws-check-type.md) §5). Nothing of
it outlives the run, on purpose: the credentials are proven at the top of each run, so
an expired login is one failure at the moment a session is opened and not the same
news in the words of whatever was read first.

**What that weighs.** boto3 builds every session on a botocore core session of its own,
and a core session builds a loader of service models of its own, on first use. The
loader parses a service's model — the JSON of its operations and shapes, and the
endpoint ruleset beside it — for the first client of that service, and keeps what it
parsed in caches of its own. So a session that lives one run parses the models of every
service it opens on every run, three accounts parse them three times, and all of it is
garbage the moment the run ends — but garbage only the cycle collector frees, since
what a session built is reachable through reference cycles alone, and the collector
runs on a count of allocations and not on what they weigh.

Measured with no call made, on Linux on arm64, Python 3.14.6, boto3 1.43.108: a probe
builds what a run of the check builds — a base session, and for each of three accounts
an `sts` client on it, a session on keys made up and five aspect clients — thirty times,
each shape in a process of its own that stood at 37 MiB before its first run, and reads
the process's resident size around it. In MiB:

| What a run does | After the first run | Highest | At the end | A run's build |
|---|---|---|---|---|
| as built | 149 | 419 | 388 | 0.24 to 0.25 s |
| as built, and a collection after each run | 109 | 150 | 137 | 0.21 to 0.25 s |
| every session is handed one loader of service models | 74 | 91 | 91 | 0.03 s |
| the first run's sessions and clients are used again | 149 | 149 | 149 | none |

A `logs` client on a session that has built one already is 266 KiB and a millisecond.
The same probe, run when the weight was first measured, on the same machine and
versions, gave the same rows within a few MiB (149, 420 and 390 as built; 74, 91 and 91
with one loader), and showed that the level is the collector's and not the
configuration's: one account stood at 490 MiB at its highest, three at 420 and five
at 510.

The same probe building its sessions through this package's own builder,
`identity.new_session`, before and after this record — the process stands at 43 to 44
MiB before the first run, the package imported:

| Every session the package builds | After the first run | Highest | At the end | A run's build |
|---|---|---|---|---|
| on a loader of its own, as released in 0.1.5 | 153 | 424 | 394 | 0.24 to 0.26 s |
| on the process's one loader, this record | 79 | 95 to 96 | 95 to 96 | 0.03 s |

**One deployment shows it.** An instance of 916 MiB that reads three accounts every two
minutes runs at 418 to 519 MiB after its first half hour against a limit of 504, and is
replaced every three and a half hours with 29 MiB available, no swap and the machine
thrashing its code pages. The process is what fills it: 430 MiB eleven minutes after a
start, 490 to 520 after an hour.

**Whether a session should outlive a run** was left open when the weight was first
measured, the answer depending on the deployment and the period. Three shapes were
weighed, and the table says what each is worth: one loader for every session keeps
what is built and takes most of the weight and nine tenths of the build; sessions and
clients kept across runs take the rest of the build, the `sts:AssumeRole` an account
costs on every run and a new connection for every client; a collection after each run
holds the process at a third of its size and is the library's to offer, since it walks
the whole process on every poll whatever the type.

## Decision

### 1. Every session this package builds is built on one loader of service models

`identity.new_session` builds the botocore core session itself, as boto3 would build
it, sets the profile on it, registers the process's loader as the session's
`data_loader` component, and hands the core session to `boto3.Session`. Every surface
reaches that builder: the check through its `_new_session` seam, the keeper and the
secret provider through `open_session`'s default factory. So the models are parsed once
in a process — for the first client of each service, whichever surface built it — and a
run's sessions hold nothing a loader of their own would have held.

The loader is **process-wide, beside the type** — `SERVICE_MODELS`, module state in
`identity.py` for the reason `SSO_LOGINS` is ([ADR-0001](0001-the-aws-check-type.md)
§5): the models are the process's, not a caller's, and two checks in one process, or a
check and the secret provider, must not load twice. It is **one loader for each search
path a session resolves**, built on first use and kept for the life of the process:
botocore's own `create_loader` on the session's `data_path`, which is `AWS_DATA_PATH`
or `data_path` in the profile's section of the config file, so botocore's rule for
where a model is found keeps its meaning, and a process that names none has one loader.

**Its search path takes a directory once.** boto3 appends its own `data` directory to
the loader of every session it builds; on a loader that was one session's that was one
line, and on the loader every session shares it would be one line more for every
session, for as long as the process runs, on a list the loader walks for every model it
has not cached. The loader this package builds is botocore's own on a search path that
refuses a directory it holds.

### 2. The seam is botocore's component, which boto3 itself stands on

Read in botocore 1.43.108 before this was built. A core session registers its loader
lazily, as `create_loader(self.get_config_variable('data_path'))`, and reads it with
`get_component('data_loader')` whenever it creates a client; `register_component(name,
component)` replaces the lazy registration with the object given. Both methods are
public by name, and botocore keeps its internal components apart from them: fetching
`endpoint_resolver` or `exceptions_factory` through `get_component` is answered with a
deprecation warning that says they *have always been considered an internal interface
of botocore*, which is the line between what a caller may hold and what it may not,
and the loader is on the caller's side of it. boto3 stands on the same seam:
`boto3.Session` takes a `botocore_session` as a documented argument, and reads
`get_component('data_loader')` from it to set up its own loader.

What the published reference says, at the same version: the reference has pages for
the request, the configuration, event streams, **the loaders**, responses and the
stubber, and one for each service — and none for the session; `register_component`
is in no index there. The Loaders page documents `Loader`, `create_loader`, the search
path and `AWS_DATA_PATH`. So the loader this package builds is a published surface and
the component it is registered under is a public one, held to by boto3 — and not a
promise in botocore's reference. The suite holds the seam: two sessions the check
builds share one loader object, and a client from each is built on the one model that
loader's cache holds. The second is the test that turns red the day a botocore release
stops reading the component — the object would still be registered, and the clients
would be built on parses of their own — where the weight would otherwise come back
without a word.

### 3. Two threads on one loader parse a model twice at worst, and read it after

A loader's caches are per instance, filled on first use and under no lock: each cached
method looks its key up, computes on a miss, and stores. Two worker threads that open
the first client of one service at the same moment both miss, both parse, and both
store; the cache keeps the one stored last, and each thread's client holds the model it
parsed, whole and valid — a run's worth of memory for the one that lost, and nothing
else. botocore's own session accepts the same race for the loader itself, in so many
words, where a lazily registered component is built by two threads at once.

What botocore writes into loaded data after the load converges, so two readers of one
cache are no worse off than two readers of two. Its service model, its paginator and
waiter models, its endpoint resolver and its default-configuration resolver read the
loaded mappings and write nothing into them; the endpoint ruleset is read into rule
objects from a keyword copy of each rule. Two writes there are, and each sets what a
second writer would set again. One is the loader's own, inside the cached call: the
`sdk-extras` file a service ships beside its model is merged into the model as it is
loaded, and merging the same extras a second time sets the same values. The other is
the retry configuration, in the legacy mode every client of the check runs in: the
first client of a service to read it replaces each `$ref` entry in that service's
section with the definition it names, in place, and a later reader finds it replaced —
or, reading at the same moment, replaces it with the same object. With a loader a
session those writes happened once a session; now they happen once. No handler of
botocore's touches a loaded model either: the event a session emits when it loads
service data has no built-in handler, and the client builder does not emit it.

### 4. A session is still a run's

Nothing of a run's sessions outlives it, as before: the base session and each account's
are opened at the top of the run and their credentials proven there. What this record
takes is the weight and the build — the models — and leaves the rest where it was,
because a session kept across runs would answer three questions this record does not:

- **What `sts:AssumeRole` hands out lasts an hour** as this type asks for it, so a kept
  session opens it again before that; and an expired login is one failure today, at the
  moment `open_session` proves it, which a kept session would meet in the middle of a
  read.
- **For a check that runs once an hour it saves nothing**, and holds its clients
  between two runs for nothing. What it would save at a two-minute period is what the
  table leaves after the loader: the `sts:AssumeRole` an account costs on every run,
  and a new connection for every client, worth one or two tenths of a second each on a
  slow path to AWS — measured on a developer machine inside a company's network, where
  a poll of three accounts made 32 calls on 24 clients built for that poll and waited
  10.7 to 11.7 s for AWS in polls of 12.0 to 14.1 s. Whether a connection kept across
  runs two minutes apart would still be open is not measured.
- **Where it would live.** A deployment reads more of AWS beside this type and not at
  this pace — what a bucket holds, what a month has cost — and until the library lets
  an aspect have a period of its own, an aspect with another period is a second check
  with the others switched off, and a second set of sessions on each of its runs. A
  session that outlives a run is weighed
  together with that: on a check nothing shares it; beside the type every check of a
  process does, where the loader and `SSO_LOGINS` live already.

That is what would change this: a period an aspect can have of its own, and a reading
of the deployment's lines on this release that says the rest of the weight is worth a
session that renews itself. Until then a session is a run's, and the record that
decides otherwise supersedes this one.

## Consequences

- **The process is lighter by what the models weighed.** Three accounts over thirty
  runs stood at 424 MiB at their highest through this package's builder and stand at
  95 to 96; a run's build fell from a quarter of a second to three hundredths.
- **Nothing a deployment configures or pins moves**: no `type:` name, no configuration
  key, no slug, no setting of the identity file or the keeper's, no entry in `.env`.
  A deployment's own code that opens its sessions through `open_session` or
  `new_session` shares the loader without a change; one that builds `boto3.Session`
  itself does not, and still parses the models for each session it builds.
- **`new_session` resolves the profile where boto3 did.** A profile the machine's
  config file lacks is refused when the session is built, as `boto3.Session` refused
  it, with the same error.
- **`AWS_DATA_PATH` and a profile's `data_path` keep their meaning**, and a process
  whose sessions resolve two search paths holds two loaders, one for each.
- **What the SDK writes at every new session** ([ADR-0010](0010-the-package-declares-what-its-sdk-writes.md))
  is unchanged: a session is still opened at every run and still says where it found
  its credentials, under the rows that cap it.
- **A client is still built for every run.** A `logs` client for each function where
  `read_log_status` is on, and a client for each aspect of each account, are built anew
  at every run on the shared models, at 266 KiB and a millisecond each: what remains of
  a run's weight is the clients, the readings and the cycles the collector frees late.
- **The suite runs the SDK itself for this**, in the process: real sessions and clients
  on keys made up there, every endpoint this machine where nothing listens, and the one
  call the check's path makes answered by a `before-send` handler on the session that
  would make it. Nothing is sent, and the fakes the other suites inject at the session
  seams are untouched.

## Alternatives considered

- **Sessions and clients kept across runs**, which the probe measured at 149 MiB
  throughout and no build at all. Rejected for now, for the three questions of
  decision 4; the loader takes most of the weight without opening any of them.
- **A collection after each run**, 137 MiB at the end and a run's build unchanged.
  The library's to offer, since it walks the whole process on every poll whatever the
  type, and it would leave the parsing in place.
- **A loader on the check**, built with it. Two checks in one process would parse
  twice, the secret provider and the keeper would parse for themselves, and a check's
  own loader would be as long-lived as the process anyway.
- **One loader for the process whatever a session's search path**, built from the
  environment alone. Simpler by a dictionary, and silently wrong for a profile that
  names a `data_path` of its own, which botocore honors.
- **Letting boto3's directory accrue on the search path**, or pruning it after each
  session. The first grows a list the loader walks on every miss for as long as the
  process runs; the second is a race between two threads building sessions, where
  both prune and the directory is gone until the next session puts it back.
- **A subclass of `boto3.Session` that appends its directory once.** It would stand
  on a private method of boto3's, where the search path that refuses a duplicate
  stands on a list.

