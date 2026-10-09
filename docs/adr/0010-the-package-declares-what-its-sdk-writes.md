# ADR-0010 — The package declares what its SDK writes into a log

- **Status:** Accepted
- **Date:** 2026-10-04
- **Related:** [ADR-0001](0001-the-aws-check-type.md) (§3, boto3 as this package's one
  dependency beyond the library; §5, the identity seam every surface opens its sessions
  through), [ADR-0002](0002-aws-secret-references.md) (decision 1, the provider that
  registers nothing on import, which stands, and the values that provider reads),
  [ADR-0004](0004-the-s3-keeper.md) (the keeper, which registers nothing on import
  either), little-sister **ADR-0121** (a noise cap is declared by the package that
  brings the noise: the call, what a package may declare, where the rows are set, and
  `LOG_LEVEL` by name), little-sister **ADR-0049** (decision 4, logging promised as a
  behavior), little-sister **ADR-0100** (the *Installed* view, where the rows are shown)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

little-sister logs at `INFO` unless `LOG_LEVEL` says otherwise, and what a dependency
wrote into that log was each deployment's to find, by reading it. little-sister ADR-0121
hands that to the package which brings the dependency. The package has one call,
`little_sister.noise.cap`, and the call records a row: a logger's name, the level it is
capped at, and a sentence that says what the cap hides. little-sister sets the rows
where the application is imported. A level the deployment's own startup file set stands
against them, and `LOG_LEVEL` has any logger back by name. Which rows this package
declares for boto3 is its own to say, and is decided here.

What boto3 writes was measured for what this package does with it, on boto3 1.43.108
and with no call to AWS: every client was pointed at a server in the measuring process.

**A new session says where it found its credentials.** `botocore.credentials` writes one
`INFO` line for a session that reads them from the environment, from a credentials or a
configuration file, or from an instance's role: *Found credentials in shared credentials
file: ~/.aws/credentials*. The check opens its sessions anew at every run, so that is a
line a run: 192 of the 6,987 lines one instance wrote in sixteen hours (little-sister
ADR-0121, in its context), and the only line of the SDK's among them.

**Where the credentials come from an SSO session, the sentence is another logger's.**
`botocore.tokens` writes *Loading cached SSO token for …* at `INFO` each time a session
loads its token: three sessions were measured, and wrote three lines. The same logger
says at `INFO` that a token was refreshed, or that a refresh could not be tried. An
attempt that failed is a warning.

**At `DEBUG`, botocore writes every step of every call.** One session, a client for each
of the ten services this package reads and four calls made 193 lines under `botocore`,
every one of them at `DEBUG`, beside the one sentence at `INFO`. A `LOG_LEVEL=DEBUG`
session is how a deployment reads its own code, and little-sister `architecture.md` §11
has one deployment's measure of what it read instead: two thirds of the log were
botocore's request detail.

**Some of those lines belong in no log.** A session on temporary credentials read one
secret from Secrets Manager and one parameter from Parameter Store. Of what botocore
wrote at `DEBUG`, four lines held the session's token: two under `botocore.auth`, in
the canonical request it signs, and two under `botocore.endpoint`, in the request as it
is sent. One line held the secret's value and one the parameter's, both under
`botocore.parsers`, which writes what a call answered. None held the secret access key.
An account that is read through a role is read on such a token, the secret provider
reads exactly such values ([ADR-0002](0002-aws-secret-references.md)), and
little-sister's default keeps its log in a file.

**urllib3 writes a `DEBUG` line for each connection it opens and each request it
sends**, under `urllib3.connectionpool`: eight for the four calls. botocore brings
urllib3, and little-sister does not depend on it.

**`boto3` and `s3transfer` wrote nothing.** They log from resources and from managed
transfers, and this package builds clients and calls them.

## Decision

### 1. Four rows

| Logger | Capped at | What the cap hides |
|---|---|---|
| `botocore` | `INFO` | a `DEBUG` line for each step of every call, a session's token and what a call answered among them, a secret's value where one is read |
| `botocore.credentials` | `WARNING` | where each new session found its credentials, a line a run |
| `botocore.tokens` | `WARNING` | which cached SSO token each new session loaded, a line a run, and each refresh of one unless the attempt failed |
| `urllib3` | `INFO` | a `DEBUG` line for each connection opened and each request sent |

The third column is the row's own sentence, as `/system/installed` prints it and as the
log says it where it begins (little-sister ADR-0121 decision 7).

**`INFO` on `botocore` and on `urllib3`** takes their `DEBUG` lines and leaves what they
say at `INFO`. That is little, and each line of it says that something is not as usual:
an instance's credentials kept past their end because their service could not be
reached, an endpoint taken from the environment, an answer this SDK is too old to read
in full, a redirect followed.

**`WARNING` on the two loggers beneath `botocore`** takes the sentence a session says of
itself, and what else those two say at `INFO`.

**No row for `boto3` or `s3transfer`.** A row that would take no line away is not
declared. A use of the SDK that writes under another logger — a resource, a managed
transfer — is measured when it is built, and declared with it.

### 2. Declared where the package is imported, and no level is set

The four calls stand in `little_sister_aws/__init__.py`, after `require_api()`. Every
way into this package passes that module, and every one of them opens its sessions
through boto3 ([ADR-0001](0001-the-aws-check-type.md) §5): the check type, the secret
provider, the keeper, and the identity seam used alone. So the rows hold whichever of
them a deployment uses. And they are declared in time: a deployment's startup file
imports this package before it imports the application, which is where the rows are
set.

A row sets nothing. The package calls no `setLevel` and installs no filter
(little-sister ADR-0121 decision 2). What stands on a logger is little-sister's to set
and the deployment's to overrule.

**[ADR-0002](0002-aws-secret-references.md)'s decision 1 stands**: the provider
registers nothing on import, and neither does the keeper. Which stores an installation
reads its credentials from, and where it keeps its state, are decisions, and a decision
is read at the place it is taken. A row is no such decision. It is what this package
knows of its dependency, which a deployment could learn only from its own log. It is a
default, shown on a page with what it hides, and every deployment overrules it by name.

### 3. Nothing the SDK says as a warning is taken out

A package caps at `INFO` or at `WARNING` (little-sister ADR-0121 decision 3), so the
rows take `DEBUG` and `INFO` lines and nothing above them. What botocore says as a
warning stays in the log, also where the check says the same on a node: a session that
has run out makes `botocore.credentials` and `botocore.tokens` warn at every run, each
time with a traceback. Taking those out is the deployment's, by name:
`LOG_LEVEL=INFO,botocore.credentials=ERROR,botocore.tokens=ERROR`.

### 4. What is not decided here

Whether this package should say a session's end once and hold botocore's repeats of it
back. That hides by content, and little-sister ADR-0121 decision 9 leaves such a filter
undecided. And what is written before the application is imported, which no row reaches
(see *Consequences*).

## Consequences

- **A log no longer holds the sentence at every run**, with nothing configured and no
  line of the deployment's own. Where the rows are set the log says so, a line for each
  row that was set and none for one that was not. `/system/installed` lists them under
  *Logging* with what each hides, and those that were not set with the reason
  (little-sister ADR-0121 decision 7).
- **The lines come back by name, at the next start**:
  `LOG_LEVEL=INFO,botocore.credentials=DEBUG`, in `.env` or in the environment, for a
  login that fails on one machine. An entry speaks for its name and for every name
  beneath it, so `botocore=DEBUG` has everything the SDK writes back, the token and the
  answers with it. That is the reason to name the narrowest logger that answers the
  question.
- **A `LOG_LEVEL=DEBUG` session holds the deployment's lines, little-sister's and this
  package's own, and of the SDK's none below `INFO`** — from where the application is
  imported.
- **The startup file is written under no row** (little-sister ADR-0121, in its
  consequences). What it reads from AWS before it imports the application — the secret
  provider resolving a door's credential, say — is written at the root's level alone. At
  a bare `LOG_LEVEL=DEBUG` the SDK's `DEBUG` lines of that read are in the log, the
  value among them. Two things hold there from the first line: an entry of the
  variable, and a level the startup file sets before the read.
  `LOG_LEVEL=DEBUG,botocore=WARNING,urllib3=WARNING` is a `DEBUG` session without the
  SDK. An entry on `botocore` speaks for the two loggers beneath it as well, so at
  `botocore=INFO` the sentence a session says of itself is back.
- **A deployment that capped the SDK in its startup file keeps its levels**: no row is
  set on a logger it set, nor on one beneath it (little-sister ADR-0121 decision 4), and
  the page says so. It may take its own lines out once it runs this release. One thing
  differs then: a cap of its own at `WARNING` on `botocore` took the SDK's few `INFO`
  lines as well, and the rows leave them.
- **The floor rises** to the release of little-sister that first carries the call
  (little-sister ADR-0121 decision 8). Against an older library the import of this
  package fails, whichever of its surfaces was asked for.
- **A row names a logger that is botocore's to rename.** If a sentence moves to another
  logger, the row caps nothing and nothing fails. So the suite has the SDK itself write
  each kind of line, in an interpreter of its own that sends nothing to AWS, and holds
  the rows against what was written.
- **The import of this package does one thing more**: it registers the check type and
  declares these rows. It still opens no session and registers no provider.

## Alternatives considered

- **One row, `botocore.credentials`**, the line a deployment reported and the example
  little-sister ADR-0121 gives. A machine signed in through an SSO session would have
  the other sentence at every run, and a `DEBUG` session would stay the SDK's.
- **One row, `botocore` at `WARNING`**, which is what one deployment wrote in its
  startup file. It hides the two sentences without naming them, and every other `INFO`
  line of the SDK with them. Of two rows that reach one logger the higher stands
  (little-sister ADR-0121 decision 4), so another package that brings boto3 and
  declares `botocore` at `INFO` could not have those lines either.
- **Rows on the three loggers that write the token and the answers** —
  `botocore.auth`, `botocore.endpoint` and `botocore.parsers` — and `DEBUG` left open
  beside them. The rest of the SDK's `DEBUG` lines would stay in a `DEBUG` session,
  which is the two thirds nobody asked for. And which logger writes what is botocore's
  to change in any release.
- **No row on `urllib3`**, which another dependency of a deployment may write under as
  well. Its lines are written for this package's calls in every deployment that
  installs it, a cap at `INFO` takes `DEBUG` lines alone, and whoever wants them names
  the logger.
- **Declaring where a provider is registered and where the check type is**, so that
  importing the package would declare nothing. The same rows would be declared in three
  places, and code that uses the identity seam alone would have none.
- **Setting the levels where the package is imported.** little-sister ADR-0121 decision
  2 rules it out, and says why: a level for somebody else's log, set by code the
  deployment did not write, and holding or not by the order of its imports.
- **A filter that lets a session's sentence through once.** It hides by content (§4).

