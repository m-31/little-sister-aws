# ADR-0003 — A graded threshold is a pair, and a rule owns names

- **Status:** Accepted
- **Date:** 2026-08-29
- **Related:** [ADR-0001](0001-the-aws-check-type.md) (the type these aspects
  belong to, and the line between what is true of the type and what is true of an
  installation), little-sister **ADR-0042** (an entry carries its own status),
  little-sister **ADR-0050** (a declared slug is an identity claim), little-sister
  **ADR-0013** (a check reports its own configuration)

## Context

Every graded threshold in this type was **one number that could produce one
severity**, applied to every name in every account.

The `ec2` aspect is where that hurt first, because an estate keeps unlike things
under one aspect. `max_per_name` warned and could never burn: a hundred boxes under
a name that should be unique was the same yellow as two. `max_age` burned and could
never warn: there was no way to say "look at this next week" before "this is a
finding". Both were global, while a real account holds an instance that must be
unique forever *and* a load test that is fine at fifty for three hours. `fleet_size`
was the patch for that — a group larger than some number was read as a deliberate
fleet and judged by a shorter clock — and it keyed on the **reading** rather than on
the name, so it could only ever be one rule for every estate.

And none of them said *why*. A yellow line reading `grafana: 2 (3d)` is a number the
operator has to take back to the configuration file to interpret, and the answer is
different for two names carrying the same count: a second Grafana can come from an
autostart, while a second box under a name that owns a single block device cannot
have attached it.

The same shape sits in `codepipeline` (one staleness clock for a pipeline that runs
nightly and one that runs at a release) and in `lambda`. Answering it once per
aspect would be three answers to one question, which this family already knows the
cost of.

## Decision

### 1. A graded threshold is a pair, with a sentence

`<limit>_warn` and `<limit>_error`, and `<limit>_reason` beside them. The two
levels are the same judgment at two severities; the sentence is what the judgment
*means*, and it rides on the line when that judgment fires.

Two judgments meeting on one line are resolved by taking the **worse** of them, and
both contribute their sentence, count first. That replaces the old rule where age
outranked count: the outcome is the same wherever the old rule applied, and it is
now what the levels mean rather than a special case.

The comparison is **strictly above** — `max_per_name_warn: 1` warns at two —
because the key is named for the largest value that is still fine. It follows that
`0` is the spelling of *tell me about any of these at all*.

### 2. A level is a number or it is absent, and absent is not graded

There is no infinity to configure and no sentinel to remember: a level with no
number is a comparison that does not happen. Written as `null`, a whole judgment is
switched off for the names it applies to — which is how an instance kept
deliberately old is expressed, and it keeps the age on the line while never
coloring by it.

### 3. The package ships no thresholds and no sentences

A default that is a fact about **AWS** survives — a terminated instance lingers in
`describe_instances` for about an hour, so it is not counted. A default that is a
judgment about somebody's **estate** does not: what a name may carry and how long a
box may run are facts this package has never seen.

An aspect that grades nothing is therefore legal, and is an inventory: every name,
its count, the ages of its boxes, uncolored. It is announced once in the log rather
than refused, because a contradiction is a refusal and an omission is a line in the
log — and an inventory is a coherent thing to ask for from an aspect whose roster is
half of what a reader came for.

The alternative was to keep the numbers that were there. They were an opinion about
how often an estate replaces its boxes, held by a package with no way to know, and
the one installation that ran them had never chosen them.

### 4. A rule owns a set of names

A `rules:` list, each rule matching by exact `names:`, by `prefixes:`, by `regexes:`
(case-insensitive, matched anywhere unless anchored), or by `unnamed: true` for the
instances with no `Name` tag. Plural, because a set of names sharing one set of
limits is the ordinary case and a rule per name would copy every level and every
sentence once per member.

Four properties, and each was chosen against a plausible alternative:

- **The first matching rule decides, wholly.** Not the first rule that sets each
  key, which is a merge and asks the question again per key; not "the most specific
  rule", because there is no total order on regexes and a faked one is worse than
  arbitrary. An exception is therefore a rule written **above** the rule it excepts,
  and there is no negation key.
- **A rule inherits by pair.** Writing either level of a pair takes that pair whole;
  a pair the rule does not mention comes from the block, whole. Inheriting by *key*
  would mean a rule that raises a warning level inherits an error level below it —
  an inversion the parser then has to refuse, so the common case would pay for the
  rare one.
- **An override may loosen.** A fleet rule raises a count *and* shortens a clock,
  which rules out any "strictest wins" resolution: under it the block's tight count
  would win and every member of a declared fleet would be yellow forever.
- **A rule's limits are applied to each matching name on its own**, never to their
  sum. The reading is *this name carries too many boxes*, and two load tests
  carrying ten and twelve are two lines against the rule's levels, not twenty-two.

### 5. Ignoring is a rule action

`ignore: true` drops the names a rule matches: no line, not counted in scope. It
replaces the substring ignore list this aspect had, which leaves the aspect with one
matcher vocabulary, makes ignoring **ordered** — "ignore `tmp-` except `tmp-db`" is
two rules in the obvious order, which a flat list could not say — and keeps the
distinction between *ignored* (no line) and *not graded* (a line, uncolored) visible
in the configuration.

### 6. What is named, and what is not

Rules match the **raw** `Name` tag, never a display name: a shortening rule is about
how a card reads and must not decide which limits apply.

The group of instances with no `Name` tag is addressed by `unnamed: true` rather
than by the placeholder a card prints for it. That placeholder is display text this
package may reword, and a configuration matching it would have made it a stored key.

Every rule carries a required `name:`. It identifies the rule in a refusal, in the
log line about rules that matched nothing, and — when a judgment fires with no
sentence of its own — on the status line itself, which is a worse sentence than one
somebody wrote and much better than an unexplained color.

### 7. A rule that matches nothing is a log line, never a node

A rule whose matcher is a typo is a fact about the **configuration**, not a finding
in the estate. Reporting it on a node would color a card over a mistake in a file
and send an operator hunting through an account where nothing is wrong. It is
reported at `INFO`, naming the rules, and only when that set changes — at
`frequency: 60s` an unconditional line is fourteen hundred identical records a day
about a mistake that was true at breakfast.

### 8. A group's ages are a range, and the oldest still grades

A line used to carry its oldest member's age, which is the verdict but a third of
the reading: a name being rolled and a name started once and left both read
`(16h)`. The line now carries a range whose shape follows **how many distinct
strings the ages render to**, not how many boxes there are — one value where they
all read alike, both values where there are exactly two, youngest to oldest where
there are more.

Two distinct values are not an interval: an interval says there is a spread with
members inside it, while two adjacent readings are two readings. And the display's
own granularity decides what counts as distinct, because the reader is never shown
more precision than that: printing `1d 1h - 1d 1h` would be noise manufactured out
of a difference the card does not display.

The **oldest** member remains what the age is graded on. An instance is patched by
being replaced, so the box that has run longest is the security fact.

## Consequences

- **Slugs do not move.** A group's entry is still keyed `slug(region, name)`, so
  every maintenance pin held against an EC2 line survives all of this — including
  the group with no `Name` tag, which is keyed internally by absence and slugged by
  the same placeholder as before.
- **Old configurations are refused, by name, at startup.** `max_per_name`,
  `max_age`, `fleet_size`, `fleet_max_age` and this aspect's `ignore_name_patterns`
  are unknown keys now, and meet the message any typo meets. Nothing is owed to
  them: a hint naming each replacement would be a permanent line in the parser for a
  one-time reading of one error message, and what a version changed is what a
  CHANGELOG is for.
- **An installation that wrote nothing down loses its grading**, deliberately and
  visibly: it gets an inventory and a log line saying so, rather than an opinion it
  never chose.
- **The vocabulary is the type's, not this aspect's.** The parsing is shared from
  the first commit, and `codepipeline` and `lambda` adopt it: levels where there is
  a threshold to grade, rules and reasons everywhere. `lambda`'s `error_max_age` is
  a **gate** — whether a newest error is graded at all — rather than a threshold to
  split, so it gains rules and a sentence and no second level; forcing a pair onto
  it would produce `error_max_age_warn`, which means nothing.
- **`cloudwatch` stays outside the graded half.** It grades on the alarm's own state
  through `state_map`, so it has no threshold to split into levels.
- **The card carries more, and has to.** With no defaults left, a check's own
  configuration report is the only place a reader can see what an installation
  actually grades on — so it lists the effective levels, the sentence each judgment
  says, and the rules in the order they are consulted.

## Alternatives considered

- **Keep the key names and give them nested `{warn, error}` values.** Rejected: it
  reads better and it changes what an existing key *means*, differently for each of
  the two — `max_per_name` was a warn threshold and `max_age` an error one — so a
  config that kept working would have been regraded silently in one of the two
  cases. Four new names cannot do that.
- **A compatibility window in which both spellings work.** Rejected: a permanent
  branch in the parser to save one reading of one error message, in a package whose
  installations can be counted.
- **Keep `fleet_size` as a rule condition** (`when_count_over:`), so an
  unanticipated large group still gets a short clock. Rejected as a mechanism that
  exists for a case the block's own levels already cover: those levels are what the
  check says about a name nobody classified, and they catch a new name on the day it
  appears rather than after four hours.
- **A budget over everything a rule matches** — "no more than thirty loadtest
  instances in total". Rejected here, not forever: it grades a set that has no line
  of its own, and it answers a cost question rather than a leftover-and-patching
  one.
- **Report a rule that matched nothing on the node.** Rejected: see decision 7.
- **A `not:` on a rule, for exceptions.** Rejected: first-match-wins already
  expresses an exception as an ordered rule, and a second way to say it is a second
  thing to reason about when two rules disagree.
- **Match the unnamed group by its placeholder string.** Rejected: it turns display
  text into a stored key, and this package would then be unable to reword its own
  card.
