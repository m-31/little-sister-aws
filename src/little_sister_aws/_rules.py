"""The configuration vocabulary the aspects share.

Every graded threshold in this type used to be **one number that could produce one
severity**: `ec2`'s `max_per_name` warned and never burned, its `max_age` burned and
never warned, and each of them judged every name in every account. This module is the
shape that replaces all of them, so that a second aspect does not answer the same
question a second way (the family's rule about plumbing solved once).

A threshold is a **pair**, `<name>_warn` and `<name>_error`, with a `<name>_reason`
beside it — the sentence a line carries when that judgment is what colored it. Three
properties are load-bearing, and each is a decision rather than an implementation
detail:

- **A level is a number or it is absent, and absent is not graded.** There is no
  infinity to write and no sentinel to remember: a level with no number is a
  comparison that does not happen. A key written as `null` reads the same as a key
  left out here; the difference between the two matters only where a rule inherits
  from the block above it, which is later work.
- **Nothing here has a default.** A default that is a fact about AWS may live in an
  aspect — a terminated instance lingers in `describe_instances` for about an hour,
  so it is not counted — but a threshold is a judgment about somebody's estate, and
  this package has never seen it. An installation that grades nothing gets an
  inventory and one log line, not an opinion.
- **The comparison is strictly above.** `max_per_name_warn: 1` warns at *two*,
  because the key is named for the largest value that is still fine. It follows that
  `0` is the useful spelling of "tell me about any of these at all", and that the
  library's `grade()` helper — which is at-or-above — is not what this is.

Beside the pair sits the **rule**: a set of names — exact ones, prefixes, regexes,
or the group nobody named — carrying its own pairs, which override the block's for
the names it matches. Four things about them are decisions rather than mechanics:

- **The first matching rule decides, wholly.** Not the first rule that sets each
  key, which would be a merge and would ask the same question once per key. An
  exception is therefore a rule placed *above* the rule it excepts, and there is no
  negation key.
- **A rule inherits by pair, not by key.** Writing either level of a pair takes the
  whole pair from the rule; a pair the rule does not mention comes from the block
  above it, whole. This is what lets a fleet rule say `max_per_name_warn: 50` on one
  line without also having to restate an error level it does not want.
- **A rule's limits are applied to each matching name on its own**, never to their
  sum. Two names under one rule carrying ten and twelve instances are two lines
  judged against the rule's levels; they are not twenty-two.
- **Ignoring is one of the things a rule can say.** `ignore: true` drops the names
  it matches — no line, not counted — which is what a flat list of substrings used
  to do, except that it is now ordered and speaks the same matcher as everything
  else.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from little_sister.checks import CheckError, parse_duration
from little_sister.status import StatusCode

#: The suffixes one threshold owns in a configuration block. Derived rather than
#: written out at each call site, so an aspect's ``known`` key set and its parser
#: cannot disagree about what a pair is called.
SUFFIXES = ("warn", "error", "reason")


@dataclass(frozen=True)
class Threshold:
    """One graded judgment: two optional levels, and the sentence it adds.

    ``reason`` is what the operator reads. A number decides the color and says
    nothing about what is wrong — two instances under one name is "there should be
    only one of these" for one name and "a second one cannot have attached the block
    device" for another, and the count is the same reading in both.
    """

    warn: int | None = None
    error: int | None = None
    reason: str = ""

    @property
    def grades(self) -> bool:
        """Whether this judgment can produce anything but ``OK``."""
        return self.warn is not None or self.error is not None

    def code_for(self, value: int) -> StatusCode:
        """This judgment's verdict on one value — *more than* a level, never *at*
        it (see the module docstring). A level that is not set cannot fire."""
        if self.error is not None and value > self.error:
            return StatusCode.ERROR
        if self.warn is not None and value > self.warn:
            return StatusCode.WARN
        return StatusCode.OK

    def summary(self, render: Callable[[int], str]) -> str | None:
        """The configuration card's line for this pair, or ``None`` when it grades
        nothing — there is no honest way to render a comparison that never runs.

        ``render`` is the caller's, because a count is a count and a duration is a
        span: the aspect knows which of the two it configured.
        """
        parts = [f"{level} above {render(value)}"
                 for level, value in (("warn", self.warn), ("error", self.error))
                 if value is not None]
        return ", ".join(parts) or None


#: A judgment nobody configured: no level, no sentence, no color. One shared
#: instance rather than ``Threshold()`` written at each dataclass default — a frozen
#: dataclass is perfectly safe as a default, but a *call* in one is the pattern that
#: bites when the value is not immutable, and the linter is right not to trust the
#: reader to check.
UNGRADED = Threshold()


def threshold_keys(name: str) -> set[str]:
    """The keys ``name`` owns, for an aspect's ``known`` set."""
    return {f"{name}_{suffix}" for suffix in SUFFIXES}


def parse_threshold(block: Mapping[str, Any], name: str, where: str, *,
                    duration: bool = False) -> Threshold:
    """Read ``<name>_warn`` / ``<name>_error`` / ``<name>_reason`` out of a block.

    ``where`` names the block in a refusal (``"ec2"``), so a message says which of
    five aspects the mistake is in. ``duration`` picks the level's type: a span for
    an age, an integer for a count.
    """
    warn = _level(block, f"{name}_warn", where, duration=duration)
    error = _level(block, f"{name}_error", where, duration=duration)
    if warn is not None and error is not None and error <= warn:
        # Equal is refused with the rest: the comparison is *more than*, so a warn
        # level that is not below the error one can never be the answer — every
        # value that passes it has passed the error level too. A threshold that
        # cannot be reached is a configuration saying something it cannot mean.
        raise CheckError(
            f"{where} '{name}_error' ({error}) must be above '{name}_warn' "
            f"({warn}), or the warning can never be reported")
    reason = _reason(block, f"{name}_reason", where)
    if reason and warn is None and error is None:
        raise CheckError(
            f"{where} '{name}_reason' is set but neither '{name}_warn' nor "
            f"'{name}_error' is, so the sentence could never be shown")
    return Threshold(warn=warn, error=error, reason=reason)


def _level(block: Mapping[str, Any], key: str, where: str, *,
           duration: bool) -> int | None:
    """One level, or ``None`` for a key that is absent or explicitly ``null``."""
    if key not in block:
        return None
    value = block[key]
    if value is None:
        return None
    if duration:
        if isinstance(value, bool):
            raise CheckError(f"{where} '{key}' must be a duration of at least 1s")
        seconds = parse_duration(value, 0)
        if seconds < 1:
            raise CheckError(f"{where} '{key}' must be a duration of at least 1s")
        return seconds
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        # Zero is allowed and is the point: it is how a block says that *any* value
        # above nothing is worth reporting, which is what an estate writes for the
        # names it has not classified.
        raise CheckError(f"{where} '{key}' must be an integer of 0 or more")
    return value


def _reason(block: Mapping[str, Any], key: str, where: str) -> str:
    if key not in block or block[key] is None:
        return ""
    value = block[key]
    if not isinstance(value, str) or not value.strip():
        raise CheckError(f"{where} '{key}' must be a non-empty sentence")
    return value.strip()


@dataclass(frozen=True)
class Matcher:
    """The set of names one rule owns.

    Plural on purpose: a set of names sharing one set of limits is the ordinary
    case, and a rule per name would mean copying every level and every sentence
    once per member of a group that is a group *because* it is judged alike.

    All three forms are case-insensitive, and a regex is matched with ``search``
    rather than ``fullmatch`` — the sibling package settled that for its own
    patterns, and anchoring is what ``^`` is for. What a matcher never sees is a
    display name: matching is on the value the API returned, so a shortening rule
    can never change which rule applies.
    """

    names: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    regexes: tuple[re.Pattern[str], ...] = ()
    unnamed: bool = False

    def matches(self, name: str | None) -> bool:
        """``name`` is ``None`` for the group of things nobody named — the one
        group that has no name to match, and the one an estate most wants to
        grade. It is addressed by ``unnamed:`` rather than by the placeholder
        text a card happens to print, which stays this package's to reword."""
        if name is None:
            return self.unnamed
        lowered = name.lower()
        return (lowered in self.names
                or any(lowered.startswith(prefix) for prefix in self.prefixes)
                or any(pattern.search(name) for pattern in self.regexes))


#: A matcher that owns nothing. Same reasoning as ``UNGRADED``: a shared instance
#: rather than a call in a dataclass default.
MATCHES_NOTHING = Matcher()


@dataclass(frozen=True)
class Rule:
    """One named set of names, and what is true of them.

    ``overrides`` carries only the pairs the rule actually wrote — that is the
    whole of "inherit by pair": a pair absent here comes from the block above,
    whole, and a pair present here is used whole, including the half the author
    left unset.
    """

    name: str
    matcher: Matcher = MATCHES_NOTHING
    ignore: bool = False
    overrides: tuple[tuple[str, Threshold], ...] = ()
    #: Everything an aspect overrides that is **not** a graded pair — a gate, a
    #: switch, a sentence. Parsed by the aspect (``parse_extra`` below), because
    #: what they mean is its business; carried here so that first-match-wins and
    #: "absent means inherit" are answered in one place for all of them.
    values: tuple[tuple[str, object], ...] = ()

    def threshold(self, pair: str) -> Threshold | None:
        """This rule's version of ``pair``, or ``None`` to inherit it."""
        for name, threshold in self.overrides:
            if name == pair:
                return threshold
        return None

    def value(self, key: str) -> object | None:
        """This rule's version of a non-graded setting, or ``None`` to inherit."""
        for name, value in self.values:
            if name == key:
                return value
        return None

    @property
    def says_something(self) -> bool:
        """Whether this rule sets anything at all beyond matching names."""
        return bool(self.overrides or self.values)


def rule_for(rules: Sequence[Rule], name: str | None) -> Rule | None:
    """The first rule that matches, or ``None`` — first-match-wins, in the order
    the configuration wrote them, so an exception is a rule placed above the rule
    it excepts."""
    for rule in rules:
        if rule.matcher.matches(name):
            return rule
    return None


def resolved(rule: Rule | None, pair: str, block: Threshold) -> Threshold:
    """The judgment in force for one group: the matched rule's version of *pair*
    if it wrote one, and the block's otherwise.

    This is inheritance **by pair** in one place, tested against ``None`` rather
    than truthiness — an *explicitly ungraded* pair is a real override, and
    reading it as "nothing here, inherit" would silently put the block's limits
    back on exactly the names somebody had exempted.
    """
    if rule is None:
        return block
    own = rule.threshold(pair)
    return block if own is None else own


def sentence_for(threshold: Threshold, rule: Rule | None) -> str:
    """What a fired judgment says: its own sentence, else the name of the rule
    that supplied it, else nothing.

    The rule's name is a worse sentence than one somebody wrote and much better
    than an unexplained color, because it says where in the configuration the
    decision was made. With no rule there is nothing to name, and inventing
    "count above the limit" would be prose about an estate written by a package
    that has never seen it.
    """
    if threshold.reason:
        return threshold.reason
    return rule.name if rule is not None else ""


def parse_pair(block: Mapping[str, Any], name: str, where: str, *,
               duration: bool = False) -> Threshold | None:
    """One pair, or ``None`` when the block says nothing about it at all.

    Three states, and the third is why this exists: a pair can be **absent**
    (``None`` here — a rule inherits it, a top-level block simply grades nothing),
    **explicitly ungraded** (``max_age: null`` — the whole judgment switched off,
    inheriting nothing, which is how an instance kept deliberately old is written),
    or **set**. There is no infinity to compare against; there is a comparison that
    does not happen.
    """
    if not any(key in block for key in {name} | threshold_keys(name)):
        return None
    if name in block:
        if block[name] is not None:
            raise CheckError(
                f"{where} '{name}' accepts only null, which switches the whole "
                f"judgment off — set a level with '{name}_warn' or "
                f"'{name}_error'")
        conflicting = sorted(key for key in threshold_keys(name) if key in block)
        if conflicting:
            raise CheckError(
                f"{where} '{name}: null' switches the judgment off, so it cannot "
                f"be written beside {', '.join(repr(key) for key in conflicting)}")
        return UNGRADED
    return parse_threshold(block, name, where, duration=duration)


#: An aspect's own reader for the rule keys that are not graded pairs: given the
#: rule mapping and how a refusal should name it, it returns what to carry.
ExtraReader = Callable[[Mapping[str, Any], str], "tuple[tuple[str, object], ...]"]


def parse_rules(value: object, where: str, pairs: Sequence[tuple[str, bool]], *,
                allow_unnamed: bool = False,
                extra_keys: Sequence[str] = (),
                parse_extra: ExtraReader | None = None) -> tuple[Rule, ...]:
    """The ``rules:`` list of an aspect that has one.

    ``pairs`` is what this aspect grades — ``(("max_age", True),)`` for a name and
    whether it is a duration — so the vocabulary is one parser and each aspect
    says what it measures.

    ``allow_unnamed`` is the same idea for the matcher. Only EC2 has a group of
    things nobody named; a pipeline and a Lambda function are named by existing,
    so ``unnamed: true`` there would be a rule that can never match — dead
    configuration, and the kind that looks like it is working.

    ``extra_keys`` and ``parse_extra`` are for an aspect whose rules override
    something that is not a graded pair — a gate, a switch, a sentence. The
    matching, the ordering and the refusals stay here; what those keys *mean*
    stays with the aspect that has them.
    """
    if value is None:
        return ()
    if not isinstance(value, list):
        raise CheckError(f"{where} 'rules' must be a list of mappings")
    known = {"name", "ignore", "names", "prefixes", "regexes"}
    if allow_unnamed:
        known.add("unnamed")
    known |= set(extra_keys)
    for pair, _ in pairs:
        known |= {pair} | threshold_keys(pair)
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, item in enumerate(value, 1):
        if not isinstance(item, dict):
            raise CheckError(f"{where} rules[{index}] must be a mapping")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise CheckError(
                f"{where} rules[{index}] needs a 'name' — it is what a refusal, "
                f"the log line about rules that matched nothing, and a line with "
                f"no sentence of its own all call this rule")
        name = name.strip()
        rule_at = f"{where} rules[{index}] ({name!r})"
        if name.lower() in seen:
            raise CheckError(f"{rule_at}: another rule is already called that")
        seen.add(name.lower())
        unknown = sorted(str(key) for key in item if str(key) not in known)
        if unknown:
            raise CheckError(
                f"unknown key(s) in {rule_at}: {', '.join(unknown)} "
                f"(a rule takes: {', '.join(sorted(known))})")
        rules.append(_parse_rule(item, rule_at, pairs, allow_unnamed,
                                 parse_extra))
    return tuple(rules)


def _parse_rule(item: Mapping[str, Any], rule_at: str,
                pairs: Sequence[tuple[str, bool]], allow_unnamed: bool,
                parse_extra: ExtraReader | None) -> Rule:
    matcher = _parse_matcher(item, rule_at, allow_unnamed)
    ignore = item.get("ignore", False)
    if not isinstance(ignore, bool):
        raise CheckError(f"{rule_at}: 'ignore' must be true or false")
    overrides = tuple(
        (pair, threshold)
        for pair, duration in pairs
        if (threshold := parse_pair(item, pair, rule_at, duration=duration))
        is not None)
    values = parse_extra(item, rule_at) if parse_extra is not None else ()
    rule = Rule(name=item["name"].strip(), matcher=matcher, ignore=ignore,
                overrides=overrides, values=values)
    if ignore and rule.says_something:
        # Both halves are somebody's intention and only one of them can happen:
        # an ignored name has no line to color.
        raise CheckError(
            f"{rule_at}: 'ignore' drops these names entirely, so it cannot be "
            f"written beside a limit, a switch or a sentence")
    return rule


def _parse_matcher(item: Mapping[str, Any], rule_at: str,
                   allow_unnamed: bool) -> Matcher:
    names = tuple(text.lower()
                  for text in _name_list(item, "names", rule_at))
    prefixes = tuple(text.lower()
                     for text in _name_list(item, "prefixes", rule_at))
    regexes = []
    for pattern in _name_list(item, "regexes", rule_at):
        try:
            regexes.append(re.compile(pattern, re.IGNORECASE))
        except re.error as error:
            raise CheckError(
                f"{rule_at}: 'regexes' entry {pattern!r} is not a regular "
                f"expression: {error}") from error
    unnamed = item.get("unnamed", False) if allow_unnamed else False
    if not isinstance(unnamed, bool):
        raise CheckError(f"{rule_at}: 'unnamed' must be true or false")
    forms = "'names', 'prefixes', 'regexes' or 'unnamed'" if allow_unnamed \
        else "'names', 'prefixes' or 'regexes'"
    if not (names or prefixes or regexes or unnamed):
        raise CheckError(
            f"{rule_at}: a rule needs at least one of {forms} — a rule that "
            f"means to match everything says so with regexes: ['.*']")
    return Matcher(names=names, prefixes=prefixes, regexes=tuple(regexes),
                   unnamed=unnamed)


def _name_list(item: Mapping[str, Any], key: str, rule_at: str) -> list[str]:
    value = item.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise CheckError(f"{rule_at}: '{key}' must be a list")
    entries = []
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            # An empty prefix matches every name, which is the accidental
            # spelling of a rule that swallows the estate.
            raise CheckError(
                f"{rule_at}: every '{key}' entry must be a non-empty string")
        entries.append(entry.strip())
    return entries
