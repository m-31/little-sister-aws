"""One run of a check, the way the engine does it.

The engine calls :meth:`~little_sister.checks.Check.measure` and then
:meth:`~little_sister.checks.Check.grade` (little-sister ADR-0086), and a test that
wants *the result of running this check* wants both. Written once here rather than in
every test, and deliberately **not** a method on the check: a convenience that ran the
two halves together would be the thing every author reached for, and the seam would
quietly stop being a seam. The library's own suite keeps the same helper for the same
reason; its tests do not ship, so this one is ours.

``now`` defaults to the clock the ``aws`` module reads, ``_utcnow``, which the suite
holds still — so a test that froze the one clock the check reads while measuring
hands the grading the same instant, and every age on a line is measured to it.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from little_sister.checks import Check, CheckResult, Measurement

from little_sister_aws import aws


def measured(check: Check) -> tuple[Measurement, ...]:
    """What one ``measure()`` handed back, normalized the way the engine does."""
    answer = check.measure()
    if isinstance(answer, Measurement):
        return (answer,)
    return tuple(answer)


def run_check(check: Check, *, now: datetime | None = None,
              measurements: Sequence[Measurement] | None = None) -> CheckResult:
    """Measure, then grade, and answer the result the engine would store.

    ``measurements`` replaces the measuring half, for a test that grades a reading
    it wrote itself — which is the whole point of the split.
    """
    taken = measured(check) if measurements is None else tuple(measurements)
    return check.grade(taken, now or aws._utcnow())
