# ADR-0007 — A level stands in the tree only where the configuration names several

- **Status:** Accepted
- **Date:** 2026-10-03
- **Related:** [ADR-0001](0001-the-aws-check-type.md) (account first, aspect second —
  its §2 is amended here — and the region in every slug, which stays),
  [ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md) (a subject names
  its account and its region, which is why a history survives a change of shape, and a
  root that grades nothing — its §6 is amended here),
  [ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) (a function's
  node, the first to hang by this rule),
  [ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md) (a pipeline's node and a job
  queue's, which hang by it too, and the queue's level, which this rule does not count),
  little-sister **ADR-0106** (where a subject's node hangs is its type's to say), little-sister **ADR-0109** (what could not be read
  has a level of its own, and a pin that stands without a node), little-sister
  **ADR-0087** (a series is keyed by its check and its subject, and never by a path),
  little-sister **ADR-0118** (a node a run names says so, and takes nothing declared for
  its name)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

The tree was `/<path>/<account>/<aspect>` for every check (ADR-0001 §2, before this
record), with one account as with five. The three reasons that record gives for the
account's level are reasons to tell accounts apart: one pin silences one account, one
account's refusal reddens its own node while the others keep reporting, and a label on
every line is a tree that was not available. Where a check names one account there is
nothing to tell apart. The level then says one word in every path, every address and
every card, and the check's own node above it says nothing the account's does not.

The question arrives a second time with
[ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md). A function has
a node of its own, a pipeline and a job name follow it
([ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md)), and two regions may each hold a
function of one name, so something in a path has to tell them apart — and nothing has to
where an account reads one region.

This package has answered such a question once, and the other way: a line's slug carries
the region whether or not the line prints it, since every pin would otherwise re-point
the day a second region is configured (ADR-0001). That is stability bought with a part
that says nothing. In a slug the part costs nothing a reader sees. In a path it is a
level on the wall of every deployment.

## Decision

### 1. A level stands only where the configuration names more than one of it

**The account's level stands where a check names several accounts, and a region's where
an account reads several regions.** The parts of a subject that are constant in a
deployment — its one account, its one region — are left out of its node's path.

**What is counted is the configuration** — the accounts a check names, and the regions
an account lists, its own or the check's — **and never what AWS answers.** An account
that could not be read is still one of those named, and a region that holds nothing
still has its level where there are several. So a tree changes its shape when its
configuration does, and at no other time.

The shape is each account's own: one check may hold a region's level under the account
that reads two regions, and none under the account that reads one.

**A level's node says that the configuration names it** (little-sister ADR-0118). An
account's node and a region's are named by what a deployment wrote, as a function's is
by what AWS calls the function
([ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) §9), and each
says so, read or not. What this type declares for an aspect — its title, its `about`,
that it stays in view while it is quiet — is declared for the aspect's name, and so
reaches no account, region or function that happens to carry one: an account called
`ec2` shows its own `title` and `about`, and the `ec2` aspect beneath it the aspect's.

### 2. One account is the check's own node

Where a check names one account, the account has no node. Its aspects hang beneath the
check's `path:`, and what refused the account — the reason, and the command that renews
an expired login — is said on the check's node, which is then `ERROR`. A pin on that
node is the pin on the account.

**An account's `title` and `about` label the account's node, so where the account has
none they are not shown**, and the check's own `title:` and `about:` are. The check says
so once, in the log, when it is loaded: which account, which of the two keys, and that
the check's own are where to say it. The configuration loads as it did, and the text is
shown again the day the check names a second account.

**What the account's node said of its configuration, the check's page says**: the
regions the account is read in, its own where it lists them, and where its credentials
come from.

This amends ADR-0001 §2, whose tree is the one a check that names several accounts still
has, and ADR-0005 §6: the root grades nothing where it stands above its accounts' nodes,
and it takes its one account's refusal where it stands for that account. The estate's
reading, its subject and its state are what they were.

### 3. A region's level stands beneath an aspect whose subjects are nodes

An aspect that writes a line for each thing it reads has no levels beneath it, and its
lines print the region where an account reads several, as they do today. An aspect that
hands back a node for each subject — `lambda` is the first
([ADR-0006](0006-a-functions-runs-are-kept-and-a-function-has-a-node.md) §9), and
`codepipeline` and `batch` follow it ([ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md))
— holds a node for each region where its account reads several, and the subjects beneath
that:

```
<path>/lambda/<function>                       one account, which reads one region
<path>/lambda/<region>/<function>              one account, which reads several
<path>/<account>/lambda/<function>             several accounts; this one reads one region
<path>/<account>/lambda/<region>/<function>    several accounts; this one reads several
```

A pipeline hangs beneath `codepipeline` the same way, and a job queue beneath `batch`,
with its job names beneath it.

That level is what tells two regions' subjects of one name apart. A region's node is
named by the region and grades nothing of its own, unless the region could not be read,
which it then says. And it is the node that says its children are complete
(little-sister ADR-0109 decision 2): a region that could not be read keeps the nodes it
had, while its neighbors still remove what is gone. It declines the density trade as its
aspect does (little-sister ADR-0063): it is the box a region's subjects stand in, and
which subjects there are is read while all is well.

**The line on a subject's own node prints no region**: where an account reads several
the level says it, and where it reads one nothing has to. Its slug keeps the region
(§5).

### 4. The aspect is always a level

A function hangs beneath `lambda` where `lambda` is the one aspect its check runs, too.
`enabled:` is configuration as an account is, and the rule stops before it. The aspect
is the one word in a path that says **what** the nodes beneath it are, where an account
and a region say where; its node has lines of its own; and an aspect is what a
deployment switches on later.

### 5. A subject keeps every part, and so does a slug

A subject names its account and its region whatever shape the tree has (ADR-0005 §4),
and a series is keyed by its check and its subject, never by a path (little-sister
ADR-0087 decision 1). So a history is found again after a tree has changed its shape. A
line's slug keeps the region, as ADR-0001 has it.

### 6. What moves, and when

**With the release that carries this**, the paths of every deployment whose check names
one account lose the account's level, once.

**The day a configuration names a second account, or an account a second region, every
path beneath the new level moves**, and with it what is keyed by a path: a pin, which
stays and is listed as one whose node is no longer reported until it expires
(little-sister ADR-0109 decision 4); a node's status history; a `nodes.yaml` entry; a
path a client watches. That is the price of this decision, and it was named before the
decision was taken. A configuration changes its shape rarely, and by an edit somebody
makes on purpose.

## Consequences

- **ADR-0001 §2 and ADR-0005 §6 are amended**, and ADR-0001's rule for a slug stands.
- **A deployment whose check names one account sees its paths move** with the release
  that carries this, and that release's notes say which.
- **A tree's shape depends on its configuration in two places**, and the tests cover
  each combination.
- **An account's `title` and `about` belong to the account's node.** Where the account
  has none they are not shown, the check's own are, and the log says so once when the
  check is loaded (§2).
- **Nothing a history holds is lost** by a change of shape (§5).
- **A pipeline and a job queue hang by the same rule**
  ([ADR-0009](0009-a-job-name-and-a-pipeline-have-nodes.md)). A queue is nothing a
  configuration names, so this rule does not count one, and that record makes it a level
  in every Batch path.

## Alternatives considered

- **A region's level in every path.** Refused in §1: no path would ever move, and every
  deployment that reads one region would carry a level that says nothing.
- **A region's level only where two regions do hold a subject of one name.** Refused in
  §1: a path would move by what AWS answers, on a day nobody edited anything.
- **The account's level kept, and a region's alone by this rule.** Refused in §2: the
  reasons for the account's level are reasons to tell accounts apart.
- **The region in every node's name.** Refused in §3: one level and never a move, and a
  node that is no longer named by what AWS calls the thing.
- **An account's `title` and `about` filling the check's own where the check says
  none**, or **refused at load**, or **dropped without a word**. Refused in §2: the
  first is a precedence between two sources of one label, for a configuration no
  deployment has; the second makes a configuration that is valid with two accounts
  invalid with one, and pins a deployment's check at an upgrade until its file is
  edited; the third reads a key and says nothing of it.
- **Every configured level skipped, the aspect with them**, so that a check which runs
  one aspect holds its subjects directly beneath its `path:`. Refused in §4.

