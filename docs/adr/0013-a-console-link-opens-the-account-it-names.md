# ADR-0013 — A console link opens the account it names

- **Status:** Accepted
- **Date:** 2026-10-10
- **Related:** [ADR-0001](0001-the-aws-check-type.md) (§2, an account's `regions:` and
  `profile:` over the check's; and the consequence that keeps the account id off every
  path, slug and link — amended here for a link),
  [ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md) (§4, an account
  named by its configured name and never by its id — amended here for a link),
  [ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) (§1,
  what is counted is the configuration; §2, a check that names one account stands for
  it, its card included), little-sister **ADR-0086** (a grading reads what it is handed,
  the configuration and the clock), little-sister **ADR-0087** (decision 8, a kept
  reading keeps the text of the line it stood on), little-sister **ADR-0038** (a URL
  template: named tokens, every value percent-encoded, an unknown token refused)

> Every reference to one of little-sister's records is written out as **little-sister
> ADR-00NN**, because the two numbering spaces overlap.

## Context

A line that names a resource links to it in the AWS console — an alarm, an instance
name, a function, a pipeline, a Batch job, a queue's list — and every such address is
`https://<region>.console.aws.amazon.com/<path>?region=<region>`, with a fragment behind
it for five of the six (`_console_url`): a region, a service's page and a name, and
nothing of the account. The console takes the account from the browser's session. So
from the node of one account a link opens the resource of that name in whichever account
the browser is signed in to — and where two accounts carry a resource of one name, which
a live and a non-live account of one team do, it opens the other account's and looks
right.

**What that looked like on an estate.** On the first estate read with a pipeline as a
node: a pipeline of one name in two accounts, the second account's node at ERROR with
two executions that had failed that afternoon, and the console, in a session of the
first account, listing sixteen that had all succeeded. Both were right. The first
account's node held those sixteen row for row, and it took the two series side by side
to see that these were two pipelines. A link that is broken is noticed; this one is not.

**What the console offers.** No part of a console page's address selects an account. A
sign-in does. IAM Identity Center's access portal has a shortcut link that takes an
account id, a permission set where one is named and a destination, each value
URL-encoded, and asks which role where none is named (*Creating shortcut links to AWS
Management Console destinations*, in the IAM Identity Center user guide). The portal's
own address has two forms, and it is one organization's. Other estates switch to a role,
or sign in through a tool of their own. Through which of these an estate's people reach
an account, under which portal and as which role, is nothing this type can know.

**What binds the answer.** [ADR-0001](0001-the-aws-check-type.md) keeps the account id
off every path, slug and link, and
[ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md) §4 off every
subject, for one reason: those strings end up in bookmarks and tickets. And a grading
reads its readings, the configuration and the clock (little-sister ADR-0086 decision 6),
so whatever a link carries, the grading finds in one of the three.

## Decision

### 1. What a link is wrapped in is the deployment's to say: `console_link`

`console_link` is a template, a key of the check and of an account's entry. The type
fills it for every link it writes for that account — a line's and a roster's, of all six
kinds — and writes the result where it wrote the console's address. An account's own
template **replaces** the check's, as its `regions:` and its `profile:` replace the
check's, and for the reason `profile:` is layered
([ADR-0001](0001-the-aws-check-type.md) §2): one check may read accounts of two
organizations, and their people sign in through two portals. It serves an account whose
people take another role as well, since the role is text of the template.

Where neither the check nor the account sets one, a link is the console's own address,
as it was.

It is a key of the check's file and not of the identity file. `config/aws.yaml` says how
this *process* becomes somebody who may read a secret, and it differs between a laptop
and the instance a deployment runs on; how an estate's *people* sign in to the console
is the same for both. The check reads nothing of that file, and a template there would
have handed it a second file and a key to say which identity an account belongs to.

### 2. The template speaks the library's vocabulary

```yaml
console_link: "https://example.awsapps.com/start/#/console?account_id={account_id}&destination={url}"
```

Two tokens: `{url}`, the console's address of what the line names, as the type builds
it, and `{account_id}`, the account's id (§3). A token is a name in braces, every value
is percent-encoded whole as it goes in, and a template that names any other token is
refused when the check loads, with the two it may name. little-sister fills the URL of a
configured action this way (little-sister ADR-0038), and a family that fills URL
templates in two ways has given its deployments one more thing to learn.

**A template names `{url}`**, or it is refused: without it every link of an account
opens one address, under a name that promises one thing's page. `{account_id}` is
optional — a template may carry an id its author wrote into it, or wrap a link in
something that needs none.

**A template is written as a URL is.** What it produces is the destination of a Markdown
link and, on the card (§5), the content of a code span. So whitespace, a backtick, a
backslash, a parenthesis or an angle bracket in it is refused when the check loads, and
a control character with them: each is a character a URL carries percent-encoded, and
one that would end the link or the span early. A key written and left empty, or a value
that is not text, is refused as `profile:` refuses it.

### 3. The account's id comes from the configuration, and from nowhere else

- **From `role_arn`, where the account names a role.** The id is written there already,
  `arn:<partition>:iam::<id>:role/…`, and it cannot be another account's: a role is in
  the account it reads.
- **From `account_id`, where it names none**: a key of the account's entry, the twelve
  digits of the id. In quotes, because YAML reads an unquoted number that starts with
  `0` as another number; a value that is not twelve digits is refused, which is what
  such a number then is.
- **Both written, and they differ**: refused when the check loads. The refusal names the
  account and repeats neither id.
- **A template that names `{account_id}`, over an account that says neither**: refused
  when the check loads, naming the account and the key. The other answer — that
  account's links left as the console's own, and a line in the log — keeps for one
  account the failure this record removes, and says so where nobody who follows a link
  is reading.

Nothing is asked of STS. `GetCallerIdentity` would say what a session is with nothing
configured, and needs no permission. But a grading may read no session, so the id would
travel in the account's own reading, as one field more; a grading over a window of a
subject's kept records, which the library foresees as a call of its own (little-sister
ADR-0086 decision 8), would find no such reading beside them; and the call would be one
more on the ambient path, where opening a session spends none. A link is decided by the
configuration, as the shape of the tree is
([ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) §1).

### 4. The id is in the link, and nowhere else

**The type alone still writes the account id nowhere.** A deployment that sets a
template naming `{account_id}` has asked for it in its links, and that is where it is:
in the address of every link of that account, and so wherever a line's text goes — the
page, an event, a row of History, what a client polls, a line somebody pastes into a
ticket. And the series: a kept reading keeps the text of the line it stood on
(little-sister ADR-0087 decision 8), and a pipeline's line carries the execution it is
written from
([ADR-0014](0014-a-pipelines-line-keeps-its-verdict-while-an-execution-is-in-flight.md) §4),
so that execution's kept reading holds the line with its link — in the state file, and
in the bucket of a keeper that carries it. It is the consequence
[ADR-0001](0001-the-aws-check-type.md) refused for the type, taken by the one party that
can weigh it: the people who then open the right account.

With a template or without one, the id stays out of every path, slug, subject and record
— there the consequence of [ADR-0001](0001-the-aws-check-type.md) and
[ADR-0005](0005-a-run-is-its-readings-and-the-runs-keep-a-history.md) §4 stand as they
are — and the console's own address, which is what `{url}` is filled with, still names
no account: a job is linked by its id and a queue by its region's list, never by an ARN.

### 5. Where no template is set the lines are as they were, and the card says where they open

A check that sets no template writes every line as it did, to the byte. What is new is
one row of the configuration card, *console links* — on the account's card where a check
names several accounts, and on the check's own where it names one and stands for it
([ADR-0007](0007-a-level-stands-only-where-the-configuration-names-several.md) §2).
Without a template the row says that a link opens in whichever account the browser is
signed in to; with one it shows the template, which is also where an account's own is
seen to have replaced the check's. A decision and its reason on the card is what
[ADR-0001](0001-the-aws-check-type.md) §2 does for the SSO login.

Not on the line: it would be one sentence on every line of a roster, and in every line
that is pasted somewhere. And no link is withheld where it can be wrong: a check that
names several accounts and sets no template still links, because the link is right for
whoever is signed in to that account, and every installation that has not set the key
would otherwise lose it.

### 6. What is not decided here

A token for the region, or for the account's configured name: additive, and waiting for
a wrapper that needs one. The role as a key of its own, for an estate whose accounts
differ in it and in nothing else. Any use of `account_id` but a link's.

## Consequences

- **On an estate whose accounts each name a role, one line makes every link open the
  account its node stands for**: the check's `console_link`. No account gains a key.
- **An installation that sets nothing sees one row more on a card.** No line, slug,
  subject or record moves, and no call is made that was not made before.
- **A wrapped link carries the account's id** wherever its line goes, where the template
  names it (§4). The README says so beside the key.
- **A wrapped address is longer**: under the template of §2 by about a hundred
  characters on each of the six kinds, a pipeline's 214 where it was 114 — in every line
  that links, and in what the series keeps of a pipeline's line.
- **An account read through a profile alone, or through the ambient chain, says
  `account_id`** before a template that names the id can wrap its links. Until it does
  the check does not load, and says which account.
- **A mistyped `account_id` is a link that looks right and is wrong** — the one way left
  to write one, and only for an account that names no role.
- **What a portal does with the address is seen on an estate, and not in the suite.**
  The type hands over the whole console address percent-encoded, as the portal's page
  asks. Five of the six addresses carry a fragment and the pipeline's is a path, and no
  test may ask a portal whether it keeps either: the suite makes no call to AWS.
- **The suite holds the address a line writes**, with a template and without one: every
  kind of link wrapped, in a line and in a roster; one pipeline name in two accounts
  linked to two addresses; an account's template over the check's; the id out of a
  role's ARN and out of the key; every refusal; the card's row; and that the id reaches
  no slug, subject or record.

## Alternatives considered

- **The template in the identity file.** Rejected in §1: that file is about the process,
  the check does not read it, and it differs between two machines whose people sign in
  alike.
- **The template on the check alone.** Enough for a check that reads one organization.
  The links of a second organization's accounts would go through the first one's portal,
  which is the failure of the context, built in.
- **The id asked of STS**, alone or behind the configuration. Rejected in §3. Behind the
  configuration it pays both prices — the reading's field and the call — to spare an
  account's entry one line.
- **The id out of the profile's own configuration.** An SSO profile names its account in
  `~/.aws/config`. A link would then follow a file no deployment's repository holds, and
  only an SSO profile has the key.
- **A key for the portal, and the type writing the address.** The type would carry both
  forms of the portal's address and every sign-in that is not the portal; a template
  says each in the deployment's own words.
- **An account without an id left unwrapped**, with a line in the log. Rejected in §3.
- **A word on every line that links**, and **no link where no template is set.**
  Rejected in §5.

