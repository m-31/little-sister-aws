# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-16

### Added

- The **`aws`** check type: one node per account, one node per aspect beneath it.
- Five aspects: **`cloudwatch`** (metric and composite alarms), **`ec2`**
  (instances grouped by their `Name` tag, graded on count and age), **`lambda`**
  (the `Errors` metric and the newest log event's status word, on one line),
  **`codepipeline`** (each pipeline's most recent execution) and **`batch`** (job
  queues, and one line per job name carrying its finished, running and runnable
  readings).
- Per-aspect **`enabled:`** — a switched-off aspect emits no node and makes no API
  call; every aspect off is refused at startup.
- Assumed-role sessions per account, with an optional `~/.aws/config` `profile:`
  that composes with `role_arn`, and an `sso:` block that can renew an expired SSO
  login where doing so can work — bounded by a timeout and a per-profile cooldown.
