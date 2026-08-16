# little-sister-aws

The **`aws`** check type for [little-sister](https://github.com/m-31/little-sister):
one or more AWS accounts on the status tree, with a node per account and a node per
aspect beneath it.

- **Needs little-sister ≥ 0.3.12** (a floor, never a pin), and **boto3**.
- **Registers one check type: `aws`.**

```
/<path>                     what is watched
  /<path>/live              one node per account, its own assumed session
    /<path>/live/cloudwatch   alarms
    /<path>/live/ec2          instances, grouped by their Name tag
    /<path>/live/lambda       functions
    /<path>/live/codepipeline pipelines
    /<path>/live/batch        job queues and the jobs in them
  /<path>/backup
    …
```

Account first, aspect second, because the account is what an operator acts on as a
group: "staging is down for the migration" is one maintenance pin on one node, where
a flat list of alarms would be one pin per alarm. Each account's node also absorbs
its own bad news — a role that cannot be assumed reddens that account and leaves the
others reporting.

## Install

```toml
dependencies = [
    "little-sister==<the version you pin>",
    "little-sister-aws==<this version>",
]
```

and one import in the deployment's `wsgi.py`, **before** `little_sister.app`:

```python
import little_sister_aws  # noqa: F401  (registers the `aws` type)
```

## Configure

One check config, one `accounts:` list. [`examples/aws.yaml`](examples/aws.yaml) is
the whole shape with a comment per knob; the short version:

```yaml
type: aws
path: /team/aws
frequency: 60s
timeout: 120s

regions: [eu-central-1]          # the default every account inherits

accounts:
  - name: live
    role_arn: arn:aws:iam::000000000000:role/application/monitoring-role
  - name: backup
    regions: [eu-west-1]         # replaces the default, does not add to it

cloudwatch: {}                   # every aspect has an `enabled:` and its own knobs
batch:
  enabled: false                 # off: no node, and no API call
```

**Credentials.** By default the ambient AWS credential chain — an instance profile,
a task role, an SSO session, the `AWS_*` variables — and each account's `role_arn`
is assumed from it. `profile:` names an `~/.aws/config` profile to assume *from*
and composes with `role_arn`; static keys are an optional `secrets:` block of
little-sister secret references, and are mutually exclusive with `profile`.

**Switching an aspect off.** Each aspect block opens with `enabled:`. Off, the
aspect emits no node and makes no API call, which is what a role whose policy does
not carry that service needs. An aspect that says nothing is on; every aspect off is
refused at startup; and the check's card names what is off, because an absent node
otherwise reads exactly like a broken check.

## The IAM policy

One role per account, and it has to cover every aspect that is switched on, in every
region the account is watched in:

| Aspect | Actions |
|---|---|
| `cloudwatch` | `cloudwatch:DescribeAlarms` |
| `ec2` | `ec2:DescribeInstances` |
| `lambda` | `lambda:ListFunctions`, `cloudwatch:GetMetricData`, `logs:DescribeLogStreams`, `logs:GetLogEvents` |
| `codepipeline` | `codepipeline:ListPipelines`, `codepipeline:ListPipelineExecutions` |
| `batch` | `batch:DescribeJobQueues`, `batch:ListJobs` |

The deployment's own identity needs `sts:AssumeRole` on each role, and
`sts:GetCallerIdentity` is spent once per profile-only account.

## Documentation

- [`docs/adr/0001-the-aws-check-type.md`](docs/adr/0001-the-aws-check-type.md) — why
  one type with aspects rather than one type per service, why the tree is account
  first, and why this package uses boto3 where the rest of the family uses stdlib
  `urllib`.

## License

MIT — see [LICENSE](LICENSE).
