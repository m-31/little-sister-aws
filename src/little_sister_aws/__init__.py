"""little-sister's AWS package: check type, secret provider, S3 keeper, identity seam.

Importing this module registers the ``aws`` check type and declares what the SDK it
brings may write into a log, and **nothing else**. The two provider seams are switched
on by explicit calls a deployment makes in its own import-before-app block —
``secrets.register_aws_secret_resolvers()`` for the ``aws-sm://`` and ``aws-ssm://``
schemes (ADR-0002), and ``keeper.register_s3_keeper()`` for the S3 keeper that carries
little-sister's ``var/state/`` (ADR-0004) — because which stores an installation reads
its credentials from, and where it keeps its state, are decisions, and a decision
should be readable at the place it is taken.

**The noise caps are declared here** (ADR-0010) because every way into this package
passes this module, and every one of them opens its sessions through boto3: the check
type, the two providers and the identity seam. A declaration is a row and sets no
level (little-sister ADR-0121). little-sister sets the rows where the application is
imported, a level the deployment's own startup file set stands against them, and
``LOG_LEVEL`` has any of these loggers back by name.
"""
import logging

from little_sister.checks import require_api

require_api(3)                       # the check API epoch this package was built for

from little_sister import noise  # noqa: E402  the epoch speaks first

# What boto3 writes for what this package does with it, measured (ADR-0010). `INFO`
# leaves a `LOG_LEVEL=DEBUG` session readable, and keeps what botocore says at `DEBUG`
# out of a log that was not asked to hold it. `WARNING` takes out the one sentence
# every new session says of itself.
noise.cap("botocore", logging.INFO,
          hides="a DEBUG line for each step of every call, a session's token and what "
                "a call answered among them, a secret's value where one is read")
noise.cap("botocore.credentials", logging.WARNING,
          hides="where each new session found its credentials, a line a run")
noise.cap("botocore.tokens", logging.WARNING,
          hides="which cached SSO token each new session loaded, a line a run, and "
                "each refresh of one unless the attempt failed")
noise.cap("urllib3", logging.INFO,
          hides="a DEBUG line for each connection opened and each request sent")

from little_sister_aws import aws  # noqa: E402,F401  registration side effect
