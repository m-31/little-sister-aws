"""little-sister's AWS package: check type, secret provider, S3 keeper, identity seam.

Importing this module registers the ``aws`` check type, and **nothing else**. The two
provider seams are switched on by explicit calls a deployment makes in its own
import-before-app block — ``secrets.register_aws_secret_resolvers()`` for the
``aws-sm://`` and ``aws-ssm://`` schemes (ADR-0002), and
``keeper.register_s3_keeper()`` for the S3 keeper that carries little-sister's
``var/state/`` (ADR-0004) — because which stores an installation reads its credentials
from, and where it keeps its state, are decisions, and a decision should be readable at
the place it is taken.
"""
from little_sister.checks import require_api

require_api(3)                       # the check API epoch this package was built for

from little_sister_aws import aws  # noqa: E402,F401  registration side effect
