"""little-sister's AWS package: check type, secret provider, identity seam.

Importing this module registers the ``aws`` check type. It registers **no** secret
scheme: a deployment turns the provider on with an explicit
``secrets.register_aws_secret_resolvers()`` call, because which stores an
installation reads its credentials from is a decision, and a decision should be
readable at the place it is taken (ADR-0002).
"""
from little_sister.checks import require_api

require_api(2)                       # the check API epoch this package was built for

from little_sister_aws import aws  # noqa: E402,F401  registration side effect
