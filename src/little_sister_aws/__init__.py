"""little-sister check type: aws."""
from little_sister.checks import require_api

require_api(1)                       # the check API epoch this package was built for

from little_sister_aws import aws  # noqa: E402,F401  registration side effect
