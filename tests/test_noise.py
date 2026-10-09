"""What this package declares of the SDK's lines, held against the SDK itself.

ADR-0010 names four loggers boto3 writes under for what this package does with it, and
little-sister ADR-0121 says what a declaration does. A row names a logger of somebody
else's, so the claim is only as good as the name: the day botocore says where it found
a session's credentials under another one, the row caps nothing, and no test of this
package's own code would notice. So every test here starts a deployment in an
interpreter of its own — this package imported, then the application, as a `wsgi.py`
does it — and has the SDK write its own lines: a session that finds its credentials in
the environment, a cached SSO token read from a file, a client built, and one request
of urllib3's, which is redirected once.

**No call to AWS, and none possible** (PL6). Nothing here sends through botocore: a
session finds credentials and builds a client without a request, the token is read from
a file this test wrote, and the one request there is goes to a server in the child's own
process. The child refuses a connection to anywhere but its own machine before it is
made, and the endpoint its environment names is on that machine too, so a line added
here one day cannot reach out either.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: The four rows, as ADR-0010 states them.
DECLARED = {
    "botocore": "INFO",
    "botocore.credentials": "WARNING",
    "botocore.tokens": "WARNING",
    "urllib3": "INFO",
}

#: The sentence a new session says of itself, where its credentials are in the
#: environment — and where they come from an SSO session, the one it says instead.
FOUND = ("botocore.credentials", "INFO", "Found credentials in environment variables.")
LOADED = ("botocore.tokens", "INFO", "Loading cached SSO token for workstation")
#: What the SDK says at `INFO` beside those two, which the rows leave in the log:
#: botocore, that it took a client's endpoint from the environment.
ENDPOINT = ("botocore.configprovider", "INFO",
            "Found endpoint for sts via: environment_global.")
#: A line of the deployment's own, below `INFO`: what a `DEBUG` session is for.
OWN = ("startup", "DEBUG", "a line of the deployment's own")

#: The two documents that print the rows for a reader, each in a table.
TABLES = ("README.md", "docs/adr/0010-the-package-declares-what-its-sdk-writes.md")

_AWS_CONFIG = """\
[profile signed-in]
sso_session = workstation
sso_account_id = 000000000000
sso_role_name = reader
region = eu-central-1

[sso-session workstation]
sso_start_url = https://sso.example.invalid/start
sso_region = eu-central-1
"""

_ONLY_THIS_MACHINE = """
import socket

_connect = socket.socket.connect


def _only_here(self, address):
    if not (isinstance(address, tuple) and address[0] == "127.0.0.1"):
        raise OSError(f"this suite connects to its own machine alone, not {address!r}")
    return _connect(self, address)


socket.socket.connect = _only_here
"""

_WHAT_IS_DECLARED = _ONLY_THIS_MACHINE + """
import json
import logging

import little_sister_aws  # noqa: F401
from little_sister import noise

print(json.dumps({
    "rows": [[row.logger, logging.getLevelName(row.level), row.hides]
             for row in noise.rows() if row.package == "little_sister_aws"],
    "levels": {name: logging.getLogger(name).level for name in NAMES},
}))
"""

_A_DEPLOYMENT = _ONLY_THIS_MACHINE + """
import http.server
import json
import logging
import threading

#BEFORE#
import little_sister_aws  # noqa: F401  the startup file's import, as the README has it
#AFTER#
from little_sister.app import app  # noqa: F401  the rows are set here


class Heard(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append((record.name, record.levelname, record.getMessage()))


heard = Heard()
logging.getLogger().addHandler(heard)
logging.getLogger("startup").debug("a line of the deployment's own")

import boto3
import botocore.session
import urllib3

# botocore.credentials: a session says where it found its credentials.
session = boto3.Session(region_name="eu-central-1")
assert session.get_credentials().method == "env"
# botocore: what building a client writes. Nothing is sent.
session.client("sts")
# botocore.tokens: the token of an SSO session, read from the cache. It is years from
# its end, so nothing asks for another.
botocore.session.Session(profile="signed-in").get_auth_token().get_frozen_token()


class Answering(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/there")
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


# urllib3: a connection, a request and a redirect it follows, to a server in this
# process.
server = http.server.HTTPServer(("127.0.0.1", 0), Answering)
threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01},
                 daemon=True).start()
urllib3.PoolManager().request("GET", f"http://127.0.0.1:{server.server_port}/")
server.shutdown()
print(json.dumps(heard.lines))
"""

Line = tuple[str, str, str]


def _environment(directory: Path, **given: str) -> dict[str, str]:
    """What the child is handed: this process's environment without what would reach
    a real account or another instance's settings, and with a home of its own."""
    kept = {name: value for name, value in os.environ.items()
            if not name.startswith(("AWS_", "LITTLE_SISTER_"))
            and name not in ("LOG_LEVEL", "LOG_FILE", "BOTO_CONFIG")}
    return {**kept,
            "HOME": str(directory), "USERPROFILE": str(directory),
            "AWS_CONFIG_FILE": str(directory / ".aws" / "config"),
            "AWS_SHARED_CREDENTIALS_FILE": str(directory / ".aws" / "credentials"),
            "AWS_ACCESS_KEY_ID": "AKIAEXAMPLEEXAMPLE00",
            "AWS_SECRET_ACCESS_KEY": "not-a-key",
            "AWS_EC2_METADATA_DISABLED": "true",
            # Where nothing listens, on this machine: a client built in the child has
            # nowhere else to send, and botocore says at INFO where it took that from.
            "AWS_ENDPOINT_URL": "http://127.0.0.1:1",
            "LOG_FILE": os.devnull,
            **given}


def _child(directory: Path, script: str, **environment: str) -> str:
    """Run ``script`` in an interpreter of its own, in ``directory``, and answer the
    last line it printed."""
    done = subprocess.run(
        [sys.executable, "-c", script], cwd=directory,
        env=_environment(directory, **environment),
        capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return done.stdout.splitlines()[-1]


def _a_deployment_starts(directory: Path, *, before: str = "", after: str = "",
                         **environment: str) -> list[Line]:
    """Start a deployment once in ``directory`` and answer every line that reached
    the root logger from then on, the SDK's among them: ``(logger, level, message)``.

    ``before`` and ``after`` are what the deployment's own startup file does ahead of
    this package's import, and between it and the application's. The directory is the
    whole installation: an empty configuration root, and a home whose ``~/.aws`` holds
    one profile signed in through an SSO session, with its token in the cache.
    """
    (directory / "config").mkdir()
    aws = directory / ".aws"
    (aws / "sso" / "cache").mkdir(parents=True)
    (aws / "config").write_text(_AWS_CONFIG, encoding="utf-8")
    cached = hashlib.sha1(b"workstation").hexdigest()
    (aws / "sso" / "cache" / f"{cached}.json").write_text(json.dumps({
        "startUrl": "https://sso.example.invalid/start", "region": "eu-central-1",
        "accessToken": "not-a-token", "expiresAt": "2099-01-01T00:00:00Z"}),
        encoding="utf-8")
    script = _A_DEPLOYMENT
    for place, written in (("#BEFORE#", before), ("#AFTER#", after)):
        assert script.count(place) == 1, f"the deployment's script has lost {place}"
        script = script.replace(place, written)
    heard = json.loads(_child(directory, script, **environment))
    return [(name, level, said) for name, level, said in heard]


def _under(logger: str, lines: list[Line]) -> list[Line]:
    """The lines written under ``logger``: by it, or by a logger beneath it."""
    return [line for line in lines
            if line[0] == logger or line[0].startswith(logger + ".")]


def _below_info(lines: list[Line]) -> list[Line]:
    return [line for line in lines if line[1] == "DEBUG"]


def _redirected(lines: list[Line]) -> list[Line]:
    """urllib3's own line at `INFO`, that it followed the redirect."""
    return [line for line in lines
            if line[:2] == ("urllib3.poolmanager", "INFO")
            and line[2].startswith("Redirecting http://127.0.0.1:")]


@pytest.fixture(scope="module")
def declared(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """What importing the package declared and what it left on the four loggers, read
    in an interpreter that did nothing else: ``rows`` and ``levels``."""
    script = _WHAT_IS_DECLARED.replace("NAMES", repr(sorted(DECLARED)))
    said = json.loads(_child(tmp_path_factory.mktemp("declared"), script))
    assert isinstance(said, dict)
    return said


def _table(document: str) -> list[list[str]]:
    """The caps' table in ``document``, row by row as a reader has it on the rendered
    page: the logger, the level, and what the cap hides, without their code spans."""
    lines = (ROOT / document).read_text(encoding="utf-8").splitlines()
    start = lines.index("| Logger | Capped at | What the cap hides |")
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip().replace("`", "")
                     for cell in line.strip("|").split("|")])
    return rows


def test_the_package_declares_four_rows_and_sets_no_level(
        declared: dict[str, Any]) -> None:
    """Importing the package is the whole declaration, and it touches no logger: a
    row is a default little-sister sets later, where the application is imported."""
    assert {logger: level for logger, level, _ in declared["rows"]} == DECLARED
    assert len(declared["rows"]) == len(DECLARED)
    assert declared["levels"] == dict.fromkeys(DECLARED, logging.NOTSET)


@pytest.mark.parametrize("document", TABLES)
def test_a_documents_table_is_the_rows_as_declared(declared: dict[str, Any],
                                                   document: str) -> None:
    """The third column is the row's own sentence, which little-sister prints on
    `/system/installed` and says in the log: a reader who has the one finds the
    other."""
    assert _table(document) == declared["rows"]


def test_a_new_session_no_longer_says_where_it_found_its_credentials(
        tmp_path: Path) -> None:
    """With nothing configured and no line of the deployment's own: the root is at
    `INFO`, and neither sentence is in the log. What else the SDK says at `INFO` is."""
    heard = _a_deployment_starts(tmp_path)

    assert _under("botocore.credentials", heard) == []
    assert _under("botocore.tokens", heard) == []
    assert ENDPOINT in heard and _redirected(heard)
    assert OWN not in heard                # the root is at INFO: no DEBUG session


def test_a_debug_session_holds_none_of_the_sdks_debug_lines(tmp_path: Path) -> None:
    """`LOG_LEVEL=DEBUG` lowers the root and lifts no cap: the deployment's own lines
    are there, and of the SDK's nothing below `INFO` — which is where botocore writes
    a session's token and what a call answered."""
    heard = _a_deployment_starts(tmp_path, LOG_LEVEL="DEBUG")

    assert OWN in heard
    assert _below_info(_under("botocore", heard)) == []
    assert _below_info(_under("urllib3", heard)) == []
    assert FOUND not in heard and LOADED not in heard
    assert ENDPOINT in heard and _redirected(heard)     # a cap at INFO leaves INFO


def test_log_level_has_one_capped_loggers_lines_back_by_name(tmp_path: Path) -> None:
    """The entry names the narrowest logger that answers the question, and nothing
    beside it comes back with it."""
    heard = _a_deployment_starts(tmp_path,
                                 LOG_LEVEL="INFO,botocore.credentials=DEBUG")

    assert FOUND in heard
    assert _under("botocore.tokens", heard) == []
    assert _below_info(_under("botocore", heard)) == _below_info(
        _under("botocore.credentials", heard))
    assert _below_info(_under("urllib3", heard)) == []


def test_naming_the_sdks_loggers_has_everything_they_write_back(
        tmp_path: Path) -> None:
    """An entry speaks for its name and every name beneath it — and here is what the
    four rows hide, each line under the logger its row names."""
    heard = _a_deployment_starts(tmp_path,
                                 LOG_LEVEL="INFO,botocore=DEBUG,urllib3=DEBUG")

    assert FOUND in heard and LOADED in heard
    building = [line for line in _below_info(_under("botocore", heard))
                if not _under("botocore.credentials", [line])
                and not _under("botocore.tokens", [line])]
    assert building, "building a client wrote no DEBUG line under botocore"
    assert [said.split(":")[0] for _, level, said
            in _under("urllib3.connectionpool", heard) if level == "DEBUG"][:1] == [
        "Starting new HTTP connection (1)"]
    assert OWN not in heard                # the root stayed at INFO


@pytest.mark.parametrize("place", ["before", "after"])
def test_a_level_the_startup_file_set_stands_against_the_rows(tmp_path: Path,
                                                              place: str) -> None:
    """Set ahead of this package's import or between it and the application's, as a
    deployment that wants the SDK's lines writes it: the import overwrites nothing,
    and no row is set on that logger or beneath it."""
    wanted = 'logging.getLogger("botocore").setLevel(logging.DEBUG)'

    heard = _a_deployment_starts(tmp_path, **{place: wanted})

    assert FOUND in heard and LOADED in heard
    assert _below_info(_under("botocore", heard))
    assert _below_info(_under("urllib3", heard)) == []      # no level was set there
