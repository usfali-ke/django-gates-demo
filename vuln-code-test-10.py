
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from pathlib import Path
import base64
import hashlib
import html
import json
import pickle
import subprocess
import tempfile

HOST = "127.0.0.1"
PORT = 8001

# All example data is fake, and files live in a throwaway lab directory.
LAB = Path(tempfile.mkdtemp(prefix="owasp-lab-v2-"))
PUBLIC = LAB / "public"
PRIVATE = LAB / "private"
PLUGINS = LAB / "plugins"

for folder in (PUBLIC, PRIVATE, PLUGINS):
    folder.mkdir()

(PUBLIC / "welcome.txt").write_text(
    "Public training document\n"
)

(PRIVATE / "staff.txt").write_text(
    "CONFIDENTIAL DEMO: fictional staff notes\n"
)

(PLUGINS / "community.py").write_text(
    "def run():\n"
    "    return 'Unverified community plugin ran'\n"
)

AUDIT_LOG = LAB / "security.log"

ORDERS = {
    "ORDER-100": {
        "paid": 50,
        "refunded": 0
    }
}

WALLETS = {
    "alice": 100,
    "bob": 100
}

SIGNING_KEY = b"hardcoded-demo-xor-key"


def param(query, name, default=""):
    return query.get(name, [default])[0]


# ============================================================
# A01:2025 - BROKEN ACCESS CONTROL
# Vulnerability: Path Traversal (CWE-22)
# ============================================================

def a01_path_traversal(q):
    filename = param(q, "file", "welcome.txt")

    # VULNERABLE:
    # ../ allows a caller to escape the public directory.
    target = PUBLIC / filename

    return {
        "file": str(target),
        "contents": target.read_text()
    }


# ============================================================
# A02:2025 - SECURITY MISCONFIGURATION
# Vulnerability: Permissive CORS (CWE-942)
# ============================================================

def a02_cors(q):

    # VULNERABLE:
    # The HTTP response handler reflects arbitrary Origin
    # values and allows credentialed requests.

    return {
        "private_demo_data": "Fictional dashboard information",
        "issue": "Arbitrary Origin accepted with credentials",
        "hint": "Send Origin: https://untrusted.example"
    }


# ============================================================
# A03:2025 - SOFTWARE SUPPLY CHAIN FAILURES
# Vulnerability: Unverified Plugin Execution
# ============================================================

def a03_plugin(q):
    plugin = param(q, "plugin", "community")

    # VULNERABLE:
    # Plugin selection is externally influenced.
    # No integrity or provenance verification.
    path = PLUGINS / (plugin + ".py")

    namespace = {}

    # Executes unverified plugin code.
    exec(path.read_text(), namespace)

    return {
        "plugin": plugin,
        "result": namespace["run"]()
    }


# ============================================================
# A04:2025 - CRYPTOGRAPHIC FAILURES
# Vulnerability: Weak Encryption (CWE-327/CWE-321)
# ============================================================

def a04_weak_crypto(q):
    message = param(
        q,
        "message",
        "fictional medical record"
    )

    data = message.encode()

    # VULNERABLE:
    # Repeating-key XOR with a hardcoded key is not
    # appropriate for protecting confidential data.
    ciphertext = bytes(
        byte ^ SIGNING_KEY[i % len(SIGNING_KEY)]
        for i, byte in enumerate(data)
    )

    return {
        "algorithm": "repeating-key XOR",
        "ciphertext_hex": ciphertext.hex()
    }


# ============================================================
# A05:2025 - INJECTION
# Vulnerability: OS Command Injection (CWE-78)
# ============================================================

def a05_command_injection(q):
    value = param(q, "label", "hello")

    # VULNERABLE:
    # User-controlled input is concatenated into a shell
    # command that is executed by the operating system.
    command = "echo " + value

    result = subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
        timeout=2
    )

    return {
        "command": command,
        "stdout": result.stdout,
        "stderr": result.stderr
    }


# ============================================================
# A06:2025 - INSECURE DESIGN
# Vulnerability: Duplicate Refund / Business Logic Abuse
# ============================================================

def a06_duplicate_refund(q):
    order_id = param(q, "order", "ORDER-100")
    amount = int(param(q, "amount", "25"))

    order = ORDERS[order_id]

    # VULNERABLE:
    # No validation of refund eligibility.
    # No check that the order was already refunded.
    # No maximum refund amount enforcement.
    order["refunded"] += amount

    return {
        "order": order_id,
        "paid": order["paid"],
        "refunded": order["refunded"]
    }


# ============================================================
# A07:2025 - AUTHENTICATION FAILURES
# Vulnerability: Predictable Session ID / Authentication Bypass
# ============================================================

def a07_predictable_session(q):
    username = param(q, "username", "admin")

    # VULNERABLE:
    # No password verification.
    # Session token is deterministic and predictable.
    token = hashlib.md5(
        username.encode()
    ).hexdigest()

    return {
        "username": username,
        "session_token": token,
        "authenticated": True
    }


# ============================================================
# A08:2025 - SOFTWARE OR DATA INTEGRITY FAILURES
# Vulnerability: Insecure Deserialization (CWE-502)
# ============================================================

def a08_pickle(q):
    supplied = param(q, "payload")

    if not supplied:
        supplied = base64.b64encode(
            pickle.dumps({"demo": True})
        ).decode()

    # VULNERABLE:
    # Untrusted serialized objects are accepted without
    # integrity or authenticity verification.
    #
    # pickle.loads() can execute code during deserialization.
    item = pickle.loads(
        base64.b64decode(supplied)
    )

    return {
        "deserialized_object": repr(item)
    }


# ============================================================
# A09:2025 - SECURITY LOGGING AND ALERTING FAILURES
# Vulnerability: Log Injection / Log Forgery (CWE-117)
# ============================================================

def a09_log_injection(q):
    event = param(q, "event", "failed login")

    # VULNERABLE:
    # Untrusted event text is written directly to audit logs.
    # Newlines can create forged log entries.
    with AUDIT_LOG.open("a") as logfile:
        logfile.write(
            "SECURITY_EVENT: " + event + "\n"
        )

    return {
        "last_log_lines": AUDIT_LOG.read_text().splitlines()[-5:]
    }


# ============================================================
# A10:2025 - MISHANDLING OF EXCEPTIONAL CONDITIONS
# Vulnerability: Partial Transaction / Missing Rollback
# ============================================================

def a10_partial_transfer(q):
    amount = int(param(q, "amount", "10"))
    fail = param(q, "fail", "1") == "1"

    # VULNERABLE:
    # The debit is applied before the operation is complete.
    WALLETS["alice"] -= amount

    try:
        if fail:
            raise ConnectionError(
                "Fictional settlement service unavailable"
            )

        WALLETS["bob"] += amount
        outcome = "completed"

    except ConnectionError:
        # VULNERABLE:
        # The exception is swallowed without rolling back
        # the initial debit.
        outcome = "failed after debit"

    return {
        "outcome": outcome,
        "balances": dict(WALLETS)
    }


# ============================================================
# HTTP ROUTES
# ============================================================

ROUTES = {
    "/a01": (
        "A01 Path Traversal",
        a01_path_traversal,
        "?file=../private/staff.txt"
    ),
    "/a02": (
        "A02 Permissive CORS",
        a02_cors,
        ""
    ),
    "/a03": (
        "A03 Unverified Plugin Execution",
        a03_plugin,
        "?plugin=community"
    ),
    "/a04": (
        "A04 Weak Cryptography",
        a04_weak_crypto,
        "?message=hello"
    ),
    "/a05": (
        "A05 Command Injection",
        a05_command_injection,
        "?label=hello;echo%20injected"
    ),
    "/a06": (
        "A06 Duplicate Refund",
        a06_duplicate_refund,
        "?order=ORDER-100&amount=25"
    ),
    "/a07": (
        "A07 Predictable Session",
        a07_predictable_session,
        "?username=admin"
    ),
    "/a08": (
        "A08 Unsafe Pickle Deserialization",
        a08_pickle,
        ""
    ),
    "/a09": (
        "A09 Log Injection",
        a09_log_injection,
        "?event=failed%20login"
    ),
    "/a10": (
        "A10 Incomplete Transaction",
        a10_partial_transfer,
        "?amount=10&fail=1"
    ),
}


# ============================================================
# VULNERABLE HTTP SERVER
# ============================================================

class Handler(BaseHTTPRequestHandler):

    def send_output(
        self,
        body,
        content_type="application/json",
        status=200
    ):
        encoded = body.encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            content_type + "; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(encoded))
        )

        # A02 VULNERABILITY:
        # Arbitrary origins are trusted.
        origin = self.headers.get("Origin")

        if origin:
            self.send_header(
                "Access-Control-Allow-Origin",
                origin
            )

            self.send_header(
                "Access-Control-Allow-Credentials",
                "true"
            )

        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlsplit(self.path)

        if parsed.path == "/":
            links = "".join(
                f'<li><a href="'
                f'{html.escape(route + sample, quote=True)}">'
                f'{html.escape(title)}</a></li>'
                for route, (title, _, sample)
                in ROUTES.items()
            )

            page = (
                "<h1>OWASP Top 10:2025 - "
                "Vulnerable Lab v2</h1>"
                "<p>Intentionally insecure. "
                "Isolated localhost training only.</p>"
                f"<ul>{links}</ul>"
            )

            return self.send_output(
                page,
                "text/html"
            )

        selected = ROUTES.get(parsed.path)

        if selected is None:
            return self.send_output(
                '{"error":"Not found"}',
                status=404
            )

        _, function, _ = selected

        try:
            result = function(
                parse_qs(
                    parsed.query,
                    keep_blank_values=True
                )
            )

            self.send_output(
                json.dumps(result, indent=2)
            )

        except Exception as exc:
            # ADDITIONAL VULNERABILITY:
            # Internal exception details exposed to clients.
            self.send_output(
                json.dumps({
                    "error": str(exc),
                    "type": type(exc).__name__
                }),
                status=500
            )


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    print(
        "WARNING: Deliberately vulnerable; "
        "disposable training environment only"
    )

    print(f"Open http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop")
    print(f"Disposable lab files: {LAB}")

    server = HTTPServer(
        (HOST, PORT),
        Handler
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        pass

    finally:
        server.server_close()
