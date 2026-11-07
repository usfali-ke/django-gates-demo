from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import hashlib
import html
import json
import tempfile

HOST, PORT = "127.0.0.1", 8002
LAB_DIR = Path(tempfile.mkdtemp(prefix="owasp-v3-"))
(LAB_DIR / "vendor").mkdir()

# Fictional application state, reset when the process is restarted.
USERS = {"alice": {"role": "user", "email": "alice@example.test"}}
APPLICATIONS = {"APP-001": {"status": "SUBMITTED", "kyc_verified": False}}
IDENTITY = {"alice": "unverified"}
NOTIFICATIONS = {"last_delivery_confirmed": False}
LOG_FILE = LAB_DIR / "application.log"


def value(args, name, default=""):
    return args.get(name, [default])[0]


# A01:2025 — BROKEN ACCESS CONTROL
# CWE-915 / CWE-862: Mass assignment of a sensitive role field.
def a01_mass_assignment(args, headers):
    username = value(args, "user", "alice")
    field = value(args, "field", "role")
    new_value = value(args, "value", "admin")

    # VULNERABLE: No allowlist for client-controlled fields and no
    # authorization check before a user's role is modified.
    USERS[username][field] = new_value
    return {"user": username, "profile": USERS[username]}


# A02:2025 — SECURITY MISCONFIGURATION
# CWE-693: Insecure HTTP TRACE functionality (implemented below).
def a02_security_misconfiguration(args, headers):
    return {
        "trace_method_enabled": True,
        "description": "TRACE reflects incoming HTTP headers, including Cookie.",
        "example": "curl -i -X TRACE -H 'Cookie: session=DEMO' http://127.0.0.1:8002/",
    }


# A03:2025 — SOFTWARE SUPPLY CHAIN FAILURES
# CWE-345: Artifact hash is compared to another attacker-controlled value.
def a03_untrusted_artifact(args, headers):
    artifact = value(args, "artifact", "unreviewed dependency bytes")
    expected_hash = value(args, "sha256", "")
    actual_hash = hashlib.sha256(artifact.encode()).hexdigest()

    # VULNERABLE: The purportedly trusted digest is supplied by the
    # same unauthenticated caller who supplies the artifact.
    accepted = (actual_hash == expected_hash)
    if accepted:
        (LAB_DIR / "vendor" / "current-package.bin").write_bytes(
            artifact.encode()
        )

    # Staging only: no imported/installed/executed dependency.
    return {
        "accepted_for_staging": accepted,
        "sha256": actual_hash,
        "code_executed": False,
        "note": "This is a supply-chain trust simulation, not package execution.",
    }


# A04:2025 — CRYPTOGRAPHIC FAILURES
# CWE-312: Store fictional sensitive information in plaintext.
def a04_plaintext_storage(args, headers):
    patient = value(args, "patient", "DEMO-PATIENT")
    note = value(args, "note", "fictional training record")

    # VULNERABLE: Sensitive information is written without encryption.
    record_file = LAB_DIR / "patient-record.txt"
    record_file.write_text(f"patient={patient}\nnote={note}\n")
    return {
        "saved": True,
        "storage_path": str(record_file),
        "encrypted": False,
    }


# A05:2025 — INJECTION
# CWE-95: Arbitrary Python expression injection through eval().
def a05_expression_injection(args, headers):
    expression = value(args, "expression", "2 + 2")

    # VULNERABLE: Never evaluate untrusted expressions as Python.
    # This is genuine arbitrary Python expression execution.
    result = eval(expression)
    return {"expression": expression, "result": repr(result)}


# A06:2025 — INSECURE DESIGN
# CWE-841: Business workflow can skip required verification steps.
def a06_workflow_bypass(args, headers):
    application_id = value(args, "application", "APP-001")
    next_status = value(args, "status", "APPROVED")
    application = APPLICATIONS[application_id]

    # VULNERABLE: No allowed-state-transition or KYC precondition check.
    application["status"] = next_status
    return {"application_id": application_id, **application}


# A07:2025 — AUTHENTICATION FAILURES
# CWE-287: The X-User header is treated as proof of identity.
def a07_trusted_identity_header(args, headers):
    username = headers.get("X-User", "guest")

    # VULNERABLE: HTTP request headers are attacker-controlled and
    # this application does not authenticate the claimed identity.
    if username == "admin":
        return {"authenticated_as": "admin", "admin_panel": "DEMO-ADMIN-DATA"}
    return {"authenticated_as": username, "admin_panel": "not shown"}


# A08:2025 — SOFTWARE OR DATA INTEGRITY FAILURES
# CWE-345: Process an unsigned/unauthenticated event as genuine.
def a08_unsigned_webhook(args, headers):
    event = value(args, "event", "identity_verified")
    signature = value(args, "signature", "not-a-valid-signature")

    # VULNERABLE: Signature is never checked against a trusted key.
    if event == "identity_verified":
        IDENTITY["alice"] = "verified"
    return {
        "received_signature": signature,
        "signature_checked": False,
        "identity_status": IDENTITY["alice"],
    }


# A09:2025 — SECURITY LOGGING AND ALERTING FAILURES
# CWE-532: Credential-like data is included in application log lines.
def a09_sensitive_logging(args, headers):
    username = value(args, "user", "alice")
    token = value(args, "token", "FAKE-TRAINING-TOKEN")

    # VULNERABLE: Never log credential or bearer token values.
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"LOGIN user={username} token={token}\n")
    return {"logged": True, "log_file": str(LOG_FILE), "token_redacted": False}


# A10:2025 — MISHANDLING OF EXCEPTIONAL CONDITIONS
# CWE-703: Swallow a delivery error and incorrectly report success.
def a10_false_success(args, headers):
    outage = value(args, "outage", "1") == "1"
    try:
        if outage:
            raise ConnectionError("Mock notification provider unavailable")
        NOTIFICATIONS["last_delivery_confirmed"] = True
    except ConnectionError:
        # VULNERABLE: The error is silently converted into success.
        pass
    return {
        "http_result": "success",
        "message_sent": True,
        "actual_delivery_confirmed": NOTIFICATIONS["last_delivery_confirmed"],
    }


ROUTES = {
    "/a01": ("A01 Mass assignment / role change", a01_mass_assignment,
             "?user=alice&field=role&value=admin"),
    "/a02": ("A02 Enabled TRACE method", a02_security_misconfiguration, ""),
    "/a03": ("A03 User-supplied artifact integrity hash", a03_untrusted_artifact, ""),
    "/a04": ("A04 Plaintext sensitive data storage", a04_plaintext_storage,
             "?patient=DEMO-PATIENT&note=fictional"),
    "/a05": ("A05 Python expression injection", a05_expression_injection,
             "?expression=2%2B2"),
    "/a06": ("A06 Invalid business state transition", a06_workflow_bypass,
             "?application=APP-001&status=APPROVED"),
    "/a07": ("A07 Header-based authentication bypass", a07_trusted_identity_header, ""),
    "/a08": ("A08 Unsigned webhook data accepted", a08_unsigned_webhook,
             "?event=identity_verified&signature=invalid"),
    "/a09": ("A09 Credential-like tokens in logs", a09_sensitive_logging,
             "?user=alice&token=FAKE-TOKEN"),
    "/a10": ("A10 False success after service failure", a10_false_success,
             "?outage=1"),
}


class VulnerableHandler(BaseHTTPRequestHandler):
    def reply(self, body, status=200, content_type="application/json"):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_TRACE(self):
        # A02 VULNERABLE: TRACE reflects request headers unfiltered.
        reflected = f"TRACE {self.path} HTTP/1.1\n" + "\n".join(
            f"{key}: {val}" for key, val in self.headers.items()
        )
        self.reply(reflected, content_type="text/plain")

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            links = "".join(
                f'<li><a href="{html.escape(path + sample, quote=True)}">'
                f'{html.escape(title)}</a></li>'
                for path, (title, _, sample) in ROUTES.items()
            )
            page = (
                "<h1>OWASP Top 10:2025 — Vulnerable Python Lab V3</h1>"
                "<p>Fictional data. Local disposable environments only.</p>"
                f"<ul>{links}</ul>"
                "<p>A07 requires the header <code>X-User: admin</code>.</p>"
                "<p>A02 can be tested with an HTTP TRACE request.</p>"
                "<p>A03 requires a matching caller-supplied SHA-256 digest.</p>"
            )
            return self.reply(page, content_type="text/html")

        route = ROUTES.get(parsed.path)
        if route is None:
            return self.reply('{"error": "Unknown route"}', 404)

        _, handler, _ = route
        try:
            result = handler(
                parse_qs(parsed.query, keep_blank_values=True), self.headers
            )
            return self.reply(json.dumps(result, indent=2))
        except Exception as exc:
            # Additional intentionally unsafe diagnostic disclosure.
            return self.reply(json.dumps({
                "error": str(exc),
                "exception_type": type(exc).__name__,
            }), 500)


if __name__ == "__main__":
    print("WARNING: Intentionally insecure learning application")
    print("Run only in an isolated, disposable environment.")
    print(f"Home: http://{HOST}:{PORT}")
    print(f"Temporary example files: {LAB_DIR}")
    server = HTTPServer((HOST, PORT), VulnerableHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
