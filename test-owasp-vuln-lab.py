
"""
OWASP Top 10:2025 — Web Security Learning Lab

Python 3.10+ | Standard library only

WARNING:
This application intentionally contains vulnerable code.
Run ONLY on localhost for educational purposes.
Never expose it to the internet or use real credentials/data.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import threading

HOST = "127.0.0.1"
PORT = 8000

# Fictional application data.
CURRENT_USER = "alice"

RECORDS = {
    "1": {"owner": "alice", "note": "Alice's training note"},
    "2": {"owner": "bob", "note": "Bob's private training note"},
}

SIGNING_KEY = secrets.token_bytes(32)

APPROVED_ARTIFACT = "trusted package bytes v1"
APPROVED_SHA256 = hashlib.sha256(
    APPROVED_ARTIFACT.encode()
).hexdigest()

FAILED_ATTEMPTS = 0
SECURITY_EVENTS = []
STATE_LOCK = threading.Lock()


# ------------------------------------------------------------
# Lab definitions
# ------------------------------------------------------------

LABS = [
    (
        "A01",
        "Broken Access Control",
        "IDOR: Request Bob's note while signed in as Alice",
        {"record_id": "2"},
    ),
    (
        "A02",
        "Security Misconfiguration",
        "Debug endpoint exposes a fake secret",
        {},
    ),
    (
        "A03",
        "Software Supply Chain Failures",
        "Trust a modified package without verifying its contents",
        {
            "package": "training-lib",
            "artifact": "tampered package bytes",
        },
    ),
    (
        "A04",
        "Cryptographic Failures",
        "Compare weak password hashing with salted password hashing",
        {"password": "demo-password"},
    ),
    (
        "A05",
        "Injection — SQL Injection",
        "Try: %' OR 1=1 --",
        {"term": "%' OR 1=1 --"},
    ),
    (
        "A05X",
        "Injection — Cross-Site Scripting",
        "Try a harmless XSS alert",
        {"name": "<script>alert('XSS demo')</script>"},
    ),
    (
        "A06",
        "Insecure Design",
        "Negative item quantities create a negative total",
        {"quantity": "-5"},
    ),
    (
        "A07",
        "Authentication Failures",
        "Repeated bad credentials; secure mode locks after 3 attempts",
        {"password": "wrong-password"},
    ),
    (
        "A08",
        "Software or Data Integrity Failures",
        "Alter signed invoice data and reuse its previous signature",
        {
            "payload": "invoice-1:amount-1000",
            "signature": "",
        },
    ),
    (
        "A09",
        "Security Logging and Alerting Failures",
        "Submit three mock failed-login events",
        {"username": "alice"},
    ),
    (
        "A10",
        "Mishandling of Exceptional Conditions",
        "Permission service unavailable: fail open or fail closed",
        {"service": "down"},
    ),
]


def correct_signature(payload):
    return hmac.new(
        SIGNING_KEY,
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()


# A signature for the original, unmodified invoice.
LABS[8][3]["signature"] = correct_signature(
    "invoice-1:amount-10"
)


# ------------------------------------------------------------
# Vulnerability demonstrations
# ------------------------------------------------------------

def run_lab(category, secure, data):
    global FAILED_ATTEMPTS

    # ========================================================
    # A01 — BROKEN ACCESS CONTROL
    # ========================================================
    if category == "A01":
        record_id = data.get("record_id", "2")
        record = RECORDS.get(record_id)

        if not record:
            return {
                "status": 404,
                "error": "Record not found",
            }

        # SECURE: Verify resource ownership.
        if secure and record["owner"] != CURRENT_USER:
            return {
                "status": 403,
                "error": "Forbidden: not your record",
            }

        # VULNERABLE: Returns another user's record.
        return {
            "status": 200,
            "record": record,
            "logged_in_as": CURRENT_USER,
        }

    # ========================================================
    # A02 — SECURITY MISCONFIGURATION
    # ========================================================
    if category == "A02":
        config = {
            "service": "training-app",
            "environment": "local",
        }

        if not secure:
            # VULNERABLE: Exposes debug data.
            # This is a fake key, not a real secret.
            config.update({
                "debug": True,
                "mock_api_key": "FAKE-DO-NOT-USE",
            })

        return {
            "status": 200,
            "config": config,
        }

    # ========================================================
    # A03 — SOFTWARE SUPPLY CHAIN FAILURES
    # ========================================================
    if category == "A03":
        package = data.get("package", "")
        artifact = data.get("artifact", "")

        digest = hashlib.sha256(
            artifact.encode()
        ).hexdigest()

        if secure:
            # SECURE: Only accept approved artifact bytes.
            trusted = (
                package == "training-lib"
                and hmac.compare_digest(
                    digest,
                    APPROVED_SHA256,
                )
            )
        else:
            # VULNERABLE: Trust anything provided.
            trusted = True

        return {
            "package": package,
            "accepted": trusted,
            "sha256": digest,
            "explanation": (
                "Production builds should use pinned "
                "dependencies, verified artifacts, "
                "trusted provenance and SBOMs."
            ),
        }

    # ========================================================
    # A04 — CRYPTOGRAPHIC FAILURES
    # ========================================================
    if category == "A04":
        password = data.get(
            "password",
            "demo-password",
        )

        if secure:
            # SECURE: Salted, deliberately slow hashing.
            salt = secrets.token_bytes(16)

            digest = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt,
                300_000,
            )

            return {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": 300_000,
                "salt_hex": salt.hex(),
                "derived_key_hex": digest.hex(),
                "note": (
                    "Use a vetted password hashing API. "
                    "Argon2id is generally preferred."
                ),
            }

        # VULNERABLE: Fast, unsalted password hashing.
        digest = hashlib.sha256(
            password.encode()
        ).hexdigest()

        return {
            "algorithm": "SHA-256 UNSALTED",
            "hash_hex": digest,
            "warning": (
                "Fast, unsalted hashes are unsuitable "
                "for password storage."
            ),
        }

    # ========================================================
    # A05 — INJECTION: SQL INJECTION
    # ========================================================
    if category == "A05":
        term = data.get("term", "")

        # In-memory database with fictional records.
        with sqlite3.connect(":memory:") as db:
            db.execute(
                "CREATE TABLE notes "
                "(owner TEXT, title TEXT)"
            )

            db.executemany(
                "INSERT INTO notes VALUES (?, ?)",
                [
                    ("alice", "schedule"),
                    ("bob", "private note"),
                ],
            )

            if secure:
                # SECURE: Parameterized SQL.
                results = db.execute(
                    """
                    SELECT owner, title
                    FROM notes
                    WHERE owner = ?
                    AND title LIKE ?
                    """,
                    (
                        CURRENT_USER,
                        "%" + term + "%",
                    ),
                ).fetchall()

            else:
                # VULNERABLE: SQL string concatenation.
                sql = (
                    "SELECT owner, title "
                    "FROM notes "
                    "WHERE owner = 'alice' "
                    "AND title LIKE '%"
                    + term +
                    "%'"
                )

                try:
                    results = db.execute(sql).fetchall()

                except sqlite3.Error as error:
                    return {
                        "status": 400,
                        "sql_error": str(error),
                    }

        return {
            "rows": [
                {
                    "owner": row[0],
                    "title": row[1],
                }
                for row in results
            ],
        }

    # ========================================================
    # A05X — INJECTION: CROSS-SITE SCRIPTING (XSS)
    # ========================================================
    if category == "A05X":
        name = data.get("name", "")

        if secure:
            # SECURE: Escape untrusted HTML content.
            visible = html.escape(
                name,
                quote=True,
            )
        else:
            # VULNERABLE: Raw HTML injection.
            visible = name

        page = (
            "<!doctype html>"
            "<title>XSS Lab</title>"
            "<h2>Hello "
            + visible +
            "</h2>"
            "<p>Use your browser's Back button "
            "to test the other mode.</p>"
        )

        return {"html": page}

    # ========================================================
    # A06 — INSECURE DESIGN
    # ========================================================
    if category == "A06":
        try:
            quantity = int(
                data.get("quantity", "1")
            )

        except ValueError:
            return {
                "status": 400,
                "error": "Quantity must be an integer",
            }

        if secure:
            # SECURE: Validate business rules.
            if not (1 <= quantity <= 10):
                return {
                    "status": 400,
                    "error": (
                        "Allowed quantity is 1 to 10"
                    ),
                }

        # VULNERABLE: Negative quantities accepted.
        return {
            "status": 200,
            "quantity": quantity,
            "unit_price": 25,
            "total": quantity * 25,
            "note": "No real payment occurs.",
        }

    # ========================================================
    # A07 — AUTHENTICATION FAILURES
    # ========================================================
    if category == "A07":
        candidate = data.get("password", "")

        with STATE_LOCK:
            if secure and FAILED_ATTEMPTS >= 3:
                return {
                    "authenticated": False,
                    "locked": True,
                    "failed_attempts": FAILED_ATTEMPTS,
                }

            # Fictional training password.
            success = hmac.compare_digest(
                candidate,
                "training123",
            )

            if secure:
                if success:
                    FAILED_ATTEMPTS = 0
                else:
                    FAILED_ATTEMPTS += 1

            return {
                "authenticated": success,
                "locked": False,
                "failed_attempts": (
                    FAILED_ATTEMPTS
                    if secure
                    else "not tracked"
                ),
            }

    # ========================================================
    # A08 — SOFTWARE OR DATA INTEGRITY FAILURES
    # ========================================================
    if category == "A08":
        payload = data.get("payload", "")
        signature = data.get("signature", "")

        verified = hmac.compare_digest(
            signature,
            correct_signature(payload),
        )

        if secure:
            # SECURE: Reject modified data.
            accepted = verified
        else:
            # VULNERABLE: Skip integrity verification.
            accepted = True

        return {
            "accepted": accepted,
            "integrity_valid": verified,
            "note": (
                "This example uses HMAC. "
                "Real supply-chain verification may "
                "require digital signatures and "
                "trusted signing identities."
            ),
        }

    # ========================================================
    # A09 — SECURITY LOGGING AND ALERTING FAILURES
    # ========================================================
    if category == "A09":
        username = data.get(
            "username",
            "unknown",
        )

        # Basic log-injection mitigation.
        username = (
            username
            .replace("\n", " ")
            .replace("\r", " ")
        )[:50]

        if not secure:
            # VULNERABLE: No logging or detection.
            return {
                "event_recorded": False,
                "alert_triggered": False,
            }

        # SECURE: Record and detect suspicious events.
        with STATE_LOCK:
            SECURITY_EVENTS.append({
                "type": "failed_login",
                "user": username,
            })

            if len(SECURITY_EVENTS) > 100:
                del SECURITY_EVENTS[:-100]

            count = sum(
                event["type"] == "failed_login"
                and event["user"] == username
                for event in SECURITY_EVENTS
            )

        return {
            "event_recorded": True,
            "count_for_user": count,
            "alert_triggered": count >= 3,
            "note": (
                "Alert simulated locally. "
                "No external notification is sent."
            ),
        }

    # ========================================================
    # A10 — MISHANDLING OF EXCEPTIONAL CONDITIONS
    # ========================================================
    if category == "A10":
        service = data.get(
            "service",
            "down",
        )

        if service == "down":
            if secure:
                # SECURE: Deny when authorization fails.
                return {
                    "access_granted": False,
                    "reason": "Secure fail-closed",
                }

            # VULNERABLE: Grant access when checks fail.
            return {
                "access_granted": True,
                "reason": "Insecure fail-open",
            }

        return {
            "access_granted": service == "up",
            "reason": "Mock policy check",
        }

    return {
        "status": 404,
        "error": "Unknown category",
    }


# ------------------------------------------------------------
# Browser interface
# ------------------------------------------------------------

PAGE_STYLE = """
<style>
body {
    font: 16px system-ui, Arial, sans-serif;
    max-width: 980px;
    margin: 2rem auto;
    padding: 0 1rem;
    color: #1b2430;
}
header {
    background: #102b45;
    color: white;
    padding: 1rem 1.4rem;
    border-radius: 10px;
}
article {
    border: 1px solid #d5deea;
    border-radius: 10px;
    padding: 1rem 1.3rem;
    margin: 1rem 0;
}
h2 {
    margin: 0 0 .3rem;
    font-size: 1.15rem;
}
p {
    margin: .35rem 0 .9rem;
}
label {
    display: inline-block;
    margin: .25rem .5rem .25rem 0;
}
input {
    padding: .35rem;
    border: 1px solid #a8b3c4;
    border-radius: 5px;
}
button {
    border: 0;
    border-radius: 6px;
    padding: .65rem .9rem;
    cursor: pointer;
    font-weight: 600;
}
.bad {
    background: #ffe4df;
}
.good {
    background: #d8f4e3;
}
small {
    color: #5a6778;
}
</style>
"""


def home_page():
    result = [
        '<!doctype html>',
        '<html lang="en">',
        '<meta charset="utf-8">',
        '<title>OWASP Top 10:2025 Lab</title>',
        PAGE_STYLE,
        '<header>',
        '<h1>OWASP Top 10:2025 — Learning Lab</h1>',
        '<p>Vulnerable versus secure implementations.'
        ' Fictional data only.</p>',
        '</header>',
        '<p><strong>Warning:</strong> Run only '
        'on localhost. Never deploy to production.</p>',
    ]

    for category, title, hint, fields in LABS:
        result.append(
            '<article><h2>'
            + html.escape(category + ' — ' + title)
            + '</h2><p>'
            + html.escape(hint)
            + '</p>'
        )

        result.append(
            '<form method="post" action="/lab/'
            + category
            + '">'
        )

        for key, val in fields.items():
            label = html.escape(key)
            value = html.escape(
                str(val),
                quote=True,
            )

            result.append(
                '<label>'
                + label
                + ': <input name="'
                + label
                + '" value="'
                + value
                + '" size="38" maxlength="512">'
                + '</label>'
            )

        result.append(
            '<p>'
            '<button class="bad" name="mode" '
            'value="vulnerable">Try vulnerable</button> '
            '<button class="good" name="mode" '
            'value="secure">Try secure</button>'
            '</p></form></article>'
        )

    result.append(
        '<small>Official documentation: '
        'https://top10.owasp.org/2025/'
        '</small></html>'
    )

    return ''.join(result)


# ------------------------------------------------------------
# Local HTTP server
# ------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):

    def respond(
        self,
        code,
        content_type,
        content,
        csp=None,
    ):
        body = content.encode("utf-8")

        self.send_response(code)
        self.send_header(
            "Content-Type",
            content_type + "; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.send_header(
            "X-Content-Type-Options",
            "nosniff",
        )

        if csp:
            self.send_header(
                "Content-Security-Policy",
                csp,
            )

        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/":
            self.respond(
                200,
                "text/html",
                home_page(),
                "default-src 'none'; "
                "style-src 'unsafe-inline'; "
                "form-action 'self'",
            )

        else:
            self.respond(
                404,
                "application/json",
                '{"error":"Not found"}',
            )

    def do_POST(self):
        path = urlsplit(self.path).path

        if not path.startswith("/lab/"):
            return self.respond(
                404,
                "application/json",
                '{"error":"Not found"}',
            )

        try:
            size = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )
        except ValueError:
            size = -1

        if not 0 <= size <= 8192:
            return self.respond(
                413,
                "application/json",
                '{"error":"Request too large"}',
            )

        body = self.rfile.read(size).decode(
            "utf-8",
            errors="replace",
        )

        form = parse_qs(
            body,
            keep_blank_values=True,
        )

        data = {
            key: values[0]
            for key, values in form.items()
        }

        mode = data.pop("mode", "")
        category = path.split("/")[-1]

        valid = {
            item[0]
            for item in LABS
        }

        if (
            category not in valid
            or mode not in {"vulnerable", "secure"}
        ):
            return self.respond(
                400,
                "application/json",
                '{"error":"Unknown category or mode"}',
            )

        secure = mode == "secure"

        result = run_lab(
            category,
            secure,
            data,
        )

        if category == "A05X":
            csp = (
                "default-src 'none'; script-src 'none'"
                if secure
                else None
            )

            return self.respond(
                200,
                "text/html",
                result["html"],
                csp,
            )

        self.respond(
            result.get("status", 200),
            "application/json",
            json.dumps(
                {
                    "category": category,
                    "mode": mode,
                    **result,
                },
                indent=2,
            ),
        )


# ------------------------------------------------------------
# Start learning lab
# ------------------------------------------------------------

if __name__ == "__main__":
    print(
        f"OWASP Learning Lab: http://{HOST}:{PORT}"
    )
    print("LOCAL USE ONLY — Press Ctrl+C to exit")

    ThreadingHTTPServer(
        (HOST, PORT),
        Handler,
    ).serve_forever()
