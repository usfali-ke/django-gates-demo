
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import hashlib
import json

HOST = "127.0.0.1"
PORT = 8000

# Fictional training records
USERS = {
    "1": {"username": "alice", "email": "alice@example.test"},
    "2": {"username": "bob", "email": "bob@example.test"},
}

CURRENT_USER = "alice"


def database():
    db = sqlite3.connect(":memory:")

    db.execute("""
        CREATE TABLE users (
            id INTEGER,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)

    db.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        [
            (1, "alice", "alice123", "user"),
            (2, "bob", "bob123", "user"),
            (3, "admin", "admin123", "admin"),
        ]
    )

    return db


# ============================================================
# A01:2025 - BROKEN ACCESS CONTROL (IDOR)
# ============================================================

def a01_broken_access_control(params):
    user_id = params.get("id", ["2"])[0]

    # VULNERABILITY:
    # No check whether the current user owns this record.
    return USERS.get(user_id, {"error": "User not found"})


# ============================================================
# A02:2025 - SECURITY MISCONFIGURATION
# ============================================================

def a02_security_misconfiguration(params):

    # VULNERABILITY:
    # Debug configuration and mock credentials are exposed.
    config = {
        "debug": True,
        "environment": "development",
        "database_host": "localhost",
        "database_username": "admin",
        "database_password": "FAKE_PASSWORD_123",
        "mock_api_key": "FAKE_API_KEY_12345",
        "directory_listing": True,
    }

    return config


# ============================================================
# A03:2025 - SOFTWARE SUPPLY CHAIN FAILURES
# ============================================================

def a03_supply_chain(params):
    package = params.get("package", ["untrusted-package"])[0]
    version = params.get("version", ["1.0"])[0]

    # VULNERABILITY:
    # An artifact is trusted without signature, checksum,
    # provenance or approved dependency verification.
    approved = True

    return {
        "package": package,
        "version": version,
        "approved": approved,
        "integrity_verified": False,
        "message": "Package accepted without verification"
    }


# ============================================================
# A04:2025 - CRYPTOGRAPHIC FAILURES
# ============================================================

def a04_cryptographic_failures(params):
    password = params.get("password", ["password123"])[0]

    # VULNERABILITY:
    # SHA-1 is fast and unsalted, unsuitable for passwords.
    password_hash = hashlib.sha1(
        password.encode()
    ).hexdigest()

    return {
        "algorithm": "SHA-1",
        "password_hash": password_hash,
        "salt_used": False,
    }


# ============================================================
# A05:2025 - INJECTION (SQL INJECTION)
# ============================================================

def a05_sql_injection(params):
    username = params.get("username", ["alice"])[0]

    db = database()

    # VULNERABILITY:
    # Untrusted input directly concatenated into SQL.
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = '" + username + "'"
    )

    try:
        cursor = db.execute(query)
        rows = cursor.fetchall()

        return {
            "query": query,
            "results": rows,
        }

    except sqlite3.Error as error:
        return {
            "query": query,
            "database_error": str(error),
        }

    finally:
        db.close()


# ============================================================
# A05:2025 - INJECTION (CROSS-SITE SCRIPTING)
# ============================================================

def a05_xss(params):
    name = params.get("name", ["Guest"])[0]

    # VULNERABILITY:
    # User input inserted directly into HTML without escaping.
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>XSS Lab</title></head>
    <body>
        <h1>Welcome {name}</h1>
        <p>Intentionally vulnerable XSS demonstration.</p>
    </body>
    </html>
    """


# ============================================================
# A06:2025 - INSECURE DESIGN
# ============================================================

def a06_insecure_design(params):
    quantity = int(params.get("quantity", ["1"])[0])
    price = 100

    # VULNERABILITY:
    # No business-rule validation for negative quantities.
    total = quantity * price

    return {
        "quantity": quantity,
        "price": price,
        "total": total,
        "order_accepted": True,
    }


# ============================================================
# A07:2025 - AUTHENTICATION FAILURES
# ============================================================

def a07_authentication_failures(params):
    username = params.get("username", ["admin"])[0]
    password = params.get("password", ["wrong"])[0]

    # VULNERABILITY:
    # Static plaintext credential comparison.
    # No rate limiting or account lockout.
    if username == "admin" and password == "admin123":
        return {
            "authenticated": True,
            "role": "admin",
        }

    return {
        "authenticated": False,
        "rate_limit": "disabled",
        "account_lockout": "disabled",
    }


# ============================================================
# A08:2025 - SOFTWARE OR DATA INTEGRITY FAILURES
# ============================================================

def a08_integrity_failures(params):
    invoice_id = params.get("invoice_id", ["INV-001"])[0]
    amount = params.get("amount", ["1000"])[0]

    # VULNERABILITY:
    # Client-controlled invoice data accepted without verifying
    # an authoritative record or integrity signature.
    invoice = {
        "invoice_id": invoice_id,
        "amount": amount,
        "payment_approved": True,
        "integrity_verified": False,
    }

    return invoice


# ============================================================
# A09:2025 - SECURITY LOGGING AND ALERTING FAILURES
# ============================================================

def a09_logging_failures(params):
    username = params.get("username", ["admin"])[0]

    # VULNERABILITY:
    # Simulated failed login, but no security event logging,
    # detection, monitoring or alert generation.
    return {
        "username": username,
        "login_status": "failed",
        "event_logged": False,
        "alert_generated": False,
    }


# ============================================================
# A10:2025 - MISHANDLING OF EXCEPTIONAL CONDITIONS
# ============================================================

def a10_exception_handling(params):
    service = params.get("service", ["down"])[0]

    try:
        if service == "down":
            raise ConnectionError(
                "Authorization service unavailable"
            )

        authorized = service == "up"

    except Exception:
        # VULNERABILITY:
        # Authorization failure defaults to access granted.
        authorized = True

    return {
        "authorization_service": service,
        "access_granted": authorized,
    }


# ============================================================
# HTTP ROUTES
# ============================================================

ROUTES = {
    "/a01": a01_broken_access_control,
    "/a02": a02_security_misconfiguration,
    "/a03": a03_supply_chain,
    "/a04": a04_cryptographic_failures,
    "/a05-sqli": a05_sql_injection,
    "/a05-xss": a05_xss,
    "/a06": a06_insecure_design,
    "/a07": a07_authentication_failures,
    "/a08": a08_integrity_failures,
    "/a09": a09_logging_failures,
    "/a10": a10_exception_handling,
}


class VulnerableApp(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            page = """
            <html>
            <head><title>OWASP Top 10 Vulnerable Lab</title></head>
            <body>
            <h1>OWASP Top 10:2025 - Vulnerable Python Lab</h1>
            <p>Intentionally vulnerable. Local training only.</p>

            <ul>
              <li><a href="/a01?id=2">A01 - Broken Access Control</a></li>
              <li><a href="/a02">A02 - Security Misconfiguration</a></li>
              <li><a href="/a03?package=unknown">A03 - Supply Chain</a></li>
              <li><a href="/a04?password=hello">A04 - Cryptographic Failures</a></li>
              <li><a href="/a05-sqli?username=alice">A05 - SQL Injection</a></li>
              <li><a href="/a05-xss?name=Guest">A05 - XSS</a></li>
              <li><a href="/a06?quantity=-5">A06 - Insecure Design</a></li>
              <li><a href="/a07?username=admin&password=wrong">A07 - Authentication</a></li>
              <li><a href="/a08?amount=1">A08 - Integrity Failures</a></li>
              <li><a href="/a09">A09 - Logging Failures</a></li>
              <li><a href="/a10?service=down">A10 - Exception Handling</a></li>
            </ul>
            </body>
            </html>
            """

            self.respond(page, "text/html")
            return

        handler = ROUTES.get(path)

        if not handler:
            self.respond(
                json.dumps({"error": "Not found"}),
                "application/json",
                404,
            )
            return

        try:
            result = handler(params)

            if isinstance(result, str):
                self.respond(result, "text/html")
            else:
                self.respond(
                    json.dumps(result, indent=2),
                    "application/json",
                )

        except Exception as error:
            # VULNERABILITY:
            # Internal exception details exposed to clients.
            self.respond(
                json.dumps({
                    "error": str(error),
                    "exception_type": type(error).__name__,
                }),
                "application/json",
                500,
            )

    def respond(self, body, content_type, status=200):
        data = body.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":
    print("=" * 55)
    print("OWASP TOP 10:2025 - VULNERABLE PYTHON LAB")
    print("=" * 55)
    print(f"URL: http://{HOST}:{PORT}")
    print("WARNING: Intentionally vulnerable application")
    print("LOCAL TRAINING ONLY")
    print("Press Ctrl+C to stop")
    print("=" * 55)

    server = HTTPServer(
        (HOST, PORT),
        VulnerableApp,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping vulnerable lab...")
    finally:
        server.server_close()
