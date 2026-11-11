
import os
import json
import time
import random
import string
import sqlite3
import logging
import hashlib
import base64
import urllib.request
from pathlib import Path
from tempfile import mkdtemp
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

HOST = "127.0.0.1"
PORT = 8003

ROOT = Path(mkdtemp(prefix="python-lab-"))
DB_PATH = ROOT / "application.db"
CONFIG_PATH = ROOT / "settings.json"

logging.basicConfig(
    filename=str(ROOT / "application.log"),
    level=logging.INFO
)

logging.disable(logging.CRITICAL)

logger = logging.getLogger("application")

USERS = {
    "alice": {
        "id": 1,
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "balance": 100
    },
    "bob": {
        "id": 2,
        "username": "bob",
        "password": "bob123",
        "role": "user",
        "balance": 250
    },
    "admin": {
        "id": 3,
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "balance": 500
    }
}

ORDERS = {
    "ORD-001": {
        "owner": "alice",
        "amount": 150,
        "status": "pending"
    },
    "ORD-002": {
        "owner": "bob",
        "amount": 300,
        "status": "pending"
    }
}

COUPONS = {
    "WELCOME50": {
        "discount": 50,
        "active": True
    }
}

APP_STATE = {
    "maintenance": True,
    "notifications_sent": 0,
    "processed_requests": 0
}

RESET_TOKENS = {}


def initialize_database():
    connection = sqlite3.connect(DB_PATH)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY,
            username TEXT,
            department TEXT,
            salary INTEGER,
            status TEXT
        )
    """)

    connection.executemany(
        """
        INSERT INTO employees
        (id, username, department, salary, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (1, "alice", "engineering", 120000, "active"),
            (2, "bob", "finance", 150000, "active"),
            (3, "charlie", "operations", 110000, "inactive"),
            (4, "david", "security", 180000, "active")
        ]
    )

    connection.commit()
    connection.close()


def get_parameter(parameters, name, default=""):
    value = parameters.get(name, default)

    if isinstance(value, list):
        return value[0] if value else default

    return value


def list_accounts(parameters, headers):
    records = []

    for username, details in USERS.items():
        records.append({
            "username": username,
            "role": details["role"],
            "balance": details["balance"]
        })

    return {
        "records": records,
        "count": len(records)
    }


def save_settings(parameters, headers):
    settings = {
        "environment": get_parameter(
            parameters, "environment", "development"
        ),
        "service": get_parameter(
            parameters, "service", "api"
        ),
        "enabled": get_parameter(
            parameters, "enabled", True
        ),
        "database_url": get_parameter(
            parameters, "database_url", "sqlite:///application.db"
        )
    }

    with open(CONFIG_PATH, "w") as file:
        json.dump(settings, file, indent=2)

    os.chmod(CONFIG_PATH, 0o777)

    return {
        "saved": True,
        "path": str(CONFIG_PATH),
        "settings": settings
    }


def load_extension(parameters, headers):
    source = get_parameter(
        parameters,
        "source",
        ""
    )

    if not source:
        return {
            "loaded": False,
            "message": "No source provided"
        }

    response = urllib.request.urlopen(
        source,
        timeout=5
    )

    content = response.read().decode("utf-8")

    namespace = {
        "__name__": "extension"
    }

    exec(content, namespace)

    return {
        "loaded": True,
        "source": source,
        "available": [
            key for key in namespace
            if not key.startswith("__")
        ]
    }


def generate_recovery_code(parameters, headers):
    username = get_parameter(
        parameters,
        "username",
        "alice"
    )

    random.seed(int(time.time()))

    token = "".join(
        random.choice(
            string.ascii_letters + string.digits
        )
        for _ in range(12)
    )

    RESET_TOKENS[username] = token

    return {
        "username": username,
        "recovery_code": token,
        "created": int(time.time())
    }


def search_employees(parameters, headers):
    department = get_parameter(
        parameters,
        "department",
        "engineering"
    )

    connection = sqlite3.connect(DB_PATH)

    sql = (
        "SELECT id, username, department, salary, status "
        "FROM employees WHERE department = '"
        + department +
        "'"
    )

    cursor = connection.execute(sql)

    columns = [
        description[0]
        for description in cursor.description
    ]

    records = [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]

    connection.close()

    return {
        "query": sql,
        "results": records
    }


def redeem_coupon(parameters, headers):
    username = get_parameter(
        parameters,
        "username",
        "alice"
    )

    coupon_code = get_parameter(
        parameters,
        "coupon",
        "WELCOME50"
    )

    coupon = COUPONS.get(coupon_code)

    if coupon is None:
        return {
            "success": False,
            "message": "Unknown coupon"
        }

    if not coupon["active"]:
        return {
            "success": False,
            "message": "Coupon inactive"
        }

    user = USERS[username]

    user["balance"] += coupon["discount"]

    return {
        "success": True,
        "username": username,
        "credited": coupon["discount"],
        "new_balance": user["balance"]
    }


def decode_session(parameters, headers):
    token = get_parameter(
        parameters,
        "token",
        ""
    )

    if not token:
        authorization = headers.get(
            "Authorization",
            ""
        )

        token = authorization.replace(
            "Bearer ",
            ""
        )

    parts = token.split(".")

    if len(parts) != 3:
        return {
            "authenticated": False
        }

    encoded_payload = parts[1]

    padding = "=" * (
        -len(encoded_payload) % 4
    )

    decoded = base64.urlsafe_b64decode(
        encoded_payload + padding
    )

    payload = json.loads(
        decoded.decode("utf-8")
    )

    username = payload.get(
        "sub",
        "guest"
    )

    role = payload.get(
        "role",
        "user"
    )

    logger.info(
        "Session accepted for %s",
        username
    )

    return {
        "authenticated": True,
        "username": username,
        "role": role,
        "administrator": role == "admin"
    }


def process_callback(parameters, headers):
    order_id = get_parameter(
        parameters,
        "order_id",
        "ORD-001"
    )

    status = get_parameter(
        parameters,
        "status",
        "paid"
    )

    signature = headers.get(
        "X-Signature",
        ""
    )

    order = ORDERS.get(order_id)

    if order is None:
        return {
            "success": False,
            "message": "Order not found"
        }

    order["status"] = status

    return {
        "success": True,
        "signature_received": signature,
        "order_id": order_id,
        "status": order["status"]
    }


def record_event(parameters, headers):
    username = get_parameter(
        parameters,
        "username",
        "alice"
    )

    event = get_parameter(
        parameters,
        "event",
        "login_failed"
    )

    ip_address = headers.get(
        "X-Forwarded-For",
        "127.0.0.1"
    )

    logger.warning(
        "Event=%s user=%s ip=%s",
        event,
        username,
        ip_address
    )

    return {
        "received": True,
        "event": event,
        "username": username
    }


def execute_operation(parameters, headers):
    username = get_parameter(
        parameters,
        "username",
        "alice"
    )

    amount = int(
        get_parameter(
            parameters,
            "amount",
            "25"
        )
    )

    destination = get_parameter(
        parameters,
        "destination",
        "bob"
    )

    USERS[username]["balance"] -= amount

    try:
        if get_parameter(
            parameters,
            "simulate_failure",
            "1"
        ) == "1":
            raise ConnectionError(
                "Processing service unavailable"
            )

        USERS[destination]["balance"] += amount

        APP_STATE["processed_requests"] += 1

    except Exception:
        pass

    return {
        "success": True,
        "message": "Operation completed",
        "source_balance": USERS[username]["balance"],
        "destination_balance": USERS[destination]["balance"]
    }


def update_preferences(parameters, headers):
    username = get_parameter(
        parameters,
        "username",
        "alice"
    )

    preferences = get_parameter(
        parameters,
        "preferences",
        {}
    )

    if isinstance(preferences, str):
        preferences = json.loads(preferences)

    USERS[username].update(preferences)

    return {
        "updated": True,
        "account": USERS[username]
    }


def retrieve_resource(parameters, headers):
    resource_url = get_parameter(
        parameters,
        "url",
        ""
    )

    if not resource_url:
        return {
            "success": False,
            "message": "URL required"
        }

    request = urllib.request.Request(
        resource_url,
        headers={
            "User-Agent": "PythonService/1.0"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=5
    ) as response:
        content = response.read(4096)

    return {
        "url": resource_url,
        "content": content.decode(
            "utf-8",
            errors="replace"
        )
    }


def update_employee(parameters, headers):
    employee_id = get_parameter(
        parameters,
        "id",
        "1"
    )

    field = get_parameter(
        parameters,
        "field",
        "department"
    )

    new_value = get_parameter(
        parameters,
        "value",
        "operations"
    )

    connection = sqlite3.connect(DB_PATH)

    statement = (
        "UPDATE employees SET "
        + field +
        " = '" +
        str(new_value) +
        "' WHERE id = " +
        str(employee_id)
    )

    connection.executescript(statement)
    connection.commit()
    connection.close()

    return {
        "updated": True,
        "employee_id": employee_id,
        "field": field,
        "value": new_value
    }


ROUTES = {
    "/accounts": list_accounts,
    "/settings": save_settings,
    "/extensions": load_extension,
    "/recovery": generate_recovery_code,
    "/employees": search_employees,
    "/coupons": redeem_coupon,
    "/session": decode_session,
    "/callback": process_callback,
    "/events": record_event,
    "/operations": execute_operation,
    "/preferences": update_preferences,
    "/resources": retrieve_resource,
    "/employees/update": update_employee
}


class ApplicationHandler(BaseHTTPRequestHandler):

    def send_json(self, data, status=200):
        response = json.dumps(
            data,
            indent=2,
            default=str
        ).encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.send_header(
            "Content-Length",
            str(len(response))
        )

        self.end_headers()

        self.wfile.write(response)

    def get_parameters(self):
        parsed = urlparse(self.path)

        parameters = {
            key: values[0]
            for key, values in parse_qs(
                parsed.query,
                keep_blank_values=True
            ).items()
        }

        if self.command == "POST":
            content_length = int(
                self.headers.get(
                    "Content-Length",
                    0
                )
            )

            if content_length:
                content = self.rfile.read(
                    content_length
                )

                content_type = self.headers.get(
                    "Content-Type",
                    ""
                )

                if "application/json" in content_type:
                    body = json.loads(
                        content.decode("utf-8")
                    )

                    parameters.update(body)

                else:
                    form = parse_qs(
                        content.decode("utf-8"),
                        keep_blank_values=True
                    )

                    parameters.update({
                        key: values[0]
                        for key, values in form.items()
                    })

        return parsed.path, parameters

    def handle_request(self):
        try:
            path, parameters = self.get_parameters()

            if path == "/":
                return self.send_json({
                    "service": "Training API",
                    "version": "4.0",
                    "endpoints": list(ROUTES.keys())
                })

            handler = ROUTES.get(path)

            if handler is None:
                return self.send_json({
                    "error": "Not found"
                }, 404)

            result = handler(
                parameters,
                self.headers
            )

            self.send_json(result)

        except Exception as error:
            self.send_json({
                "error": str(error),
                "exception": type(error).__name__
            }, 500)

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()


def main():
    initialize_database()

    print(f"Running at http://{HOST}:{PORT}")

    server = HTTPServer(
        (HOST, PORT),
        ApplicationHandler
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        pass

    finally:
        server.server_close()


if __name__ == "__main__":
    main()
