"""
The app has two login endpoints that share the same SQLite database:

    POST /login        -> INTENTIONALLY VULNERABLE (string concatenation)
    POST /login/fixed  -> SAFE (parameterized query)

Run locally with:  python app.py
Then open:         http://127.0.0.1:5000/login
"""

from contextlib import closing
from pathlib import Path
import sqlite3

from flask import Flask, redirect, render_template, request, url_for

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "demo.db"

app = Flask(__name__)

# Fake accounts. Passwords are plaintext only so the demo is easy to read.
# Admin is inserted first so the classic "' OR '1'='1' --" payload returns it.
SEED_USERS = (
    ("admin", "admin123"),
    ("alice", "alice-pass"),
    ("bob", "bob-pass"),
)


def init_db() -> None:
    """Create the users table and add the demo accounts if they are missing."""
    with closing(sqlite3.connect(DATABASE)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
            """
        )
        for username, password in SEED_USERS:
            # INSERT ... SELECT ... WHERE NOT EXISTS keeps this idempotent.
            db.execute(
                """
                INSERT INTO users (username, password)
                SELECT ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM users WHERE username = ?
                )
                """,
                (username, password, username),
            )
        db.commit()


def make_result(
    row: sqlite3.Row | None,
    query: str,
    parameters: tuple[str, ...] | None = None,
    error: str | None = None,
) -> dict:
    """Turn a database result into the small structure the template displays."""
    result = {
        "success": False,
        "matched_username": None,
        "is_admin": False,
        "query": query,
        "parameters": parameters,
        "error": error,
    }

    if row is not None:
        matched_username = row["username"]
        result.update(
            success=True,
            matched_username=matched_username,
            is_admin=matched_username == "admin",
        )

    return result


def vulnerable_login(username: str, password: str) -> dict:
    """Login using unsafe string concatenation. Intentionally exploitable.

    The input is placed directly inside the SQL text, so a quote character in
    the input can end the string literal and change the query's logic. For
    example, the username

        ' OR '1'='1' --

    produces:

        ... WHERE username='' OR '1'='1' --' AND password='...'

    The WHERE clause becomes true for every row, and "--" comments out the
    password check. The query therefore returns a user without a valid
    password. This is the vulnerability being demonstrated.
    """
    query = (
        "SELECT id, username, password FROM users "
        f"WHERE username='{username}' AND password='{password}'"
    )

    try:
        with closing(sqlite3.connect(DATABASE)) as db:
            db.row_factory = sqlite3.Row
            row = db.execute(query).fetchone()
    except sqlite3.Error as exc:
        # Showing database errors is convenient for a teaching demo. Real
        # applications should not expose raw SQL errors to users.
        return make_result(None, query, error=str(exc))

    return make_result(row, query)


def fixed_login(username: str, password: str) -> dict:
    """Login using a parameterized query, the safe version of the same check.

    The SQL text contains only placeholders (?). SQLite compiles the query
    first and then binds the supplied values as data. Quotes, "--", OR
    clauses, and other SQL syntax inside the input stay literal text; they
    cannot alter the query structure. With the injection payload above, the
    database simply searches for a username that literally contains the
    payload and therefore finds no row.

    Note: passwords are still plaintext here only to keep the demo focused on
    injection. A real application should also hash passwords and use a session
    or identity provider after a successful login.
    """
    query = (
        "SELECT id, username, password FROM users "
        "WHERE username = ? AND password = ?"
    )

    try:
        with closing(sqlite3.connect(DATABASE)) as db:
            db.row_factory = sqlite3.Row
            row = db.execute(query, (username, password)).fetchone()
    except sqlite3.Error as exc:
        return make_result(None, query, error=str(exc))

    return make_result(row, query, parameters=(username, password))


@app.get("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """The intentionally vulnerable login page."""
    result = None
    username = ""
    password = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        result = vulnerable_login(username, password)

    return render_template(
        "login.html",
        vulnerable_result=result,
        fixed_result=None,
        vulnerable_username=username,
        vulnerable_password=password,
        fixed_username="",
        fixed_password="",
    )


@app.route("/login/fixed", methods=["GET", "POST"])
def login_fixed():
    """The fixed login page, using a parameterized query."""
    result = None
    username = ""
    password = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        result = fixed_login(username, password)

    return render_template(
        "login.html",
        vulnerable_result=None,
        fixed_result=result,
        vulnerable_username="",
        vulnerable_password="",
        fixed_username=username,
        fixed_password=password,
    )


# Create/seed the database at import time, so both `python app.py` and a test
# client get a working database.
init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
