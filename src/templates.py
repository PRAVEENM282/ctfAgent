"""Vetted fallback challenge templates.

qwen2.5-coder:1.5b and other small local models cannot reliably write a whole
stdlib application from scratch. When the agent loop fails to produce source
that passes the static and private checks, the lab manager falls back to this
vetted template so the lab still completes end to end. Fallback use is always
recorded (``llm_fallback_used``) and is never presented as model-generated.

The template is a single stdlib ``http.server`` app that implements every
supported vulnerability profile (``sql_injection``, ``reflected_xss``,
``path_traversal``, ``idor``) plus a ``/health`` route. All data is read from
the trusted, control-plane-seeded SQLite database and fixture files inside the
guest; no flag or private marker literal is embedded in the source. It is
deliberately written to satisfy :func:`src.agent.tools.validate_generated_source`
and :func:`src.challenge.static_check` for any profile selection.
"""

from __future__ import annotations

from src.challenge import ChallengeVariation

# One vetted app covering every profile. The private control plane seeds the
# 'secrets' table (flag), the records and profiles tables, and the fixture
# files under /root/vulnforge_files before this app is started.
VETTED_APP_SOURCE = '''"""VulnForge educational lab (vetted fallback template)."""
import http.server
import os
import sqlite3
import urllib.parse

DB_PATH = "/root/app.db"
# The trusted control plane seeds the 'secrets' table with the flag value,
# the 'records' and 'profiles' tables, and files under vulnforge_files.
FILES_ROOT = "/root/vulnforge_files/public"


def _search_records(term):
    conn = sqlite3.connect(DB_PATH)
    try:
        # Intentional SQL injection: the q value is concatenated, not bound.
        statement = "SELECT name FROM records WHERE name LIKE '%" + term + "%'"
        return [str(row[0]) for row in conn.execute(statement).fetchall()]
    finally:
        conn.close()


def _lookup_profile(identifier):
    conn = sqlite3.connect(DB_PATH)
    try:
        # Intentional IDOR: no authorization check on the requested id.
        statement = "SELECT username, email, secret FROM profiles WHERE id = " + identifier
        return conn.execute(statement).fetchone()
    finally:
        conn.close()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        route = parsed.path
        if route == "/health":
            return self._send(200, "ok")
        if route == "/":
            return self._send(200, "<h1>VulnForge Lab</h1><p>Educational sandbox.</p>")
        if route == "/search":
            term = params.get("q", [""])[0]
            try:
                hits = _search_records(term)
            except Exception as error:
                return self._send(200, "query error: " + str(error))
            return self._send(200, "results: " + ", ".join(hits))
        if route == "/echo":
            visitor = params.get("name", [""])[0]
            # Intentional reflected XSS: the name value is not escaped.
            return self._send(200, "<p>Hello " + visitor + "</p>")
        if route == "/download":
            requested = params.get("file", [""])[0]
            # Intentional path traversal: the file value is joined unnormalized.
            target = os.path.join(FILES_ROOT, requested)
            try:
                with open(target, "rb") as handle:
                    data = handle.read()
            except OSError:
                return self._send(404, "file not found")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if route == "/profile":
            identifier = params.get("id", [""])[0]
            try:
                row = _lookup_profile(identifier)
            except Exception as error:
                return self._send(200, "lookup error: " + str(error))
            if row is None:
                return self._send(404, "no such profile")
            return self._send(200, "profile %s <%s> secret=%s" % (row[0], row[1], row[2]))
        return self._send(404, "not found")

    def _send(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        return None


def main():
    server = http.server.HTTPServer(("0.0.0.0", 8000), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
'''


def build_fallback_source(variation: ChallengeVariation) -> str:
    """Return the vetted source for a variation's selected profiles.

    The same vetted app serves every profile, so the selection only determines
    which routes the private verifier exercises. The variation is accepted for
    forward compatibility and to keep the call site explicit.
    """
    _ = variation
    return VETTED_APP_SOURCE
