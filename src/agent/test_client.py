"""Deterministic, test-only agent client.

The production dashboard uses the configured cloud provider. Evidence and unit
tests may use this client to exercise the full guarded Celesto path without
making an LLM request or claiming provider-generated output.
"""

from __future__ import annotations

import json
from typing import Any

from src.agent.provider import ProviderResponse

TEST_SOURCE = """import http.server
import os
import sqlite3
import urllib.parse


def query_value(path, key):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(path).query).get(key, [''])[0]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/search?'):
            query = query_value(self.path, 'q')
            statement = "SELECT email FROM records WHERE name LIKE '%" + query + "%'"
            with sqlite3.connect('/root/app.db') as database:
                database.execute('SELECT value FROM secrets LIMIT 0').fetchall()
                rows = database.execute(statement).fetchall()
            body = ('\\n'.join(str(row[0]) for row in rows) or 'no results').encode()
        elif self.path.startswith('/echo?'):
            body = query_value(self.path, 'name').encode()
        elif self.path.startswith('/download?'):
            filename = query_value(self.path, 'file')
            target = os.path.join('/root/vulnforge_files/public', filename)
            try:
                with open(target, 'rb') as handle:
                    body = handle.read()
            except OSError:
                self.send_response(404)
                self.end_headers()
                return
        elif self.path.startswith('/profile?'):
            profile_id = query_value(self.path, 'id')
            with sqlite3.connect('/root/app.db') as database:
                rows = database.execute(
                    'SELECT secret FROM profiles WHERE id = ' + profile_id
                ).fetchall()
            body = ('\\n'.join(str(row[0]) for row in rows) or 'not found').encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


if __name__ == '__main__':
    http.server.HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
"""


class DeterministicTestClient:
    """Return the fixed safe profile-bundle source without contacting a provider."""

    source = "test_policy"

    def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
    ) -> ProviderResponse:
        del messages, max_tokens
        if not tools or not isinstance(tools[0], dict):
            raise ValueError("the test client requires the write_app tool")
        function = tools[0].get("function")
        if not isinstance(function, dict) or function.get("name") != "write_app":
            raise ValueError("the test client only supports write_app")
        call = {
            "id": "test-write-app-1",
            "type": "function",
            "function": {
                "name": "write_app",
                "arguments": json.dumps({"source": TEST_SOURCE}),
            },
        }
        return ProviderResponse(
            model="deterministic-test-policy",
            message={"role": "assistant", "content": None, "tool_calls": [call]},
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            headers={},
            status_code=200,
        )


def build_test_client() -> DeterministicTestClient:
    """Build the test-only client; production code should use provider settings."""

    return DeterministicTestClient()
