from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote

import pytest
from httpx2 import ASGITransport, AsyncClient

from src.api.main import create_app

FLAG = re.compile(r"VF\{[0-9a-fA-F]{32}\}")
BEARER = re.compile(r"(?i)\bBearer\s+(?!\[REDACTED\])[A-Za-z0-9._~+/-]{8,}")
CREDENTIAL = re.compile(
    r"(?i)\b(?:CELESTO_API_KEY|LLM_API_KEY|OPERATOR_TOKEN|"
    r"API[_-]?KEY|ACCESS[_-]?TOKEN|APPROVAL[_-]?TOKEN|PASSWORD|SECRET)"
    r"\s*[:=]\s*(?!\[REDACTED\]|<REDACTED>|replace-me|"
    r"replace-with-a-token|unknown|none|null)[^\s,;\"']+"
)
RAW_PROVIDER_TOKEN = re.compile(r"\b(?:cel|sk)-[A-Za-z0-9_-]{20,}\b")
APPROVAL_ID = re.compile(r"\bapproval-[a-z0-9]{16,}\b")
RAW_PUBLISHED_URL = re.compile(
    r"https://(?!<route-label>)[a-z0-9][a-z0-9-]*\.celesto\.dev(?:/[^\s\"']*)?"
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_every_api_served_report_is_sanitized() -> None:
    report_root = Path(__file__).resolve().parents[1] / "reports"
    app = create_app(repository=object(), reports_dir=report_root)
    files = sorted(path for path in report_root.rglob("*") if path.is_file())
    assert files

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        for path in files:
            relative = path.relative_to(report_root).as_posix()
            response = await client.get("/reports/" + quote(relative, safe="/"))
            assert response.status_code == 200, relative
            text = response.content.decode("utf-8", errors="replace")
            leaks = []
            if FLAG.search(text):
                leaks.append("flag")
            if BEARER.search(text):
                leaks.append("bearer")
            if CREDENTIAL.search(text):
                leaks.append("credential_assignment")
            if RAW_PROVIDER_TOKEN.search(text):
                leaks.append("provider_token")
            if APPROVAL_ID.search(text):
                leaks.append("approval_id")
            if RAW_PUBLISHED_URL.search(text):
                leaks.append("published_url")
            assert not leaks, f"{relative}: {','.join(leaks)}"
