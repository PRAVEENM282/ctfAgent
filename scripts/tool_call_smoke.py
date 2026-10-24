"""Exercise the configured OpenAI-compatible model five times without logging secrets."""

from __future__ import annotations

import json
import os
import sys
import traceback
import urllib.error
import urllib.request

try:
    from scripts.reap_orphans import reap_orphans
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    from reap_orphans import reap_orphans

CALL_COUNT = 5


def _redact(value: str) -> str:
    for key_name in ("CELESTO_API_KEY", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        secret = os.environ.get(key_name)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _endpoint(base_url: str) -> str:
    base = base_url.rstrip("/")
    return base if base.endswith("/chat/completions") else f"{base}/chat/completions"


def _request(endpoint: str, api_key: str, model: str) -> tuple[bool, int, int, int, dict[str, str]]:
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with only OK."}],
            "temperature": 0,
            "max_tokens": 16,
        }
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "ctfAgent/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            response_headers = dict(response.headers.items())
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        try:
            error_payload = json.loads(response_body).get("error") or {}
            detail = error_payload.get("message") or error_payload.get("type") or str(error_payload)
        except (json.JSONDecodeError, AttributeError):
            detail = response_body[:500]
        raise RuntimeError(f"LLM HTTP status={exc.code}; detail={_redact(str(detail))!r}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM transport error={type(exc.reason).__name__}") from None

    safe_headers = {
        str(key).lower(): str(value)[:200]
        for key, value in response_headers.items()
        if str(key).lower() == "x-ratelimit-remaining-requests"
        or str(key).lower() == "x-ratelimit-remaining-tokens"
        or str(key).lower() == "retry-after"
    }
    usage = payload.get("usage") or {}
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    total_tokens = usage.get("total_tokens")
    if not all(isinstance(value, int) and value >= 0 for value in (prompt_tokens, completion_tokens, total_tokens)):
        raise RuntimeError("LLM response omitted integer prompt/completion/total token usage")
    return (
        payload.get("model") == model,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        safe_headers,
    )


def main() -> int:
    step = "reap_orphans"
    try:
        os.environ.setdefault("CELESTO_NO_TELEMETRY", "1")
        reap_orphans()

        step = "validate_llm_configuration"
        endpoint_base = os.environ.get("LLM_BASE_URL", "").strip()
        api_key = os.environ.get("LLM_API_KEY", "")
        model = os.environ.get("LLM_MODEL", "").strip()
        if not endpoint_base or not api_key or not model:
            raise ValueError("LLM_BASE_URL, LLM_API_KEY, and LLM_MODEL must be configured")

        step = "five_call_model_smoke"
        endpoint = _endpoint(endpoint_base)
        totals = {"prompt": 0, "completion": 0, "total": 0}
        all_models_match = True
        for call_number in range(1, CALL_COUNT + 1):
            matches, prompt, completion, total, headers = _request(endpoint, api_key, model)
            all_models_match = all_models_match and matches
            totals["prompt"] += prompt
            totals["completion"] += completion
            totals["total"] += total
            header_note = ""
            if call_number == 1:
                header_note = (
                    f" remaining_requests={headers.get('x-ratelimit-remaining-requests', 'unknown')}"
                    f" remaining_tokens_header={headers.get('x-ratelimit-remaining-tokens', 'unknown')}"
                    " remaining_tokens_header_scope=provider-defined-not-daily"
                )
            print(
                f"LLM_CALL {call_number}/{CALL_COUNT} model_match={str(matches).lower()} "
                f"prompt_tokens={prompt} completion_tokens={completion} total_tokens={total}{header_note}"
            )

        pinned_model = model.lower() not in {"openrouter/free", "auto", "auto-router"}
        print(
            f"LLM_TOTAL calls={CALL_COUNT} model_match={str(all_models_match).lower()} "
            f"pinned_model={str(pinned_model).lower()} prompt_tokens={totals['prompt']} "
            f"completion_tokens={totals['completion']} total_tokens={totals['total']}"
        )
        if not all_models_match:
            raise AssertionError("at least one response model differed from configured LLM_MODEL")
        if not pinned_model:
            raise AssertionError("configured LLM_MODEL is an auto-router, not a pinned model")
        print("PASS five_call_model_pin_smoke")
        return 0
    except Exception as exc:  # noqa: BLE001 - emit required redacted failure diagnostics.
        frames = traceback.extract_tb(exc.__traceback__)
        frame = frames[-1] if frames else None
        location = f"{frame.filename}:{frame.lineno}" if frame else "unavailable"
        print(f"FAIL step={step} error={_redact(repr(exc))} last_frame={location}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
