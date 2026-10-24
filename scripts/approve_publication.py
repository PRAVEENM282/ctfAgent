"""Approve or deny a pending publication through the token-protected API."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("approval_id")
    parser.add_argument("--decision", choices=("approved", "denied"), required=True)
    parser.add_argument("--decided-by", required=True)
    parser.add_argument("--base-url", default=os.getenv("APPROVAL_API_BASE_URL", "http://127.0.0.1:8080"))
    args = parser.parse_args()
    token = os.getenv("OPERATOR_TOKEN", "")
    if not token or token.startswith("replace-"):
        print("OPERATOR_TOKEN is not configured", file=sys.stderr)
        return 2
    body = json.dumps({"decision": args.decision, "decided_by": args.decided_by}).encode()
    request = urllib.request.Request(
        f"{args.base_url.rstrip('/')}/api/approvals/{args.approval_id}/decision",
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(response.read().decode("utf-8", "replace"))
            return 0
    except urllib.error.HTTPError as exc:
        print(f"approval request failed status={exc.code}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"approval transport failed error_type={type(exc.reason).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
