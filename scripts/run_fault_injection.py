"""Run the trusted Step-7 fault-injection gate when live prerequisites exist."""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.recovery import Step7FaultInjector, failure_policy_document


def main() -> int:
    try:
        if os.environ.get("VULNFORGE_INJECT_STEP7_FAILURE") not in {"1", "true", "TRUE", "yes", "on"}:
            raise RuntimeError("set VULNFORGE_INJECT_STEP7_FAILURE=1 in trusted control-plane configuration")
        injector = Step7FaultInjector.from_environment()
        injector.before_verifier()
    except Exception as exc:  # noqa: BLE001 - required safe diagnostic.
        frames = traceback.extract_tb(exc.__traceback__)
        frame = frames[-1] if frames else None
        location = f"{frame.filename}:{frame.lineno}" if frame else "unavailable"
        print(f"M8 gate step=7 error={type(exc).__name__}: {exc} last_frame={location}", file=sys.stderr)
        return 2
    print(f"fault_injection_ready policy={failure_policy_document()['policy']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
