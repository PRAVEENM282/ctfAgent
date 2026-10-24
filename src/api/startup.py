"""Opt-in startup actions; the default startup action is intentionally inert."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path


async def launch_startup_action() -> None:
    action = os.getenv("VULNFORGE_STARTUP_ACTION", "none").strip().lower()
    if action == "none":
        return
    if action not in {"demo", "eval"}:
        raise RuntimeError("VULNFORGE_STARTUP_ACTION must be none, demo, or eval")
    root = Path(__file__).resolve().parents[2]
    command = [sys.executable, "scripts/run_m6.py"] if action == "demo" else [sys.executable, "scripts/run_evaluation.py", "--attempts", "20", "--execute"]
    log_path = Path(os.getenv("VULNFORGE_STATE_DIR", "/var/lib/vulnforge")) / f"startup-{action}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("ab", buffering=0)
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=root,
        env=os.environ.copy(),
        stdout=handle,
        stderr=asyncio.subprocess.STDOUT,
    )
    asyncio.create_task(_close_after(process, handle))


async def _close_after(process: asyncio.subprocess.Process, handle: object) -> None:
    await process.wait()
    close = getattr(handle, "close", None)
    if close is not None:
        close()
