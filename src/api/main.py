"""FastAPI application for health and run-ledger operations."""

from __future__ import annotations

import inspect
import mimetypes
import os
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from src.api.schemas import (
    ApprovalCreate,
    ApprovalDecision,
    HealthResponse,
    LabCreate,
    RunCreate,
)
from src.api.startup import launch_startup_action
from src.approval import (
    authorization_header_token,
    operator_token_matches,
    public_approval_notice,
)
from src.lab_manager import LabConflict, LabExecutionError, LabManager
from src.ledger.repository import (
    DuplicateRunId,
    DuplicateSandboxName,
    LedgerUnavailable,
    RunNotFound,
    RunRepository,
)

ERROR_MESSAGES = {
    "invalid_run_id": "run_id must use the run- prefix and 12 to 32 lowercase letters or digits",
    "invalid_sandbox_name": "sandbox_name must use the sbx- prefix and at least 8 lowercase letters or digits",
    "invalid_problem_id": "problem_id must not be empty",
    "invalid_state": "state is not supported",
    "invalid_execution_target": "execution_target must be celesto_sandbox",
    "invalid_description": "description must be a non-empty string of at most 2000 characters",
    "invalid_payload": "request body is invalid",
    "duplicate_run_id": "run_id already exists",
    "duplicate_sandbox_name": "sandbox_name already exists",
    "ledger_unavailable": "ledger is unavailable",
    "operator_auth_required": "operator authorization is required",
    "approval_unavailable": "approval storage is unavailable",
    "approval_not_found": "approval was not found",
    "lab_not_found": "lab was not found",
    "lab_action_not_available": "this lab action is not available in the current phase",
    "provider_request_failed": "The model provider could not complete generation.",
    "rate_limited": "The provider rate-limited generation. Check its quota or wait before retrying.",
    "http_400": "The provider rejected the request. Check the model, API format, and tool-calling support.",
    "http_401": "The provider rejected authentication. Check the API key and authentication header.",
    "http_403": "The provider denied access. Check the account, model access, and endpoint permissions.",
    "http_404": "The provider endpoint or model was not found. Check the base URL and model ID.",
    "http_413": "The provider rejected the request size. Lower the request token setting or prompt size.",
    "http_422": "The provider rejected the request format. Check API format and tool-calling support.",
    "provider_not_configured": "The configured model provider is not ready.",
    "provider_protocol_failed": "The model provider returned an unusable response.",
    "generation_incomplete": (
        "The model responded but did not produce a valid app. Check tool-calling support and retry."
    ),
    "sandbox_create_failed": "The isolated sandbox could not be created.",
    "private_app_start_failed": "The generated site did not start privately.",
    "private_app_readiness_failed": "The generated site did not become ready privately.",
    "private_verification_failed": "The generated site did not pass private verification.",
    "publication_failed": "The verified lab could not be published safely.",
    "cleanup_unconfirmed": "Cleanup could not be confirmed.",
    "lab_execution_failed": "The lab could not be completed safely.",
}


class RunStore(Protocol):
    async def check_health(self) -> None: ...

    async def list_runs(self) -> list[dict[str, Any]]: ...

    async def create_run(self, values: dict[str, Any]) -> dict[str, Any]: ...


def _error_response(code: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": ERROR_MESSAGES[code]}},
    )


def _validation_error_code(exc: RequestValidationError) -> str:
    field_codes = {
        "run_id": "invalid_run_id",
        "sandbox_name": "invalid_sandbox_name",
        "problem_id": "invalid_problem_id",
        "state": "invalid_state",
        "execution_target": "invalid_execution_target",
        "description": "invalid_description",
    }
    for error in exc.errors():
        location = error.get("loc", ())
        if len(location) > 1 and location[0] == "body":
            code = field_codes.get(str(location[1]))
            if code:
                return code
    return "invalid_payload"


def create_app(
    repository: RunStore | None = None,
    reports_dir: Path | None = None,
    lab_manager: LabManager | None = None,
    frontend_dir: Path | None = None,
) -> FastAPI:
    app = FastAPI(title="VulnForge Local Dashboard", version="0.1.0")
    app.state.repository = repository or RunRepository(os.getenv("DATABASE_URL"))
    app.state.lab_manager = lab_manager or LabManager(app.state.repository)
    report_root = (
        reports_dir or Path(__file__).resolve().parents[2] / "reports"
    ).resolve()
    frontend_root = (
        frontend_dir or Path(__file__).resolve().parents[2] / "ui" / "dist"
    ).resolve()
    asset_root = frontend_root / "assets"
    if asset_root.is_dir():
        app.mount("/assets", StaticFiles(directory=asset_root), name="dashboard-assets")

    @app.on_event("startup")
    async def startup_action() -> None:
        migrate = getattr(app.state.repository, "migrate_runtime_schema", None)
        if callable(migrate):
            result = migrate()
            if inspect.isawaitable(result):
                await result
        await launch_startup_action()

    @app.on_event("shutdown")
    async def shutdown_action() -> None:
        await app.state.lab_manager.close()

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return _error_response(_validation_error_code(exc))

    @app.get("/health", response_model=HealthResponse)
    async def health() -> Any:
        return {"status": "ok"}

    @app.get("/health/db", response_model=HealthResponse)
    async def database_health(request: Request) -> Any:
        try:
            await request.app.state.repository.check_health()
        except LedgerUnavailable:
            return _error_response("ledger_unavailable", status_code=503)
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    async def dashboard_shell() -> Response:
        index = frontend_root / "index.html"
        if index.is_file():
            return FileResponse(index)
        return HTMLResponse(
            "<html><head><title>VulnForge</title></head>"
            "<body><h1>VulnForge dashboard build is unavailable.</h1></body></html>",
            status_code=503,
        )

    @app.get("/api/runs")
    async def get_runs(request: Request) -> Any:
        try:
            return await request.app.state.repository.list_runs()
        except LedgerUnavailable:
            return _error_response("ledger_unavailable", status_code=503)

    @app.post("/api/runs", status_code=201)
    async def post_run(payload: RunCreate, request: Request) -> Any:
        try:
            row = await request.app.state.repository.create_run(payload.model_dump())
        except DuplicateRunId:
            return _error_response("duplicate_run_id")
        except DuplicateSandboxName:
            return _error_response("duplicate_sandbox_name")
        except LedgerUnavailable:
            return _error_response("ledger_unavailable", status_code=503)
        return jsonable_encoder(row)

    @app.post("/api/labs", status_code=202)
    async def post_lab(payload: LabCreate, request: Request) -> Any:
        try:
            snapshot = await request.app.state.lab_manager.create_lab(
                payload.description
            )
        except LabExecutionError as exc:
            return _error_response(exc.code, status_code=502)
        except LedgerUnavailable:
            return _error_response("ledger_unavailable", status_code=503)
        return jsonable_encoder(snapshot)

    @app.get("/api/labs/{run_id}")
    async def get_lab(run_id: str, request: Request) -> Any:
        try:
            snapshot = await request.app.state.lab_manager.get_lab(run_id)
        except RunNotFound:
            return _error_response("lab_not_found", status_code=404)
        except LedgerUnavailable:
            return _error_response("ledger_unavailable", status_code=503)
        return jsonable_encoder(snapshot)

    @app.post("/api/labs/{run_id}/publish")
    async def publish_lab(run_id: str, request: Request) -> Any:
        try:
            snapshot = await request.app.state.lab_manager.publish_lab(run_id)
        except RunNotFound:
            return _error_response("lab_not_found", status_code=404)
        except LabConflict:
            return _error_response("lab_action_not_available", status_code=409)
        except LabExecutionError as exc:
            return _error_response(exc.code, status_code=502)
        except LedgerUnavailable:
            return _error_response("ledger_unavailable", status_code=503)
        return jsonable_encoder(snapshot)

    @app.post("/api/labs/{run_id}/stop")
    async def stop_lab(run_id: str, request: Request) -> Any:
        try:
            snapshot = await request.app.state.lab_manager.stop_lab(run_id)
        except RunNotFound:
            return _error_response("lab_not_found", status_code=404)
        except LabConflict:
            return _error_response("lab_action_not_available", status_code=409)
        except LabExecutionError as exc:
            return _error_response(exc.code, status_code=502)
        except LedgerUnavailable:
            return _error_response("ledger_unavailable", status_code=503)
        return jsonable_encoder(snapshot)

    def _require_operator(request: Request) -> JSONResponse | None:
        candidate = authorization_header_token(
            request.headers.get("authorization"),
            request.headers.get("x-operator-token"),
        )
        if not operator_token_matches(candidate):
            return _error_response("operator_auth_required", status_code=403)
        return None

    @app.post("/api/approvals", status_code=201)
    async def create_approval(payload: ApprovalCreate, request: Request) -> Any:
        auth_error = _require_operator(request)
        if auth_error is not None:
            return auth_error
        create = getattr(request.app.state.repository, "create_approval", None)
        if create is None:
            return _error_response("approval_unavailable", status_code=503)
        try:
            row = await create(**payload.model_dump())
        except LedgerUnavailable:
            return _error_response("approval_unavailable", status_code=503)
        return jsonable_encoder(
            {
                "approval_id": row["approval_id"],
                "run_id": row["run_id"],
                "attempt_id": row["attempt_id"],
                "sandbox_name": row["sandbox_name"],
                "action": row["action"],
                "port": row["port"],
                "app_sha256": row["app_sha256"],
                "expires_at": row["expires_at"],
                "decision": row["decision"],
                "mode": row["mode"],
                "notice": public_approval_notice(row["expires_at"]),
            }
        )

    @app.get("/api/approvals/{approval_id}")
    async def get_approval(approval_id: str, request: Request) -> Any:
        auth_error = _require_operator(request)
        if auth_error is not None:
            return auth_error
        getter = getattr(request.app.state.repository, "get_approval", None)
        if getter is None:
            return _error_response("approval_unavailable", status_code=503)
        try:
            row = await getter(approval_id)
        except LedgerUnavailable:
            return _error_response("approval_unavailable", status_code=503)
        if row is None:
            return _error_response("approval_not_found", status_code=404)
        return jsonable_encoder(row)

    @app.post("/api/approvals/{approval_id}/decision")
    async def decide_approval(
        approval_id: str, payload: ApprovalDecision, request: Request
    ) -> Any:
        auth_error = _require_operator(request)
        if auth_error is not None:
            return auth_error
        decider = getattr(request.app.state.repository, "decide_approval", None)
        if decider is None:
            return _error_response("approval_unavailable", status_code=503)
        try:
            row = await decider(approval_id, **payload.model_dump())
        except RunNotFound:
            return _error_response("approval_not_found", status_code=404)
        except ValueError as exc:
            return JSONResponse(
                status_code=409,
                content={
                    "error": {"code": "approval_not_pending", "message": str(exc)}
                },
            )
        except LedgerUnavailable:
            return _error_response("approval_unavailable", status_code=503)
        return jsonable_encoder(row)

    @app.get("/reports/{report_path:path}", include_in_schema=False)
    async def get_report(report_path: str) -> Response:
        requested_path = (report_root / report_path).resolve()
        try:
            requested_path.relative_to(report_root)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Report not found") from exc
        if not requested_path.is_file():
            raise HTTPException(status_code=404, detail="Report not found")
        media_type = (
            mimetypes.guess_type(requested_path.name)[0] or "application/octet-stream"
        )
        return Response(content=requested_path.read_bytes(), media_type=media_type)

    return app


app = create_app()
