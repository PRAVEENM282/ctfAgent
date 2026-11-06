from pathlib import Path


def test_docker_image_includes_tests_and_report_mount_probe() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    audit_script = Path("scripts/audit_fresh_boot.sh").read_text(encoding="utf-8")
    approval_script = Path("scripts/live_approval.sh").read_text(encoding="utf-8")
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    # Backend image is Python-only; the frontend is a separate service.
    assert "COPY --chown=vulnforge:vulnforge tests ./tests" in dockerfile
    assert "FROM python:3.11-slim" in dockerfile
    assert "frontend-build" not in dockerfile
    assert 'USER vulnforge' in dockerfile
    assert 'EXPOSE 8080' in dockerfile

    # The dashboard has its own Dockerfile (node build -> nginx) and compose service.
    ui_dockerfile = Path("ui/Dockerfile").read_text(encoding="utf-8")
    assert "FROM node:22-bookworm-slim AS build" in ui_dockerfile
    assert "RUN npm run build" in ui_dockerfile
    assert "FROM nginx:" in ui_dockerfile

    assert "python scripts/test_reports_mount.py" in audit_script
    assert "tests/test_ledger_integration.py tests/test_llm_budget_integration.py" in audit_script
    assert "tests/test_report_serving_safety.py" in audit_script
    assert "approval-[a-z0-9]{16,}" in approval_script
    assert "REDACTED_APPROVAL_ID" in approval_script
    assert "reports-data:/app/reports" in compose
    assert '127.0.0.1:${API_PORT:-8080}:8080' in compose
    assert 'condition: service_healthy' in compose
    # The web (frontend) service exists and depends on the API.
    assert "web:" in compose
    assert "context: ./ui" in compose
