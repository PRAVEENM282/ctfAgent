from pathlib import Path


def test_docker_image_includes_tests_and_report_mount_probe() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    audit_script = Path("scripts/audit_fresh_boot.sh").read_text(encoding="utf-8")
    approval_script = Path("scripts/live_approval.sh").read_text(encoding="utf-8")
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "COPY --chown=vulnforge:vulnforge tests ./tests" in dockerfile
    assert "FROM node:22.23.3-bookworm-slim AS frontend-build" in dockerfile
    assert "RUN npm run build --prefix ui" in dockerfile
    assert "COPY --from=frontend-build" in dockerfile
    assert 'USER vulnforge' in dockerfile
    assert 'EXPOSE 8080' in dockerfile
    assert "python scripts/test_reports_mount.py" in audit_script
    assert "tests/test_ledger_integration.py tests/test_llm_budget_integration.py" in audit_script
    assert "tests/test_report_serving_safety.py" in audit_script
    assert "approval-[a-z0-9]{16,}" in approval_script
    assert "REDACTED_APPROVAL_ID" in approval_script
    assert "reports-data:/app/reports" in compose
    assert '127.0.0.1:${API_PORT:-8080}:8080' in compose
    assert 'condition: service_healthy' in compose
