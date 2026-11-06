"""Single source of truth for VulnForge runtime configuration.

Configuration comes entirely from environment variables (`.env` in local
setups, Compose-passed values in containers). Validation never raises at import
or startup time: the API must boot and answer `/health` even with placeholder
credentials so Compose health checks pass. Instead, :func:`config_errors`
reports actionable problems that `GET /api/config` surfaces and that lab
creation refuses to run against.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

CELESTO_PROVIDERS = ("local", "cloud")
LLM_PROVIDERS = ("ollama", "openai_compatible")

_PLACEHOLDER_PREFIX = "replace-"


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _is_placeholder(value: str) -> bool:
    return not value or value.lower().startswith(_PLACEHOLDER_PREFIX)


def _int_env(name: str, default: int, *, minimum: int = 1) -> int:
    raw = _env(name, str(default))
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed >= minimum else default


@dataclass(frozen=True)
class AppConfig:
    celesto_provider: str
    celesto_backend: str
    celesto_api_key_present: bool
    llm_provider: str
    llm_model: str
    llm_base_url: str
    llm_api_key_present: bool
    ollama_base_url: str
    max_active_labs: int
    sandbox_ttl_minutes: int
    access_code_required: bool
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def valid(self) -> bool:
        return not self.errors

    def public_dict(self) -> dict[str, object]:
        """Non-secret view for `GET /api/config` and the dashboard badge."""
        return {
            "celesto_provider": self.celesto_provider,
            "celesto_backend": self.celesto_backend,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "max_active_labs": self.max_active_labs,
            "sandbox_ttl_minutes": self.sandbox_ttl_minutes,
            "access_code_required": self.access_code_required,
            "valid": self.valid,
            "errors": list(self.errors),
        }


def load_config() -> AppConfig:
    """Read and validate configuration from the environment."""
    errors: list[str] = []

    celesto_provider = _env("CELESTO_PROVIDER", "cloud").lower()
    if celesto_provider not in CELESTO_PROVIDERS:
        errors.append(
            f"CELESTO_PROVIDER must be one of {CELESTO_PROVIDERS}, got "
            f"'{celesto_provider or '(empty)'}'"
        )

    celesto_backend = _env("CELESTO_BACKEND", "firecracker")
    celesto_key = _env("CELESTO_API_KEY")
    celesto_key_present = not _is_placeholder(celesto_key)
    if celesto_provider == "cloud" and not celesto_key_present:
        errors.append("CELESTO_PROVIDER=cloud but CELESTO_API_KEY is empty")

    # LLM_PROVIDER accepts the two documented values; the historical "openai"
    # alias maps to openai_compatible so existing .env files keep working.
    raw_llm_provider = _env("LLM_PROVIDER", "ollama").lower()
    llm_provider = "openai_compatible" if raw_llm_provider == "openai" else raw_llm_provider
    if llm_provider not in LLM_PROVIDERS:
        errors.append(
            f"LLM_PROVIDER must be one of {LLM_PROVIDERS}, got "
            f"'{raw_llm_provider or '(empty)'}'"
        )

    ollama_base_url = _env("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    llm_base_url = _env("LLM_BASE_URL")
    llm_api_key = _env("LLM_API_KEY")
    llm_api_key_present = not _is_placeholder(llm_api_key)
    llm_model = _env("LLM_MODEL") or _env("OLLAMA_MODEL")

    if llm_provider == "openai_compatible":
        if not llm_base_url:
            errors.append("LLM_PROVIDER=openai_compatible but LLM_BASE_URL is empty")
        if not llm_api_key_present:
            errors.append("LLM_PROVIDER=openai_compatible but LLM_API_KEY is empty")
        if not llm_model:
            errors.append("LLM_PROVIDER=openai_compatible but LLM_MODEL is empty")
    elif llm_provider == "ollama":
        if not ollama_base_url:
            errors.append("LLM_PROVIDER=ollama but OLLAMA_BASE_URL is empty")
        if not llm_model:
            errors.append("LLM_PROVIDER=ollama but LLM_MODEL is empty")

    return AppConfig(
        celesto_provider=celesto_provider,
        celesto_backend=celesto_backend,
        celesto_api_key_present=celesto_key_present,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_base_url=llm_base_url,
        llm_api_key_present=llm_api_key_present,
        ollama_base_url=ollama_base_url,
        max_active_labs=_int_env("MAX_ACTIVE_LABS", 1),
        sandbox_ttl_minutes=_int_env("SANDBOX_TTL_MINUTES", 15),
        access_code_required=bool(_env("ACCESS_CODE")),
        errors=tuple(errors),
    )


def config_errors() -> list[str]:
    return list(load_config().errors)


def access_code() -> str | None:
    value = _env("ACCESS_CODE")
    return value or None


def access_code_matches(candidate: str | None) -> bool:
    """Return True when no access code is configured or the candidate matches."""
    required = access_code()
    if required is None:
        return True
    return isinstance(candidate, str) and candidate == required


def max_active_labs() -> int:
    return _int_env("MAX_ACTIVE_LABS", 1)


def sandbox_ttl_minutes() -> int:
    return _int_env("SANDBOX_TTL_MINUTES", 15)
