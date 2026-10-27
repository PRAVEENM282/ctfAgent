"""Request and response contracts for the run ledger API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.vulnerability_profiles import normalize_selection

RunState = Literal["created", "ready", "running", "succeeded", "failed", "deleted"]
ExecutionTarget = Literal["celesto_sandbox"]
LabPhase = Literal[
    "queued",
    "generating",
    "verifying",
    "awaiting_publication",
    "published",
    "cleaning_up",
    "cleaned_up",
    "failed",
]
VulnerabilityMode = Literal["single", "bundle"]
VulnerabilityId = Literal[
    "sql_injection",
    "reflected_xss",
    "path_traversal",
    "idor",
]


class RunCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    run_id: str = Field(pattern=r"^run-[a-z0-9]{12,32}$")
    sandbox_name: str = Field(pattern=r"^sbx-[a-z0-9]{8,}$")
    problem_id: str = Field(min_length=1, max_length=120)
    state: RunState
    execution_target: ExecutionTarget


class HealthResponse(BaseModel):
    status: Literal["ok"]


class LabCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    description: str = Field(min_length=1, max_length=2000)
    mode: VulnerabilityMode = "single"
    vulnerabilities: list[VulnerabilityId] | None = None

    @field_validator("description")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
            raise ValueError("description contains unsupported control characters")
        return value

    @model_validator(mode="after")
    def validate_vulnerability_selection(self) -> "LabCreate":
        normalize_selection(self.mode, self.vulnerabilities)
        return self


class LabSnapshot(BaseModel):
    run_id: str
    state: RunState
    phase: LabPhase
    message: str
    can_publish: bool
    can_stop: bool
    cleanup_confirmed: bool
    public_url: str | None = None
    public_access_warning: str | None = None
    error_code: str | None = None


class ApprovalCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    run_id: str = Field(pattern=r"^run-[a-z0-9]{12,32}$")
    attempt_id: str = Field(pattern=r"^attempt-[a-z0-9]{12,32}$")
    sandbox_name: str = Field(pattern=r"^sbx-[a-z0-9]{8,}$")
    action: Literal["publish_public_lab"]
    port: int = Field(ge=1024, le=65535)
    app_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ttl_seconds: int = Field(default=300, ge=1, le=3600)
    mode: Literal["interactive", "pre_approved"] = "interactive"


class ApprovalDecision(BaseModel):
    decision: Literal["approved", "denied"]
    decided_by: str = Field(min_length=1, max_length=120)
