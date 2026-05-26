from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ─── Text & DOM ──────────────────────────────────────────────────────────


class Rect(BaseModel):
    x: float = 0
    y: float = 0
    width: float = 0
    height: float = 0


class TextNode(BaseModel):
    """Each text fragment with positional metadata."""

    content: str
    selector: str = ""
    tag: str = ""
    visible: bool = True
    position: Rect | None = None
    color: str | None = None
    background_color: str | None = None
    font_size: int | None = None
    z_index: int | None = None
    opacity: float = 1.0
    parent_tag: str | None = None
    is_hidden: bool = False
    hidden_method: str | None = None
    provenance: str | None = None


# ─── Findings ────────────────────────────────────────────────────────────


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    detector: str = ""
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    confidence: float = 1.0
    title: str = ""
    description: str = ""
    text_nodes: list[TextNode] = Field(default_factory=list)
    snippet: str = ""
    context: str = ""
    category: str = ""
    recommendation: str = ""
    metadata: dict | None = None


class Provenance(BaseModel):
    origin: Literal[
        "visible_content",
        "hidden_content",
        "metadata",
        "comment",
        "attribute",
        "iframe",
        "third_party",
    ]
    layer_depth: int = 0
    source_url: str | None = None


class PolicyRule(BaseModel):
    id: str
    type: str
    description: str
    trigger: str
    pattern: str
    action: str
    severity: str


# ─── Scan ────────────────────────────────────────────────────────────────


class ScanReport(BaseModel):
    url: str
    timestamp: datetime = Field(default_factory=_utcnow)
    total_findings: int = 0
    risk_score: int = 0
    risk_category: Literal["none", "low", "medium", "high", "critical"] = "none"
    findings: list[Finding] = Field(default_factory=list)
    provenances: list[Provenance] = Field(default_factory=list)
    summary: str = ""
    policies: list[PolicyRule] = Field(default_factory=list)
    scan_time_ms: int = 0


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    scan_id: str = ""
    url: str
    findings: list[Finding] = Field(default_factory=list)
    risk_score: int = 0
    risk_category: str = "none"
    scan_time_ms: int = 0
    timestamp: datetime = Field(default_factory=_utcnow)

    @classmethod
    def from_report(cls, report: ScanReport) -> ScanResult:
        return cls(
            url=report.url,
            findings=report.findings,
            risk_score=report.risk_score,
            risk_category=report.risk_category,
            scan_time_ms=report.scan_time_ms,
        )


# ─── Agent Validation ────────────────────────────────────────────────────


class Mission(BaseModel):
    instruction: str = ""
    page_type: str = "generic"
    budget: float | None = None
    constraints: list[str] = Field(default_factory=list)


class AgentStep(BaseModel):
    step_number: int
    thought: str = ""
    action: str = ""
    screenshot: str | None = None
    dom_snapshot: str | None = None
    url_after: str = ""
    timestamp: datetime = Field(default_factory=_utcnow)


class AgentSession(BaseModel):
    url: str
    mission: Mission
    steps: list[AgentStep] = Field(default_factory=list)
    success: bool = False
    total_cost: float = 0.0
    duration_ms: int = 0


class InjectionImpact(BaseModel):
    finding_id: str
    injection_text: str
    severity: str = "medium"
    triggered_at_step: int = 0
    triggered_by_action: str = ""
    impact: Literal["triggered", "partially_triggered", "ignored"] = "ignored"


class SuspiciousAction(BaseModel):
    step_number: int
    action: str
    reason: str


class AgentVulnerabilityReport(BaseModel):
    agent_provider: str = "browser_use"
    mission: Mission
    total_steps: int = 0
    mission_success: bool = False
    mission_deviation_score: float = 0.0
    injections_triggered: list[InjectionImpact] = Field(default_factory=list)
    injections_ignored: list[InjectionImpact] = Field(default_factory=list)
    unknown_threat_actions: list[SuspiciousAction] = Field(default_factory=list)
    overall_vulnerability_score: int = 0
    summary: str = ""


# ─── Reputation ──────────────────────────────────────────────────────────


class ReputationEntry(BaseModel):
    domain: str
    path: str | None = None
    trust_level: Literal["unknown", "trusted", "suspicious", "malicious", "pending_review"] = "unknown"
    score: float = 0.0
    total_scans: int = 0
    total_findings: int = 0
    last_scan_at: datetime | None = None
    last_finding_at: datetime | None = None
    first_seen_at: datetime = Field(default_factory=_utcnow)
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    jailbreak_count: int = 0
    exfiltration_count: int = 0
    impersonation_count: int = 0
    hidden_instruction_count: int = 0
    role_override_count: int = 0
    tool_manipulation_count: int = 0
    domain_age_days: int | None = None
    has_https: bool = False


class ReputationQuery(BaseModel):
    url: str
    trust_level: str = "unknown"
    score: float = 0.0
    history: list[dict] = Field(default_factory=list)


# ─── Red Team ─────────────────────────────────────────────────────────────


class InjectionSpec(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:8])
    text: str
    category: Literal[
        "jailbreak",
        "exfiltration",
        "impersonation",
        "role_override",
        "tool_manipulation",
        "hidden_instruction",
    ] = "jailbreak"
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    embedding_method: str = "hidden_div"
    css_selector: str = ""
    variant_of: str | None = None


class GeneratedPage(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    html: str
    url: str | None = None
    template_used: str = "generic"
    injections: list[InjectionSpec] = Field(default_factory=list)
    ground_truth: list[dict] = Field(default_factory=list)


class PageResult(BaseModel):
    page_id: str
    template: str
    num_expected: int = 0
    num_detected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    latency_ms: int = 0


class EvaluationReport(BaseModel):
    total_pages: int = 0
    total_injections: int = 0
    total_detections: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    by_category: dict = Field(default_factory=dict)
    by_method: dict = Field(default_factory=dict)
    by_severity: dict = Field(default_factory=dict)
    page_results: list[PageResult] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# ─── Certification ───────────────────────────────────────────────────────


class Certificate(BaseModel):
    certificate_id: str
    url: str
    domain: str
    status: Literal["pending", "active", "suspended", "revoked", "expired"] = "pending"
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    initial_scan_id: str = ""
    initial_score: float = 0.0
    total_scans_during_monitoring: int = 0
    avg_score_during_monitoring: float = 0.0
    highest_score_during_monitoring: float = 0.0
    agent_validations_passed: int = 0
    agent_validations_failed: int = 0
    owner_email: str | None = None
    organization: str | None = None
    verification_hash: str = ""

    def is_valid(self) -> bool:
        return (
            self.status == "active"
            and self.expires_at is not None
            and self.expires_at > _utcnow()
        )
