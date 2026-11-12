"""Result schemas: what an analysis subagent must write for `sdive record`."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(_Strict):
    path: str = Field(description="Repo-relative path in the snapshot")
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(default=None, description="Enclosing function, if any")


class UnitStatus(_Strict):
    key: str = Field(description="Unit key exactly as given in the brief")
    status: Literal["clean", "hypotheses", "partial"] = Field(
        description="clean: examined, nothing found; hypotheses: examined, raised "
        "at least one; partial: not examined thoroughly enough to count as covered"
    )
    note: str = ""


class Hypothesis(_Strict):
    title: str = Field(max_length=120)
    claim: str = Field(
        description="What is wrong, where attacker-influenced data enters, and how it "
        "reaches the defect. This is all the blind verifier sees besides locations."
    )
    locations: list[Location] = Field(min_length=1)
    property: str | None = Field(default=None, description="Threat-model property, e.g. P1")
    attacker: str | None = Field(default=None, description="Attacker class, e.g. A2")
    cwe: str | None = Field(default=None, description="e.g. CWE-787")
    confidence: Literal["low", "medium", "high"]
    auditor_notes: str = Field(default="", description="Not shown to the verifier")
    slug: str | None = Field(default=None, description="Optional short kebab-case id")


class UpstreamNote(_Strict):
    """A suspected defect inside an external (reference) component, e.g. a
    crypto library. Kept for later triage and filing with that project; never
    an MCUboot/Zephyr finding."""

    component: str = Field(description="Reference tree path as given in the brief")
    title: str = Field(max_length=120)
    description: str = Field(
        description="The suspected defect in the external code, and how this project "
        "is or could be affected"
    )
    locations: list[Location] = []


class DossierNote(_Strict):
    area: str
    text: str = Field(
        description="Markdown: trust boundaries, invariants (with where they are "
        "enforced), and cleared patterns with the reason they are safe"
    )


class AuditResult(_Strict):
    """Output of a sweep or dive run."""

    run_id: int
    model: str = Field(description="Model ID the agent is running as")
    summary: str
    units: list[UnitStatus]
    hypotheses: list[Hypothesis] = Field(
        default=[],
        description="Defects in this project's code: each needs at least one location "
        "in an indexed unit. Locations in reference trees may be added as evidence.",
    )
    dossier: list[DossierNote] = []
    upstream_notes: list[UpstreamNote] = []


class VerifyResult(_Strict):
    """Output of a verify run: an independent verdict on one hypothesis."""

    run_id: int
    model: str
    verdict: Literal["verified", "rejected", "duplicate", "inconclusive"]
    reasoning: str = Field(description="The code-grounded argument for the verdict")
    property: str | None = None
    attacker: str | None = None
    cwe: str | None = None
    severity: str | None = Field(default=None, description="CVSS vector, if verified")
    duplicate_of: str | None = Field(
        default=None, description="Finding slug, GHSA id, or disclosure id"
    )
    revised_title: str | None = None
    revised_claim: str | None = None
    dossier: list[DossierNote] = []
    upstream_notes: list[UpstreamNote] = []

    @model_validator(mode="after")
    def _check(self) -> VerifyResult:
        if self.verdict == "verified" and not (self.property and self.attacker):
            raise ValueError("a verified finding must name property and attacker")
        if self.verdict == "duplicate" and not self.duplicate_of:
            raise ValueError("a duplicate verdict must give duplicate_of")
        return self


SCHEMAS: dict[str, type[BaseModel]] = {"audit": AuditResult, "verify": VerifyResult}
