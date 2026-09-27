"""Domain pack registry: which agent commands, gates and ship policy apply to each domain."""

from __future__ import annotations

from dataclasses import dataclass, field

from .data_types import DomainPack, ShipPolicy


@dataclass(frozen=True)
class DomainSpec:
    name: DomainPack
    description: str
    analyze_command: str | None          # agent interpretation step for domain ADWs
    extra_commands: tuple[str, ...] = ()
    ship_policy: ShipPolicy = "pr_only"
    required_gates: tuple[str, ...] = field(default_factory=tuple)

    @property
    def zte_allowed(self) -> bool:
        return self.ship_policy == "zte_allowed"


DOMAINS: dict[str, DomainSpec] = {
    "swe": DomainSpec(
        name="swe",
        description="Issue -> plan -> build -> test -> review -> redteam -> document -> ship",
        analyze_command=None,
        ship_policy="zte_allowed",
        required_gates=("lint", "types", "unit", "client", "e2e", "spec_review", "redteam", "secret_scan"),
    ),
    "devops": DomainSpec(
        name="devops",
        description="IaC plan risk analysis, drift detection, rollback planning. Never applies.",
        analyze_command="/devops_iac_plan",
        extra_commands=("/devops_drift_review",),
        ship_policy="pr_only",
    ),
    "soc": DomainSpec(
        name="soc",
        description="Log/network triage, vulnerability prioritization, Sigma rule tuning.",
        analyze_command="/soc_triage",
        extra_commands=("/soc_tune_rule",),
        ship_policy="report_only",
    ),
    "iam": DomainSpec(
        name="iam",
        description="Policy lint, RBAC/ABAC checks, dormant account audit, revocation plans. Never revokes.",
        analyze_command="/iam_access_review",
        extra_commands=("/iam_policy_fix",),
        ship_policy="pr_only",
    ),
}


def get_domain(name: str) -> DomainSpec:
    if name not in DOMAINS:
        raise ValueError(f"unknown domain {name!r}; choose from {sorted(DOMAINS)}")
    return DOMAINS[name]
