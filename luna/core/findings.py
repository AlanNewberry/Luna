from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    evidence: str
    affected_resource: str
    remediation: str
    references: list[str] = field(default_factory=list)
