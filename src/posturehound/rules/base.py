"""Rule engine base types and registry.

Rules are Python callables registered with full metadata. This keeps them
testable and version-control friendly; externalising to YAML is a later
enhancement (the metadata schema below is the contract). Each rule declares the
node kinds it needs; if none are present, the rule is reported as *not assessed*
rather than as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..model import Category, Graph, NodeKind, Severity


@dataclass
class Entity:
    id: str
    name: str
    kind: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    entities: list[Entity] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    frameworks: dict[str, str] = field(default_factory=dict)
    best_practice: bool = False

    @property
    def count(self) -> int:
        return len(self.entities)


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    data_source: list[NodeKind]
    fn: Callable[[Graph], list[Entity]]
    references: list[str] = field(default_factory=list)
    frameworks: dict[str, str] = field(default_factory=dict)
    best_practice: bool = False
    # AzureHound RECORD kinds whose logic this rule depends on beyond node presence.
    # Node presence alone cannot tell "no dangerous grants exist" from "grant records
    # were never collected": a rule reading app-role grants sees empty SP nodes and
    # passes clean either way. If none of these record kinds were ingested, the rule
    # is reported not_assessed rather than a silent clean pass.
    requires_records: list[str] = field(default_factory=list)
    # Node PROPERTIES whose presence this rule's entire signal depends on. The
    # node kind can be present (e.g. 562 Key Vaults) while the specific property
    # (publicNetworkAccess, softDeleteRetentionInDays, securityProfile, ...) was
    # never collected by AzureHound. Such a rule then reads absent data and returns
    # nothing, which the report would otherwise show as a clean pass ("Key Vault
    # network exposure: OK") when the control was never actually assessed. If no
    # node of data_source carries any of these props (checked at top level and one
    # level under a nested "properties" dict), the rule is reported not_assessed.
    requires_props: list[str] = field(default_factory=list)


REGISTRY: list[Rule] = []


def _any_node_has_prop(g: Graph, kinds: list[NodeKind], props: list[str]) -> bool:
    """True if any node of the given kinds carries any of the named properties,
    at the top level or one level down under a nested 'properties' dict."""
    wanted = set(props)
    nodes = g.nodes_of_kind(*kinds) if kinds else g.nodes()
    for n in nodes:
        p = n.props or {}
        if wanted & p.keys():
            return True
        nested = p.get("properties")
        if isinstance(nested, dict) and wanted & nested.keys():
            return True
    return False


def rule(**kwargs) -> Callable:
    def deco(fn: Callable[[Graph], list[Entity]]) -> Callable:
        REGISTRY.append(Rule(fn=fn, **kwargs))
        return fn
    return deco


@dataclass
class AssessmentResult:
    findings: list[Finding]
    not_assessed: list[dict]  # rules whose data source was absent
    assessed_kinds: set[str]


def run_rules(g: Graph) -> AssessmentResult:
    present = {n.kind for n in g.nodes()}
    # Which AzureHound record kinds were actually ingested (relationship data, not
    # just nodes). Absence of a required relationship record is why a rule reading it
    # sees "nothing" and must NOT be read as a clean pass.
    by_kind = set(((g.ingest_summary or {}).get("by_kind") or {}).keys())
    findings: list[Finding] = []
    not_assessed: list[dict] = []
    for r in REGISTRY:
        needs = set(r.data_source)
        if needs and not (needs & present):
            not_assessed.append({
                "rule_id": r.id, "title": r.title,
                "reason": "required data not present in collection",
                "needs": [k.value for k in r.data_source],
            })
            continue
        # The relationship data this rule reads was never collected - its silence is
        # "not assessed", never a clean pass.
        if r.requires_records and by_kind and not (set(r.requires_records) & by_kind):
            not_assessed.append({
                "rule_id": r.id, "title": r.title,
                "reason": ("relationship data not collected ("
                           + " / ".join(r.requires_records) + ")"),
                "needs": r.requires_records,
            })
            continue
        # The node kind is present but the specific property this rule reads was
        # never collected - silence is "not assessed", not a clean pass.
        if r.requires_props and not _any_node_has_prop(g, r.data_source, r.requires_props):
            not_assessed.append({
                "rule_id": r.id, "title": r.title,
                "reason": ("property not collected ("
                           + " / ".join(r.requires_props) + ")"),
                "needs": r.requires_props,
            })
            continue
        try:
            entities = r.fn(g)
        except Exception as exc:
            not_assessed.append({
                "rule_id": r.id, "title": r.title,
                "reason": f"rule raised {type(exc).__name__}: {exc}",
                "needs": [k.value for k in r.data_source],
            })
            continue
        if entities:
            findings.append(Finding(
                rule_id=r.id, title=r.title, severity=r.severity, category=r.category,
                description=r.description, remediation=r.remediation, entities=entities,
                references=r.references, frameworks=r.frameworks, best_practice=r.best_practice,
            ))
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
    return AssessmentResult(findings=findings, not_assessed=not_assessed,
                            assessed_kinds={k.value for k in present})
