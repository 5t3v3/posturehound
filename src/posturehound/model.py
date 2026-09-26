"""Core normalized domain model for PostureHound.

The deterministic engine is the single source of truth. Everything downstream
(scoring, reporting, API, and any future AI agent) reads from this model and may
not assert facts it does not contain.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

import networkx as nx


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def weight(self) -> int:
        return {"Critical": 40, "High": 20, "Medium": 8, "Low": 3, "Info": 1}[self.value]

    @property
    def rank(self) -> int:
        return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}[self.value]


class Category(str, Enum):
    IDENTITY = "Privileged Identity"
    APPLICATION = "Applications & Service Principals"
    RBAC = "Azure RBAC"
    GROUP = "Groups & Membership"
    KEYVAULT = "Key Vault"
    MANAGED_IDENTITY = "Managed Identities & Resources"
    COMPUTE = "Compute & Resource Abuse"
    STORAGE = "Storage & Data"
    HYGIENE = "Hygiene & Lifecycle"
    GUEST = "Guest & Cross-Tenant"
    ATTACK_PATH = "Attack Path"
    BEST_PRACTICE = "Best Practice"


class NodeKind(str, Enum):
    TENANT = "AZTenant"
    MANAGEMENT_GROUP = "AZManagementGroup"
    SUBSCRIPTION = "AZSubscription"
    RESOURCE_GROUP = "AZResourceGroup"
    USER = "AZUser"
    GROUP = "AZGroup"
    SERVICE_PRINCIPAL = "AZServicePrincipal"
    APP = "AZApp"
    DEVICE = "AZDevice"
    ROLE = "AZRole"
    VM = "AZVM"
    AKS = "AZManagedCluster"
    KEY_VAULT = "AZKeyVault"
    STORAGE = "AZStorageAccount"
    AUTOMATION = "AZAutomationAccount"
    FUNCTION_APP = "AZFunctionApp"
    LOGIC_APP = "AZLogicApp"
    WEB_APP = "AZWebApp"
    VMSS = "AZVMScaleSet"
    CONTAINER_REGISTRY = "AZContainerRegistry"
    UNKNOWN = "AZUnknown"


class EdgeType(str, Enum):
    # Raw relationships (present in / directly mapped from the collection)
    MEMBER_OF = "MemberOf"
    OWNS = "Owns"
    HAS_ENTRA_ROLE = "HasEntraRole"
    HAS_RBAC_ROLE = "HasRBACRole"
    CONTAINS = "Contains"
    KV_ACCESS = "KVAccess"
    HAS_MANAGED_IDENTITY = "HasManagedIdentity"
    HAS_APP_ROLE = "HasAppRole"
    # Derived abuse edges
    EFFECTIVE_ROLE = "EffectiveRole"
    CAN_ADD_SECRET = "CanAddSecret"
    CAN_ADD_OWNER = "CanAddOwner"
    CAN_ADD_MEMBER = "CanAddMember"
    CAN_GRANT_ROLE = "CanGrantRole"
    CAN_GRANT_APP_ROLE = "CanGrantAppRole"
    CAN_ESCALATE_RBAC = "CanEscalateRBAC"
    CAN_REACH_KV_SECRET = "CanReachKVSecret"
    CAN_STEAL_MANAGED_IDENTITY = "CanStealManagedIdentity"
    CAN_RESET_PASSWORD = "CanResetPassword"
    CAN_GET_STORAGE_KEY = "CanGetStorageKey"
    CAN_EXEC_AKS = "CanExecAKS"
    CAN_READ_STORAGE_BLOB = "CanReadStorageBlob"
    CAN_PUSH_CONTAINER = "CanPushContainer"
    ELIGIBLE_FOR_ROLE = "EligibleForRole"


@dataclass
class Node:
    id: str
    kind: NodeKind
    name: str
    props: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)


@dataclass
class Edge:
    src: str
    dst: str
    type: EdgeType
    derived: bool = False
    primitive: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


def _edge_sort_key_light(e: "Edge") -> tuple:
    """Cheap, stable order for the hot per-node accessors (out_edges / in_edges), called
    inside tight scoring loops. Endpoints + type give a deterministic order without paying
    to serialize evidence on every call."""
    return (e.src, e.dst, e.type.value, e.primitive or "")


def _edge_sort_key(e: "Edge") -> tuple:
    """Total, order-independent key for the full edge sweep. Folds evidence in as a final
    tie-break so two parallel edges with the SAME endpoints and type but DIFFERENT evidence
    (e.g. different scope) keep a stable relative order - which one survives a size cap must
    never depend on the collection's object order."""
    ev = e.evidence or {}
    return (e.src, e.dst, e.type.value, e.primitive or "",
            json.dumps(ev, sort_keys=True, default=str) if ev else "")


class Graph:
    """Wrapper over a networkx MultiDiGraph with security-domain query helpers."""

    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()
        self.tenant_id: str | None = None
        self.meta: dict[str, Any] = {}
        self.ingest_summary: dict[str, Any] = {}
        # Case-insensitive id index: lowercased id -> canonical id as first seen.
        # Azure treats ARM resource paths and Entra object GUIDs case-insensitively,
        # but AzureHound emits the SAME object with different casing across record
        # types (e.g. AZSubscription uses /SUBSCRIPTIONS/<GUID> while AZContains
        # references /subscriptions/<guid>). Without this index those became two
        # separate nodes and every edge between them pointed at a phantom.
        self._ci_index: dict[str, str] = {}
        # Derived-edge dedup key set. The derivations in derive.py emit one edge per
        # (principal, rbac_assignment, resource, identity) tuple, so a principal holding
        # Contributor at many scopes re-emits the same (src, dst, type) once per scope.
        # On a real tenant that turned ~37K distinct escalation edges into 10,059,917
        # attempts - enough to exhaust 32 GB of RAM+swap before build_fact_pack could
        # finish, and to starve the 5,000-edge fact-pack window with 99.6% duplicates.
        # Deduping here is semantically neutral: path-finding only cares whether an
        # edge of a given type exists between two nodes, not how many scopes imply it.
        self._derived_seen: set[tuple[str, str, str]] = set()
        # appId (client ID) -> node id. Nodes are keyed by object GUID, but several
        # AzureHound record types reference an app by its appId instead, so without
        # this index those records resolve to nothing.
        self._app_id_index: dict[str, str] = {}

    # ---- mutation ------------------------------------------------------
    def add_node(self, node: Node) -> None:
        canonical = self.resolve_id(node.id)
        if canonical is not None:
            existing = self.g.nodes[canonical]["node"]
            existing.props.update(node.props)
            existing.tags |= node.tags
            if existing.name in ("", None):
                existing.name = node.name
            # A real typed node supersedes a placeholder created earlier by an edge.
            if existing.kind == NodeKind.UNKNOWN and node.kind != NodeKind.UNKNOWN:
                existing.kind = node.kind
                existing.props.pop("_synthetic", None)
            # Props were just merged, so an appId may have arrived only now.
            self._index_app_id(existing)
            return
        self.g.add_node(node.id, node=node)
        self._ci_index[node.id.lower()] = node.id
        self._index_app_id(node)

    def _index_app_id(self, node: "Node") -> None:
        app_id = (node.props or {}).get("appId")
        if app_id:
            self._app_id_index.setdefault(str(app_id).lower(), node.id)

    def node_by_app_id(self, app_id: str | None) -> "Node | None":
        """Look up a service principal / app registration by its appId (client ID)."""
        if not app_id:
            return None
        nid = self._app_id_index.get(str(app_id).lower())
        return self.node(nid) if nid else None

    def resolve_id(self, node_id: str | None) -> "str | None":
        """Return the canonical node id matching *node_id* case-insensitively, or None.

        Use this before creating a node/edge endpoint so differently-cased references
        to the same Azure object converge on one node.
        """
        if not node_id:
            return None
        if self.g.has_node(node_id):
            return node_id
        return self._ci_index.get(node_id.lower())

    def add_edge(self, edge: Edge) -> None:
        # Collapse duplicate DERIVED edges (see _derived_seen). Raw ingested edges are
        # left alone: their evidence (scope, role) is distinct per assignment and is
        # consumed as an inventory, whereas a derived edge only asserts "this primitive
        # exists between these two nodes" and is therefore idempotent.
        if edge.derived:
            key = (edge.src, edge.dst, edge.type.value)
            if key in self._derived_seen:
                return
            self._derived_seen.add(key)
        self.g.add_edge(edge.src, edge.dst, key=f"{edge.type.value}:{id(edge)}", edge=edge)

    # ---- access --------------------------------------------------------
    def node(self, node_id: str) -> Node | None:
        if self.g.has_node(node_id):
            return self.g.nodes[node_id].get("node")
        return None

    def nodes(self) -> Iterable[Node]:
        # Yield in a STABLE, id-sorted order - never networkx insertion order, which follows
        # the collection's object order. A live re-collection returns the tenant's objects in
        # a different order every run; without this, that order flowed downstream into which
        # rows survived the fact-pack size caps, so the SAME tenant produced a different pack
        # (and a different AI analysis) each scan. Sorting here makes every consumer
        # (fact pack, scoring, derive) order-independent and the whole scan reproducible.
        ns = [d["node"] for _, d in self.g.nodes(data=True) if d.get("node") is not None]
        # Networkx auto-creates bare nodes when add_edge references a node id that doesn't
        # exist yet (scope strings used as edge destinations in derive.py); those have no
        # "node" payload and are skipped above.
        ns.sort(key=lambda n: n.id)
        return iter(ns)

    def edges(self) -> Iterable[Edge]:
        es = [d["edge"] for _, _, d in self.g.edges(data=True)]
        es.sort(key=_edge_sort_key)
        return iter(es)

    def nodes_of_kind(self, *kinds: NodeKind) -> list[Node]:
        kset = set(kinds)
        return [n for n in self.nodes() if n.kind in kset]

    def out_edges(self, node_id: str, etype: EdgeType | None = None) -> list[Edge]:
        if not self.g.has_node(node_id):
            return []
        out = [d["edge"] for _, _, d in self.g.out_edges(node_id, data=True)]
        out.sort(key=_edge_sort_key_light)
        return [e for e in out if etype is None or e.type == etype]

    def in_edges(self, node_id: str, etype: EdgeType | None = None) -> list[Edge]:
        if not self.g.has_node(node_id):
            return []
        ins = [d["edge"] for _, _, d in self.g.in_edges(node_id, data=True)]
        ins.sort(key=_edge_sort_key_light)
        return [e for e in ins if etype is None or e.type == etype]

    def display(self, node_id: str) -> str:
        n = self.node(node_id)
        return f"{n.name} ({n.kind.value})" if n else node_id
