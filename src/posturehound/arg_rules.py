"""Rules over Azure Resource Graph data (PostureHound v2, Track B).

These consume the rows returned by azure_arg.collect(), network exposure and
data-service configuration that AzureHound cannot see. The rows have a fixed
shape because azure_arg's KQL `project`s explicit named fields, so the rule input
is a contract this codebase defines. If an underlying Azure property path were
wrong, that field arrives as None and the rule reports UNCONFIRMED, never a
false finding and never a false pass, exactly as the graph rules do for a
not-collected property.

Each rule is self-contained (carries its own drill-down detail) so it needs no
knowledge.py entry. run_arg_rules() emits findings in the same dict shape as the
deterministic graph findings, so the report / scoring / AI layers treat them
identically.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .model import Category, Severity


@dataclass
class Entity:
    id: str
    name: str
    kind: str
    evidence: dict = field(default_factory=dict)


@dataclass
class ArgRule:
    id: str
    title: str
    severity: Severity
    category: Category
    query_key: str          # which azure_arg.ARG_QUERIES result to read
    description: str
    remediation: str
    detail: dict            # summary/why/scenario/impact/steps/detection
    fn: Callable[[list[dict]], list[Entity]]
    frameworks: dict = field(default_factory=dict)
    best_practice: bool = False


REGISTRY: list[ArgRule] = []


def arg_rule(**kwargs):
    def deco(fn):
        REGISTRY.append(ArgRule(fn=fn, **kwargs))
        return fn
    return deco


# --------------------------------------------------------------------------- helpers
def _e(row: dict, kind: str, **evidence) -> Entity:
    return Entity(id=str(row.get("id") or row.get("name") or "?"),
                  name=str(row.get("name") or row.get("id") or "?"),
                  kind=kind,
                  evidence={"subscription": row.get("subscriptionId"),
                            "resourceGroup": row.get("resourceGroup"), **evidence})


def _enabled(v) -> bool:
    return isinstance(v, str) and v.strip().lower() == "enabled"


def _weak_tls(v) -> "str | None":
    """Return the value if it names a TLS version below 1.2, else None. Handles
    both '1.0'/'1.1' and the '1_0'/'1_1' spellings Azure uses across services."""
    if isinstance(v, str) and v.strip().replace("_", ".").lstrip("TLStls") in ("1.0", "1.1"):
        return v
    return None


_MGMT_PORTS = {"22", "3389", "5985", "5986", "1433", "3306", "5432", "6379", "27017", "*"}


# =========================================================================== #
# Network exposure
# =========================================================================== #
@arg_rule(id="ARG-NET-001", title="Network security group allows inbound access from any source",
          severity=Severity.HIGH, category=Category.COMPUTE, query_key="nsg_rules_any_inbound",
          description="A network security group has an inbound Allow rule whose source is the internet (Any / 0.0.0.0/0 / Internet). Any resource behind the NSG is reachable from the whole internet on the rule's ports, removing network-layer containment.",
          remediation="Scope inbound rules to specific source IP ranges or Application Security Groups. Never expose management ports (SSH 22, RDP 3389, WinRM, database ports) to the internet; use a bastion or Just-in-Time access.",
          frameworks={"CIS Azure": "6.x", "MITRE ATT&CK": "T1190", "Azure Threat Matrix": "AZT103"},
          detail={
              "summary": "An NSG rule allows inbound traffic from any internet source.",
              "why": "An allow-any inbound rule places the protected resources directly on the internet. If the rule covers a management port (SSH, RDP, WinRM) or a database port, the service is exposed to continuous internet-wide scanning, brute force and exploit attempts with no network barrier in front of it.",
              "scenario": "An attacker scans Azure IP ranges, finds the open management or database port, and brute-forces or exploits the service directly, no foothold inside the tenant network required.",
              "impact": "Direct internet exposure of the protected workload; the first step in most external-compromise chains.",
              "steps": [
                  "Replace 'Any'/'0.0.0.0/0'/'Internet' sources with specific IP ranges or ASGs.",
                  "Remove internet exposure of management and database ports entirely; use a bastion or Just-in-Time VM access.",
                  "Audit NSG rules with Azure Policy so new allow-any rules are denied.",
              ],
              "detection": "Azure Resource Graph over NSG securityRules for inbound Allow with a wildcard source. Alert on NSG rule changes in the activity log.",
          })
def nsg_any_inbound(rows):
    out = []
    for r in rows:
        port = str(r.get("destPort") or "")
        sev_note = ("ALL ports" if port == "*"
                    else "management/database port" if port in _MGMT_PORTS
                    else f"port {port}")
        out.append(_e(r, "Network Security Group", confirmed=True,
                      rule=r.get("ruleName"), port=port,
                      note=f"inbound Allow from any source on {sev_note}"))
    return out


@arg_rule(id="ARG-NET-002", title="Public IP address is associated to a resource",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="public_ips", best_practice=True,
          description="A public IP address is attached to a resource, giving it a directly internet-routable address. This is sometimes required, but each associated public IP is an internet-facing entry point that should be justified and protected by an NSG / firewall.",
          remediation="Confirm each associated public IP is required. Prefer private endpoints, load balancers, or a gateway; ensure any exposed resource sits behind a restrictive NSG.",
          frameworks={"Best Practice": "Minimise public exposure"},
          detail={
              "summary": "A resource has a directly internet-routable public IP.",
              "why": "Every associated public IP is an internet-facing entry point. Unneeded public IPs expand the external attack surface and are easy to forget once a workload changes.",
              "scenario": "A resource retains a public IP after its need has passed; an attacker reaches it directly and probes the exposed services.",
              "impact": "Expanded internet-facing attack surface.",
              "steps": [
                  "Inventory associated public IPs and confirm each is required.",
                  "Remove or replace unneeded public IPs with private connectivity.",
                  "Ensure every exposed resource is behind a restrictive NSG or firewall.",
              ],
              "detection": "Azure Resource Graph over publicipaddresses with a non-null ipConfiguration.",
          })
def public_ip_associated(rows):
    return [_e(r, "Public IP Address", confirmed=True, ipAddress=r.get("ipAddress"),
               note="associated to a resource, internet-routable")
            for r in rows if r.get("associated")]


@arg_rule(id="ARG-NET-003", title="Subscription has no Azure Bastion host", best_practice=True,
          severity=Severity.LOW, category=Category.COMPUTE, query_key="bastion_hosts_missing",
          description="A subscription has no Azure Bastion host. Without a managed Bastion broker, administrative RDP/SSH to VMs tends to be reached by exposing those ports to the network directly, which is the far riskier path.",
          remediation="Deploy an Azure Bastion host and reach VM RDP/SSH through it, so management ports need never be exposed to the internet or the broader network.",
          frameworks={"CIS Azure": "8.1", "MITRE ATT&CK": "T1021", "Azure Threat Matrix": "AZT301"},
          detail={
              "summary": "No Azure Bastion host exists in the subscription.",
              "why": "Bastion provides brokered, audited RDP/SSH over TLS without a public IP on the VM. Without it, operators commonly open management ports directly, placing the VM's RDP/SSH on the network for anyone to reach.",
              "scenario": "With no Bastion, an admin opens RDP to a VM over a public IP; an attacker finds the open port and brute-forces or exploits it.",
              "impact": "Encourages direct exposure of VM management ports.",
              "steps": ["Deploy an Azure Bastion host in the hub / management VNet.",
                        "Reach VM RDP/SSH through Bastion only.",
                        "Remove any public IPs and NSG rules that expose management ports."],
              "detection": "Azure Resource Graph: subscriptions with no microsoft.network/bastionHosts resource.",
          })
def no_bastion_host(rows):
    # The KQL left-join already resolved absence, so every returned row is a subscription with
    # zero Bastion hosts; the query returns nothing when every subscription has one.
    return [_e(r, "Subscription", confirmed=True,
               note="no Azure Bastion host in this subscription")
            for r in rows]


# =========================================================================== #
# Data services
# =========================================================================== #
@arg_rule(id="ARG-SQL-001", title="SQL server allows public network access",
          severity=Severity.HIGH, category=Category.STORAGE, query_key="sql_servers",
          description="An Azure SQL logical server has publicNetworkAccess enabled, so its endpoint is reachable from the public internet (subject to firewall rules). Combined with a permissive firewall this exposes the database directly to the internet.",
          remediation="Set publicNetworkAccess=Disabled and connect via a Private Endpoint, or restrict the server firewall to specific IP ranges / VNets.",
          frameworks={"CIS Azure": "4.x", "MITRE ATT&CK": "T1190", "Azure Threat Matrix": "AZT103"},
          detail={
              "summary": "An Azure SQL server is reachable over the public internet.",
              "why": "Public network access puts the database endpoint on the internet. With any permissive firewall rule an attacker can reach it directly and attempt credential attacks or exploit known SQL surface, with no need for a network foothold.",
              "scenario": "An attacker finds the public SQL endpoint, and with an open or weak firewall rule attempts credential spraying or exploitation against the database.",
              "impact": "Direct internet exposure of a database and its data.",
              "steps": [
                  "Set publicNetworkAccess=Disabled.",
                  "Use a Private Endpoint for application access.",
                  "If public access is unavoidable, restrict the firewall to specific IPs/VNets and enable Entra-only auth.",
              ],
              "detection": "Azure Resource Graph over microsoft.sql/servers for properties.publicNetworkAccess == 'Enabled'.",
          })
def sql_public_access(rows):
    out = []
    for r in rows:
        v = r.get("publicNetworkAccess")
        if _enabled(v):
            out.append(_e(r, "SQL Server", confirmed=True, publicNetworkAccess=v,
                          note="public network access enabled"))
        elif v is None:
            out.append(_e(r, "SQL Server", confirmed=False, publicNetworkAccess="not returned",
                          note="publicNetworkAccess not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-SQL-002", title="SQL server accepts a weak minimum TLS version",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="sql_servers",
          description="An Azure SQL server's minimalTlsVersion permits TLS below 1.2, allowing deprecated, weak transport encryption for database connections.",
          remediation="Set the server minimalTlsVersion to 1.2.",
          frameworks={"CIS Azure": "4.x", "MITRE ATT&CK": "T1040"},
          detail={
              "summary": "An Azure SQL server allows TLS below 1.2.",
              "why": "TLS 1.0/1.1 carry known weaknesses; permitting them lets a network attacker downgrade a database connection and attack its confidentiality, including the credentials exchanged.",
              "scenario": "An on-path attacker forces a weak TLS session to the database and attacks the cipher to recover connection contents.",
              "impact": "Weakened transport security for database traffic and credentials.",
              "steps": ["Set minimalTlsVersion=1.2 on every SQL server.",
                        "Confirm clients support TLS 1.2 before enforcing."],
              "detection": "Azure Resource Graph over microsoft.sql/servers for properties.minimalTlsVersion below '1.2'.",
          })
def sql_weak_tls(rows):
    out = []
    for r in rows:
        v = r.get("minimalTlsVersion")
        if isinstance(v, str) and v.strip() in ("1.0", "1.1"):
            out.append(_e(r, "SQL Server", confirmed=True, minimalTlsVersion=v,
                          note=f"minimum TLS {v}, below 1.2"))
    return out


@arg_rule(id="ARG-SQL-003", title="SQL server firewall allows the entire internet",
          severity=Severity.CRITICAL, category=Category.STORAGE, query_key="sql_firewall_allow_all",
          description="A SQL server firewall rule spans 0.0.0.0 to 255.255.255.255, the entire IPv4 internet. Every host on the internet can reach the database endpoint; only credentials stand between an attacker and the data.",
          remediation="Delete the allow-all firewall rule immediately. Restrict to specific IP ranges/VNets and prefer a Private Endpoint.",
          frameworks={"CIS Azure": "4.x", "MITRE ATT&CK": "T1190", "Azure Threat Matrix": "AZT103"},
          detail={
              "summary": "A SQL server firewall rule allows the entire internet (0.0.0.0-255.255.255.255).",
              "why": "This is the maximally-permissive firewall rule: the database is reachable from every internet host. It is a frequent cause of database breaches, as only credential strength remains as a control.",
              "scenario": "An attacker discovers the public SQL endpoint and, because the firewall allows all addresses, attempts credential spraying or exploitation from anywhere.",
              "impact": "The database is exposed to the entire internet.",
              "steps": ["Delete the 0.0.0.0-255.255.255.255 firewall rule now.",
                        "Restrict to specific IPs/VNets and use a Private Endpoint.",
                        "Enable Entra-only authentication and auditing."],
              "detection": "Azure Resource Graph over microsoft.sql/servers/firewallrules for start 0.0.0.0 and end 255.255.255.255.",
          })
def sql_firewall_allow_all(rows):
    return [_e(r, "SQL Firewall Rule", confirmed=True,
               note="firewall rule allows the entire internet (0.0.0.0-255.255.255.255)")
            for r in rows]


@arg_rule(id="ARG-COSMOS-001", title="Cosmos DB account allows public network access",
          severity=Severity.HIGH, category=Category.STORAGE, query_key="cosmos_accounts",
          description="A Cosmos DB account has publicNetworkAccess enabled, exposing its endpoint to the public internet subject to IP rules.",
          remediation="Set publicNetworkAccess=Disabled and use a Private Endpoint, or restrict with IP rules and disable local (key) auth.",
          frameworks={"CIS Azure": "4.x", "MITRE ATT&CK": "T1190", "Azure Threat Matrix": "AZT103"},
          detail={
              "summary": "A Cosmos DB account is reachable over the public internet.",
              "why": "Public network access exposes the Cosmos endpoint to the internet; combined with key-based auth still enabled, a leaked key is usable from anywhere.",
              "scenario": "An attacker with a leaked Cosmos key (from source control or a captured request) reaches the public endpoint and reads or writes data directly.",
              "impact": "Internet exposure of a NoSQL data store.",
              "steps": ["Set publicNetworkAccess=Disabled and use a Private Endpoint.",
                        "Restrict IP rules if public access is required.",
                        "Disable local auth and use Entra RBAC."],
              "detection": "Azure Resource Graph over microsoft.documentdb/databaseaccounts for properties.publicNetworkAccess == 'Enabled'.",
          })
def cosmos_public_access(rows):
    out = []
    for r in rows:
        v = r.get("publicNetworkAccess")
        if _enabled(v):
            out.append(_e(r, "Cosmos DB Account", confirmed=True, publicNetworkAccess=v,
                          note="public network access enabled"))
        elif v is None:
            out.append(_e(r, "Cosmos DB Account", confirmed=False, publicNetworkAccess="not returned",
                          note="publicNetworkAccess not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-COSMOS-002", title="Cosmos DB account allows key-based (local) authentication",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="cosmos_accounts",
          description="A Cosmos DB account has not disabled local authentication, so primary/secondary keys grant full data access. Keys bypass Entra identity, cannot be scoped per-user, and are frequently leaked in application config.",
          remediation="Set disableLocalAuth=true and use Entra RBAC data-plane roles for access.",
          frameworks={"CIS Azure": "4.x", "MITRE ATT&CK": "T1552.001"},
          detail={
              "summary": "A Cosmos DB account still permits access via account keys.",
              "why": "Account keys are all-or-nothing, unscoped, and hard to rotate; a single leaked key exposes the whole account. Disabling local auth forces Entra RBAC, which is scoped and audited.",
              "scenario": "A Cosmos key leaks in a config file or repository; because local auth is enabled, the key grants full data access with no per-user scoping.",
              "impact": "A single leaked key exposes all data in the account.",
              "steps": ["Set disableLocalAuth=true.",
                        "Grant access through Entra RBAC data-plane roles.",
                        "Rotate existing keys after migrating clients."],
              "detection": "Azure Resource Graph over microsoft.documentdb/databaseaccounts for properties.disableLocalAuth != true.",
          })
def cosmos_local_auth(rows):
    out = []
    for r in rows:
        v = r.get("disableLocalAuth")
        if v is False:
            out.append(_e(r, "Cosmos DB Account", confirmed=True, disableLocalAuth=False,
                          note="key-based (local) authentication is enabled"))
        elif v is None:
            # Null is the insecure DEFAULT (local auth enabled) AND the value Azure returns when the
            # flag was never set, so a missing value is surfaced UNCONFIRMED, never a silent pass.
            out.append(_e(r, "Cosmos DB Account", confirmed=False, disableLocalAuth="not returned",
                          note="disableLocalAuth not returned by Resource Graph (default is enabled), UNCONFIRMED"))
    return out


@arg_rule(id="ARG-COSMOS-003", title="Cosmos DB account has no private endpoint", best_practice=True,
          severity=Severity.LOW, category=Category.STORAGE, query_key="cosmos_accounts",
          description="A Cosmos DB account has no Private Endpoint connection, so its data endpoint is reached over a public or service endpoint rather than a private link. A private endpoint keeps data-plane traffic on the backbone network and off the public internet.",
          remediation="Add a Private Endpoint for the Cosmos DB account and set publicNetworkAccess=Disabled so the data plane is reachable only over private connectivity.",
          frameworks={"CIS Azure": "5.4.2", "MITRE ATT&CK": "T1530"},
          detail={
              "summary": "A Cosmos DB account is not fronted by a private endpoint.",
              "why": "Without a private endpoint the account endpoint is served publicly; private endpoints confine data-plane traffic to the VNet/backbone and remove the public attack surface even when a key leaks.",
              "scenario": "An attacker with a leaked connection string reaches the account over its public endpoint; a private endpoint plus disabled public access would have blocked that reach.",
              "impact": "Data-plane reachable without private connectivity.",
              "steps": ["Create a Private Endpoint for the Cosmos DB account.",
                        "Set publicNetworkAccess=Disabled once clients use the private endpoint.",
                        "Disable local auth and use Entra RBAC."],
              "detection": "Azure Resource Graph over microsoft.documentdb/databaseaccounts for an empty properties.privateEndpointConnections.",
          })
def cosmos_no_private_endpoint(rows):
    out = []
    for r in rows:
        pe = r.get("privateEndpointConnections")
        if isinstance(pe, list) and len(pe) == 0:
            out.append(_e(r, "Cosmos DB Account", confirmed=True, privateEndpointConnections=0,
                          note="no private endpoint connection"))
        elif pe is None:
            out.append(_e(r, "Cosmos DB Account", confirmed=False, privateEndpointConnections="not returned",
                          note="privateEndpointConnections not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-PG-001", title="PostgreSQL flexible server allows public network access",
          severity=Severity.HIGH, category=Category.STORAGE, query_key="postgres_flexible",
          description="A PostgreSQL flexible server has public network access enabled, exposing the database endpoint to the internet.",
          remediation="Switch the server to private access (VNet integration) or disable public network access and use a Private Endpoint.",
          frameworks={"CIS Azure": "4.x", "MITRE ATT&CK": "T1190", "Azure Threat Matrix": "AZT103"},
          detail={
              "summary": "A PostgreSQL flexible server is reachable over the public internet.",
              "why": "Public network access exposes the PostgreSQL endpoint to internet-wide credential attacks and exploitation of the database surface.",
              "scenario": "An attacker finds the public PostgreSQL endpoint and attempts credential spraying or exploitation directly.",
              "impact": "Direct internet exposure of a relational database.",
              "steps": ["Move the server to VNet-integrated private access.",
                        "Or disable public network access and use a Private Endpoint.",
                        "Restrict firewall rules and enforce SSL."],
              "detection": "Azure Resource Graph over microsoft.dbforpostgresql/flexibleservers for properties.network.publicNetworkAccess == 'Enabled'.",
          })
def postgres_public_access(rows):
    out = []
    for r in rows:
        v = r.get("publicNetworkAccess")
        if _enabled(v):
            out.append(_e(r, "PostgreSQL Server", confirmed=True, publicNetworkAccess=v,
                          note="public network access enabled"))
        elif v is None:
            out.append(_e(r, "PostgreSQL Server", confirmed=False, publicNetworkAccess="not returned",
                          note="network.publicNetworkAccess not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-MYSQL-001", title="MySQL flexible server allows public network access",
          severity=Severity.HIGH, category=Category.STORAGE, query_key="mysql_flexible",
          description="A MySQL flexible server has public network access enabled, exposing the database endpoint to the internet.",
          remediation="Switch the server to private access (VNet integration) or disable public network access and use a Private Endpoint.",
          frameworks={"CIS Azure": "4.x", "MITRE ATT&CK": "T1190", "Azure Threat Matrix": "AZT103"},
          detail={
              "summary": "A MySQL flexible server is reachable over the public internet.",
              "why": "Public network access exposes the MySQL endpoint to internet-wide credential attacks and exploitation of the database surface.",
              "scenario": "An attacker finds the public MySQL endpoint and attempts credential spraying or exploitation directly.",
              "impact": "Direct internet exposure of a relational database.",
              "steps": ["Move the server to VNet-integrated private access.",
                        "Or disable public network access and use a Private Endpoint.",
                        "Restrict firewall rules and enforce SSL."],
              "detection": "Azure Resource Graph over microsoft.dbformysql/flexibleservers for properties.network.publicNetworkAccess == 'Enabled'.",
          })
def mysql_public_access(rows):
    out = []
    for r in rows:
        v = r.get("publicNetworkAccess")
        if _enabled(v):
            out.append(_e(r, "MySQL Server", confirmed=True, publicNetworkAccess=v,
                          note="public network access enabled"))
        elif v is None:
            out.append(_e(r, "MySQL Server", confirmed=False, publicNetworkAccess="not returned",
                          note="network.publicNetworkAccess not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-DEFENDER-001", title="Microsoft Defender for Cloud plan is on the Free tier",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="defender_pricings",
          description="A Microsoft Defender for Cloud plan is set to the Free tier, so the enhanced threat protection, vulnerability assessment and detection for that resource type are not active. Workloads of that type run without Defender's runtime protection and alerting.",
          remediation="Enable the Standard tier of Microsoft Defender for Cloud for the affected resource types (at minimum Servers, Storage, SQL, Containers, Key Vault).",
          frameworks={"CIS Azure": "2.x", "Best Practice": "Threat protection"},
          detail={
              "summary": "A Defender for Cloud plan is on the Free tier (enhanced protection off).",
              "why": "The Free tier provides only basic recommendations; it lacks the behavioural threat detection, vulnerability assessment and alerting that catch active attacks against that resource type. Blind spots here mean an in-progress compromise is far less likely to be detected.",
              "scenario": "An attacker compromises a resource whose Defender plan is Free; the malicious activity generates no Defender alert, extending dwell time.",
              "impact": "Reduced detection of active threats against the affected resource type.",
              "steps": ["Enable Defender for Cloud Standard for the resource types in use.",
                        "Prioritise Servers, Storage, SQL, Containers and Key Vault.",
                        "Route Defender alerts to your SIEM / on-call."],
              "detection": "Azure Resource Graph over microsoft.security/pricings for properties.pricingTier == 'Free'.",
          })
def defender_free_tier(rows):
    out = []
    for r in rows:
        tier = r.get("pricingTier")
        if isinstance(tier, str) and tier.strip().lower() == "free":
            out.append(_e(r, "Defender Plan", confirmed=True, pricingTier=tier,
                          note=f"Defender plan '{r.get('name')}' is on the Free tier"))
    return out


@arg_rule(id="ARG-DEFENDER-002", title="Defender for Cloud agent auto-provisioning is disabled",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="defender_autoprovisioning",
          best_practice=True,
          description="Microsoft Defender for Cloud auto-provisioning is Off for a subscription, so the monitoring agent is not deployed automatically to new resources. Those resources are onboarded to Defender late, or not at all, leaving coverage gaps.",
          remediation="Enable auto-provisioning of the monitoring agent (Defender for Cloud > Environment settings > Auto provisioning) so new resources are covered as they are created.",
          frameworks={"CIS Azure": "2.3", "Best Practice": "Threat protection"},
          detail={
              "summary": "Defender for Cloud auto-provisioning is Off (agents not deployed automatically).",
              "why": "Without auto-provisioning, new VMs and resources are not automatically onboarded to Defender, so their telemetry, vulnerability assessment and detections are missing until an operator onboards them by hand.",
              "scenario": "A new VM is created and compromised before anyone manually onboards it to Defender; the activity produces no Defender alert.",
              "impact": "Delayed or absent threat detection on newly created resources.",
              "steps": ["Enable auto-provisioning of the Log Analytics / Azure Monitor agent.",
                        "Confirm the setting across every subscription."],
              "detection": "Azure Resource Graph over microsoft.security/autoProvisioningSettings for properties.autoProvision == 'Off'.",
          })
def defender_autoprovisioning_off(rows):
    out = []
    for r in rows:
        ap = r.get("autoProvision")
        if isinstance(ap, str) and ap.strip().lower() == "off":
            out.append(_e(r, "Subscription", confirmed=True, autoProvision=ap,
                          note="Defender for Cloud auto-provisioning is Off"))
    return out


@arg_rule(id="ARG-DEFENDER-003", title="Subscription has no Defender for Cloud security contact configured",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="defender_security_contacts_missing",
          best_practice=True,
          description="A subscription has no Microsoft Defender for Cloud security contact, so Defender alert and attack notifications have no destination. A high-severity alert can be raised with nobody notified.",
          remediation="Configure a security contact email and enable alert notifications in Microsoft Defender for Cloud (Environment settings > Email notifications) for every subscription.",
          frameworks={"CIS Azure": "2.4", "Best Practice": "Threat protection"},
          detail={
              "summary": "No Defender for Cloud security contact / alert notification is configured for the subscription.",
              "why": "Defender detects threats, but if no security contact receives its alerts a high-severity detection can go unseen. Timely notification is what turns a detection into a response.",
              "scenario": "Defender raises a high-severity alert for an in-progress attack, but with no contact configured nobody is paged and the attacker continues uninterrupted.",
              "impact": "Defender alerts for active attacks may reach no one.",
              "steps": ["Add a security contact email for the subscription.",
                        "Enable notifications for high-severity alerts and for attack notifications.",
                        "Route to a monitored distribution list or on-call, not a single person."],
              "detection": "Azure Resource Graph: subscriptions (resourcecontainers) with no microsoft.security/securityContacts resource.",
          })
def defender_no_security_contact(rows):
    # Each row is already a subscription with zero security contacts (the KQL left-join resolved the
    # absence), so every returned row is a finding; the query returns nothing when all are covered.
    return [_e(r, "Subscription", confirmed=True,
               note="No Defender for Cloud security contact configured for this subscription")
            for r in rows]


# --- Defender for Cloud per-plan components (sub-extensions of a Standard plan) --------------
def _defender_extension_off(rows, ext_name: str, label: str):
    """Flag a named Defender component (`properties.extensions[].name`) that is explicitly
    isEnabled=False on a plan that is ON the Standard tier. Confirmed-only: an absent extension or
    a Free-tier plan is never flagged here (the Free plan itself is ARG-DEFENDER-001), so this can
    never produce a false finding from an extension the API simply did not return."""
    out = []
    for r in rows:
        exts = r.get("extensions")
        if not isinstance(exts, list):
            continue
        if str(r.get("pricingTier") or "").lower() != "standard":
            continue
        for e in exts:
            if not isinstance(e, dict) or str(e.get("name") or "").lower() != ext_name.lower():
                continue
            if e.get("isEnabled") is False:
                out.append(_e(r, "Defender Plan", confirmed=True, extension=ext_name,
                              plan=r.get("name"),
                              note=f"Defender component '{label}' is disabled on the '{r.get('name')}' plan"))
    return out


def _defender_component_detail(label: str, plan: str) -> dict:
    return {
        "summary": f"The Defender component '{label}' is off on a Standard {plan} plan.",
        "why": f"The {plan} plan is on the Standard tier but its '{label}' component is disabled, so that specific detection / assessment capability is not running even though the plan is paid for. The protection is partial, not the full Standard coverage.",
        "scenario": f"An attacker operates in the blind spot the disabled '{label}' component would have covered; the plan is on but this detection never fires.",
        "impact": f"A Standard Defender plan runs without its '{label}' capability.",
        "steps": [f"Enable the '{label}' component on the {plan} Defender plan.",
                  "Confirm every subscription enables the component.",
                  "Enforce component state with Azure Policy."],
        "detection": "Azure Resource Graph over microsoft.security/pricings for an extensions[] entry with isEnabled == false on a Standard-tier plan.",
    }


@arg_rule(id="ARG-DEFENDER-004", title="Defender for Servers endpoint-protection (MDE) component is off",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="defender_pricings", best_practice=True,
          description="Microsoft Defender for Servers is on the Standard tier but its Microsoft Defender for Endpoint (MdeDesignatedSubscription) integration component is disabled, so endpoint detection and response is not deployed to the covered machines.",
          remediation="Enable the Microsoft Defender for Endpoint integration component on the Defender for Servers plan.",
          frameworks={"CIS Azure": "3.1.3.3", "Best Practice": "Threat protection"},
          detail=_defender_component_detail("endpoint protection (MDE)", "Defender for Servers"))
def defender_endpoint_protection_off(rows):
    return _defender_extension_off(rows, "MdeDesignatedSubscription", "endpoint protection (MDE)")


@arg_rule(id="ARG-DEFENDER-005", title="Defender for Servers agentless scanning component is off",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="defender_pricings", best_practice=True,
          description="Microsoft Defender for Servers is on the Standard tier but its agentless scanning for machines (AgentlessVmScanning) component is disabled, so agentless vulnerability and malware scanning of the machines is not running.",
          remediation="Enable the agentless scanning for machines component on the Defender for Servers plan.",
          frameworks={"CIS Azure": "3.1.3.4", "Best Practice": "Threat protection"},
          detail=_defender_component_detail("agentless scanning for machines", "Defender for Servers"))
def defender_agentless_scanning_off(rows):
    return _defender_extension_off(rows, "AgentlessVmScanning", "agentless scanning for machines")


@arg_rule(id="ARG-DEFENDER-006", title="Defender for Servers file-integrity-monitoring component is off",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="defender_pricings", best_practice=True,
          description="A Standard-tier Defender plan has its File Integrity Monitoring (FileIntegrityMonitoring) component disabled, so changes to critical operating-system and application files are not being watched.",
          remediation="Enable the File Integrity Monitoring component on the Defender plan that offers it.",
          frameworks={"CIS Azure": "3.1.3.5", "Best Practice": "Threat protection"},
          detail=_defender_component_detail("file integrity monitoring", "Defender for Servers"))
def defender_fim_off(rows):
    return _defender_extension_off(rows, "FileIntegrityMonitoring", "file integrity monitoring")


@arg_rule(id="ARG-DEFENDER-007", title="Defender for Containers agentless Kubernetes discovery is off",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="defender_pricings", best_practice=True,
          description="Microsoft Defender for Containers is on the Standard tier but its agentless discovery for Kubernetes (AgentlessDiscoveryForKubernetes) component is disabled, so the Kubernetes control-plane posture is not being assessed agentlessly.",
          remediation="Enable the agentless discovery for Kubernetes component on the Defender for Containers plan.",
          frameworks={"CIS Azure": "3.1.4.2", "Best Practice": "Threat protection"},
          detail=_defender_component_detail("agentless discovery for Kubernetes", "Defender for Containers"))
def defender_agentless_k8s_off(rows):
    return _defender_extension_off(rows, "AgentlessDiscoveryForKubernetes", "agentless discovery for Kubernetes")


@arg_rule(id="ARG-DEFENDER-008", title="Defender for Containers registry vulnerability assessment is off",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="defender_pricings", best_practice=True,
          description="Microsoft Defender for Containers is on the Standard tier but its agentless container-registry vulnerability assessment (ContainerRegistriesVulnerabilityAssessments) component is disabled, so pushed container images are not scanned for known vulnerabilities.",
          remediation="Enable the agentless container vulnerability assessment component on the Defender for Containers plan.",
          frameworks={"CIS Azure": "3.1.4.3", "Best Practice": "Threat protection"},
          detail=_defender_component_detail("agentless container vulnerability assessment", "Defender for Containers"))
def defender_container_vuln_off(rows):
    return _defender_extension_off(rows, "ContainerRegistriesVulnerabilityAssessments",
                                   "agentless container vulnerability assessment")


# =========================================================================== #
# App Service configuration
# =========================================================================== #
@arg_rule(id="ARG-APP-001", title="App Service does not enforce HTTPS-only",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="app_services_config",
          description="A Web/Function App has httpsOnly disabled, so it answers plaintext HTTP. Requests, cookies and any bearer tokens can be captured or replayed by a network attacker.",
          remediation="Set httpsOnly=true on every App Service and Function App.",
          frameworks={"CIS Azure": "9.x", "MITRE ATT&CK": "T1040"},
          detail={
              "summary": "An App Service serves plaintext HTTP (httpsOnly is off).",
              "why": "Without HTTPS-only, traffic, including auth cookies and tokens, can traverse the network unencrypted and be captured or replayed.",
              "scenario": "An attacker on the network captures a plaintext request to the app and replays its session token.",
              "impact": "Disclosure of session tokens and data in transit.",
              "steps": ["Set httpsOnly=true.",
                        "Redirect HTTP to HTTPS and enable HSTS.",
                        "Enforce with Azure Policy."],
              "detection": "Azure Resource Graph over microsoft.web/sites for properties.httpsOnly == false.",
          })
def appservice_no_https(rows):
    out = []
    for r in rows:
        v = r.get("httpsOnly")
        if v is False:
            out.append(_e(r, "App Service", confirmed=True, httpsOnly=False,
                          note="HTTPS-only not enforced, serves plaintext HTTP"))
        elif v is None:
            out.append(_e(r, "App Service", confirmed=False, httpsOnly="not returned",
                          note="httpsOnly not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-APP-002", title="App Service accepts a weak minimum TLS version",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="app_services_config",
          description="A Web/Function App's siteConfig.minTlsVersion permits TLS below 1.2.",
          remediation="Set the app's minTlsVersion to 1.2.",
          frameworks={"CIS Azure": "9.x", "MITRE ATT&CK": "T1040"},
          detail={
              "summary": "An App Service allows TLS below 1.2.",
              "why": "Deprecated TLS versions let a network attacker downgrade the connection and attack its confidentiality.",
              "scenario": "An on-path attacker forces a weak TLS session to the app and attacks the cipher.",
              "impact": "Weakened transport security for the application.",
              "steps": ["Set minTlsVersion=1.2 on the app.", "Confirm clients support TLS 1.2."],
              "detection": "Azure Resource Graph over microsoft.web/sites for properties.siteConfig.minTlsVersion below '1.2'.",
          })
def appservice_weak_tls(rows):
    out = []
    for r in rows:
        v = r.get("minTlsVersion")
        if isinstance(v, str) and v.strip() in ("1.0", "1.1"):
            out.append(_e(r, "App Service", confirmed=True, minTlsVersion=v,
                          note=f"minimum TLS {v}, below 1.2"))
    return out


@arg_rule(id="ARG-APP-003", title="App Service allows plaintext FTP deployment",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="app_services_config",
          description="A Web/Function App's ftpsState is 'AllAllowed', so code can be deployed over plaintext FTP. FTP credentials and content cross the network unencrypted and can be captured to tamper with the deployed application.",
          remediation="Set ftpsState to 'FtpsOnly' or 'Disabled' on every App Service.",
          frameworks={"CIS Azure": "9.x", "MITRE ATT&CK": "T1040"},
          detail={
              "summary": "An App Service permits plaintext FTP deployment.",
              "why": "Plaintext FTP exposes deployment credentials and the application content to network capture; an attacker who captures them can deploy malicious code to the app.",
              "scenario": "An attacker on the network captures the plaintext FTP publish credentials and deploys a web shell or backdoor into the running app.",
              "impact": "Deployment-credential theft and application tampering.",
              "steps": ["Set ftpsState=FtpsOnly (or Disabled if FTP is unused).",
                        "Prefer deployment via CI/CD with managed identity over FTP."],
              "detection": "Azure Resource Graph over microsoft.web/sites for properties.siteConfig.ftpsState == 'AllAllowed'.",
          })
def appservice_ftp(rows):
    out = []
    for r in rows:
        v = r.get("ftpsState")
        if isinstance(v, str) and v.strip().lower() == "allallowed":
            out.append(_e(r, "App Service", confirmed=True, ftpsState=v,
                          note="plaintext FTP deployment allowed (ftpsState=AllAllowed)"))
    return out


@arg_rule(id="ARG-SQL-004", title="SQL server auditing is not enabled",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="sql_auditing",
          description="An Azure SQL server's auditing state is not Enabled. Without auditing there is no record of database access and administrative actions, so a data breach or malicious query leaves no trail for detection or forensics.",
          remediation="Enable auditing on the SQL server (to a Log Analytics workspace or storage account) and alert on anomalous access.",
          frameworks={"CIS Azure": "4.1.1", "MITRE ATT&CK": "T1562.008"},
          detail={
              "summary": "Azure SQL auditing is disabled.",
              "why": "Auditing is the record of who accessed the database and what they did. Without it, an attacker's queries and exfiltration are invisible, and there is no forensic trail after an incident.",
              "scenario": "An attacker with database access reads sensitive tables; with auditing off, the access produces no log and goes undetected.",
              "impact": "No detection or forensic record of database access and administrative actions.",
              "steps": ["Enable server-level auditing to Log Analytics or a storage account.",
                        "Set retention appropriately and alert on anomalous access.",
                        "Enforce auditing tenant-wide with Azure Policy."],
              "detection": "Azure Resource Graph over microsoft.sql/servers/auditingsettings for properties.state != 'Enabled'.",
          })
def sql_auditing_off(rows):
    out = []
    for r in rows:
        v = r.get("state")
        if isinstance(v, str) and v.strip().lower() != "enabled":
            out.append(_e(r, "SQL Server Auditing", confirmed=True, state=v,
                          note=f"auditing state is '{v}', not Enabled"))
    return out


@arg_rule(id="ARG-SQL-005", title="SQL database transparent data encryption is not enabled",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="sql_tde_databases",
          description="An Azure SQL database has Transparent Data Encryption (TDE) disabled, so the database files, backups and transaction logs are stored unencrypted at rest. Anyone who obtains the underlying storage can read the data directly.",
          remediation="Enable Transparent Data Encryption on the SQL database (it is on by default for new databases).",
          frameworks={"CIS Azure": "5.1.5", "MITRE ATT&CK": "T1530"},
          detail={
              "summary": "A SQL database is not encrypted at rest (TDE off).",
              "why": "TDE encrypts the database at rest; with it off, the data files and backups are plaintext, so a copy of the storage or a stolen backup exposes all data without needing the database credentials.",
              "scenario": "An attacker obtains a database backup or the underlying storage; because TDE is off, the data is readable directly.",
              "impact": "Database data at rest is unencrypted.",
              "steps": ["Enable Transparent Data Encryption on the database.",
                        "Confirm TDE is on for every user database.",
                        "Enforce with Azure Policy."],
              "detection": "Azure Resource Graph over microsoft.sql/servers/databases/transparentdataencryption for properties.state != 'Enabled'.",
          })
def sql_tde_off(rows):
    out = []
    for r in rows:
        # The system 'master' database's TDE is platform-managed and not user-configurable; exclude
        # it so a posture report is about the user databases the control actually targets.
        if "/databases/master/" in str(r.get("id") or "").lower():
            continue
        v = r.get("state")
        if isinstance(v, str) and v.strip().lower() != "enabled":
            out.append(_e(r, "SQL Database", confirmed=True, state=v,
                          note=f"transparent data encryption is '{v}', not Enabled"))
    return out


@arg_rule(id="ARG-SQL-006", title="SQL TDE protector is not a customer-managed key", best_practice=True,
          severity=Severity.LOW, category=Category.STORAGE, query_key="sql_tde_protector",
          description="An Azure SQL server's Transparent Data Encryption protector uses a service-managed key rather than a customer-managed key (CMK / BYOK) in Key Vault. A customer-managed protector lets the organisation control, rotate and revoke the key that protects the database encryption.",
          remediation="Configure the SQL server's TDE protector to use a customer-managed key stored in Azure Key Vault.",
          frameworks={"CIS Azure": "5.1.3", "Best Practice": "Encryption key management"},
          detail={
              "summary": "A SQL server's TDE protector is a service-managed key, not a CMK.",
              "why": "With a service-managed protector the organisation cannot independently rotate or revoke the key that protects the database at rest. A customer-managed key in Key Vault gives control and the ability to cut access by revoking the key.",
              "scenario": "A compliance or incident-response requirement needs the encryption key revoked or rotated independently; with a service-managed protector that control does not exist.",
              "impact": "No independent control over the database encryption key.",
              "steps": ["Create or designate a key in Azure Key Vault.",
                        "Set the SQL server TDE protector to that customer-managed key.",
                        "Enable key rotation and guard the vault with RBAC and soft-delete/purge protection."],
              "detection": "Azure Resource Graph over microsoft.sql/servers/encryptionprotector for properties.serverKeyType == 'ServiceManaged'.",
          })
def sql_tde_protector_not_cmk(rows):
    out = []
    for r in rows:
        v = r.get("serverKeyType")
        if isinstance(v, str) and v.strip().lower() == "servicemanaged":
            out.append(_e(r, "SQL Server", confirmed=True, serverKeyType=v,
                          note="TDE protector is a service-managed key (not a customer-managed key)"))
    return out


@arg_rule(id="ARG-SQL-007", title="SQL server has no Microsoft Entra administrator",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="sql_entra_admin_missing",
          description="An Azure SQL server has no Microsoft Entra administrator configured, so it can only be administered with SQL authentication (username/password). Entra administration enables centralized identity, MFA and Conditional Access for database access.",
          remediation="Configure a Microsoft Entra administrator on the SQL server and prefer Entra authentication over SQL logins.",
          frameworks={"CIS Azure": "5.1.4", "MITRE ATT&CK": "T1078"},
          detail={
              "summary": "A SQL server has no Microsoft Entra administrator set.",
              "why": "Without an Entra administrator the server relies on SQL logins, which are local, unfederated credentials with no MFA or Conditional Access. Entra administration brings database access under central identity governance.",
              "scenario": "A SQL login leaks; because Entra administration is not configured, there is no MFA or Conditional Access in front of the database and the login works directly.",
              "impact": "Database administration relies on unfederated SQL logins.",
              "steps": ["Set a Microsoft Entra administrator (a group, ideally) on the SQL server.",
                        "Prefer Entra authentication and disable or minimise SQL logins.",
                        "Consider Entra-only authentication where supported."],
              "detection": "Azure Resource Graph: microsoft.sql/servers with no microsoft.sql/servers/administrators child resource.",
          })
def sql_no_entra_admin(rows):
    # The KQL left-join already resolved absence, so every returned row is a server with no Entra
    # administrator; the query returns nothing when every server has one.
    return [_e(r, "SQL Server", confirmed=True, note="no Microsoft Entra administrator configured")
            for r in rows]


@arg_rule(id="ARG-SQL-008", title="SQL audit log retention is 90 days or less", best_practice=True,
          severity=Severity.LOW, category=Category.STORAGE, query_key="sql_auditing",
          description="An Azure SQL server has auditing enabled but its audit-log retention is a finite period of 90 days or less. CIS recommends greater than 90 days so an investigation that begins weeks after a breach still has the audit trail.",
          remediation="Set the SQL auditing retention to greater than 90 days, or 0 for unlimited retention.",
          frameworks={"CIS Azure": "5.1.6", "Best Practice": "Log retention"},
          detail={
              "summary": "SQL audit-log retention is 90 days or less.",
              "why": "Breaches are often discovered long after they happen. A short retention window means the audit records covering the actual intrusion have already been purged by the time anyone investigates.",
              "scenario": "A breach is discovered three months later, but the audit logs were retained for only 90 days, so the records of the intrusion are gone.",
              "impact": "Audit evidence may be purged before an investigation needs it.",
              "steps": ["Set the SQL auditing retention to greater than 90 days (or 0 for unlimited).",
                        "Ship audit logs to long-term storage or Log Analytics.",
                        "Apply the retention standard across every server."],
              "detection": "Azure Resource Graph over microsoft.sql/servers/auditingsettings for an Enabled state with a retentionDays value between 1 and 90.",
          })
def sql_short_audit_retention(rows):
    out = []
    for r in rows:
        if str(r.get("state") or "").strip().lower() != "enabled":
            continue  # only meaningful when auditing is on (ARG-SQL-004 covers the off case)
        rd = r.get("retentionDays")
        try:
            days = int(rd)
        except (TypeError, ValueError):
            continue  # retention not returned -> do not guess
        if 1 <= days <= 90:   # 0 means unlimited retention, which is compliant
            out.append(_e(r, "SQL Server Auditing", confirmed=True, retentionDays=days,
                          note=f"audit retention is {days} days (<= 90)"))
    return out


# --- PostgreSQL / MySQL flexible-server parameters (CIS 5.2.x / 5.3.x) -----------------------
# Each rule checks one server parameter's value. A parameter the query did not return is never
# flagged (confirmed-only), so a renamed parameter can only lose coverage, never produce a false
# finding. `bad(value)` returns True when the (lower-cased) value is NON-COMPLIANT.
def _not_on(v: str) -> bool:
    return v.strip().lower() != "on"


def _retention_le_3(v: str) -> bool:
    try:
        return int(v) <= 3
    except (TypeError, ValueError):
        return False


def _mysql_weak_tls(v: str) -> bool:
    # Non-compliant when the allowed TLS set still admits a version below 1.2.
    s = v.lower()
    return "tlsv1," in s or "tlsv1.1" in s or s.strip() in ("tlsv1", "tlsv1.0")


def _lacks_connection(v: str) -> bool:
    return "connection" not in v.lower()


_DB_PARAM_RULES: tuple[tuple, ...] = (
    # (rule id, CIS id, query_key, engine, param name, label, predicate, remediation)
    ("ARG-PG-002", "5.2.1", "postgres_flex_configs", "PostgreSQL", "require_secure_transport",
     "require secure transport (SSL)", _not_on,
     "Set the 'require_secure_transport' server parameter to ON so clients must connect over SSL."),
    ("ARG-PG-003", "5.2.2", "postgres_flex_configs", "PostgreSQL", "log_checkpoints",
     "log checkpoints", _not_on,
     "Set the 'log_checkpoints' server parameter to ON."),
    ("ARG-PG-004", "5.2.3", "postgres_flex_configs", "PostgreSQL", "connection_throttle.enable",
     "connection throttling", _not_on,
     "Set the 'connection_throttle.enable' server parameter to ON to slow brute-force attempts."),
    ("ARG-PG-005", "5.2.4", "postgres_flex_configs", "PostgreSQL", "logfiles.retention_days",
     "log retention greater than 3 days", _retention_le_3,
     "Set the 'logfiles.retention_days' server parameter to a value greater than 3."),
    ("ARG-MYSQL-002", "5.3.1", "mysql_flex_configs", "MySQL", "require_secure_transport",
     "require secure transport (SSL)", _not_on,
     "Set the 'require_secure_transport' server parameter to ON so clients must connect over TLS."),
    ("ARG-MYSQL-003", "5.3.2", "mysql_flex_configs", "MySQL", "tls_version",
     "minimum TLS version 1.2", _mysql_weak_tls,
     "Set the 'tls_version' server parameter to TLSv1.2 (and TLSv1.3) only."),
    ("ARG-MYSQL-004", "5.3.3", "mysql_flex_configs", "MySQL", "audit_log_enabled",
     "audit logging enabled", _not_on,
     "Set the 'audit_log_enabled' server parameter to ON."),
    ("ARG-MYSQL-005", "5.3.4", "mysql_flex_configs", "MySQL", "audit_log_events",
     "audit logging of CONNECTION events", _lacks_connection,
     "Include CONNECTION in the 'audit_log_events' server parameter so connections are audited."),
)


def _db_param_fn(param: str, bad):
    def fn(rows):
        out = []
        for r in rows:
            if str(r.get("name") or "").strip().lower() != param.lower():
                continue
            v = r.get("value")
            if isinstance(v, str) and v != "" and bad(v):
                out.append(Entity(id=str(r.get("serverId") or r.get("id") or "?"),
                                  name=str(r.get("serverId") or r.get("id") or "?").split("/")[-1],
                                  kind="Database Server",
                                  evidence={"subscription": r.get("subscriptionId"),
                                            "resourceGroup": r.get("resourceGroup"),
                                            "parameter": param, "value": v, "confirmed": True,
                                            "note": f"server parameter '{param}' = '{v}'"}))
        return out
    return fn


def _register_db_param_rules():
    for rid, cis_id, qkey, engine, param, label, pred, remediation in _DB_PARAM_RULES:
        REGISTRY.append(ArgRule(
            id=rid, title=f"{engine} flexible server: {label} not configured",
            severity=Severity.LOW, category=Category.STORAGE, best_practice=True, query_key=qkey,
            description=(f"A {engine} flexible server does not have {label} configured correctly "
                         f"(server parameter '{param}'). This weakens the database's transport "
                         f"security or audit posture."),
            remediation=remediation,
            frameworks={"CIS Azure": cis_id, "MITRE ATT&CK": "T1562",
                        "Azure Threat Matrix": "AZT805"},
            detail={
                "summary": f"{engine} flexible server parameter '{param}' is not set as recommended.",
                "why": (f"The '{param}' parameter governs {label} on the {engine} flexible server. "
                        f"Left at a non-compliant value it weakens transport security or removes the "
                        f"audit trail the control relies on."),
                "scenario": (f"The {engine} server runs with '{param}' misconfigured; an attacker "
                             f"exploits the weaker transport or operates without being audited."),
                "impact": f"Weakened {label} on the database server.",
                "steps": [remediation,
                          "Apply the parameter across every flexible server of this engine.",
                          "Enforce the parameter value with Azure Policy."],
                "detection": (f"Azure Resource Graph over microsoft.dbfor{engine.lower()}/"
                              f"flexibleservers/configurations for name == '{param}'."),
            },
            fn=_db_param_fn(param, pred)))


_register_db_param_rules()


# =========================================================================== #
# Storage-account encryption / key / SAS / soft-delete policy (CIS 4.2/4.3/4.5/4.10/4.11)
# =========================================================================== #
@arg_rule(id="ARG-STOR-001", title="Storage account is not encrypted with a customer-managed key",
          best_practice=True, severity=Severity.LOW, category=Category.STORAGE, query_key="storage_config",
          description="A storage account encrypts data at rest with a Microsoft-managed key (keySource = Microsoft.Storage) rather than a customer-managed key (CMK) in Key Vault. A CMK lets the organisation control, rotate and revoke the key protecting the data.",
          remediation="Configure the storage account to encrypt with a customer-managed key stored in Azure Key Vault.",
          frameworks={"CIS Azure": "4.11", "Best Practice": "Encryption key management"},
          detail={"summary": "A storage account uses a platform-managed key, not a CMK.",
                  "why": "With a Microsoft-managed key the organisation cannot independently rotate or revoke the key that protects the data at rest. A customer-managed key in Key Vault gives that control, including cutting access by revoking the key.",
                  "scenario": "An incident requires revoking access to the data at rest; with a service-managed key there is no independent key to revoke.",
                  "impact": "No independent control over the storage encryption key.",
                  "steps": ["Create or designate a key in Azure Key Vault.",
                            "Set the storage account to encrypt with that customer-managed key.",
                            "Enable key rotation and protect the vault with RBAC and purge protection."],
                  "detection": "Azure Resource Graph over microsoft.storage/storageaccounts for properties.encryption.keySource == 'Microsoft.Storage'."})
def storage_not_cmk(rows):
    out = []
    for r in rows:
        v = r.get("keySource")
        if isinstance(v, str) and v.strip().lower() == "microsoft.storage":
            out.append(_e(r, "Storage Account", confirmed=True, keySource=v,
                          note="encrypted with a platform-managed key (not a customer-managed key)"))
    return out


@arg_rule(id="ARG-STOR-002", title="Storage account does not have infrastructure encryption enabled",
          best_practice=True, severity=Severity.LOW, category=Category.STORAGE, query_key="storage_config",
          description="A storage account does not have infrastructure (double) encryption enabled, so data at rest is encrypted once rather than with a second independent layer. Infrastructure encryption protects against a single-layer cryptographic failure.",
          remediation="Recreate the storage account with infrastructure encryption enabled (it can only be set at creation).",
          frameworks={"CIS Azure": "4.2", "Best Practice": "Encryption at rest"},
          detail={"summary": "A storage account is not using infrastructure (double) encryption.",
                  "why": "Infrastructure encryption adds a second, independent layer of encryption at rest, so a weakness or compromise in one layer does not expose the data. It can only be enabled at account creation.",
                  "scenario": "A single-layer encryption weakness is discovered; an account with infrastructure encryption keeps the data protected by the second layer, one without does not.",
                  "impact": "Data at rest has a single layer of encryption.",
                  "steps": ["Create storage accounts with infrastructure encryption enabled.",
                            "Migrate critical data to such an account (the flag cannot be toggled after creation).",
                            "Enforce the setting at creation with Azure Policy."],
                  "detection": "Azure Resource Graph over microsoft.storage/storageaccounts for properties.encryption.requireInfrastructureEncryption != true."})
def storage_no_infra_encryption(rows):
    out = []
    for r in rows:
        v = r.get("requireInfraEnc")
        if v is False:
            out.append(_e(r, "Storage Account", confirmed=True, requireInfrastructureEncryption=False,
                          note="infrastructure (double) encryption not enabled"))
        elif v is None:
            out.append(_e(r, "Storage Account", confirmed=False, requireInfrastructureEncryption="not returned",
                          note="requireInfrastructureEncryption not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-STOR-003", title="Storage account has no key-rotation reminder policy",
          best_practice=True, severity=Severity.LOW, category=Category.STORAGE, query_key="storage_config",
          description="A storage account has no key-expiration (key-rotation reminder) policy set, so there is no scheduled prompt to rotate the account access keys. Regular key rotation limits how long a leaked key stays valid.",
          remediation="Set a key-expiration period (keyPolicy.keyExpirationPeriodInDays) on the storage account so key-rotation reminders are raised.",
          frameworks={"CIS Azure": "4.3", "Best Practice": "Key rotation"},
          detail={"summary": "A storage account has no key-rotation reminder configured.",
                  "why": "Without a key-expiration policy there is no reminder to rotate the account keys, so a leaked shared key can stay valid indefinitely. A rotation reminder bounds that exposure window.",
                  "scenario": "An account key leaks and is never rotated because nothing prompts it; the leaked key keeps working.",
                  "impact": "Account keys may go unrotated indefinitely.",
                  "steps": ["Set a keyPolicy.keyExpirationPeriodInDays on the storage account.",
                            "Rotate account keys on that schedule (or disable shared-key access entirely).",
                            "Prefer Entra RBAC over shared keys where possible."],
                  "detection": "Azure Resource Graph over microsoft.storage/storageaccounts for an absent properties.keyPolicy.keyExpirationPeriodInDays."})
def storage_no_key_rotation_reminder(rows):
    out = []
    for r in rows:
        v = r.get("keyExpirationDays")
        if v is None:
            out.append(_e(r, "Storage Account", confirmed=False, keyPolicy="not set",
                          note="no key-expiration (rotation reminder) policy set, UNCONFIRMED (review)"))
    return out


def _sas_seconds(v: str) -> "int | None":
    """Parse an Azure SAS-expiration period '[d.]hh:mm:ss' to total seconds, or None if unparseable."""
    try:
        days = 0
        rest = v.strip()
        if "." in rest and rest.split(".")[0].isdigit() and ":" in rest.split(".", 1)[1]:
            days, rest = int(rest.split(".")[0]), rest.split(".", 1)[1]
        hh, mm, ss = (int(x) for x in rest.split(":"))
        return days * 86400 + hh * 3600 + mm * 60 + ss
    except (TypeError, ValueError):
        return None


@arg_rule(id="ARG-STOR-004", title="Storage account SAS tokens do not expire within an hour",
          best_practice=True, severity=Severity.LOW, category=Category.STORAGE, query_key="storage_config",
          description="A storage account has no SAS-expiration policy, or one longer than an hour, so shared access signature tokens it issues remain valid for an extended period. A short SAS lifetime limits the damage from a leaked token.",
          remediation="Set a SAS-expiration policy (sasPolicy.sasExpirationPeriod) of one hour or less on the storage account.",
          frameworks={"CIS Azure": "4.5", "MITRE ATT&CK": "T1552.001"},
          detail={"summary": "Storage SAS tokens are not constrained to a one-hour lifetime.",
                  "why": "A SAS token grants scoped data access without a login; the longer it lives, the longer a leaked token is usable. A short, enforced expiration caps that exposure.",
                  "scenario": "A long-lived SAS token leaks in a URL or log; because the account's SAS-expiration policy is loose, the token keeps granting data access for a long time.",
                  "impact": "Leaked SAS tokens stay valid longer than necessary.",
                  "steps": ["Set a sasPolicy.sasExpirationPeriod of 01:00:00 or less.",
                            "Issue user-delegation SAS tokens over account-key SAS where possible.",
                            "Monitor for long-lived or over-scoped SAS issuance."],
                  "detection": "Azure Resource Graph over microsoft.storage/storageaccounts for an absent or > 1h properties.sasPolicy.sasExpirationPeriod."})
def storage_sas_not_short(rows):
    out = []
    for r in rows:
        v = r.get("sasExpiration")
        if v is None or (isinstance(v, str) and v.strip() == ""):
            out.append(_e(r, "Storage Account", confirmed=False, sasPolicy="not set",
                          note="no SAS-expiration policy set, UNCONFIRMED (review)"))
            continue
        secs = _sas_seconds(v)
        if secs is not None and secs > 3600:
            out.append(_e(r, "Storage Account", confirmed=True, sasExpirationPeriod=v,
                          note=f"SAS-expiration policy '{v}' exceeds one hour"))
    return out


@arg_rule(id="ARG-STOR-005", title="Storage account blob soft delete is not enabled",
          best_practice=True, severity=Severity.LOW, category=Category.STORAGE, query_key="storage_blob_soft_delete",
          description="A storage account's blob service does not have soft delete enabled, so deleted or overwritten blobs cannot be recovered. Soft delete protects against accidental deletion and ransomware-style data destruction.",
          remediation="Enable blob (and container) soft delete with a retention period on the storage account's blob service.",
          frameworks={"CIS Azure": "4.10", "MITRE ATT&CK": "T1485"},
          detail={"summary": "Blob soft delete is not enabled on a storage account.",
                  "why": "Without soft delete, a deleted or overwritten blob is gone immediately, so accidental deletion or a destructive attacker leaves no recovery path. Soft delete keeps a recoverable copy for the retention window.",
                  "scenario": "An attacker (or a mistake) deletes blobs; with soft delete off there is no way to recover them.",
                  "impact": "Deleted or overwritten blob data is unrecoverable.",
                  "steps": ["Enable blob soft delete with a retention period on the blob service.",
                            "Enable container soft delete as well.",
                            "Consider versioning and immutability for critical data."],
                  "detection": "Azure Resource Graph over microsoft.storage/storageaccounts/blobservices for properties.deleteRetentionPolicy.enabled != true."})
def storage_blob_no_soft_delete(rows):
    out = []
    for r in rows:
        v = r.get("deleteEnabled")
        if v is False:
            out.append(_e(r, "Storage Account", confirmed=True, blobSoftDelete=False,
                          note="blob soft delete is not enabled"))
        elif v is None:
            out.append(_e(r, "Storage Account", confirmed=False, blobSoftDelete="not returned",
                          note="blob deleteRetentionPolicy.enabled not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-APP-004", title="App Service has remote debugging enabled",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="app_services_config",
          description="A Web/Function App has remote debugging enabled, exposing a debugging endpoint an attacker can attach to for code inspection and manipulation. Remote debugging is a development convenience that must never be left on in production.",
          remediation="Disable remote debugging on the App Service.",
          frameworks={"CIS Azure": "9.x", "MITRE ATT&CK": "T1210"},
          detail={"summary": "An App Service has remote debugging left enabled.",
                  "why": "Remote debugging opens an interactive endpoint into the running app; an attacker who reaches it can inspect memory, read secrets and alter execution.",
                  "scenario": "An attacker discovers the remote-debugging endpoint and attaches to the process to read in-memory secrets or manipulate the app.",
                  "impact": "Interactive access to a running production application.",
                  "steps": ["Disable remote debugging.", "Restrict App Service networking.",
                            "Enforce with Azure Policy."],
                  "detection": "Azure Resource Graph over microsoft.web/sites for properties.siteConfig.remoteDebuggingEnabled == true."})
def appservice_remote_debug(rows):
    return [_e(r, "App Service", confirmed=True, remoteDebugging=True,
               note="remote debugging enabled")
            for r in rows if r.get("remoteDebugging") is True]


@arg_rule(id="ARG-APP-007", title="App Service does not have HTTP/2 enabled", best_practice=True,
          severity=Severity.LOW, category=Category.COMPUTE, query_key="app_services_config",
          description="A Web/Function App has HTTP/2 disabled. HTTP/2 is the current protocol version and carries connection-handling and header-compression hardening over HTTP/1.1; leaving it off keeps the app on the older protocol.",
          remediation="Set http20Enabled=true on the App Service so clients negotiate HTTP/2.",
          frameworks={"CIS Azure": "9.10", "Best Practice": "Transport hardening"},
          detail={"summary": "An App Service is not serving HTTP/2.",
                  "why": "HTTP/2 is the current, more efficient and better-hardened protocol version; keeping an app on HTTP/1.1 only forgoes those improvements and signals an unreviewed transport configuration.",
                  "scenario": "An app left on HTTP/1.1 misses the protocol-level hardening and multiplexing of HTTP/2; the gap is a configuration-drift indicator picked up in a posture review.",
                  "impact": "App stays on the older HTTP protocol version.",
                  "steps": ["Set http20Enabled=true on the App Service.",
                            "Confirm clients and any front door negotiate HTTP/2.",
                            "Enforce with Azure Policy."],
                  "detection": "Azure Resource Graph over microsoft.web/sites for properties.siteConfig.http20Enabled == false."})
def appservice_no_http2(rows):
    out = []
    for r in rows:
        v = r.get("http20Enabled")
        if v is False:
            out.append(_e(r, "App Service", confirmed=True, http20Enabled=False,
                          note="HTTP/2 not enabled"))
        elif v is None:
            out.append(_e(r, "App Service", confirmed=False, http20Enabled="not returned",
                          note="http20Enabled not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-APP-008", title="App Service HTTP logging is not enabled", best_practice=True,
          severity=Severity.LOW, category=Category.LOGGING, query_key="app_services_config",
          description="A Web/Function App has HTTP logging disabled, so there is no record of the requests reaching the application. Without web-server logs an attack against the app (probing, injection, abuse) leaves no trail for detection or investigation.",
          remediation="Enable HTTP logging (httpLoggingEnabled) on the App Service and ship the logs to storage or Log Analytics.",
          frameworks={"CIS Azure": "6.1.6", "MITRE ATT&CK": "T1562.008"},
          detail={"summary": "An App Service is not recording HTTP request logs.",
                  "why": "HTTP logs are the record of who called the application and how. Without them, probing and exploitation of the app are invisible and there is no forensic trail after an incident.",
                  "scenario": "An attacker probes and exploits the web app; with HTTP logging off, the requests are never recorded and the activity is undetectable.",
                  "impact": "No request-level visibility or forensic trail for the application.",
                  "steps": ["Enable HTTP logging on the App Service.",
                            "Ship logs to a storage account or Log Analytics with retention.",
                            "Enforce logging across apps with Azure Policy."],
                  "detection": "Azure Resource Graph over microsoft.web/sites for properties.siteConfig.httpLoggingEnabled == false."})
def appservice_no_http_logging(rows):
    out = []
    for r in rows:
        v = r.get("httpLoggingEnabled")
        if v is False:
            out.append(_e(r, "App Service", confirmed=True, httpLoggingEnabled=False,
                          note="HTTP logging not enabled"))
        elif v is None:
            out.append(_e(r, "App Service", confirmed=False, httpLoggingEnabled="not returned",
                          note="httpLoggingEnabled not returned by Resource Graph, UNCONFIRMED"))
    return out


@arg_rule(id="ARG-APP-009", title="App Service has no authentication configured", best_practice=True,
          severity=Severity.LOW, category=Category.COMPUTE, query_key="appservice_auth_missing",
          description="A Web/Function App has no App Service authentication (EasyAuth) enabled, so the platform performs no identity check in front of the app. Any authorization is left entirely to the application code; EasyAuth provides a platform-level gate (Entra sign-in) that runs before a request reaches the app.",
          remediation="Enable App Service authentication (EasyAuth) with Microsoft Entra as the identity provider and require authentication for unauthenticated requests, where the app is not a deliberately public site.",
          frameworks={"CIS Azure": "9.2", "MITRE ATT&CK": "T1190"},
          detail={"summary": "An App Service has no platform authentication (EasyAuth) enabled.",
                  "why": "EasyAuth gives a platform-level identity gate in front of the app, so unauthenticated requests are rejected before reaching application code. Without it, the app's own code is the only thing standing between the internet and its functionality.",
                  "scenario": "An app endpoint intended to be internal has no EasyAuth; an attacker reaches it directly because the only access control was assumed to be the network.",
                  "impact": "No platform-level identity gate in front of the application.",
                  "steps": ["Enable App Service authentication with Microsoft Entra.",
                            "Set unauthenticated requests to require a login (not 'allow anonymous').",
                            "Leave disabled only for intentionally public sites, and document that."],
                  "detection": "Azure Resource Graph: microsoft.web/sites with no enabled authsettingsV2 config."})
def appservice_no_auth(rows):
    # Left-join resolved absence, so every returned row is a site with authentication off.
    return [_e(r, "App Service", confirmed=True, note="App Service authentication (EasyAuth) not enabled")
            for r in rows]


@arg_rule(id="ARG-APP-010", title="App Service allows basic (publishing) authentication",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="appservice_basic_auth",
          description="A Web/Function App still allows basic authentication for a publishing endpoint (FTP or SCM/Kudu). Basic auth uses a static username/password that bypasses Entra identity, MFA and Conditional Access, and is a common target for credential attacks against the deployment surface.",
          remediation="Disable basic authentication on both the FTP and SCM basic-publishing-credentials policies and deploy via Entra-authenticated CI/CD or managed identity.",
          frameworks={"CIS Azure": "9.6", "MITRE ATT&CK": "T1078"},
          detail={"summary": "An App Service permits basic authentication on a publishing endpoint.",
                  "why": "Basic publishing auth is a static credential that bypasses Entra, MFA and Conditional Access. It is a direct path to deploy code or read the app's content if the credential leaks or is brute-forced.",
                  "scenario": "An attacker brute-forces or captures the SCM/FTP basic credential and deploys a web shell to the app, because basic auth was left enabled.",
                  "impact": "A static credential can reach the app's deployment surface.",
                  "steps": ["Set 'allow' = false on both the ftp and scm basicPublishingCredentialsPolicies.",
                            "Deploy via Entra-authenticated CI/CD or managed identity.",
                            "Enforce the disabled state with Azure Policy."],
                  "detection": "Azure Resource Graph over microsoft.web/sites/basicpublishingcredentialspolicies for properties.allow == true."})
def appservice_basic_auth(rows):
    # One row per enabled publishing policy (ftp, scm); fold them into ONE entity per site so a
    # site with both endpoints enabled is counted once, and name the site, not the child policy.
    by_site: dict[str, dict] = {}
    for r in rows:
        sid = str(r.get("id") or r.get("name") or "?")
        agg = by_site.setdefault(sid, {"sub": r.get("subscriptionId"),
                                       "rg": r.get("resourceGroup"), "pol": set()})
        if r.get("policy"):
            agg["pol"].add(str(r.get("policy")))
    out = []
    for sid, agg in by_site.items():
        pol = ", ".join(sorted(agg["pol"])) or "ftp/scm"
        out.append(Entity(id=sid, name=sid.split("/")[-1], kind="App Service",
                          evidence={"subscription": agg["sub"], "resourceGroup": agg["rg"],
                                    "policies": pol, "confirmed": True,
                                    "note": f"basic authentication allowed on the {pol} publishing endpoint(s)"}))
    return out


# =========================================================================== #
# Containers, AKS / ACR / Container Apps (config AzureHound cannot see)
# =========================================================================== #
@arg_rule(id="ARG-AKS-001", title="AKS cluster has local (static) admin accounts enabled",
          severity=Severity.HIGH, category=Category.COMPUTE, query_key="aks_clusters",
          description="An AKS cluster has local accounts enabled (disableLocalAccounts is not true), so the cluster-admin kubeconfig with static, non-Entra credentials can be retrieved and used. These credentials bypass Entra authentication and Conditional Access and cannot be centrally revoked.",
          remediation="Set disableLocalAccounts=true and use Entra integration (AKS-managed Entra) with Azure RBAC for Kubernetes authorization.",
          frameworks={"CIS AKS": "3.x", "MITRE ATT&CK": "T1078.001"},
          detail={"summary": "AKS local admin accounts are enabled.",
                  "why": "Local accounts hand out a static cluster-admin kubeconfig that bypasses Entra and Conditional Access and cannot be revoked per-user; anyone who can call listClusterAdminCredential gets full cluster control.",
                  "scenario": "An attacker with the RBAC to list cluster admin credentials pulls the static kubeconfig and gets cluster-admin, bypassing Entra MFA/CA entirely.",
                  "impact": "Static, unrevocable cluster-admin access that bypasses identity controls.",
                  "steps": ["Set disableLocalAccounts=true.", "Enable AKS-managed Entra integration.",
                            "Use Azure RBAC for Kubernetes authorization."],
                  "detection": "Azure Resource Graph over microsoft.containerservice/managedclusters for properties.disableLocalAccounts != true."})
def aks_local_accounts(rows):
    out = []
    for r in rows:
        v = r.get("disableLocalAccounts")
        if v is False:
            out.append(_e(r, "AKS Cluster", confirmed=True, disableLocalAccounts=False,
                          note="local (static) admin accounts enabled"))
        elif v is None:
            out.append(_e(r, "AKS Cluster", confirmed=False, disableLocalAccounts="not returned",
                          note="disableLocalAccounts not returned, UNCONFIRMED (Azure default is enabled)"))
    return out


@arg_rule(id="ARG-AKS-002", title="AKS API server is publicly reachable without IP restrictions",
          severity=Severity.HIGH, category=Category.COMPUTE, query_key="aks_clusters",
          description="An AKS cluster is not a private cluster and has no authorized IP ranges on its API server, so the Kubernetes control plane is reachable from the entire internet. Only credentials stand between an attacker and the cluster API.",
          remediation="Make the cluster private (enablePrivateCluster=true), or restrict the API server to specific authorized IP ranges.",
          frameworks={"CIS AKS": "5.x", "MITRE ATT&CK": "T1190"},
          detail={"summary": "The AKS API server is exposed to the internet with no IP allow-list.",
                  "why": "A public API server with no authorized ranges is scannable and attackable from anywhere; combined with any credential weakness it is direct cluster compromise.",
                  "scenario": "An attacker reaches the public AKS API endpoint and attempts token/credential attacks against the control plane from their own infrastructure.",
                  "impact": "Internet exposure of the Kubernetes control plane.",
                  "steps": ["Enable a private cluster, or set apiServerAccessProfile.authorizedIPRanges.",
                            "Front management access with a bastion or VPN."],
                  "detection": "Azure Resource Graph: managedclusters where enablePrivateCluster != true and authorizedIPRanges is empty."})
def aks_public_api(rows):
    out = []
    for r in rows:
        private = r.get("privateCluster") is True
        has_ranges = bool(r.get("authorizedIPRanges"))
        if not private and not has_ranges:
            out.append(_e(r, "AKS Cluster", confirmed=True, privateCluster=False,
                          note="public API server with no authorized IP ranges"))
    return out


@arg_rule(id="ARG-AKS-003", title="AKS cluster has Kubernetes RBAC disabled",
          severity=Severity.HIGH, category=Category.COMPUTE, query_key="aks_clusters",
          description="An AKS cluster has Kubernetes RBAC disabled (enableRBAC=false), so there is no in-cluster authorization: any authenticated principal has unrestricted access to all cluster resources.",
          remediation="Recreate the cluster with Kubernetes RBAC enabled (it cannot be toggled on an existing cluster).",
          frameworks={"CIS AKS": "4.x"},
          detail={"summary": "Kubernetes RBAC is disabled on the AKS cluster.",
                  "why": "Without RBAC there is no authorization boundary inside the cluster, every authenticated identity can read secrets, modify workloads and escalate.",
                  "scenario": "Any principal that authenticates to the cluster (even low-privilege) can read all secrets and modify any workload because no RBAC restricts them.",
                  "impact": "No in-cluster authorization; full access for any authenticated identity.",
                  "steps": ["Recreate the cluster with enableRBAC=true.", "Define least-privilege Kubernetes roles."],
                  "detection": "Azure Resource Graph: managedclusters where properties.enableRBAC == false."})
def aks_rbac_disabled(rows):
    return [_e(r, "AKS Cluster", confirmed=True, enableRBAC=False,
               note="Kubernetes RBAC disabled")
            for r in rows if r.get("enableRBAC") is False]


@arg_rule(id="ARG-ACR-001", title="Container registry has the admin user enabled",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="acr_registries",
          description="A container registry has the admin account enabled, providing a single shared username/password with push and pull rights. The credential is not tied to an identity, cannot be scoped, and is commonly embedded in CI config and pipelines.",
          remediation="Disable the admin user and use Entra identities (service principals / managed identities) with AcrPush / AcrPull roles.",
          frameworks={"Best Practice": "Registry hardening", "MITRE ATT&CK": "T1552.001"},
          detail={"summary": "The container registry admin account is enabled.",
                  "why": "The admin account is a shared, unscoped credential with full push/pull; a single leak lets an attacker pull private images or push tampered ones into the supply chain.",
                  "scenario": "The admin credential leaks from CI config; an attacker pushes a backdoored image tag that downstream deployments pull and run.",
                  "impact": "Supply-chain tampering and disclosure of private images via a shared credential.",
                  "steps": ["Disable the admin user.", "Use Entra RBAC (AcrPush/AcrPull) with managed identities."],
                  "detection": "Azure Resource Graph over microsoft.containerregistry/registries for properties.adminUserEnabled == true."})
def acr_admin_user(rows):
    return [_e(r, "Container Registry", confirmed=True, adminUserEnabled=True,
               note="admin user (shared credential) enabled")
            for r in rows if r.get("adminUserEnabled") is True]


@arg_rule(id="ARG-ACR-002", title="Container registry allows anonymous pull",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="acr_registries",
          description="A container registry has anonymous pull enabled, so any unauthenticated client can pull its images. Private images and anything embedded in them (config, sometimes secrets) are exposed to the internet.",
          remediation="Disable anonymous pull unless the registry is intentionally a public distribution point.",
          frameworks={"MITRE ATT&CK": "T1213"},
          detail={"summary": "The container registry permits anonymous (unauthenticated) image pulls.",
                  "why": "Anonymous pull exposes every image in the registry to the internet, including anything sensitive baked into layers.",
                  "scenario": "An attacker enumerates the registry and pulls private images anonymously, then mines them for secrets and internal details.",
                  "impact": "Disclosure of private images and their contents.",
                  "steps": ["Disable anonymous pull.", "If public distribution is intended, isolate those artifacts in a dedicated registry."],
                  "detection": "Azure Resource Graph: registries where properties.anonymousPullEnabled == true."})
def acr_anonymous_pull(rows):
    return [_e(r, "Container Registry", confirmed=True, anonymousPullEnabled=True,
               note="anonymous pull enabled")
            for r in rows if r.get("anonymousPullEnabled") is True]


@arg_rule(id="ARG-CA-001", title="Container App is exposed to the public internet",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="container_apps", best_practice=True,
          description="A Container App has external ingress, so it is reachable from the public internet. This is often intended for web front-ends, but each externally-exposed app is an internet-facing entry point that should be justified and protected.",
          remediation="Confirm external ingress is required; use internal ingress for back-end services and front internet-facing apps with a WAF/gateway.",
          frameworks={"Best Practice": "Minimise public exposure"},
          detail={"summary": "A Container App accepts traffic from the public internet.",
                  "why": "External ingress puts the app directly on the internet. Back-end services with external ingress are needless attack surface.",
                  "scenario": "A back-end Container App is left with external ingress and is reached and probed directly from the internet.",
                  "impact": "Unnecessary internet exposure of an application.",
                  "steps": ["Use internal ingress for back-end apps.", "Front public apps with a WAF/gateway."],
                  "detection": "Azure Resource Graph over microsoft.app/containerapps for properties.configuration.ingress.external == true."})
def containerapp_external(rows):
    return [_e(r, "Container App", confirmed=True, external=True,
               note="external (public) ingress enabled")
            for r in rows if r.get("external") is True]


# =========================================================================== #
# Disks, caches, messaging, gateways, AI services
# =========================================================================== #
@arg_rule(id="ARG-DISK-001", title="Managed disk allows public network access",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="managed_disks",
          description="A managed disk has its network access policy set to allow access from any network (or public network access enabled), so disk export/download can be initiated over the public internet. Disk contents include OS and data volumes.",
          remediation="Set networkAccessPolicy to DenyAll or AllowPrivate and disable public network access; use Private Endpoints for disk import/export.",
          frameworks={"CIS Azure": "7.x"},
          detail={"summary": "A managed disk is reachable for export over the public network.",
                  "why": "A public disk access policy lets an attacker with the right RBAC generate a SAS and download the full disk image, OS and data, over the internet.",
                  "scenario": "An attacker with disk-export rights generates a download SAS and exfiltrates the entire disk image from outside the tenant network.",
                  "impact": "Full disk-image exfiltration over the public internet.",
                  "steps": ["Set networkAccessPolicy=DenyAll or AllowPrivate.", "Disable public network access.",
                            "Use Private Endpoints for any legitimate import/export."],
                  "detection": "Azure Resource Graph over microsoft.compute/disks for properties.networkAccessPolicy == 'AllowAll' or publicNetworkAccess == 'Enabled'."})
def disk_public_access(rows):
    out = []
    for r in rows:
        policy = str(r.get("networkAccessPolicy") or "")
        if policy.lower() == "allowall" or _enabled(r.get("publicNetworkAccess")):
            out.append(_e(r, "Managed Disk", confirmed=True,
                          networkAccessPolicy=r.get("networkAccessPolicy"),
                          note="public network access to the disk is allowed"))
    return out


@arg_rule(id="ARG-REDIS-001", title="Redis cache allows non-TLS (plaintext) connections",
          severity=Severity.HIGH, category=Category.STORAGE, query_key="redis_caches",
          description="A Redis cache has the non-SSL port enabled, so clients can connect in plaintext. The access key and all cached data cross the network unencrypted and can be captured.",
          remediation="Disable the non-SSL port (enableNonSslPort=false) and require TLS 1.2.",
          frameworks={"Best Practice": "Encryption in transit", "MITRE ATT&CK": "T1040"},
          detail={"summary": "A Redis cache accepts plaintext (non-TLS) connections.",
                  "why": "The non-SSL port sends the Redis access key and all data in cleartext; a network observer captures the key and gains full read/write to the cache.",
                  "scenario": "An attacker on the network captures a plaintext Redis connection, lifts the access key, and reads or poisons the cache.",
                  "impact": "Access-key theft and full cache compromise.",
                  "steps": ["Set enableNonSslPort=false.", "Require minimumTlsVersion=1.2.", "Rotate the access keys."],
                  "detection": "Azure Resource Graph over microsoft.cache/redis for properties.enableNonSslPort == true."})
def redis_non_ssl(rows):
    return [_e(r, "Redis Cache", confirmed=True, enableNonSslPort=True,
               note="non-TLS (plaintext) port enabled")
            for r in rows if r.get("enableNonSslPort") is True]


@arg_rule(id="ARG-REDIS-002", title="Redis cache allows public network access",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="redis_caches",
          description="A Redis cache has public network access enabled, exposing its endpoint to the internet subject to firewall rules.",
          remediation="Disable public network access and use a Private Endpoint, or restrict with firewall rules.",
          frameworks={"MITRE ATT&CK": "T1190", "Azure Threat Matrix": "AZT103"},
          detail={"summary": "A Redis cache endpoint is reachable over the public internet.",
                  "why": "Public network access exposes the cache to internet-wide attack; combined with a leaked key it is usable from anywhere.",
                  "scenario": "An attacker with a leaked Redis key reaches the public endpoint and reads or writes cached data directly.",
                  "impact": "Internet exposure of a data cache.",
                  "steps": ["Disable public network access.", "Use a Private Endpoint.", "Restrict firewall rules."],
                  "detection": "Azure Resource Graph over microsoft.cache/redis for properties.publicNetworkAccess == 'Enabled'."})
def redis_public(rows):
    return [_e(r, "Redis Cache", confirmed=True, publicNetworkAccess=r.get("publicNetworkAccess"),
               note="public network access enabled")
            for r in rows if _enabled(r.get("publicNetworkAccess"))]


@arg_rule(id="ARG-MSG-001", title="Messaging namespace allows shared-key (local) authentication",
          severity=Severity.MEDIUM, category=Category.STORAGE,
          query_key="servicebus_namespaces",
          description="A Service Bus or Event Hub namespace has local (SAS shared-key) authentication enabled. Shared keys are unscoped, hard to rotate, and frequently leaked in application config; disabling them forces Entra RBAC, which is scoped and audited.",
          remediation="Set disableLocalAuth=true and use Entra RBAC for send/receive.",
          frameworks={"MITRE ATT&CK": "T1552.001"},
          detail={"summary": "A messaging namespace permits SAS shared-key authentication.",
                  "why": "SAS keys are all-or-scope-of-the-key credentials that bypass Entra; a leaked key grants send/receive from anywhere with no per-identity audit.",
                  "scenario": "A Service Bus SAS key leaks in config; an attacker sends or drains messages using it, undetected by identity logs.",
                  "impact": "Unscoped, unaudited access to the message stream via a leaked key.",
                  "steps": ["Set disableLocalAuth=true.", "Grant send/receive via Entra RBAC.", "Rotate existing SAS keys."],
                  "detection": "Azure Resource Graph over microsoft.servicebus/namespaces for properties.disableLocalAuth != true."})
def servicebus_local_auth(rows):
    out = []
    for r in rows:
        v = r.get("disableLocalAuth")
        if v is False:
            out.append(_e(r, "Service Bus Namespace", confirmed=True, disableLocalAuth=False,
                          note="shared-key (local) authentication enabled"))
        elif v is None:
            out.append(_e(r, "Service Bus Namespace", confirmed=False, disableLocalAuth="not returned",
                          note="disableLocalAuth not returned by Resource Graph (default is enabled), UNCONFIRMED"))
    return out


@arg_rule(id="ARG-MSG-002", title="Event Hub namespace allows shared-key (local) authentication",
          severity=Severity.MEDIUM, category=Category.STORAGE,
          query_key="eventhub_namespaces",
          description="An Event Hub namespace has local (SAS shared-key) authentication enabled. Shared keys bypass Entra identity, cannot be scoped per-identity, and are commonly leaked in application config.",
          remediation="Set disableLocalAuth=true and use Entra RBAC for send/receive.",
          frameworks={"MITRE ATT&CK": "T1552.001"},
          detail={"summary": "An Event Hub namespace permits SAS shared-key authentication.",
                  "why": "SAS keys bypass Entra and are unscoped; a leaked key grants stream access from anywhere with no per-identity audit trail.",
                  "scenario": "An Event Hub SAS key leaks; an attacker reads the event stream (potentially sensitive telemetry) using it.",
                  "impact": "Unscoped, unaudited access to an event stream via a leaked key.",
                  "steps": ["Set disableLocalAuth=true.", "Use Entra RBAC.", "Rotate existing SAS keys."],
                  "detection": "Azure Resource Graph over microsoft.eventhub/namespaces for properties.disableLocalAuth != true."})
def eventhub_local_auth(rows):
    out = []
    for r in rows:
        v = r.get("disableLocalAuth")
        if v is False:
            out.append(_e(r, "Event Hub Namespace", confirmed=True, disableLocalAuth=False,
                          note="shared-key (local) authentication enabled"))
        elif v is None:
            out.append(_e(r, "Event Hub Namespace", confirmed=False, disableLocalAuth="not returned",
                          note="disableLocalAuth not returned by Resource Graph (default is enabled), UNCONFIRMED"))
    return out


@arg_rule(id="ARG-COG-001", title="AI / Cognitive Services account allows key-based auth and public access",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="cognitive_accounts",
          description="An Azure AI / Cognitive Services account (including Azure OpenAI) has local (API-key) authentication enabled and/or public network access, so a leaked API key grants use of the service, and its data, from anywhere on the internet.",
          remediation="Set disableLocalAuth=true and use Entra RBAC; set publicNetworkAccess=Disabled with a Private Endpoint.",
          frameworks={"MITRE ATT&CK": "T1552.001"},
          detail={"summary": "An AI/Cognitive Services account is key-authenticated and/or publicly reachable.",
                  "why": "API keys are unscoped shared secrets; combined with public access, a single leaked key lets an attacker use the model/service (incurring cost and exposing prompts/data) from anywhere.",
                  "scenario": "An Azure OpenAI key leaks from an app; an attacker calls the endpoint over the internet, running up cost and probing the deployed data/model.",
                  "impact": "Unauthorised, billable use of AI services and exposure of their data via a leaked key.",
                  "steps": ["Set disableLocalAuth=true and use Entra RBAC.", "Set publicNetworkAccess=Disabled + Private Endpoint."],
                  "detection": "Azure Resource Graph over microsoft.cognitiveservices/accounts for properties.disableLocalAuth != true or publicNetworkAccess == 'Enabled'."})
def cognitive_exposed(rows):
    out = []
    for r in rows:
        local_auth = r.get("disableLocalAuth") is False
        public = _enabled(r.get("publicNetworkAccess"))
        if local_auth or public:
            issues = []
            if local_auth:
                issues.append("key-based auth enabled")
            if public:
                issues.append("public network access enabled")
            out.append(_e(r, "AI / Cognitive Services", confirmed=True,
                          service_kind=r.get("kind"), note="; ".join(issues)))
        elif r.get("disableLocalAuth") is None:
            # Local-auth status unknown and not caught by the public-access signal: surface it as
            # UNCONFIRMED (key auth is the insecure default) rather than a silent pass.
            out.append(_e(r, "AI / Cognitive Services", confirmed=False, service_kind=r.get("kind"),
                          note="disableLocalAuth not returned by Resource Graph (default is enabled), UNCONFIRMED"))
    return out


@arg_rule(id="ARG-APIM-001", title="API Management gateway allows public network access",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="apim_services", best_practice=True,
          description="An API Management service has public network access enabled. This is common for public APIs, but an internal-only gateway left publicly reachable is unnecessary exposure.",
          remediation="Set publicNetworkAccess=Disabled for internal gateways and use a Private Endpoint / internal VNet mode.",
          frameworks={"Best Practice": "Minimise public exposure"},
          detail={"summary": "An API Management gateway is reachable over the public internet.",
                  "why": "A public gateway is internet attack surface; an internal-only gateway that is public is needless exposure of the APIs behind it.",
                  "scenario": "An internal API gateway is left publicly reachable and its backend APIs are probed from the internet.",
                  "impact": "Unnecessary internet exposure of a gateway and its backends.",
                  "steps": ["Set publicNetworkAccess=Disabled for internal gateways.", "Use internal VNet mode / Private Endpoint."],
                  "detection": "Azure Resource Graph over microsoft.apimanagement/service for properties.publicNetworkAccess == 'Enabled'."})
def apim_public(rows):
    return [_e(r, "API Management", confirmed=True, publicNetworkAccess=r.get("publicNetworkAccess"),
               note="public network access enabled")
            for r in rows if _enabled(r.get("publicNetworkAccess"))]


# =========================================================================== #
# CIS best-practice / hardening batch (defense-in-depth, not offensive)
# =========================================================================== #
@arg_rule(id="ARG-APP-005", title="App Service is reachable from the public internet",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="app_services_config",
          best_practice=True,
          description="An App Service (Web/Function App) has publicNetworkAccess enabled, so its management/data endpoint is reachable from the internet rather than only via a private endpoint or access restrictions.",
          remediation="Set publicNetworkAccess=Disabled and use a Private Endpoint / VNet integration, or apply access restrictions to trusted ranges.",
          frameworks={"CIS Azure": "9.x", "MITRE ATT&CK": "T1190"},
          detail={"summary": "An App Service is exposed to the public internet.",
                  "why": "A publicly reachable app increases attack surface: its endpoints, any exposed admin/SCM site, and its authentication can be probed by anyone. CIS recommends restricting network access for App Services.",
                  "scenario": "An attacker enumerates the public app endpoint and attacks its authentication, exposed APIs, or a vulnerable dependency directly.",
                  "impact": "Wider internet-facing attack surface for the application.",
                  "steps": ["Set publicNetworkAccess=Disabled where a private path exists.",
                            "Use Private Endpoint / VNet integration, or access restrictions for trusted IPs.",
                            "Confirm the SCM/Kudu site is not left publicly open."],
                  "detection": "Azure Resource Graph over microsoft.web/sites for properties.publicNetworkAccess == 'Enabled'."})
def app_public_network(rows):
    return [_e(r, "App Service", confirmed=True, app_kind=r.get("kind"), publicNetworkAccess=r.get("publicNetworkAccess"),
               note="public network access enabled")
            for r in rows if _enabled(r.get("publicNetworkAccess"))]


@arg_rule(id="ARG-APP-006", title="App Service has no managed identity",
          severity=Severity.LOW, category=Category.BEST_PRACTICE, query_key="app_services_config",
          best_practice=True,
          description="An App Service has no managed identity assigned, so it must hold secrets/connection strings to reach other Azure resources instead of using a credential-free managed identity.",
          remediation="Enable a system-assigned (or user-assigned) managed identity and use it for downstream Azure access; remove stored secrets.",
          frameworks={"CIS Azure": "9.x", "Best Practice": "Managed identity"},
          detail={"summary": "An App Service authenticates to other resources without a managed identity.",
                  "why": "Without a managed identity the app relies on stored secrets/connection strings, which are far easier to leak than a platform-managed, auto-rotated identity. CIS recommends managed identities for App Service.",
                  "scenario": "A leaked app setting or connection string grants an attacker the same downstream access the app has, with nothing to rotate quickly.",
                  "impact": "Standing secrets in app config instead of a credential-free identity.",
                  "steps": ["Enable a managed identity on the app.",
                            "Grant it least-privilege RBAC to the resources it needs.",
                            "Replace stored secrets/connection strings with managed-identity access."],
                  "detection": "Azure Resource Graph over microsoft.web/sites where identity.type is null/None."})
def app_no_managed_identity(rows):
    out = []
    for r in rows:
        t = r.get("identityType")
        if t is None or (isinstance(t, str) and t.strip().lower() in ("", "none")):
            out.append(_e(r, "App Service", confirmed=True, app_kind=r.get("kind"),
                          identityType=t or "None", note="no managed identity assigned"))
    return out


@arg_rule(id="ARG-REDIS-003", title="Redis cache accepts a weak minimum TLS version",
          severity=Severity.LOW, category=Category.BEST_PRACTICE, query_key="redis_caches",
          best_practice=True,
          description="A Redis cache's minimumTlsVersion permits TLS below 1.2, allowing deprecated transport encryption for cache connections.",
          remediation="Set the cache minimum TLS version to 1.2.",
          frameworks={"Best Practice": "Encryption in transit", "MITRE ATT&CK": "T1040"},
          detail={"summary": "A Redis cache allows TLS below 1.2.",
                  "why": "TLS 1.0/1.1 have known weaknesses; permitting them lets a network attacker downgrade and attack the confidentiality of cache traffic, which often carries session or application data.",
                  "scenario": "An on-path attacker forces a weak TLS session to the cache and attacks the cipher to recover its contents.",
                  "impact": "Weakened transport security for cache data.",
                  "steps": ["Set minimumTlsVersion=1.2 on the Redis cache.",
                            "Confirm clients support TLS 1.2 before enforcing."],
                  "detection": "Azure Resource Graph over microsoft.cache/redis for properties.minimumTlsVersion below '1.2'."})
def redis_weak_tls(rows):
    out = []
    for r in rows:
        v = _weak_tls(r.get("minimumTlsVersion"))
        if v:
            out.append(_e(r, "Redis Cache", confirmed=True, minimumTlsVersion=v,
                          note=f"minimum TLS {v}, below 1.2"))
    return out


@arg_rule(id="ARG-COG-002", title="AI / Cognitive Services account is reachable from the public internet",
          severity=Severity.LOW, category=Category.COMPUTE, query_key="cognitive_accounts",
          best_practice=True,
          description="A Cognitive Services / Azure OpenAI account has publicNetworkAccess enabled, exposing its inference/management endpoints to the internet.",
          remediation="Set publicNetworkAccess=Disabled and use a Private Endpoint, or restrict to trusted networks.",
          frameworks={"Best Practice": "Network restriction", "MITRE ATT&CK": "T1190"},
          detail={"summary": "An AI / Cognitive Services account is exposed to the public internet.",
                  "why": "A public AI endpoint can be probed and abused (prompt/data exfiltration, quota abuse) by anyone who obtains a key or exploits weak controls. Restricting network access limits that surface.",
                  "scenario": "An attacker who leaks or guesses a key reaches the public endpoint directly and abuses the model or extracts data.",
                  "impact": "Internet-facing exposure of an AI service and its data.",
                  "steps": ["Set publicNetworkAccess=Disabled where possible.",
                            "Use a Private Endpoint or restrict to trusted IP/VNets.",
                            "Prefer Entra (disableLocalAuth) over API keys."],
                  "detection": "Azure Resource Graph over microsoft.cognitiveservices/accounts for properties.publicNetworkAccess == 'Enabled'."})
def cognitive_public_network(rows):
    return [_e(r, "Cognitive Services", confirmed=True, app_kind=r.get("kind"),
               publicNetworkAccess=r.get("publicNetworkAccess"), note="public network access enabled")
            for r in rows if _enabled(r.get("publicNetworkAccess"))]


@arg_rule(id="ARG-DISK-002", title="Managed disk network access policy allows access from anywhere",
          severity=Severity.LOW, category=Category.BEST_PRACTICE, query_key="managed_disks",
          best_practice=True,
          description="A managed disk's networkAccessPolicy is AllowAll, so its export/SAS surface is not restricted to a private network or a specific VNet.",
          remediation="Set the disk networkAccessPolicy to DenyAll (or AllowPrivate with a disk access resource).",
          frameworks={"CIS Azure": "7.x", "MITRE ATT&CK": "T1537"},
          detail={"summary": "A managed disk permits network access from anywhere.",
                  "why": "AllowAll leaves the disk's export/SAS path reachable without a private-network restriction, widening the surface for data exfiltration if export is abused.",
                  "scenario": "An attacker with rights to generate a disk SAS/export downloads the disk contents over the open network path.",
                  "impact": "Unrestricted network path to disk export/SAS.",
                  "steps": ["Set networkAccessPolicy=DenyAll, or AllowPrivate with a disk access resource.",
                            "Review who can generate disk SAS/export."],
                  "detection": "Azure Resource Graph over microsoft.compute/disks for properties.networkAccessPolicy == 'AllowAll'."})
def disk_network_allow_all(rows):
    out = []
    for r in rows:
        v = r.get("networkAccessPolicy")
        if isinstance(v, str) and v.strip().lower() == "allowall":
            out.append(_e(r, "Managed Disk", confirmed=True, networkAccessPolicy=v,
                          note="networkAccessPolicy=AllowAll"))
    return out


@arg_rule(id="ARG-DISK-003", title="Managed disk is encrypted with a platform-managed key, not a customer-managed key",
          severity=Severity.LOW, category=Category.BEST_PRACTICE, query_key="managed_disks",
          best_practice=True,
          description="A managed disk uses a platform-managed key (the Azure default) for encryption at rest rather than a customer-managed key (CMK). CMK gives the organisation control over the key lifecycle, including rotation and revocation of the data's encryption.",
          remediation="Where your data-classification policy requires customer control of encryption keys, attach a disk encryption set backed by a Key Vault key (CMK) to the disk.",
          frameworks={"CIS Azure": "7.4", "Best Practice": "Encryption at rest"},
          detail={"summary": "Managed disk encryption at rest uses a platform key, not a customer-managed key.",
                  "why": "With a platform-managed key the organisation cannot rotate or revoke the key independently. A customer-managed key lets you cut access to the data by disabling the key, which matters for regulated or highly sensitive workloads.",
                  "scenario": "A regulatory or incident requirement calls for revoking access to data at rest; with only a platform key there is no customer-controlled revocation lever.",
                  "impact": "No customer control over the encryption-key lifecycle for this disk.",
                  "steps": ["Create a disk encryption set backed by a Key Vault key.",
                            "Apply it to disks holding regulated or sensitive data.",
                            "Enable key rotation on the Key Vault key."],
                  "detection": "Azure Resource Graph over microsoft.compute/disks for properties.encryption.type == 'EncryptionAtRestWithPlatformKey'."})
def disk_platform_key_only(rows):
    out = []
    for r in rows:
        et = r.get("encryptionType")
        # Only flag a disk we can POSITIVELY see is platform-key-only; None (field absent) is left
        # unflagged, so a wrong property path can never produce a false finding.
        if isinstance(et, str) and et.strip().lower() == "encryptionatrestwithplatformkey":
            out.append(_e(r, "Managed Disk", confirmed=True, encryptionType=et,
                          note="Disk uses a platform-managed key (no CMK)"))
    return out


@arg_rule(id="ARG-DISK-004", title="Virtual machine uses an unmanaged (classic VHD) OS disk",
          severity=Severity.MEDIUM, category=Category.COMPUTE, query_key="vm_unmanaged_disk",
          description="A virtual machine boots from an unmanaged OS disk (a VHD blob in a storage account) rather than a managed disk. Unmanaged disks miss managed-disk platform encryption, RBAC, and snapshot/backup management, and the backing storage account is a separate exposure surface.",
          remediation="Migrate the virtual machine to managed disks.",
          frameworks={"CIS Azure": "8.2", "MITRE ATT&CK": "T1530"},
          detail={"summary": "A VM uses an unmanaged (classic VHD) OS disk.",
                  "why": "Managed disks provide platform-managed encryption at rest, RBAC on the disk, and integrated snapshots/backup. An unmanaged VHD stores the OS disk as a blob whose storage account is a separate, often less-governed, exposure surface.",
                  "scenario": "An attacker who reaches the VHD's storage account (leaked key or public access) reads or tampers with the VM's OS disk directly.",
                  "impact": "VM disk security and management are weaker and the backing storage account widens the surface.",
                  "steps": ["Deallocate the VM and migrate it to managed disks.",
                            "Remove the leftover unmanaged VHD blobs and their storage account if unused.",
                            "Enforce managed disks for new VMs with Azure Policy."],
                  "detection": "Azure Resource Graph over microsoft.compute/virtualmachines for a non-empty properties.storageProfile.osDisk.vhd."})
def vm_unmanaged_disk(rows):
    return [_e(r, "Virtual Machine", confirmed=True, note="OS disk is an unmanaged (classic VHD) disk")
            for r in rows]


@arg_rule(id="ARG-DISK-005", title="Managed disk data-access authentication mode is not enabled",
          best_practice=True, severity=Severity.LOW, category=Category.COMPUTE, query_key="managed_disks",
          description="A managed disk has data-access authentication mode set to None, so SAS/export URLs for the disk are not gated by a Microsoft Entra identity check. Enabling the mode requires an Entra token to download or copy the disk, closing off anonymous use of an export URL.",
          remediation="Set the managed disk's dataAccessAuthMode to AzureActiveDirectory so disk export/download requires Entra authentication.",
          frameworks={"CIS Azure": "8.6", "MITRE ATT&CK": "T1530"},
          detail={"summary": "A managed disk's data-access authentication mode is None.",
                  "why": "With the mode off, a generated SAS/export URL for the disk can be used by anyone who holds the URL. Requiring Entra authentication for data access means a leaked export URL alone is not enough to pull the disk image.",
                  "scenario": "An export URL for a disk leaks; because data-access authentication mode is None, the holder downloads the full OS/data disk without any identity check.",
                  "impact": "Disk export/download is not gated by an identity check.",
                  "steps": ["Set dataAccessAuthMode = AzureActiveDirectory on the managed disk.",
                            "Issue short-lived, identity-bound export URLs when export is needed.",
                            "Enforce the mode with Azure Policy."],
                  "detection": "Azure Resource Graph over microsoft.compute/disks for properties.dataAccessAuthMode == 'None'."})
def disk_no_data_access_auth(rows):
    out = []
    for r in rows:
        v = r.get("dataAccessAuthMode")
        if isinstance(v, str) and v.strip().lower() == "none":
            out.append(_e(r, "Managed Disk", confirmed=True, dataAccessAuthMode=v,
                          note="data-access authentication mode is None (no Entra gate on disk export)"))
    return out


# =========================================================================== #
# Logging & monitoring (SETTINGS only: whether audit logging is ENABLED).
# These read the presence of a diagnostic / flow-log setting, never any log
# contents or tenant data. Each query resolves ABSENCE in KQL, so every row
# returned is a resource with logging OFF -> a finding.
# =========================================================================== #
@arg_rule(id="ARG-LOG-001", title="Key Vault audit logging is not enabled",
          severity=Severity.HIGH, category=Category.LOGGING, query_key="keyvault_diagnostics_missing",
          description="A Key Vault has no diagnostic setting, so AuditEvent logging (who read which secret, key or certificate) is not sent anywhere. Secret access is the single most sensitive data-plane operation in the tenant, and without audit logs a credential theft from the vault leaves no trace for detection or forensics.",
          remediation="Add a diagnostic setting on the Key Vault sending the AuditEvent category to a Log Analytics workspace, Event Hub or Storage account.",
          frameworks={"CIS Azure": "5.1.x", "MITRE ATT&CK": "T1552.001", "Azure Threat Matrix": "AZT605"},
          detail={"summary": "A Key Vault has no diagnostic/audit logging configured.",
                  "why": "The Key Vault holds the tenant's secrets, keys and certificates. Without AuditEvent logging there is no record of secret reads, so exfiltration of credentials from the vault is invisible and cannot be investigated.",
                  "scenario": "An attacker who reaches the vault reads its secrets; with no audit log the access is never detected and the incident cannot be scoped.",
                  "impact": "Secret, key and certificate access is unaudited: credential theft from the vault is invisible.",
                  "steps": ["Add a diagnostic setting on the vault with the AuditEvent category.",
                            "Send it to a Log Analytics workspace (and optionally archive to Storage).",
                            "Alert on anomalous secret-read volume."],
                  "detection": "Azure Resource Graph: microsoft.keyvault/vaults with no child microsoft.insights/diagnosticSettings."})
def keyvault_logging_missing(rows):
    return [_e(r, "Key Vault", confirmed=True,
               note="no diagnostic setting: AuditEvent logging is not enabled") for r in rows]


@arg_rule(id="ARG-LOG-002", title="Storage account logging is not enabled",
          severity=Severity.MEDIUM, category=Category.LOGGING, query_key="storage_diagnostics_missing",
          description="A storage account has no diagnostic setting, so data-plane access logging (blob/file/queue/table reads and writes) is not captured. Exfiltration from or tampering with the account leaves no access trail.",
          remediation="Add a diagnostic setting on the storage account's blob/file/queue/table services sending StorageRead/StorageWrite/StorageDelete to a Log Analytics workspace.",
          frameworks={"CIS Azure": "5.1.x", "MITRE ATT&CK": "T1530", "Azure Threat Matrix": "AZT605"},
          detail={"summary": "A storage account has no diagnostic/data-plane logging configured.",
                  "why": "Without data-plane logging there is no record of who read or wrote the account's data, so exfiltration of a sensitive container is undetectable after the fact.",
                  "scenario": "An attacker with a key or over-broad role reads a container's objects; with no logging the exfiltration is never recorded.",
                  "impact": "Blob/file/queue/table access is unaudited: data exfiltration leaves no trail.",
                  "steps": ["Add a diagnostic setting on each storage service (blob/file/queue/table).",
                            "Send StorageRead/StorageWrite/StorageDelete to Log Analytics.",
                            "Retain the logs per your data-governance policy."],
                  "detection": "Azure Resource Graph: microsoft.storage/storageaccounts with no child microsoft.insights/diagnosticSettings."})
def storage_logging_missing(rows):
    return [_e(r, "Storage Account", confirmed=True,
               note="no diagnostic setting: data-plane access logging is not enabled") for r in rows]


@arg_rule(id="ARG-LOG-003", title="Subscription activity log is not exported",
          severity=Severity.HIGH, category=Category.LOGGING, query_key="subscription_activitylog_missing",
          description="A subscription has no diagnostic setting exporting its Activity Log. The Activity Log is the control-plane audit trail (role assignments, resource changes, policy edits, credential additions). Without export it is retained for only 90 days and cannot be centrally monitored or alerted on, so administrative abuse and attacker persistence go unseen.",
          remediation="Create a subscription-level diagnostic setting exporting the Activity Log (Administrative, Security, Policy categories at minimum) to a Log Analytics workspace, and alert on sensitive operations.",
          frameworks={"CIS Azure": "5.x", "MITRE ATT&CK": "T1562.008", "Azure Threat Matrix": "AZT605"},
          detail={"summary": "A subscription does not export its Activity Log anywhere.",
                  "why": "The Activity Log is the record of every control-plane change. Unexported, it survives only 90 days and has no alerting, so role grants, resource tampering and attacker persistence are neither monitored nor retained for investigation.",
                  "scenario": "An attacker grants themselves a role and creates backdoor resources; with no exported Activity Log the actions are not alerted on and age out before a later investigation can see them.",
                  "impact": "No durable, monitorable control-plane audit trail for the subscription.",
                  "steps": ["Create a subscription diagnostic setting exporting the Activity Log.",
                            "Include Administrative, Security and Policy categories.",
                            "Send to Log Analytics and alert on sensitive operations (role writes, NSG changes)."],
                  "detection": "Azure Resource Graph: microsoft.resources/subscriptions with no subscription-scoped microsoft.insights/diagnosticSettings."})
def subscription_activitylog_missing(rows):
    return [_e(r, "Subscription", confirmed=True,
               note="no diagnostic setting: the Activity Log is not exported") for r in rows]


@arg_rule(id="ARG-LOG-004", title="Network Security Group flow logs are not enabled",
          severity=Severity.LOW, category=Category.LOGGING, query_key="nsg_flowlogs_missing",
          best_practice=True,
          description="A Network Security Group has no flow log configured, so there is no record of allowed/denied network connections through it. Flow logs are the primary source for detecting lateral movement, data exfiltration over the network and command-and-control traffic.",
          remediation="Enable NSG flow logs (Network Watcher) for the NSG, sending them to a Storage account and ideally Traffic Analytics.",
          frameworks={"CIS Azure": "6.x", "MITRE ATT&CK": "T1049", "Best Practice": "Network monitoring"},
          detail={"summary": "A Network Security Group has no flow log configured.",
                  "why": "Without flow logs there is no visibility into network connections, so lateral movement and exfiltration over the network cannot be detected or investigated.",
                  "scenario": "An attacker moves laterally between subnets; with no flow logs the traffic is never recorded and the movement is invisible.",
                  "impact": "No network-flow visibility for traffic governed by this NSG.",
                  "steps": ["Enable NSG flow logs via Network Watcher.",
                            "Send them to a Storage account and enable Traffic Analytics.",
                            "Retain and review for anomalous east-west traffic."],
                  "detection": "Azure Resource Graph: microsoft.network/networksecuritygroups with no microsoft.network/networkwatchers/flowlogs targeting them."})
def nsg_flowlogs_missing(rows):
    return [_e(r, "Network Security Group", confirmed=True,
               note="no flow log configured: network traffic is not logged") for r in rows]


@arg_rule(id="ARG-LOG-005", title="Network Security Group flow-log retention is 90 days or less",
          best_practice=True, severity=Severity.LOW, category=Category.LOGGING,
          query_key="nsg_flowlog_short_retention",
          description="An NSG flow log is enabled but retains for a finite period of 90 days or less. CIS recommends greater than 90 days so a network investigation that starts weeks after the fact still has the flow records.",
          remediation="Set the NSG flow log retention to greater than 90 days (or 0 for unlimited).",
          frameworks={"CIS Azure": "7.5", "MITRE ATT&CK": "T1049", "Best Practice": "Log retention"},
          detail={"summary": "NSG flow-log retention is 90 days or less.",
                  "why": "Network intrusions are often found long after they begin. A short flow-log retention window means the records covering the actual lateral movement or exfiltration are already purged by the time an investigation starts.",
                  "scenario": "A breach is investigated three months later, but the NSG flow logs were kept for only 90 days, so the network records of the intrusion are gone.",
                  "impact": "Network-flow evidence may be purged before an investigation needs it.",
                  "steps": ["Set the flow-log retention to greater than 90 days (0 = unlimited).",
                            "Send flow logs to long-term storage and Traffic Analytics.",
                            "Apply the retention standard across every flow log."],
                  "detection": "Azure Resource Graph over microsoft.network/networkwatchers/flowlogs for an enabled log with properties.retentionPolicy.days between 1 and 90."})
def nsg_flowlog_short_retention(rows):
    return [_e(r, "Network Security Group Flow Log", confirmed=True, retentionDays=r.get("days"),
               note=f"flow-log retention is {r.get('days')} days (<= 90)") for r in rows]


@arg_rule(id="ARG-NET-004", title="Subscription has no Network Watcher", best_practice=True,
          severity=Severity.LOW, category=Category.LOGGING, query_key="network_watcher_missing",
          description="A subscription has no Network Watcher, the regional service that backs NSG flow logs, connection troubleshooting and packet capture. Without it there is no network-level diagnostic or logging capability in the subscription.",
          remediation="Enable Network Watcher for the regions in use in the subscription.",
          frameworks={"CIS Azure": "7.6", "MITRE ATT&CK": "T1049", "Best Practice": "Network monitoring"},
          detail={"summary": "No Network Watcher exists in the subscription.",
                  "why": "Network Watcher is the prerequisite for NSG flow logs and network diagnostics. With none present, the subscription has no way to capture or investigate network traffic.",
                  "scenario": "An incident needs network flow evidence, but with no Network Watcher the flow logs were never possible, so there is nothing to investigate.",
                  "impact": "No network-level logging or diagnostics in the subscription.",
                  "steps": ["Enable Network Watcher for every region with workloads.",
                            "Turn on NSG flow logs and Traffic Analytics on top of it.",
                            "Enforce Network Watcher with Azure Policy."],
                  "detection": "Azure Resource Graph: subscriptions with no microsoft.network/networkwatchers resource."})
def no_network_watcher(rows):
    return [_e(r, "Subscription", confirmed=True, note="no Network Watcher in this subscription")
            for r in rows]


# =========================================================================== #
# Activity-log alerts (CIS 6.2.x). One query (activity_log_alerts) returns, per
# subscription, the set of operationNames that already have an ENABLED alert. A
# subscription with no enabled alert for a given control-plane operation is flagged:
# the critical change (NSG/policy/SQL-firewall/public-IP edits) can happen with no one
# notified. The query resolves absence via a left-join, so every subscription appears
# and a missing alert is a confirmed finding, never a false positive.
# =========================================================================== #
_ACTIVITY_LOG_ALERTS: tuple[tuple[str, str, str, str], ...] = (
    # (rule id, CIS id, operationName, human label)
    ("ARG-MON-001", "6.2.1",  "microsoft.authorization/policyassignments/write",   "create/update a policy assignment"),
    ("ARG-MON-002", "6.2.2",  "microsoft.authorization/policyassignments/delete",  "delete a policy assignment"),
    ("ARG-MON-003", "6.2.3",  "microsoft.network/networksecuritygroups/write",     "create/update a network security group"),
    ("ARG-MON-004", "6.2.4",  "microsoft.network/networksecuritygroups/delete",    "delete a network security group"),
    ("ARG-MON-005", "6.2.5",  "microsoft.security/securitysolutions/write",        "create/update a security solution"),
    ("ARG-MON-006", "6.2.6",  "microsoft.security/securitysolutions/delete",       "delete a security solution"),
    ("ARG-MON-007", "6.2.7",  "microsoft.sql/servers/firewallrules/write",         "create/update a SQL server firewall rule"),
    ("ARG-MON-008", "6.2.8",  "microsoft.sql/servers/firewallrules/delete",        "delete a SQL server firewall rule"),
    ("ARG-MON-009", "6.2.9",  "microsoft.network/publicipaddresses/write",         "create/update a public IP address"),
    ("ARG-MON-010", "6.2.10", "microsoft.network/publicipaddresses/delete",        "delete a public IP address"),
)


def _activity_alert_fn(operation: str, label: str):
    def fn(rows):
        out = []
        for r in rows:
            ops = {str(o).lower() for o in (r.get("alertedOps") or [])}
            if operation not in ops:
                out.append(_e(r, "Subscription", confirmed=True, operation=operation,
                              note=f"no enabled activity-log alert for: {label}"))
        return out
    return fn


def _register_activity_log_alerts():
    for rid, cis_id, operation, label in _ACTIVITY_LOG_ALERTS:
        REGISTRY.append(ArgRule(
            id=rid, title=f"No activity-log alert for '{label}'",
            severity=Severity.LOW, category=Category.LOGGING, best_practice=True,
            query_key="activity_log_alerts",
            description=(f"A subscription has no enabled activity-log alert for the operation to "
                         f"{label}. This security-relevant control-plane change can happen with no "
                         f"notification raised, so a malicious or mistaken change goes unnoticed."),
            remediation=(f"Create an enabled activity-log alert for the '{operation}' operation in "
                         f"every subscription, routed to a monitored action group."),
            frameworks={"CIS Azure": cis_id, "MITRE ATT&CK": "T1562.008",
                        "Azure Threat Matrix": "AZT805"},
            detail={
                "summary": f"No enabled activity-log alert exists for: {label}.",
                "why": ("Activity-log alerts are how security-relevant control-plane changes get "
                        "noticed in near-real time. Without one for this operation, an attacker (or "
                        "a mistaken operator) can make the change and no one is notified."),
                "scenario": (f"An attacker performs '{operation}' to weaken the environment; with no "
                             f"alert configured, the change produces no notification and is not reviewed."),
                "impact": "A security-relevant control-plane change happens with no notification.",
                "steps": [f"Create an activity-log alert for the '{operation}' operation.",
                          "Set it enabled and route it to a monitored action group.",
                          "Apply it across every subscription with Azure Policy."],
                "detection": ("Azure Resource Graph over microsoft.insights/activitylogalerts for an "
                              f"enabled alert whose condition matches operationName '{operation}'."),
            },
            fn=_activity_alert_fn(operation, label)))


_register_activity_log_alerts()


# --------------------------------------------------------------------------- runner
from dataclasses import asdict  # noqa: E402


def run_arg_rules(arg) -> tuple[list[dict], list[dict]]:
    """Run every ARG rule over an ArgResult. Returns (finding_dicts, not_assessed).

    A rule whose query is missing from the result (query errored, or ARG was not
    collected) becomes a not_assessed entry rather than a silent pass.
    """
    findings: list[dict] = []
    not_assessed: list[dict] = []
    rows_by_key = getattr(arg, "rows", {}) or {}
    for r in REGISTRY:
        if r.query_key not in rows_by_key:
            not_assessed.append({
                "rule_id": r.id, "title": r.title,
                "reason": "Azure Resource Graph query not available (no data collected)",
                "needs": [f"Azure Resource Graph: {r.query_key}"],
            })
            continue
        try:
            entities = r.fn(rows_by_key.get(r.query_key) or [])
        except Exception as exc:  # never let one rule sink the batch
            not_assessed.append({"rule_id": r.id, "title": r.title,
                                 "reason": f"rule raised {type(exc).__name__}: {exc}",
                                 "needs": [f"Azure Resource Graph: {r.query_key}"]})
            continue
        if not entities:
            continue
        findings.append({
            "source": "deterministic", "rule_id": r.id, "title": r.title,
            "severity": r.severity.value, "category": r.category.value,
            "best_practice": r.best_practice,
            "entities": [asdict(e) for e in entities],
            "affected_count": len(entities),
            "what": r.description, "why_it_matters": r.detail.get("why", r.description),
            "attack_scenario": r.detail.get("scenario", ""),
            "escalation_chain": [], "evidence": [],
            "remediation": r.remediation, "detection": r.detail.get("detection", ""),
            "detail": r.detail, "references": [], "frameworks": r.frameworks,
        })

    # False-positive-storm guard for ARG-DEFENDER-003 (subscriptions with no security contact).
    # Its query left-joins every subscription against microsoft.security/securitycontacts; if the SP
    # cannot read the microsoft.security provider at all (Reader without Security Reader), the join
    # yields zero contacts for EVERY subscription and the rule would flag them all. If no other
    # security resource came back for the whole tenant (pricings AND auto-provisioning both empty),
    # the provider is unreadable, so reclassify the finding as not_assessed instead of a false storm.
    sec_readable = bool(rows_by_key.get("defender_pricings")) or bool(rows_by_key.get("defender_autoprovisioning"))
    if not sec_readable and any(f.get("rule_id") == "ARG-DEFENDER-003" for f in findings):
        findings = [f for f in findings if f.get("rule_id") != "ARG-DEFENDER-003"]
        not_assessed.append({
            "rule_id": "ARG-DEFENDER-003",
            "title": "Subscription has no Defender for Cloud security contact configured",
            "reason": ("microsoft.security provider not readable by the service principal (no Defender "
                       "pricings or auto-provisioning returned); cannot verify security contacts"),
            "needs": ["Azure Resource Graph: microsoft.security (Security Reader on the SP)"],
        })
    return findings, not_assessed
