"""Rules over Azure Resource Graph data (PostureHound v2, Track B).

These consume the rows returned by azure_arg.collect() - network exposure and
data-service configuration that AzureHound cannot see. The rows have a fixed
shape because azure_arg's KQL `project`s explicit named fields, so the rule input
is a contract this codebase defines. If an underlying Azure property path were
wrong, that field arrives as None and the rule reports UNCONFIRMED - never a
false finding and never a false pass - exactly as the graph rules do for a
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
              "scenario": "An attacker scans Azure IP ranges, finds the open management or database port, and brute-forces or exploits the service directly - no foothold inside the tenant network required.",
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
               note="associated to a resource - internet-routable")
            for r in rows if r.get("associated")]


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
                          note="publicNetworkAccess not returned by Resource Graph - UNCONFIRMED"))
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
                          note=f"minimum TLS {v} - below 1.2"))
    return out


@arg_rule(id="ARG-SQL-003", title="SQL server firewall allows the entire internet",
          severity=Severity.CRITICAL, category=Category.STORAGE, query_key="sql_firewall_allow_all",
          description="A SQL server firewall rule spans 0.0.0.0 to 255.255.255.255 - the entire IPv4 internet. Every host on the internet can reach the database endpoint; only credentials stand between an attacker and the data.",
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
                          note="publicNetworkAccess not returned by Resource Graph - UNCONFIRMED"))
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
                          note="network.publicNetworkAccess not returned by Resource Graph - UNCONFIRMED"))
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
                          note="network.publicNetworkAccess not returned by Resource Graph - UNCONFIRMED"))
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
              "why": "Without HTTPS-only, traffic - including auth cookies and tokens - can traverse the network unencrypted and be captured or replayed.",
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
                          note="HTTPS-only not enforced - serves plaintext HTTP"))
        elif v is None:
            out.append(_e(r, "App Service", confirmed=False, httpsOnly="not returned",
                          note="httpsOnly not returned by Resource Graph - UNCONFIRMED"))
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
                          note=f"minimum TLS {v} - below 1.2"))
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
                          note=f"auditing state is '{v}' - not Enabled"))
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


# =========================================================================== #
# Containers - AKS / ACR / Container Apps (config AzureHound cannot see)
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
                          note="disableLocalAccounts not returned - UNCONFIRMED (Azure default is enabled)"))
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
                  "why": "Without RBAC there is no authorization boundary inside the cluster - every authenticated identity can read secrets, modify workloads and escalate.",
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
                  "why": "A public disk access policy lets an attacker with the right RBAC generate a SAS and download the full disk image - OS and data - over the internet.",
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
    return [_e(r, "Service Bus Namespace", confirmed=True, disableLocalAuth=False,
               note="shared-key (local) authentication enabled")
            for r in rows if r.get("disableLocalAuth") is False]


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
    return [_e(r, "Event Hub Namespace", confirmed=True, disableLocalAuth=False,
               note="shared-key (local) authentication enabled")
            for r in rows if r.get("disableLocalAuth") is False]


@arg_rule(id="ARG-COG-001", title="AI / Cognitive Services account allows key-based auth and public access",
          severity=Severity.MEDIUM, category=Category.STORAGE, query_key="cognitive_accounts",
          description="An Azure AI / Cognitive Services account (including Azure OpenAI) has local (API-key) authentication enabled and/or public network access, so a leaked API key grants use of the service - and its data - from anywhere on the internet.",
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
                          note=f"minimum TLS {v} - below 1.2"))
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
    return findings, not_assessed
