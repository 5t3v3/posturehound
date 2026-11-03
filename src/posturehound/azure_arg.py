"""Azure Resource Graph collector (PostureHound v2, Track B).

AzureHound collects the identity/authorization graph but not resource
*configuration*. This module reaches the rest of Azure via Azure Resource Graph
(ARG): one KQL API over every ARM resource with its full properties. It
authenticates with a dedicated read-only service principal (Reader /
Security Reader) using the OAuth2 client-credentials flow.

Design:
  - Pure, injectable HTTP. `collect()` takes an httpx client, so tests drive it
    with httpx.MockTransport and no network. The default client is built lazily.
  - Graceful absence. No service principal configured -> `collect()` returns
    None and the scan simply records "ARG not collected" in its coverage view;
    a clean pass is never implied for a domain that was never queried.
  - Never raises into the scan. Auth/query failures are captured in the result's
    `errors`, not propagated.

The curated KQL in ARG_QUERIES targets the v2 priority domains (network exposure,
data services, resource firewalls). The exact field paths returned by ARG must be
verified against live output before rules are written on top of them, that is the
Phase 3 step and is why this module returns raw rows rather than findings.
"""
from __future__ import annotations

import os
import ssl
import time
from dataclasses import dataclass, field

_AUTHORITY = "https://login.microsoftonline.com"
_ARM = "https://management.azure.com"
_ARG_ENDPOINT = f"{_ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
_ARM_SCOPE = f"{_ARM}/.default"
_SUBSCRIPTIONS_URL = f"{_ARM}/subscriptions?api-version=2020-01-01"
_ARG_PAGE_SIZE = 1000
_MAX_PAGES = 200  # backstop against a pathological skipToken loop


@dataclass
class ArgCredentials:
    tenant_id: str
    client_id: str
    client_secret: str

    def ok(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


@dataclass
class ArgResult:
    subscription_ids: list[str] = field(default_factory=list)
    rows: dict[str, list[dict]] = field(default_factory=dict)   # query key -> rows
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and bool(self.rows)

    def total_rows(self) -> int:
        return sum(len(v) for v in self.rows.values())


# Curated KQL for the v2 priority domains. Raw rows only, field paths are
# verified against live ARG before any rule reads them (see module docstring).
ARG_QUERIES: dict[str, str] = {
    # Network exposure ------------------------------------------------------
    "public_ips": (
        "Resources | where type =~ 'microsoft.network/publicipaddresses' "
        "| project id, name, subscriptionId, resourceGroup, "
        "ipAddress = properties.ipAddress, "
        "associated = isnotnull(properties.ipConfiguration)"
    ),
    "nsg_rules_any_inbound": (
        "Resources | where type =~ 'microsoft.network/networksecuritygroups' "
        "| mv-expand rule = properties.securityRules "
        "| where rule.properties.direction =~ 'Inbound' "
        "and rule.properties.access =~ 'Allow' "
        # A rule specifies its source as either the singular sourceAddressPrefix or
        # the plural sourceAddressPrefixes array; normalise to one array so an
        # internet-open rule set via the plural form is not missed.
        "| extend srcs = iff(array_length(rule.properties.sourceAddressPrefixes) > 0, "
        "rule.properties.sourceAddressPrefixes, pack_array(rule.properties.sourceAddressPrefix)) "
        "| mv-expand src = srcs to typeof(string) "
        "| where src in ('*','0.0.0.0/0','Internet') "
        "| project id, name, subscriptionId, resourceGroup, "
        "ruleName = rule.name, destPort = rule.properties.destinationPortRange "
        "| distinct id, name, subscriptionId, resourceGroup, ruleName, destPort"
    ),
    # Data services ---------------------------------------------------------
    "sql_servers": (
        "Resources | where type =~ 'microsoft.sql/servers' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.publicNetworkAccess, "
        "minimalTlsVersion = properties.minimalTlsVersion"
    ),
    "sql_firewall_allow_all": (
        "Resources | where type =~ 'microsoft.sql/servers/firewallrules' "
        "| where properties.startIpAddress == '0.0.0.0' "
        "and properties.endIpAddress == '255.255.255.255' "
        "| project id, name, subscriptionId, resourceGroup"
    ),
    "sql_auditing": (
        "Resources | where type =~ 'microsoft.sql/servers/auditingsettings' "
        "| project id, name, subscriptionId, resourceGroup, "
        "state = properties.state, "
        "retentionDays = properties.retentionDays"
    ),
    "cosmos_accounts": (
        "Resources | where type =~ 'microsoft.documentdb/databaseaccounts' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.publicNetworkAccess, "
        "disableLocalAuth = properties.disableLocalAuth, "
        "ipRules = properties.ipRules, "
        "privateEndpointConnections = properties.privateEndpointConnections"
    ),
    "postgres_flexible": (
        "Resources | where type =~ 'microsoft.dbforpostgresql/flexibleservers' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.network.publicNetworkAccess"
    ),
    "mysql_flexible": (
        "Resources | where type =~ 'microsoft.dbformysql/flexibleservers' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.network.publicNetworkAccess"
    ),
    # SQL transparent data encryption, per database (state Enabled/Disabled). The system 'master'
    # database is excluded by the rule, not the query.
    "sql_tde_databases": (
        "Resources | where type =~ 'microsoft.sql/servers/databases/transparentdataencryption' "
        "| project id, name, subscriptionId, resourceGroup, state = properties.state"
    ),
    # SQL TDE protector key type (ServiceManaged vs AzureKeyVault/customer-managed).
    "sql_tde_protector": (
        "Resources | where type =~ 'microsoft.sql/servers/encryptionprotector' "
        "| project id, name, subscriptionId, resourceGroup, serverKeyType = properties.serverKeyType"
    ),
    # SQL servers that have NO Microsoft Entra administrator configured (absence resolved in KQL via
    # a left-join against the servers/administrators child resource, so every returned row is a
    # server with no Entra admin and a wrong path can never flag every server).
    "sql_entra_admin_missing": (
        "Resources | where type =~ 'microsoft.sql/servers' "
        "| project serverId = id, name, subscriptionId, resourceGroup "
        "| join kind=leftouter (Resources "
        "  | where type =~ 'microsoft.sql/servers/administrators' "
        "  | extend serverId = tostring(split(id, '/administrators')[0]) "
        "  | summarize admins = count() by serverId) on serverId "
        "| extend admins = coalesce(admins, 0) | where admins == 0 "
        "| project id = serverId, name, subscriptionId, resourceGroup"
    ),
    # PostgreSQL / MySQL flexible-server parameters (one row per {server, parameter}); the rules
    # check a specific parameter's value. serverId is the parent flexible-server resource id.
    "postgres_flex_configs": (
        "Resources | where type =~ 'microsoft.dbforpostgresql/flexibleservers/configurations' "
        "| project id, name, subscriptionId, resourceGroup, "
        "serverId = tostring(split(id, '/configurations/')[0]), "
        "value = tostring(properties.value)"
    ),
    "mysql_flex_configs": (
        "Resources | where type =~ 'microsoft.dbformysql/flexibleservers/configurations' "
        "| project id, name, subscriptionId, resourceGroup, "
        "serverId = tostring(split(id, '/configurations/')[0]), "
        "value = tostring(properties.value)"
    ),
    # Storage-account encryption / key / SAS policy (CIS 4.2 / 4.3 / 4.5 / 4.11). keySource is
    # always present (defaults to Microsoft.Storage); keyPolicy / sasPolicy are optional.
    "storage_config": (
        "Resources | where type =~ 'microsoft.storage/storageaccounts' "
        "| project id, name, subscriptionId, resourceGroup, "
        "keySource = tostring(properties.encryption.keySource), "
        "requireInfraEnc = properties.encryption.requireInfrastructureEncryption, "
        "keyExpirationDays = properties.keyPolicy.keyExpirationPeriodInDays, "
        "sasExpiration = tostring(properties.sasPolicy.sasExpirationPeriod)"
    ),
    # Storage blob-service soft delete (CIS 4.10). The blobServices/default child always carries
    # the retention policy, so a missing/false enabled flag is a definite finding.
    "storage_blob_soft_delete": (
        "Resources | where type =~ 'microsoft.storage/storageaccounts/blobservices' "
        "| extend accId = tostring(split(id, '/blobServices/')[0]) "
        "| extend seg = split(accId, '/') "
        "| project id = accId, name = tostring(seg[array_length(seg) - 1]), "
        "subscriptionId, resourceGroup, "
        "deleteEnabled = properties.deleteRetentionPolicy.enabled, "
        "containerDeleteEnabled = properties.containerDeleteRetentionPolicy.enabled"
    ),
    # Threat protection -----------------------------------------------------
    "defender_pricings": (
        "securityresources | where type =~ 'microsoft.security/pricings' "
        "| project id, name, subscriptionId, "
        "pricingTier = properties.pricingTier, "
        # Per-plan sub-components (each {name, isEnabled}); drives the Defender component rules.
        "extensions = properties.extensions"
    ),
    "defender_autoprovisioning": (
        "securityresources | where type =~ 'microsoft.security/autoprovisioningsettings' "
        "| project id, name, subscriptionId, "
        "autoProvision = tostring(properties.autoProvision)"
    ),
    # Subscriptions with NO Defender security contact. The absence is resolved in KQL (a left-join
    # of every subscription against the security-contacts resource), using only stable `type`
    # filters, so a schema change to the contact's own fields can never produce a false finding.
    "defender_security_contacts_missing": (
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
        "| project subscriptionId, subName = name "
        "| join kind=leftouter (securityresources "
        "| where type =~ 'microsoft.security/securitycontacts' "
        "| summarize contacts = count() by subscriptionId) on subscriptionId "
        "| extend contacts = coalesce(contacts, 0) "
        "| where contacts == 0 "
        "| project id = strcat('/subscriptions/', subscriptionId), name = subName, subscriptionId"
    ),
    # Resource firewalls (config AzureHound does not always carry) -----------
    "app_services_config": (
        "Resources | where type =~ 'microsoft.web/sites' "
        "| project id, name, subscriptionId, resourceGroup, kind, "
        "httpsOnly = properties.httpsOnly, "
        "minTlsVersion = properties.siteConfig.minTlsVersion, "
        "ftpsState = properties.siteConfig.ftpsState, "
        "remoteDebugging = properties.siteConfig.remoteDebuggingEnabled, "
        "http20Enabled = properties.siteConfig.http20Enabled, "
        "httpLoggingEnabled = properties.siteConfig.httpLoggingEnabled, "
        "identityType = identity.type, "
        "publicNetworkAccess = properties.publicNetworkAccess"
    ),
    # App Services with NO enabled authentication (EasyAuth). Absence resolved by a left-join
    # against the authsettingsV2 config child, so every returned row is a site with auth off.
    "appservice_auth_missing": (
        "Resources | where type =~ 'microsoft.web/sites' "
        "| project siteId = id, name, subscriptionId, resourceGroup "
        "| join kind=leftouter (Resources "
        "  | where type =~ 'microsoft.web/sites/config' and name endswith 'authsettingsV2' "
        "  | extend siteId = tostring(split(id, '/config/')[0]), "
        "    enabled = tobool(properties.platform.enabled) "
        "  | where enabled == true | summarize authOn = count() by siteId) on siteId "
        "| extend authOn = coalesce(authOn, 0) | where authOn == 0 "
        "| project id = siteId, name, subscriptionId, resourceGroup"
    ),
    # App Services where basic (publishing) authentication is still ALLOWED on ftp or scm. Each
    # returned row is a site+policy with basic auth enabled.
    "appservice_basic_auth": (
        "Resources | where type =~ 'microsoft.web/sites/basicpublishingcredentialspolicies' "
        "| where properties.allow == true "
        "| project id = tostring(split(id, '/basicPublishingCredentialsPolicies/')[0]), "
        "name, subscriptionId, resourceGroup, policy = name"
    ),
    # Containers ------------------------------------------------------------
    "aks_clusters": (
        "Resources | where type =~ 'microsoft.containerservice/managedclusters' "
        "| project id, name, subscriptionId, resourceGroup, "
        "disableLocalAccounts = properties.disableLocalAccounts, "
        "enableRBAC = properties.enableRBAC, "
        "privateCluster = properties.apiServerAccessProfile.enablePrivateCluster, "
        "authorizedIPRanges = properties.apiServerAccessProfile.authorizedIPRanges"
    ),
    "acr_registries": (
        "Resources | where type =~ 'microsoft.containerregistry/registries' "
        "| project id, name, subscriptionId, resourceGroup, "
        "adminUserEnabled = properties.adminUserEnabled, "
        "anonymousPullEnabled = properties.anonymousPullEnabled, "
        "publicNetworkAccess = properties.publicNetworkAccess"
    ),
    "container_apps": (
        "Resources | where type =~ 'microsoft.app/containerapps' "
        "| project id, name, subscriptionId, resourceGroup, "
        "external = properties.configuration.ingress.external"
    ),
    # Compute / storage media ----------------------------------------------
    "managed_disks": (
        "Resources | where type =~ 'microsoft.compute/disks' "
        "| project id, name, subscriptionId, resourceGroup, "
        "networkAccessPolicy = properties.networkAccessPolicy, "
        "publicNetworkAccess = properties.publicNetworkAccess, "
        "encryptionType = tostring(properties.encryption.type), "
        "dataAccessAuthMode = tostring(properties.dataAccessAuthMode)"
    ),
    # VMs whose OS disk is UNMANAGED (an explicit vhd blob rather than a managed disk). Managed
    # disks give platform encryption, RBAC and snapshot management that classic VHDs lack.
    "vm_unmanaged_disk": (
        "Resources | where type =~ 'microsoft.compute/virtualmachines' "
        "| where isnotnull(properties.storageProfile.osDisk.vhd) "
        "| project id, name, subscriptionId, resourceGroup"
    ),
    # NSG flow logs that ARE enabled but retain for a finite period of 90 days or less (0 = retain
    # forever, which is compliant and excluded here).
    "nsg_flowlog_short_retention": (
        "resources | where type =~ 'microsoft.network/networkwatchers/flowlogs' "
        "| where properties.enabled == true "
        "| extend days = toint(properties.retentionPolicy.days) "
        "| where days > 0 and days <= 90 "
        "| project id, name, subscriptionId, resourceGroup, days"
    ),
    # Subscriptions with NO Network Watcher at all (absence resolved in KQL).
    "network_watcher_missing": (
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
        "| project subscriptionId, subName = name "
        "| join kind=leftouter (resources | where type =~ 'microsoft.network/networkwatchers' "
        "  | summarize nw = count() by subscriptionId) on subscriptionId "
        "| extend nw = coalesce(nw, 0) | where nw == 0 "
        "| project id = strcat('/subscriptions/', subscriptionId), name = subName, subscriptionId"
    ),
    # Caches, messaging, gateways, AI ---------------------------------------
    "redis_caches": (
        "Resources | where type =~ 'microsoft.cache/redis' "
        "| project id, name, subscriptionId, resourceGroup, "
        "enableNonSslPort = properties.enableNonSslPort, "
        "minimumTlsVersion = properties.minimumTlsVersion, "
        "publicNetworkAccess = properties.publicNetworkAccess"
    ),
    "servicebus_namespaces": (
        "Resources | where type =~ 'microsoft.servicebus/namespaces' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.publicNetworkAccess, "
        "disableLocalAuth = properties.disableLocalAuth, "
        "minimumTlsVersion = properties.minimumTlsVersion"
    ),
    "eventhub_namespaces": (
        "Resources | where type =~ 'microsoft.eventhub/namespaces' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.publicNetworkAccess, "
        "disableLocalAuth = properties.disableLocalAuth, "
        "minimumTlsVersion = properties.minimumTlsVersion"
    ),
    "apim_services": (
        "Resources | where type =~ 'microsoft.apimanagement/service' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.publicNetworkAccess"
    ),
    "cognitive_accounts": (
        "Resources | where type =~ 'microsoft.cognitiveservices/accounts' "
        "| project id, name, subscriptionId, resourceGroup, kind, "
        "publicNetworkAccess = properties.publicNetworkAccess, "
        "disableLocalAuth = properties.disableLocalAuth"
    ),
    # Logging / monitoring SETTINGS (whether audit logging is ENABLED). These read only the
    # presence of a diagnostic/flow-log setting, never any log contents or tenant data. Each
    # resolves ABSENCE in KQL via a left-join against microsoft.insights/diagnosticSettings
    # (the same technique as defender_security_contacts_missing), so a schema change to the
    # setting's own fields can never produce a false finding.
    "keyvault_diagnostics_missing": (
        "resources | where type =~ 'microsoft.keyvault/vaults' "
        "| extend pid = tolower(id) "
        "| join kind=leftouter (resources "
        "  | where type =~ 'microsoft.insights/diagnosticsettings' "
        "  | extend pid = tolower(substring(id, 0, indexof(id, '/providers/microsoft.insights/diagnosticsettings'))) "
        "  | summarize diag = count() by pid) on pid "
        "| extend diag = coalesce(diag, 0) | where diag == 0 "
        "| project id, name, subscriptionId, resourceGroup"
    ),
    "storage_diagnostics_missing": (
        "resources | where type =~ 'microsoft.storage/storageaccounts' "
        "| extend pid = tolower(id) "
        "| join kind=leftouter (resources "
        "  | where type =~ 'microsoft.insights/diagnosticsettings' "
        "  | extend pid = tolower(substring(id, 0, indexof(id, '/providers/microsoft.insights/diagnosticsettings'))) "
        "  | summarize diag = count() by pid) on pid "
        "| extend diag = coalesce(diag, 0) | where diag == 0 "
        "| project id, name, subscriptionId, resourceGroup"
    ),
    # Subscriptions with NO activity-log export (no subscription-scoped diagnostic setting), so
    # the control-plane audit trail is not retained anywhere.
    "subscription_activitylog_missing": (
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
        "| project subscriptionId, subName = name "
        "| join kind=leftouter (resources "
        "  | where type =~ 'microsoft.insights/diagnosticsettings' "
        "  | where id startswith '/subscriptions/' and id !has '/resourcegroups/' "
        "  | summarize diag = count() by subscriptionId) on subscriptionId "
        "| extend diag = coalesce(diag, 0) | where diag == 0 "
        "| project id = strcat('/subscriptions/', subscriptionId), name = subName, subscriptionId"
    ),
    # Network Security Groups with NO flow log configured (no network-flow visibility).
    "nsg_flowlogs_missing": (
        "resources | where type =~ 'microsoft.network/networksecuritygroups' "
        "| extend pid = tolower(id) "
        "| join kind=leftouter (resources "
        "  | where type =~ 'microsoft.network/networkwatchers/flowlogs' "
        "  | extend pid = tolower(tostring(properties.targetResourceId)) "
        "  | summarize flows = count() by pid) on pid "
        "| extend flows = coalesce(flows, 0) | where flows == 0 "
        "| project id, name, subscriptionId, resourceGroup"
    ),
    # Per subscription, the set of operationNames that have an ENABLED activity-log alert. Every
    # subscription appears (left-join), with an empty set when it has no alerts, so a rule can flag
    # a subscription that is missing the alert for a specific operation without false positives.
    "activity_log_alerts": (
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
        "| project subscriptionId, subName = name "
        "| join kind=leftouter (resources "
        "  | where type =~ 'microsoft.insights/activitylogalerts' "
        "  | where properties.enabled == true "
        "  | mv-expand cond = properties.condition.allOf "
        "  | where tostring(cond.field) =~ 'operationName' "
        "  | extend op = tolower(tostring(cond.equals)) "
        "  | summarize alertedOps = make_set(op) by subscriptionId) on subscriptionId "
        "| extend alertedOps = coalesce(alertedOps, dynamic([])) "
        "| project id = strcat('/subscriptions/', subscriptionId), name = subName, "
        "subscriptionId, alertedOps"
    ),
    # Subscriptions with NO Azure Bastion host, so administrative RDP/SSH has no managed
    # broker and tends to be reached over direct public exposure instead.
    "bastion_hosts_missing": (
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
        "| project subscriptionId, subName = name "
        "| join kind=leftouter (resources "
        "  | where type =~ 'microsoft.network/bastionhosts' "
        "  | summarize bastions = count() by subscriptionId) on subscriptionId "
        "| extend bastions = coalesce(bastions, 0) | where bastions == 0 "
        "| project id = strcat('/subscriptions/', subscriptionId), name = subName, subscriptionId"
    ),
}


# Collection record kind carrying Azure Resource Graph rows, so an uploaded (or demo)
# collection can drive the resource-config rules deterministically, exactly as a live ARG
# collection does. Each record is {"query": "<ARG_QUERIES key>", "rows": [ {row}, ... ]}.
RESOURCE_GRAPH_KIND = "AZResourceGraphResult"


def arg_result_from_records(records: "list[dict]") -> "ArgResult | None":
    """Build an ArgResult from ingested AZResourceGraphResult records, so `run_arg_rules`
    can assess a FILE collection (and the bundled demo), not only a live ARG pull. Returns
    None when the collection carries no resource-graph records (plain AzureHound dump)."""
    rows: dict[str, list[dict]] = {}
    seen = False
    for r in records:
        if r.get("kind") != RESOURCE_GRAPH_KIND:
            continue
        d = r.get("data") or {}
        key = d.get("query")
        if not key:
            continue
        seen = True
        rows.setdefault(key, []).extend(d.get("rows") or [])
    if not seen:
        return None
    return ArgResult(rows=rows)


def _read_dotenv() -> dict:
    """Parse a `.env` file in the working directory into a dict, no external
    dependency. The app runs with its cwd at the project root (start.sh cd's there),
    so a project-root `.env` is found; a CLI run finds a `.env` in the directory it is
    run from. Tolerant of blank lines, `#` comments, an optional `export ` prefix, and
    single/double quotes. `PH_DOTENV` overrides the path. Never raises."""
    import pathlib
    out: dict = {}
    try:
        p = pathlib.Path(os.environ.get("PH_DOTENV") or (pathlib.Path.cwd() / ".env"))
        if not p.is_file():
            return out
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        return out
    return out


def credentials_from_settings() -> "ArgCredentials | None":
    """Assemble the Reader-SP credentials, in precedence order (per field):

      1. the values stored in Settings, an explicit Settings entry ALWAYS wins, so
         changing the SP in the UI takes effect immediately and is never shadowed by a
         stale .env / environment value.
      2. real environment variables (PH_ARG_TENANT_ID / _CLIENT_ID / _CLIENT_SECRET)
      3. a .env file (cwd or repo root), either the PH_ARG_* names OR the standard
         Azure names AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET

    So env / .env only supply a field the operator has left blank in Settings; the
    moment they type a value in Settings, that value is authoritative. Returns None if
    no usable credential set is present.
    """
    try:
        from . import store
        s = store.get_settings()
    except Exception:
        s = {}
    env = _read_dotenv()

    def _resolve(ph_key, azure_key, settings_key):
        return (s.get(settings_key)
                or os.environ.get(ph_key)
                or env.get(ph_key) or env.get(azure_key) or "").strip()

    tenant = _resolve("PH_ARG_TENANT_ID", "AZURE_TENANT_ID", "arg_tenant_id")
    client_id = _resolve("PH_ARG_CLIENT_ID", "AZURE_CLIENT_ID", "arg_client_id")
    secret = _resolve("PH_ARG_CLIENT_SECRET", "AZURE_CLIENT_SECRET", "arg_client_secret")
    creds = ArgCredentials(tenant_id=tenant, client_id=client_id, client_secret=secret)
    return creds if creds.ok() else None


def _default_client():
    """An httpx client that survives a stale corporate SSL_CERT_FILE, mirroring
    ai_findings.build_client, a missing bundle path must degrade to system trust,
    not crash the collector."""
    import httpx
    cert = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if cert and not os.path.exists(cert):
        try:
            ctx = ssl.create_default_context()
            return httpx.Client(verify=ctx, timeout=60, trust_env=False)
        except Exception:
            return httpx.Client(verify=False, timeout=60, trust_env=False)  # noqa: S501
    return httpx.Client(timeout=60)


def get_token(creds: ArgCredentials, client) -> str:
    """OAuth2 client-credentials token for ARM. Raises on failure (caller wraps)."""
    resp = client.post(
        f"{_AUTHORITY}/{creds.tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scope": _ARM_SCOPE,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    tok = resp.json().get("access_token")
    if not tok:
        raise RuntimeError("token endpoint returned no access_token")
    return tok


_RETRY_STATUS = {429, 503}
_MAX_RETRIES = 5
_MAX_RETRY_WAIT = 60.0   # cap a server-sent Retry-After so a scan can't hang for minutes


def _sleep_for_retry(resp, attempt: int) -> None:
    """Honour a Retry-After header (seconds), else exponential backoff, capped.
    Calls time.sleep via the module so tests can patch it."""
    ra = resp.headers.get("Retry-After") if hasattr(resp, "headers") else None
    try:
        delay = float(ra) if ra is not None else min(2.0 ** attempt, _MAX_RETRY_WAIT)
    except (TypeError, ValueError):
        delay = min(2.0 ** attempt, _MAX_RETRY_WAIT)
    time.sleep(min(delay, _MAX_RETRY_WAIT))


def _send_with_retry(fn):
    """Call an httpx request thunk, retrying throttling/transient responses.

    Azure Resource Graph enforces a per-tenant query quota and returns 429 with a
    Retry-After when it is exhausted; without honouring it, one throttled query
    dropped a whole domain to not_assessed. Retries 429/503 up to _MAX_RETRIES,
    honouring Retry-After, then lets raise_for_status surface a persistent failure."""
    resp = None
    for attempt in range(_MAX_RETRIES + 1):
        resp = fn()
        if resp.status_code in _RETRY_STATUS and attempt < _MAX_RETRIES:
            _sleep_for_retry(resp, attempt)
            continue
        break
    resp.raise_for_status()
    return resp


def list_subscriptions(token: str, client) -> list[str]:
    out = []
    url = _SUBSCRIPTIONS_URL
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(_MAX_PAGES):
        resp = _send_with_retry(lambda url=url: client.get(url, headers=headers))
        payload = resp.json()
        for s in payload.get("value", []):
            sid = s.get("subscriptionId")
            state = (s.get("state") or "").lower()
            if sid and state in ("", "enabled"):
                out.append(sid)
        url = payload.get("nextLink")
        if not url:
            break
    return out


_ARG_SUBS_PER_REQUEST = 1000   # Azure Resource Graph rejects a larger subscriptions array


def run_query(token: str, kql: str, subscriptions: list[str], client) -> list[dict]:
    """Run one KQL query across the given subscriptions, following $skipToken paging.

    Azure Resource Graph caps the `subscriptions` array at 1000 per request, so a
    tenant with more subscriptions is queried in chunks and the rows concatenated.

    Paging is stabilised with an explicit sort. Azure Resource Graph's $skipToken paging
    is only consistent when the query has an `order by`; without one, rows can be silently
    skipped or duplicated across page boundaries, so a tenant with more than one page of a
    resource type collected a slightly different set each run, making the SAME tenant score
    differently scan to scan. Sorting by `id` (every query projects it) makes the collected
    set complete and deterministic. Duplicate rows would collapse in the graph build anyway,
    but a skipped row is unrecoverable, which is what this prevents.
    """
    if "order by" not in kql.lower():
        kql = kql.rstrip() + "\n| order by id asc"
    if len(subscriptions) > _ARG_SUBS_PER_REQUEST:
        rows: list[dict] = []
        for i in range(0, len(subscriptions), _ARG_SUBS_PER_REQUEST):
            rows.extend(run_query(token, kql,
                                  subscriptions[i:i + _ARG_SUBS_PER_REQUEST], client))
        return rows

    rows = []
    skip_token = None
    for _ in range(_MAX_PAGES):
        options = {"$top": _ARG_PAGE_SIZE, "resultFormat": "objectArray"}
        if skip_token:
            options["$skipToken"] = skip_token
        body = {"query": kql, "options": options}
        if subscriptions:
            body["subscriptions"] = subscriptions
        resp = _send_with_retry(lambda body=body: client.post(
            _ARG_ENDPOINT, json=body,
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"}))
        payload = resp.json()
        rows.extend(payload.get("data") or [])
        skip_token = payload.get("$skipToken") or payload.get("skipToken")
        if not skip_token:
            break
    return rows


def probe(creds: "ArgCredentials | None" = None, *, client=None) -> dict:
    """Validate the Reader service principal: authenticate and run one trivial
    ARG count query. Returns {ok, message, subscriptions}, never raises. Used by
    the Settings 'Test connection' control so the SP can be set up before a scan."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return {"ok": False, "message": "No Azure Resource Graph service principal configured.",
                "subscriptions": 0}
    owns = client is None
    client = client or _default_client()
    try:
        try:
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": f"Authentication failed: {type(e).__name__}: {e}",
                    "subscriptions": 0}
        try:
            subs = list_subscriptions(token, client)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": f"Authenticated, but cannot list subscriptions "
                    f"(grant the SP Reader): {e}", "subscriptions": 0}
        try:
            run_query(token, "Resources | limit 1", subs, client)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": f"Authenticated, but the Resource Graph query "
                    f"failed: {e}", "subscriptions": len(subs)}
        return {"ok": True, "message": f"Connected, {len(subs)} subscription(s) readable via "
                "Azure Resource Graph.", "subscriptions": len(subs)}
    finally:
        if owns:
            try:
                client.close()
            except Exception:
                pass


def collect(creds: "ArgCredentials | None" = None, *, client=None,
            on_progress=None) -> "ArgResult | None":
    """Collect the curated ARG query set. Returns None when no SP is configured.

    Never raises: authentication and per-query errors are recorded in the result's
    `errors` list so the scan can note them without failing.
    """
    creds = creds or credentials_from_settings()
    if creds is None:
        return None

    def _log(m):
        if on_progress:
            on_progress(m)

    owns_client = client is None
    client = client or _default_client()
    result = ArgResult()
    try:
        try:
            _log("[ARG] Authenticating the Reader service principal…")
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001, surface, never crash the scan
            result.errors.append(f"authentication failed: {type(e).__name__}: {e}")
            return result
        try:
            result.subscription_ids = list_subscriptions(token, client)
            _log(f"[ARG] {len(result.subscription_ids)} subscription(s) in scope.")
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"subscription enumeration failed: {e}")
            # ARG can still run tenant-wide with an empty subscription list.
        for key, kql in ARG_QUERIES.items():
            try:
                rows = run_query(token, kql, result.subscription_ids, client)
                result.rows[key] = rows
                _log(f"[ARG] {key}: {len(rows)} row(s).")
            except Exception as e:  # noqa: BLE001
                result.errors.append(f"query '{key}' failed: {e}")
        return result
    finally:
        if owns_client:
            try:
                client.close()
            except Exception:
                pass


# ── Resource-object collection (live SP equivalent of AzureHound's rm.json) ──────
# AzureHound's resource collection provides the individual resource OBJECTS (VMs, Key
# Vaults, storage accounts, AKS, ACR, automation/function/logic/web apps, VMSS) with
# their managed identities, Key Vault access policies and security config. Those are
# what the resource-plane abuse-edge derivations need: without the resource node and its
# managed-identity edge there is no managed-identity theft, no Key Vault data-plane reach,
# no storage-key / blob / ACR-push / AKS-exec edge. A read-only Reader SP can read all of
# it from Azure Resource Graph, so a live collection no longer needs an rm.json upload.

# ARM resource type -> AzureHound node kind. microsoft.web/sites is split into
# AZFunctionApp vs AZWebApp by the resource's `kind` field.
_RESOURCE_TYPE_KIND: dict[str, str] = {
    "microsoft.compute/virtualmachines":            "AZVM",
    "microsoft.keyvault/vaults":                    "AZKeyVault",
    "microsoft.storage/storageaccounts":            "AZStorageAccount",
    "microsoft.containerservice/managedclusters":   "AZManagedCluster",
    "microsoft.containerregistry/registries":       "AZContainerRegistry",
    "microsoft.automation/automationaccounts":      "AZAutomationAccount",
    "microsoft.logic/workflows":                    "AZLogicApp",
    "microsoft.compute/virtualmachinescalesets":    "AZVMScaleSet",
}

# The resource-config properties the deterministic rules read, each `requires_props`-gated:
# a rule that reads one of these is reported "not assessed" unless the collection carries it,
# so EVERY field a KV/Storage/VM rule depends on must be projected here or that rule can never
# fire on a live-SP scan. (alias, property-name), alias is "p_" + the ARM property name.
# `accessPolicies` is handled separately (emitted as AZKeyVaultAccessPolicy records, not props).
_RESOURCE_PROP_FIELDS: tuple[tuple[str, str], ...] = (
    # Key Vault config
    ("p_enableRbacAuthorization", "enableRbacAuthorization"),
    ("p_enablePurgeProtection", "enablePurgeProtection"),
    ("p_enableSoftDelete", "enableSoftDelete"),
    ("p_softDeleteRetentionInDays", "softDeleteRetentionInDays"),
    ("p_enabledForDeployment", "enabledForDeployment"),
    ("p_enabledForTemplateDeployment", "enabledForTemplateDeployment"),
    # Storage config
    ("p_allowBlobPublicAccess", "allowBlobPublicAccess"),
    ("p_allowSharedKeyAccess", "allowSharedKeyAccess"),
    ("p_minimumTlsVersion", "minimumTlsVersion"),
    ("p_supportsHttpsTrafficOnly", "supportsHttpsTrafficOnly"),
    ("p_allowCrossTenantReplication", "allowCrossTenantReplication"),
    ("p_publicNetworkAccess", "publicNetworkAccess"),
    # Firewall + private endpoints (both Key Vault and Storage)
    ("p_networkAcls", "networkAcls"),
    ("p_privateEndpointConnections", "privateEndpointConnections"),
    # Virtual-machine security posture (Trusted Launch)
    ("p_securityProfile", "securityProfile"),
)

# One Resource Graph query pulls every resource-object we model. Only the identity object,
# Key Vault access policies, and the specific config fields the rules read are projected, to
# keep payloads bounded (full VM/AKS `properties` blobs are large and mostly unused).
_RESOURCE_OBJECTS_KQL = (
    "resources "
    "| where type in~ ("
    "'microsoft.compute/virtualmachines','microsoft.keyvault/vaults',"
    "'microsoft.storage/storageaccounts','microsoft.containerservice/managedclusters',"
    "'microsoft.containerregistry/registries','microsoft.automation/automationaccounts',"
    "'microsoft.web/sites','microsoft.logic/workflows',"
    "'microsoft.compute/virtualmachinescalesets') "
    "| project id, name, type, kind, subscriptionId, resourceGroup, identity, "
    "p_accessPolicies = properties.accessPolicies, "
    # Logic App: only the trigger map is needed (AZ-LOGIC-001), not the whole workflow body.
    "p_definitionTriggers = properties.definition.triggers, "
    + ", ".join(f"{alias} = properties.{name}" for alias, name in _RESOURCE_PROP_FIELDS)
)


def _resource_kind_for(rtype: "str | None", kind_field: "str | None") -> "str | None":
    rt = (rtype or "").lower()
    if rt == "microsoft.web/sites":
        return "AZFunctionApp" if "functionapp" in (kind_field or "").lower() else "AZWebApp"
    return _RESOURCE_TYPE_KIND.get(rt)


def resource_objects_to_records(rows: "list[dict]") -> "list[dict]":
    """Map Resource Graph resource rows to AzureHound-shaped {kind, data} records.

    Emits, per resource: the resource node (id/name/scope + `identity` for the managed-
    identity edge + a `properties` object carrying the security config the rules read), and
    for each Key Vault, one AZKeyVaultAccessPolicy record per access policy (objectId +
    permissions) so the data-plane reachability edge can be derived. Pure and deterministic,
    so it is unit-testable without a live tenant."""
    records: list[dict] = []
    for r in rows:
        kind = _resource_kind_for(r.get("type"), r.get("kind"))
        if not kind or not r.get("id"):
            continue
        props: dict = {}
        for src, dst in _RESOURCE_PROP_FIELDS:
            if r.get(src) is not None:
                props[dst] = r[src]
        data: dict = {"id": r["id"], "name": r.get("name") or r["id"],
                      "subscriptionId": r.get("subscriptionId"),
                      "resourceGroup": r.get("resourceGroup")}
        ident = r.get("identity")
        if isinstance(ident, dict) and (ident.get("principalId") or ident.get("userAssignedIdentities")):
            data["identity"] = ident
        # Logic App workflow triggers, reconstructed into the shape AZ-LOGIC-001 reads.
        if r.get("p_definitionTriggers") is not None:
            props["definition"] = {"triggers": r["p_definitionTriggers"]}
        if props:
            data["properties"] = props
        records.append({"kind": kind, "data": data})
        # Attach the resource under its resource group so the ARM hierarchy
        # (subscription -> resource group -> resource) is complete for blast-radius and the
        # attack graph. The RG id is the resource id up to the "/providers/" segment; normalize
        # already links the RG to its subscription from the AZResourceGroup record.
        rg_id = r["id"].split("/providers/")[0]
        if "/resourcegroups/" in rg_id.lower() and rg_id.lower() != r["id"].lower():
            records.append({"kind": "AZContains", "data": {"parentId": rg_id, "childId": r["id"]}})
        if kind == "AZKeyVault":
            for ap in (r.get("p_accessPolicies") or []):
                if not isinstance(ap, dict) or not ap.get("objectId"):
                    continue
                records.append({"kind": "AZKeyVaultAccessPolicy", "data": {
                    "keyVaultId": r["id"], "objectId": ap["objectId"],
                    "permissions": ap.get("permissions") or {}}})
    return records


# Resource groups live in the `resourcecontainers` table, not `resources`. They are an
# intermediate ARM scope; collecting them as nodes completes the hierarchy and the coverage
# checklist (RG-scoped RBAC already resolves to resources by scope path, node or not).
_RESOURCE_GROUPS_KQL = (
    "resourcecontainers "
    "| where type =~ 'microsoft.resources/subscriptions/resourcegroups' "
    "| project id, name, subscriptionId, location"
)


def resource_groups_to_records(rows: "list[dict]") -> "list[dict]":
    """Map Resource Graph resource-group rows to AzureHound-shaped AZResourceGroup records."""
    out: list[dict] = []
    for r in rows:
        if not r.get("id"):
            continue
        out.append({"kind": "AZResourceGroup", "data": {
            "id": r["id"], "name": r.get("name") or r["id"],
            "subscriptionId": r.get("subscriptionId"), "location": r.get("location")}})
    return out


def collect_resource_objects(creds: "ArgCredentials | None" = None, *, client=None,
                             on_progress=None) -> "list[dict]":
    """Collect individual Azure resource objects (with managed identities, Key Vault access
    policies and security config) plus resource groups, as AzureHound-shaped records, via
    Azure Resource Graph. Read-only (Reader). Never raises, auth/query failures are logged
    and yield []."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return []
    owns_client = client is None
    client = client or _default_client()
    try:
        try:
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001, surface, never crash the scan
            if on_progress:
                on_progress(f"[ARG] resource-object collection: authentication failed ({e})")
            return []
        try:
            subs = list_subscriptions(token, client)
        except Exception:  # noqa: BLE001, ARG can still run tenant-wide
            subs = []
        try:
            rows = run_query(token, _RESOURCE_OBJECTS_KQL, subs, client)
        except Exception as e:  # noqa: BLE001
            if on_progress:
                on_progress(f"[ARG] resource-object query failed ({e})")
            return []
        records = resource_objects_to_records(rows)
        # Resource groups (separate `resourcecontainers` table), best-effort; their absence
        # never breaks analysis, so a failed RG query does not discard the resource objects.
        rg_records: list[dict] = []
        try:
            rg_rows = run_query(token, _RESOURCE_GROUPS_KQL, subs, client)
            rg_records = resource_groups_to_records(rg_rows)
        except Exception as e:  # noqa: BLE001
            if on_progress:
                on_progress(f"[ARG] resource-group query failed ({e})")
        records += rg_records
        if on_progress:
            kv = sum(1 for r in records if r["kind"] == "AZKeyVaultAccessPolicy")
            on_progress(f"[ARG] Collected {len(rows)} resource object(s) "
                        f"({len(records) - kv - len(rg_records)} node(s), {kv} Key Vault access "
                        f"polic(ies)) and {len(rg_records)} resource group(s).")
        return records
    finally:
        if owns_client:
            try:
                client.close()
            except Exception:
                pass
