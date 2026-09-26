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
verified against live output before rules are written on top of them - that is the
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


# Curated KQL for the v2 priority domains. Raw rows only - field paths are
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
        "state = properties.state"
    ),
    "cosmos_accounts": (
        "Resources | where type =~ 'microsoft.documentdb/databaseaccounts' "
        "| project id, name, subscriptionId, resourceGroup, "
        "publicNetworkAccess = properties.publicNetworkAccess, "
        "disableLocalAuth = properties.disableLocalAuth, "
        "ipRules = properties.ipRules"
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
    # Threat protection -----------------------------------------------------
    "defender_pricings": (
        "securityresources | where type =~ 'microsoft.security/pricings' "
        "| project id, name, subscriptionId, "
        "pricingTier = properties.pricingTier"
    ),
    # Resource firewalls (config AzureHound does not always carry) -----------
    "app_services_config": (
        "Resources | where type =~ 'microsoft.web/sites' "
        "| project id, name, subscriptionId, resourceGroup, kind, "
        "httpsOnly = properties.httpsOnly, "
        "minTlsVersion = properties.siteConfig.minTlsVersion, "
        "ftpsState = properties.siteConfig.ftpsState, "
        "remoteDebugging = properties.siteConfig.remoteDebuggingEnabled, "
        "identityType = identity.type, "
        "publicNetworkAccess = properties.publicNetworkAccess"
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
        "publicNetworkAccess = properties.publicNetworkAccess"
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
}


def _read_dotenv() -> dict:
    """Parse a `.env` file in the working directory into a dict - no external
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
    """Assemble the Reader-SP credentials, in precedence order:

      1. real environment variables (PH_ARG_TENANT_ID / _CLIENT_ID / _CLIENT_SECRET)
      2. a .env file (cwd or repo root) - either the PH_ARG_* names OR the standard
         Azure names AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
      3. the values stored in Settings

    So the secret can live in a git-ignored .env and never be persisted to
    settings.json. Returns None if no usable credential set is present.
    """
    try:
        from . import store
        s = store.get_settings()
    except Exception:
        s = {}
    env = _read_dotenv()

    def _resolve(ph_key, azure_key, settings_key):
        return (os.environ.get(ph_key)
                or env.get(ph_key) or env.get(azure_key)
                or s.get(settings_key) or "").strip()

    tenant = _resolve("PH_ARG_TENANT_ID", "AZURE_TENANT_ID", "arg_tenant_id")
    client_id = _resolve("PH_ARG_CLIENT_ID", "AZURE_CLIENT_ID", "arg_client_id")
    secret = _resolve("PH_ARG_CLIENT_SECRET", "AZURE_CLIENT_SECRET", "arg_client_secret")
    creds = ArgCredentials(tenant_id=tenant, client_id=client_id, client_secret=secret)
    return creds if creds.ok() else None


def _default_client():
    """An httpx client that survives a stale corporate SSL_CERT_FILE, mirroring
    ai_findings.build_client - a missing bundle path must degrade to system trust,
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
    resource type collected a slightly different set each run - making the SAME tenant score
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
    ARG count query. Returns {ok, message, subscriptions} - never raises. Used by
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
        return {"ok": True, "message": f"Connected - {len(subs)} subscription(s) readable via "
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
        except Exception as e:  # noqa: BLE001 - surface, never crash the scan
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

# One Resource Graph query pulls every resource-object we model. Only the identity object
# and the specific config fields the rules read are projected, to keep payloads bounded
# (full VM/AKS `properties` blobs are large and unused).
_RESOURCE_OBJECTS_KQL = (
    "resources "
    "| where type in~ ("
    "'microsoft.compute/virtualmachines','microsoft.keyvault/vaults',"
    "'microsoft.storage/storageaccounts','microsoft.containerservice/managedclusters',"
    "'microsoft.containerregistry/registries','microsoft.automation/automationaccounts',"
    "'microsoft.web/sites','microsoft.logic/workflows',"
    "'microsoft.compute/virtualmachinescalesets') "
    "| project id, name, type, kind, subscriptionId, resourceGroup, identity, "
    "p_enableRbacAuthorization = properties.enableRbacAuthorization, "
    "p_enablePurgeProtection = properties.enablePurgeProtection, "
    "p_enableSoftDelete = properties.enableSoftDelete, "
    "p_accessPolicies = properties.accessPolicies, "
    "p_allowBlobPublicAccess = properties.allowBlobPublicAccess"
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
        for src, dst in (("p_enableRbacAuthorization", "enableRbacAuthorization"),
                         ("p_enablePurgeProtection", "enablePurgeProtection"),
                         ("p_enableSoftDelete", "enableSoftDelete"),
                         ("p_allowBlobPublicAccess", "allowBlobPublicAccess")):
            if r.get(src) is not None:
                props[dst] = r[src]
        data: dict = {"id": r["id"], "name": r.get("name") or r["id"],
                      "subscriptionId": r.get("subscriptionId"),
                      "resourceGroup": r.get("resourceGroup")}
        ident = r.get("identity")
        if isinstance(ident, dict) and (ident.get("principalId") or ident.get("userAssignedIdentities")):
            data["identity"] = ident
        if props:
            data["properties"] = props
        records.append({"kind": kind, "data": data})
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
    Azure Resource Graph. Read-only (Reader). Never raises - auth/query failures are logged
    and yield []."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return []
    owns_client = client is None
    client = client or _default_client()
    try:
        try:
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001 - surface, never crash the scan
            if on_progress:
                on_progress(f"[ARG] resource-object collection: authentication failed ({e})")
            return []
        try:
            subs = list_subscriptions(token, client)
        except Exception:  # noqa: BLE001 - ARG can still run tenant-wide
            subs = []
        try:
            rows = run_query(token, _RESOURCE_OBJECTS_KQL, subs, client)
        except Exception as e:  # noqa: BLE001
            if on_progress:
                on_progress(f"[ARG] resource-object query failed ({e})")
            return []
        records = resource_objects_to_records(rows)
        # Resource groups (separate `resourcecontainers` table) - best-effort; their absence
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
