"""Microsoft Graph collector for identity-plane config (PostureHound v2, Track B).

AzureHound and Azure Resource Graph both miss the tenant's identity *security
posture* - Conditional Access policy state, MFA enforcement, legacy-auth blocking,
security defaults. This module reads it from Microsoft Graph using the same
service-principal client-credentials flow as azure_arg, with the Graph scope.

Note on permissions: the ARM Reader role does NOT grant Graph access. For this
collector the service principal additionally needs the Graph application
permission Policy.Read.All (admin-consented). Without it Graph returns 403 and
this collector records "not collected" - never a false pass.

Same contract as azure_arg: injectable HTTP (tested with httpx.MockTransport),
graceful when unconfigured, never raises into a scan.
"""
from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field

from .azure_arg import ArgCredentials, _send_with_retry, credentials_from_settings  # reuse SP creds + throttling

_AUTHORITY = "https://login.microsoftonline.com"
_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_MAX_PAGES = 100


@dataclass
class GraphResult:
    ca_policies: list[dict] = field(default_factory=list)
    security_defaults_enabled: "bool | None" = None
    collected: dict[str, bool] = field(default_factory=dict)   # endpoint -> succeeded
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return any(self.collected.values())


def _default_client():
    import httpx
    cert = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if cert and not os.path.exists(cert):
        try:
            return httpx.Client(verify=ssl.create_default_context(), timeout=60, trust_env=False)
        except Exception:
            return httpx.Client(verify=False, timeout=60, trust_env=False)  # noqa: S501
    return httpx.Client(timeout=60)


def get_token(creds: ArgCredentials, client) -> str:
    resp = client.post(
        f"{_AUTHORITY}/{creds.tenant_id}/oauth2/v2.0/token",
        data={"grant_type": "client_credentials", "client_id": creds.client_id,
              "client_secret": creds.client_secret, "scope": _GRAPH_SCOPE},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    tok = resp.json().get("access_token")
    if not tok:
        raise RuntimeError("token endpoint returned no access_token")
    return tok


def _get_all(token: str, url: str, client) -> list[dict]:
    """GET a Graph collection, following @odata.nextLink. Honours Graph throttling
    (429/Retry-After) via the shared retry wrapper."""
    out: list[dict] = []
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(_MAX_PAGES):
        resp = _send_with_retry(lambda url=url: client.get(url, headers=headers))
        payload = resp.json()
        out.extend(payload.get("value") or [])
        url = payload.get("@odata.nextLink")
        if not url:
            break
    return out


def probe(creds: "ArgCredentials | None" = None, *, client=None) -> dict:
    """Validate the SP's Microsoft Graph access: authenticate and read one
    Conditional Access policy page. Returns {ok, message} - never raises. This is
    a DIFFERENT permission from ARM Reader (it needs Policy.Read.All), so it is
    checked separately from the Resource Graph probe."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return {"ok": False, "message": "No service principal configured."}
    owns = client is None
    client = client or _default_client()
    try:
        try:
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": f"Graph authentication failed: {type(e).__name__}: {e}"}
        try:
            policies = _get_all(token, f"{_GRAPH}/identity/conditionalAccess/policies", client)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": "Authenticated, but reading Conditional Access "
                    f"failed - grant the SP Policy.Read.All and admin-consent it ({e})"}
        return {"ok": True, "message": f"Microsoft Graph OK - {len(policies)} Conditional "
                "Access policy(ies) readable."}
    finally:
        if owns:
            try:
                client.close()
            except Exception:
                pass


def collect(creds: "ArgCredentials | None" = None, *, client=None,
            on_progress=None) -> "GraphResult | None":
    """Collect identity-plane config from Microsoft Graph. None when no SP.

    Never raises: per-endpoint failures (including a 403 from a missing Graph
    permission) are recorded in the result, so the scan can note them.
    """
    creds = creds or credentials_from_settings()
    if creds is None:
        return None

    def _log(m):
        if on_progress:
            on_progress(m)

    owns = client is None
    client = client or _default_client()
    result = GraphResult()
    try:
        try:
            _log("[Graph] Authenticating for Microsoft Graph…")
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"authentication failed: {type(e).__name__}: {e}")
            return result
        try:
            result.ca_policies = _get_all(
                token, f"{_GRAPH}/identity/conditionalAccess/policies", client)
            result.collected["conditionalAccess"] = True
            _log(f"[Graph] {len(result.ca_policies)} Conditional Access policy(ies).")
        except Exception as e:  # noqa: BLE001
            result.collected["conditionalAccess"] = False
            result.errors.append(f"conditionalAccess policies: {e} "
                                 "(grant the SP Policy.Read.All)")
        try:
            resp = _send_with_retry(lambda: client.get(
                f"{_GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy",
                headers={"Authorization": f"Bearer {token}"}))
            result.security_defaults_enabled = bool(resp.json().get("isEnabled"))
            result.collected["securityDefaults"] = True
        except Exception as e:  # noqa: BLE001
            result.collected["securityDefaults"] = False
            result.errors.append(f"security defaults policy: {e}")
        return result
    finally:
        if owns:
            try:
                client.close()
            except Exception:
                pass
