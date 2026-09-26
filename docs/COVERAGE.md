# Coverage matrix

This answers "does PostureHound map *everything* AzureHound exposes?" honestly.
**It is not exhaustive of all of Azure** - nothing built only on AzureHound can be,
because AzureHound collects identity/authorization graph data, not runtime or
control-plane configuration. Within that graph, coverage is now broad: 106 rules
across 12 categories, plus a collection-completeness layer that flags when a
clean-looking result is actually an under-collected one.

## Closed in the latest build

- Expanded Tier-0 role set (Hybrid Identity Admin, Intune Admin, Directory Sync
  Accounts, Domain Name Admin, Partner Tier2 Support, SharePoint/Knowledge/Cloud
  Device Admin) so escalation targets are not silently missed.
- Dangerous Graph permissions extended: ServicePrincipalEndpoint.ReadWrite.All
  (AddOwner), UserAuthenticationMethod.ReadWrite.All, Policy.ReadWrite.Conditional
  Access / AuthenticationMethod (control-weakening), Synchronization.ReadWrite.All.
- New detections: federated identity credentials on privileged apps/SPs, SPs that
  can weaken Conditional Access / MFA, storage-account key retrieval (listKeys),
  Key Vault cryptographic-key operations, Key Vault purge-protection disabled, AKS
  cluster-admin credential access, and classic (co-)administrators.
- False positives fixed: AddSecret edges to managed identities and foreign-tenant
  service principals are excluded (both classic graph-analysis false positives), scope
  matching is hierarchy/-case-aware, and deny assignments are honored.
- Collection-completeness reconciliation: unconsumed record kinds, whole-domain
  absence (no apps / no RBAC / no roles), and AzureHound's default-$select gap that
  blanks onPremisesSyncEnabled are surfaced as explicit warnings.
- Attack-path enumeration now reports truncation and includes sensitive data sinks
  (Key Vault, storage, AKS) as path objectives, not just Tier-0.

## AzureHound object types - assessed?

| Object | Assessed | Notes |
|--------|----------|-------|
| Users | Yes | guest/disabled/synced, privileged-role holders, password-reset roles |
| Groups | Yes | role-assignable, dynamic membership, ownership, nested inheritance |
| Applications | Yes | ownership, credentials, multi-tenant, orphaned, federated credentials |
| Service principals | Yes | privileged roles, dangerous Graph app-roles, control-weakening, MI/foreign exclusions |
| Directory roles | Yes | full Tier-0 mapping, app-admin, privileged auth admin, reset roles |
| RBAC role assignments | Yes | Owner/UAA/RBAC-admin, broad scope, compute, KV, storage-key, AKS roles, classic admins |
| Management groups / subscriptions | Yes | scope of escalation; classic administrators |
| Key Vaults | Yes | data-plane (secrets + crypto keys), management-plane, purge protection |
| VMs / VMSS / AKS / Automation / Web & Logic Apps | Partial | compute-role → managed-identity theft; AKS cluster-cred; resource-specific misconfig still out of scope |
| Managed identities | Yes | broad-privilege IMDS pivot, theft via compute roles |
| Storage accounts | Partial | anonymous public blob access + key retrieval via RBAC |
| Devices | No | device-join / owner edges not yet modeled |
| Container registries (ACR) | No | not yet modeled |

## Still open

- True k-shortest-path / min-cut choke-point math (current ranking is a betweenness
  heuristic over the derived edges).
- Device-based paths, ACR, AKS resource-specific misconfig, and the AzureRM
  *NodeResourceGroup* / Website/Logic/Automation contributor edges as distinct
  primitives (currently folded into the compute-MI chain or listed as known-unmodeled).
- Deny-assignment parsing is best-effort and unvalidated against real shapes.

## What AzureHound cannot show (reported as *not assessable*, never a pass)

MFA / authentication-method registration, Conditional Access policy *state*, sign-in
and audit logs, network exposure (NSG / public IP), encryption-at-rest, and
diagnostic logging. These require a Graph/Conditional-Access export or log access and
are listed in the report's Coverage view so the result never implies false assurance.

## Needs-collection gaps (identified, would-be deterministic rules blocked on data)

These are concrete detections we *would* implement as deterministic rules but cannot
today, because the collector does not gather the required property/endpoint. They are
recorded here (rather than shipped as rules that can never fire) so the backlog is
explicit. Each lists the data source and Graph/ARM permission that would unblock it.
Until then the affected domains are reported *not assessed*, never a clean pass.

| Gap (candidate rules) | Data needed | Source / permission |
|-----------------------|-------------|---------------------|
| Privileged account without strong MFA; legacy per-user MFA; no passwordless/FIDO2 for admins | Per-user registered authentication methods | Graph `/users/{id}/authentication/methods` or `/reports/authenticationMethods` (`UserAuthenticationMethod.Read.All`, `AuditLog.Read.All`) |
| No Conditional Access enforcing MFA on admins; legacy auth not blocked; over-broad CA exclusions; report-only policies never enforced | Conditional Access policy definitions + state | Graph `/identity/conditionalAccess/policies` (`Policy.Read.All`); named locations `/identity/conditionalAccess/namedLocations` |
| Security Defaults disabled while no CA policy compensates | Security-defaults enforcement flag | Graph `/policies/identitySecurityDefaultsEnforcementPolicy` (`Policy.Read.All`) |
| Enabled account not signed in >90d; guest never signed in; privileged role never activated; dormant SP credential never used | `signInActivity` per user; sign-in logs | Graph `signInActivity` `$select` + `/auditLogs/signIns` (`AuditLog.Read.All`, Entra ID P1) - note AZ-IDENT-011 already covers *never-signed-in Tier-0* where the field is present |
| Custom RBAC / Entra role grants `roleAssignments/write`, a wildcard `*` action, or `listKeys` | Role-definition `Actions`/`DataActions` | ARM `/providers/Microsoft.Authorization/roleDefinitions` and Graph `/roleManagement/directory/roleDefinitions` - today AZ-RBAC-011 can only flag that a custom role is *held*, not analyse its actions |
| Users can consent to apps (illicit-consent surface); any user can register applications; open guest-invite settings | Tenant authorization policy | Graph `/policies/authorizationPolicy` (`Policy.Read.All`) |
| Device-based attack paths; unmanaged/non-compliant device owns a privileged identity | Device objects + compliance/join state | Graph `/devices`, `/deviceManagement/managedDevices` (`Device.Read.All`, Intune scopes) |
| Break-glass GA accidentally *in scope* of a blocking CA policy (lockout risk) | CA policies + break-glass identification | Graph `/identity/conditionalAccess/policies` (`Policy.Read.All`) |

Some of the Conditional Access / MFA / authorization-policy items are partially reached
today by the optional **v2 Track B** Microsoft Graph collection (below); the rows above
are the detections still missing even with that track, or that need audit-log / Intune
scopes Track B does not request.

## v2 Track B - live Azure collection (optional, Reader service principal)

When a read-only Reader service principal is configured, PostureHound also collects
**Azure Resource Graph** (network exposure, databases, resource config) and
**Microsoft Graph** (Conditional Access, MFA, legacy auth) and runs 32 further rules across the Azure estate
(ARG-NET/SQL/COSMOS/PG/MYSQL/APP/DEFENDER/AKS/ACR/DISK/REDIS/MSG/COG/APIM/CA, IDG-001..004). These reach the domains AzureHound cannot
see; without the SP those domains are reported *not assessed*, never a clean pass.
