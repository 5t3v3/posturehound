# PostureHound Data Model

## Graph schema

**Node kinds** (`NodeKind`): `AZTenant`, `AZManagementGroup`, `AZSubscription`, `AZResourceGroup`, `AZUser`, `AZGroup`, `AZServicePrincipal`, `AZApp`, `AZRole`, `AZVM`, `AZManagedCluster`, `AZKeyVault`, `AZStorageAccount`, `AZAutomationAccount`, `AZFunctionApp`, `AZLogicApp`, `AZWebApp`, `AZVMScaleSet`, `AZDevice`.

**Raw edge types** (mapped directly from the collection):

| Edge | Meaning |
|------|---------|
| `MemberOf` | principal → group membership |
| `Owns` | principal → app / SP / group ownership |
| `HasEntraRole` | principal → directory (Entra) role |
| `HasRBACRole` | principal → Azure RBAC role at a scope |
| `Contains` | scope hierarchy (MG → Sub → RG → resource) |
| `KVAccess` | principal → Key Vault access policy |
| `HasManagedIdentity` | resource → its managed-identity principal |
| `HasAppRole` | SP → MS Graph application permission (held in node props) |

**Derived edge types** (re-implemented abuse primitives - the high-risk module):

| Edge | Primitive | Derived from |
|------|-----------|--------------|
| `EffectiveRole` | EffectiveRole | direct role assignment + transitive (nested) role-assignable group membership |
| `CanAddSecret` | CanAddSecret | ownership of an app/SP (owner can add a credential and sign in as it) |
| `CanAddMember` | CanAddMember | ownership of a group; dangerous Graph membership-write permissions |
| `CanGrantRole` | CanGrantRole | `RoleManagement.ReadWrite.Directory` / PIM-write app roles |
| `CanGrantAppRole` | CanGrantAppRole | `AppRoleAssignment.ReadWrite.All` |
| `CanEscalateRBAC` | CanEscalateRBAC | Owner / User Access Administrator / RBAC Administrator at scope |
| `CanReachKVSecret` | CanReachKVSecret | Key Vault `get`/`list` secret permission |

Every derived edge carries its `primitive` and an `evidence` dict. Tier-0 tagging marks principals with an effective Tier-0 directory role or broad-scope RBAC escalation capability.

## AzureHound record mapping

AzureHound emits `{"meta": {...}, "data": [{"kind": "...", "data": {...}}, ...]}`. Object kinds become nodes; relationship kinds become edges:

| Record kind | Mapped to |
|-------------|-----------|
| `AZUser`, `AZGroup`, `AZServicePrincipal`, `AZApp`, `AZKeyVault`, `AZVM`, … | node |
| `AZGroupMember` | `MemberOf` |
| `AZGroupOwner`, `AZAppOwner`, `AZServicePrincipalOwner` | `Owns` |
| `AZEntraRoleAssignment` | `HasEntraRole` (+ synthesised `AZRole` node) |
| `AZAppRoleAssignment` | MS Graph app-role recorded on SP props |
| `AZRBACRoleAssignment` | `HasRBACRole` (role + scope in evidence) |
| `AZKeyVaultAccessPolicy` | `KVAccess` (permissions in evidence) |

## OQ-1 - version caveat (important)

AzureHound's exact relationship representation has changed across versions (embedded vs separate relationship records, field names). The mappings in `normalize.py` and the synthetic fixture follow a representative recent shape. **Before trusting results on a real collection, validate the field mappings against your AzureHound version** and adjust `normalize._load_relationship` accordingly.

The engine logic downstream of ingest (derivation, detection, scoring) is version-independent; only this thin adapter layer is version-sensitive.
