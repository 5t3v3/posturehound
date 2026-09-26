# Setting up the Azure Reader service principal (v2 Track B)

PostureHound's live collection needs a **read-only** service principal with these
grants:

- **Reader** on the root management group (covers all subscriptions, current and
  future) - for Azure Resource Graph. This powers both the resource-config exposure
  (network, databases, storage/Key Vault settings) AND the **resource objects**
  themselves - VMs, Key Vaults, storage accounts, AKS, ACR, automation/function/logic/web
  apps, VM scale sets - with their managed identities and Key Vault access policies. Those
  are what let the live collection derive the resource-plane attack edges (managed-identity
  theft, Key Vault data-plane reach, storage-key / blob / ACR-push / AKS-exec), the same as
  an AzureHound `rm.json`. No extra grant is needed beyond Reader.
- **Policy.Read.All** on Microsoft Graph, admin-consented - for identity config
  (Conditional Access, security defaults).
- **Directory.Read.All** on Microsoft Graph, admin-consented - for the **live
  directory collection** (the AzureHound-equivalent: users, groups, service
  principals, apps, directory roles, memberships, ownerships, app-role grants,
  federated credentials, delegated OAuth2 grants). This is the same read scope
  AzureHound uses. With it, PostureHound can assess the tenant live with **no
  AzureHound upload** - "Collect live" runs the whole pipeline from the SP alone.
- **RoleManagement.Read.Directory** on Microsoft Graph, admin-consented - for
  **PIM-eligible role assignments** (shadow admins). This is a SEPARATE grant:
  `Directory.Read.All` does NOT cover the `/roleManagement/directory/*` API, so
  without it the PIM-eligibility collection returns 403 and shadow-admin attack
  paths are missed.

Optional: **AuditLog.Read.All** enables `signInActivity`, which powers the
"dormant enabled privileged account" rule (AZ-IDENT-011). Not required; the
collector does not request sign-in activity today.

All are read-only. `Reader` reads the control plane only (resource *config*), never
the data plane (no Key Vault secret values, no storage/DB data). Nothing PostureHound
does with this SP writes to Azure.

You can still upload an AzureHound file instead of (or as well as) collecting live -
both feed the identical pipeline.

---

## One-time creation (Azure CLI)

Run as someone who can create app registrations and assign roles (typically a
Global Administrator or a Privileged Role Administrator + Owner on the scope).

```bash
# 1. Create the app + service principal
az ad sp create-for-rbac \
  --name "PostureHound-Reader" \
  --role "Reader" \
  --scopes "/subscriptions/<SUBSCRIPTION_ID>"     # or a management group scope
# Note the appId (client id), password (client secret) and tenant it prints.
```

To cover the whole tenant, scope Reader at a management group instead:

```bash
--scopes "/providers/Microsoft.Management/managementGroups/<MG_ID>"
```

```bash
# 2. Grant Microsoft Graph application permissions
APP_ID="<appId from step 1>"
# Policy.Read.All (Conditional Access / security defaults):
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 246dd0d5-5bd0-4def-940b-0421030a5b68=Role
# Directory.Read.All (live directory collection - AzureHound-equivalent):
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role
# RoleManagement.Read.Directory (PIM-eligible shadow admins):
az ad app permission add --id "$APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 483bed4a-2ad3-4361-a73b-c83ccdbdc53c=Role

# 3. Admin-consent them (required for application permissions)
az ad app permission admin-consent --id "$APP_ID"
```

> `00000003-0000-0000-c000-000000000000` is Microsoft Graph.
> `246dd0d5-5bd0-4def-940b-0421030a5b68` is the **Policy.Read.All** application role.
> `7ab1d382-f21e-4acd-a863-ba3e13f7da61` is the **Directory.Read.All** application role.
> `483bed4a-2ad3-4361-a73b-c83ccdbdc53c` is the **RoleManagement.Read.Directory** role.

Optional, if you later want MFA-registration coverage: also add
`UserAuthenticationMethod.Read.All` (`38d9df27-64da-44fd-b7c5-a6fbac20248f=Role`)
and `Reports.Read.All` the same way. Not required for the current rules.

---

## Configure PostureHound

Either in the app - **Settings → Azure live collection** - enter Tenant ID,
Client ID, Client secret, then **Test connection**. It checks *both* permissions
and shows a line for each:

```
✅ Resource Graph (Reader): Connected - N subscription(s) readable…
✅ Microsoft Graph (Policy.Read.All): Microsoft Graph OK - N policy(ies) readable.
```

A ❌ on the Graph line means the Policy.Read.All grant or its admin-consent is
missing (step 2/3 above). A ❌ on the Resource Graph line means the Reader
assignment or the secret is wrong.

Or via environment (the secret is then never persisted):

```bash
export PH_ARG_TENANT_ID="<tenant id>"
export PH_ARG_CLIENT_ID="<app/client id>"
export PH_ARG_CLIENT_SECRET="<client secret>"
```

Or via a git-ignored **`.env`** file in the project root (copy `.env.example`).
Either the `PH_ARG_*` names or the standard `AZURE_*` names work:

```dotenv
PH_ARG_TENANT_ID=<tenant id>
PH_ARG_CLIENT_ID=<app/client id>
PH_ARG_CLIENT_SECRET=<client secret>
# or: AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
```

Precedence is: real environment variables → `.env` → Settings. The `.env` secret
is never written to `settings.json`. `PH_DOTENV` overrides the file path.

Then run a scan. Live findings (ARG-* network/data, IDG-* identity) attach
automatically; the report's Coverage view shows the collection status.

---

## What "not collected" means

If no SP is configured, or a permission is missing, the affected domains are
reported **not assessed** in the Coverage view - never a clean pass. A field the
collector cannot read is marked **UNCONFIRMED** on the finding, never invented.

## Least privilege / teardown

The SP only ever reads. To remove it:

```bash
az ad sp delete --id "<appId>"
```
