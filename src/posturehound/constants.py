"""Curated, versioned security reference data.

These maps encode published privilege-escalation knowledge (Microsoft Threat
Matrix and public Azure security research). Externalised here so they can be
reviewed and updated without touching engine logic.
"""
from __future__ import annotations

# Entra (Azure AD) directory roles that are effectively Tier-0 (tenant takeover
# or able to escalate to it). Keyed by roleTemplateId with display-name fallback.
# Broad set of privileged Entra roles - used to NAME role nodes and for "privileged"
# flagging. Tier-0 (below) is a curated subset of this.
PRIVILEGED_ENTRA_ROLE_TEMPLATES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "8329153b-31d0-4727-b945-745eb3bc5f31": "Domain Name Administrator",
    "d29b2b05-8046-44ba-8758-1e26182fcf32": "Directory Synchronization Accounts",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": "Partner Tier2 Support",
    # Partner Tier1 Support: like Password Administrator (already Tier-0 above), it can reset
    # passwords / invalidate tokens for non-admins - a real takeover primitive. Included for
    # parity; leaving it out let a principal holding only this legacy role escape Tier-0.
    "4ba39ca4-527c-499a-b93d-d9b492c50246": "Partner Tier1 Support",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    # Knowledge Manager (744ec460) removed: it is a Viva Topics knowledge/taxonomy role with
    # NO privilege-escalation path to tenant compromise, so tagging its holders Tier-0 made
    # them false escalation targets that every CanResetPassword/CanAddSecret/CanAddMember SP
    # drew edges to, amplifying phantom attack paths across the graph.
    "9f06204d-73c1-4d4c-880a-6edb90606fd8": "Cloud Device Administrator",
}

PRIVILEGED_ENTRA_ROLE_NAMES = {v.lower() for v in PRIVILEGED_ENTRA_ROLE_TEMPLATES.values()}

# Tier-0 = the curated high-impact subset of the privileged roles: those with a direct
# tenant-takeover path (grant/assign roles, add credentials to any app, forge/sync
# identities, reset admin auth). Operational admin roles (Exchange/SharePoint/Intune/Cloud
# Device/Conditional Access/Auth/Password/Domain Name/Security/Partner Tier1) are privileged
# but NOT Tier-0 - a compromise there does not by itself yield tenant control.
TIER0_ENTRA_ROLE_TEMPLATES: dict[str, str] = {tpl: PRIVILEGED_ENTRA_ROLE_TEMPLATES[tpl] for tpl in (
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "d29b2b05-8046-44ba-8758-1e26182fcf32",  # Directory Synchronization Accounts
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",  # Hybrid Identity Administrator
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",  # Partner Tier2 Support
)}
# Display names that map to Tier-0 even if template id is absent.
TIER0_ENTRA_ROLE_NAMES = {v.lower() for v in TIER0_ENTRA_ROLE_TEMPLATES.values()}

# Highest-tier subset: direct path to full tenant compromise.
CRITICAL_ENTRA_ROLE_NAMES = {
    "global administrator",
    "privileged role administrator",
    "privileged authentication administrator",
}

# MS Graph application permissions (app roles) that enable privilege escalation.
# value -> (effective severity primitive, human description)
DANGEROUS_GRAPH_APP_ROLES: dict[str, dict] = {
    "RoleManagement.ReadWrite.Directory": {
        "primitive": "CanGrantRole",
        "impact": "Can assign any Entra role to itself, including Global Administrator.",
        "tier": "critical",
    },
    "AppRoleAssignment.ReadWrite.All": {
        "primitive": "CanGrantAppRole",
        "impact": "Can grant itself any app role, including RoleManagement.ReadWrite.Directory.",
        "tier": "critical",
    },
    "Application.ReadWrite.All": {
        "primitive": "CanAddSecret",
        "impact": "Can add credentials to any application/SP and authenticate as it.",
        "tier": "high",
    },
    "Directory.ReadWrite.All": {
        "primitive": "CanAddMember",
        "impact": "Broad directory write; membership and object manipulation.",
        "tier": "high",
    },
    "Group.ReadWrite.All": {
        "primitive": "CanAddMember",
        "impact": "Can modify group membership, including role-assignable groups.",
        "tier": "high",
    },
    "GroupMember.ReadWrite.All": {
        "primitive": "CanAddMember",
        "impact": "Can add members to groups, including privileged groups.",
        "tier": "high",
    },
    "PrivilegedAccess.ReadWrite.AzureAD": {
        "primitive": "CanGrantRole",
        "impact": "Can manage PIM eligible/active role assignments.",
        "tier": "high",
    },
    "RoleManagement.ReadWrite.Exchange": {
        # NOT CanGrantRole: this manages Exchange Online RBAC (mailbox/transport roles), NOT
        # Entra directory-role assignment - it cannot assign Global Administrator. Mapping it
        # to CanGrantRole fabricated an escalation edge to every Tier-0 directory role from a
        # permission commonly granted to mail/compliance apps. It stays flagged by AZ-APP-002
        # via this membership; it just no longer derives a false Tier-0 path.
        "primitive": "CanManageExchange",
        "impact": "Can manage Exchange Online RBAC roles (mailbox access escalation) - not Entra directory roles.",
        "tier": "high",
    },
    "User.ReadWrite.All": {
        # NOT CanResetPassword: the application permission User.ReadWrite.All can update
        # user profile objects but cannot reset another user's password or auth methods -
        # that requires UserAuthenticationMethod.ReadWrite.All (mapped below) or a directory
        # role, and protected admins are gated regardless. Mapping it to a reset primitive
        # fabricated a Tier-0-user takeover edge to every admin. It stays a flagged dangerous
        # permission (AZ-APP-002) via the DANGEROUS_GRAPH_APP_ROLES membership; it just no
        # longer derives a false escalation path.
        "primitive": "CanModifyUsers",
        "impact": "Can read and modify all user profile objects tenant-wide (not credentials/MFA).",
        "tier": "medium",
    },
    "ServicePrincipalEndpoint.ReadWrite.All": {
        "primitive": "CanAddOwner",
        "impact": "Can add owners to any service principal, then control it (AZMGAddOwner).",
        "tier": "high",
    },
    "UserAuthenticationMethod.ReadWrite.All": {
        "primitive": "CanResetPassword",
        "impact": "Can register/replace authentication methods (incl. MFA) for users - account takeover.",
        "tier": "high",
    },
    "Policy.ReadWrite.ConditionalAccess": {
        "primitive": "CanWeakenControls",
        "impact": "Can modify Conditional Access policies, disabling MFA or access controls tenant-wide.",
        "tier": "high",
    },
    "Policy.ReadWrite.AuthenticationMethod": {
        "primitive": "CanWeakenControls",
        "impact": "Can change tenant authentication-method policy, weakening MFA enforcement.",
        "tier": "high",
    },
    "Synchronization.ReadWrite.All": {
        # NOT CanAddSecret: managing directory synchronization does not let you add a
        # credential to arbitrary privileged service principals. Mapping it to CanAddSecret
        # fabricated an add-secret edge to every Tier-0 SP. It is a real hybrid-identity abuse
        # (sync manipulation / soft-match takeover) and stays flagged by AZ-APP-002, but it no
        # longer derives a false Tier-0 escalation path.
        "primitive": "CanAbuseDirSync",
        "impact": "Can manage directory synchronization - hybrid-identity abuse (sync manipulation, soft-match takeover).",
        "tier": "high",
    },
    "PrivilegedAccess.ReadWrite.AzureADGroup": {
        # CanAddMember, not CanGrantRole: this manages PIM for GROUPS - it can activate a
        # Tier-0 role-assignable GROUP membership, not assign a directory role directly.
        # CanGrantRole overstated it as "can assign Global Administrator"; CanAddMember
        # models the real path (through a Tier-0 role-assignable group), which the
        # CanAddMember branch already targets correctly.
        "primitive": "CanAddMember",
        "impact": "Can manage PIM assignments for Entra groups; can activate a Tier-0 role-assignable group membership on behalf of any principal.",
        "tier": "high",
    },
    "EntitlementManagement.ReadWrite.All": {
        "primitive": "CanAddMember",
        "impact": "Can create and manage access packages, adding any user to any group including Tier-0 role-assignable groups.",
        "tier": "high",
    },
    "RoleManagementPolicy.ReadWrite.Directory": {
        "primitive": "CanWeakenControls",
        "impact": "Can modify PIM activation policies - remove approval requirements, extend durations, disable MFA for Tier-0 role activations.",
        "tier": "high",
    },
    # Domain federation - can add an external IdP to the tenant, enabling tokens
    # to be issued for any user by an attacker-controlled identity provider.
    "Domain.ReadWrite.All": {
        "primitive": "CanFederateTenant",
        "impact": "Can register federated domains and configure external identity providers - attacker-controlled IdP can issue tokens for any tenant user.",
        "tier": "high",
    },
    # Data-exfiltration application permissions - broad read/write on org data.
    "Mail.ReadWrite.All": {
        "primitive": "CanExfiltrateMail",
        "impact": "Can read, write and delete all mail for every user - mass data exfiltration, business email compromise, message tampering.",
        "tier": "medium",
    },
    "Mail.Read.All": {
        "primitive": "CanExfiltrateMail",
        "impact": "Can silently read all mail for every user - reconnaissance and credential harvesting.",
        "tier": "medium",
    },
    "Mail.Send": {
        "primitive": "CanSendMail",
        "impact": "Can send mail as any user - phishing, business email compromise, impersonation.",
        "tier": "medium",
    },
    "Files.ReadWrite.All": {
        "primitive": "CanExfiltrateFiles",
        "impact": "Can read, write and delete all OneDrive files for every user - full file system access.",
        "tier": "medium",
    },
    "Sites.ReadWrite.All": {
        "primitive": "CanExfiltrateSites",
        "impact": "Can read and write all SharePoint site content across the tenant.",
        "tier": "medium",
    },
    "Contacts.ReadWrite.All": {
        "primitive": "CanExfiltrateContacts",
        "impact": "Can read and modify all Outlook contacts - useful for targeted phishing and org-chart reconnaissance.",
        "tier": "low",
    },
    "ChannelMessage.Read.All": {
        "primitive": "CanReadTeams",
        "impact": "Can read all Teams channel messages - intercept sensitive communications, credentials in chat.",
        "tier": "medium",
    },
    "Chat.ReadWrite.All": {
        "primitive": "CanReadTeams",
        "impact": "Can read and write all Teams chat messages - intercept private conversations.",
        "tier": "medium",
    },
    # Directory management & security-control permissions. These do not derive a
    # specific escalation edge (unknown primitives fall through to a tag only), but a
    # principal holding them - especially an ownerless or Tier-0 one - is genuinely
    # dangerous, and they were previously invisible to the dangerous-permission rules
    # (AZ-APP-002/013/022). AdministrativeUnit + SecurityConfiguration are the two the
    # AKS-Spoke security SP held that the deterministic set missed entirely.
    "AdministrativeUnit.ReadWrite.All": {
        "primitive": "CanManageAdminUnits",
        "impact": "Can create administrative units and scoped role assignments within them - a directory-management primitive used to hide privilege and stage scoped escalation.",
        "tier": "high",
    },
    "SecurityConfiguration.ReadWrite.All": {
        "primitive": "CanWeakenControls",
        "impact": "Can modify tenant security configuration and recommendations (Defender/Secure Score) - weaken or disable protective controls tenant-wide.",
        "tier": "high",
    },
    "Policy.ReadWrite.PermissionGrant": {
        "primitive": "CanWeakenControls",
        "impact": "Can change consent (permission-grant) policies - enable users to consent to apps, opening the illicit-consent-grant path.",
        "tier": "high",
    },
    "DeviceManagementConfiguration.ReadWrite.All": {
        "primitive": "CanManageDevices",
        "impact": "Can write Intune device-configuration and compliance policies - push scripts/profiles that execute on all managed endpoints (fleet-wide code execution).",
        "tier": "high",
    },
    "DeviceManagementApps.ReadWrite.All": {
        "primitive": "CanManageDevices",
        "impact": "Can deploy applications through Intune to managed devices - fleet-wide code execution.",
        "tier": "high",
    },
    "Organization.ReadWrite.All": {
        "primitive": "CanManageDirectory",
        "impact": "Can modify organisation-level settings and branding tenant-wide.",
        "tier": "medium",
    },
}

# Azure RBAC roles that allow self-escalation (write role assignments / full control).
RBAC_ESCALATION_ROLES = {
    "owner",
    "user access administrator",
    "role based access control administrator",
}

# Azure RBAC roles considered highly privileged at broad scope.
RBAC_PRIVILEGED_ROLES = RBAC_ESCALATION_ROLES | {
    "contributor",
}

# Key Vault data-plane permissions that expose stored secrets/keys/certs.
KV_SENSITIVE_SECRET_PERMS = {"get", "list", "all"}

# Delegated MS Graph scopes that, when admin-consented tenant-wide, let the client
# service principal act with directory-write / role-management power on behalf of a
# signed-in admin - the illicit-consent-grant escalation surface.
DANGEROUS_DELEGATED_SCOPES = {
    "directory.readwrite.all", "rolemanagement.readwrite.directory",
    "application.readwrite.all", "approleassignment.readwrite.all",
    "group.readwrite.all", "groupmember.readwrite.all", "user.readwrite.all",
    "privilegedaccess.readwrite.azureadgroup", "entitlementmanagement.readwrite.all",
}

# High-impact BULK-DATA delegated scopes: consent to these lets an app read (or write)
# every user's mailbox, files, SharePoint sites or Teams chat across the tenant - the
# mass-data-exposure / exfiltration surface, distinct from the directory-escalation
# scopes above. Deliberately EXCLUDES the ubiquitous low-risk integrations
# (calendars.*, contacts.read, mail.send, people.read.all, onlinemeetings.*) so the
# rule stays precise: a calendar-sync tool is not the same risk as "can read all mail".
BULK_DATA_DELEGATED_SCOPES = {
    "mail.read", "mail.readwrite", "mail.readbasic.all", "mailboxsettings.readwrite",
    "files.read.all", "files.readwrite.all",
    "sites.read.all", "sites.readwrite.all", "sites.fullcontrol.all",
    "chat.read", "chat.readwrite", "chatmessage.read.all", "notes.read.all",
}

# Lower-risk (but still tenant-wide) delegated scopes: reading/writing everyone's
# calendars or contacts, sending mail as any user, reading org meetings/presence.
# These are the ubiquitous productivity integrations (calendar sync, scheduling,
# mailers) - real governance surface but far lower impact than reading all mail or
# files, so they are flagged separately at Low, and only when the app does NOT also
# hold a higher-tier scope (which would already flag it under AZ-APP-023/025).
LOWER_DATA_DELEGATED_SCOPES = {
    "calendars.read", "calendars.readwrite",
    "contacts.read", "contacts.readwrite",
    "mail.send", "people.read.all",
    "onlinemeetings.read.all", "onlinemeetings.readwrite.all",
}

# Azure RBAC roles that grant code execution on a resource (and therefore theft
# of that resource's managed-identity token via IMDS). role name (lower) -> note.
COMPUTE_CONTRIBUTOR_ROLES: dict[str, str] = {
    "virtual machine contributor": "run-command / reset credentials on the VM",
    "virtual machine administrator login": "interactive admin login to the VM",
    "virtual machine user login": "interactive login to the VM",
    "azure kubernetes service cluster admin role": "cluster-admin kubeconfig (exec into pods)",
    "azure kubernetes service rbac cluster admin": "cluster-admin (exec into pods)",
    "azure kubernetes service contributor role": "manage the AKS cluster",
    "automation contributor": "create/run runbooks as the account identity",
    "website contributor": "deploy code / Kudu console on the app",
    "web plan contributor": "manage the app service plan",
    "logic app contributor": "modify workflow run as the identity",
    "contributor": "broad management incl. command execution",
    "owner": "full control incl. command execution",
}

# Entra roles able to reset passwords, with the tier they can reset.
RESET_PASSWORD_ROLES: dict[str, str] = {
    "privileged authentication administrator": "any account, including Global Administrators",
    "authentication administrator": "non-administrator accounts",
    "helpdesk administrator": "non-administrator accounts",
    "password administrator": "non-administrator accounts",
    "user administrator": "users and some admins",
}
# Subset that can reset a Tier-0 account (direct path to GA takeover).
RESET_PASSWORD_TIER0_ROLES = {"privileged authentication administrator"}

# Entra roles that can add credentials to ANY application/SP (not just owned).
APP_MANAGEMENT_ROLES = {"application administrator", "cloud application administrator"}

# Azure RBAC roles granting management-plane control of a Key Vault (can change
# access policies / RBAC to grant themselves data-plane secret access).
KV_MANAGEMENT_ROLES = {"key vault contributor", "key vault administrator", "contributor", "owner"}
# Key Vault DATA-plane RBAC roles: these grant secret/key/cert access directly (the
# canonical least-privilege secret reader is "Key Vault Secrets User"). Previously no
# derivation converted them to a reachability edge, so a purpose-granted secrets
# reader produced no attack path.
KV_DATA_ROLES = {"key vault secrets user", "key vault secrets officer",
                 "key vault crypto user", "key vault crypto officer",
                 "key vault certificates officer", "key vault administrator"}

# RBAC roles granting direct Azure Blob Storage data-plane access (Entra token auth, bypasses listKeys).
# Unlike STORAGE_KEY_ROLES, these roles grant named-identity access visible in blob audit logs,
# but the holder can still exfiltrate all blob data without needing to call listKeys.
STORAGE_BLOB_DATA_ROLES = {
    "storage blob data owner",
    "storage blob data contributor",
    "storage blob data reader",
}

# RBAC roles enabling push to an Azure Container Registry (supply-chain attack primitive).
# Pushing a malicious image poisons any workload that subsequently pulls it.
CONTAINER_PUSH_ROLES = {
    "acrpush",
    "contributor",
    "owner",
}

# RBAC roles that can retrieve storage account keys (listKeys) - full data access
# and a common lateral-movement primitive.
STORAGE_KEY_ROLES = {
    "storage account contributor", "storage account key operator service role",
    "contributor", "owner",
}

# RBAC roles that can pull AKS cluster-admin credentials (listClusterAdminCredential).
AKS_CLUSTER_ADMIN_ROLES = {
    "azure kubernetes service cluster admin role",
    "azure kubernetes service rbac cluster admin",
    "azure kubernetes service contributor role",
    "contributor", "owner",
}

# Azure RBAC (ARM) built-in role definition GUIDs -> canonical name. These IDs are
# global and stable across every tenant, so RBAC assignments (which reference a
# roleDefinitionId GUID, NOT a name) must be resolved through this map.
ARM_BUILTIN_ROLES: dict[str, str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "f25e0fa2-a7c8-4377-a976-54943a77a395": "Key Vault Contributor",
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7": "Key Vault Secrets Officer",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "14b46e9e-c2b7-41b4-b07b-48a6ebf60603": "Key Vault Crypto Officer",
    "12338af0-0e69-4776-bea7-57ae8d297424": "Key Vault Crypto User",
    "17d1049b-9a84-46fb-8f53-869881c3d3ab": "Storage Account Contributor",
    "81a9662b-bebf-436f-a333-f67b29880f12": "Storage Account Key Operator Service Role",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
    "8311e382-0749-4cb8-b61a-304f252e45ec": "AcrPush",
    "7f951dda-4ed3-4680-a7ca-43fe172d538d": "AcrPull",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
    "1c0163c0-47e6-4577-8991-ea5c82e286e4": "Virtual Machine Administrator Login",
    "fb879df8-f326-4884-b1cf-06f3ad86be52": "Virtual Machine User Login",
    "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8": "Azure Kubernetes Service Cluster Admin Role",
    "4abbcc35-e782-43d8-92c5-2d3f1bd2253f": "Azure Kubernetes Service Cluster User Role",
    "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b": "Azure Kubernetes Service RBAC Cluster Admin",
    "ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8": "Azure Kubernetes Service Contributor Role",
}

# MS Graph dangerous app-role (application permission) GUIDs -> permission value.
# AzureHound emits appRoleId GUIDs; resolve to the value our detections key on.
GRAPH_APP_ROLE_IDS: dict[str, str] = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695": "GroupMember.ReadWrite.All",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "9e640839-a198-48fb-8b9a-013fd6f6cbcd": "ServicePrincipalEndpoint.ReadWrite.All",
    "01c0a623-fc9b-48e9-b794-0756f8e8f067": "Policy.ReadWrite.ConditionalAccess",
    "29c18626-4985-4dcd-85c0-193eef327366": "Policy.ReadWrite.AuthenticationMethod",
    "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
    "292d869f-3427-49a8-9dab-8c70152b74e9": "Synchronization.ReadWrite.All",
    "32531b60-01da-4460-9f59-351ea7b4f4b1": "PrivilegedAccess.ReadWrite.AzureADGroup",
    # EntitlementManagement - can provision privileged group memberships
    "9acd699f-1e81-4958-b001-93b1d2506e4e": "EntitlementManagement.ReadWrite.All",
    # AuditLog + Reports - read authentication/sign-in logs (reconnaissance)
    "b0afded3-3588-46d8-8b3d-9842eff778da": "AuditLog.Read.All",
    "230c1aed-a721-4c5d-9cb4-a90514e508ef": "Reports.Read.All",
    # Domain config write - can federate the tenant to an external IdP (AADConnect takeover)
    "7e05723c-0bb0-42da-be95-ae9f08a6e53c": "Domain.ReadWrite.All",
    # Data-exfiltration application permissions
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite.All",
    "570282fd-fa5c-430d-a7fd-fc8dc98a9dca": "Mail.Read.All",
    "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
    "9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All",
    "6918b873-d17a-4dc1-b314-35f528134491": "Contacts.ReadWrite.All",
    "4d02b0cc-d90b-441f-8d82-4fb55a34d6d3": "ChannelMessage.Read.All",
    "294ce7c9-31ba-490a-ad7d-97a7d075e4ed": "Chat.ReadWrite.All",
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
    "5778995a-e1bf-45b8-affa-663a9f3f4d04": "Directory.AccessAsUser.All",
}


def arm_role_name(role_definition_id: str | None) -> str | None:
    """Resolve an ARM roleDefinitionId (full path or bare GUID) to a role name."""
    if not role_definition_id:
        return None
    guid = role_definition_id.rsplit("/", 1)[-1].lower()
    return ARM_BUILTIN_ROLES.get(guid)


def is_at_broad_scope(scope: str | None) -> bool:
    """Return True only for subscription-exact or management-group scope.

    Resource-group and resource-level scopes (which also start with /subscriptions/)
    return False.  A VM-level Owner or UAA is dangerous but not a subscription-wide
    threat, so broad-scope rules should not fire for it.
    """
    if not scope:
        return False
    s = scope.rstrip("/").lower()
    # Management group: any /providers/Microsoft.Management/managementGroups/<name>
    if s.startswith("/providers/microsoft.management/managementgroups"):
        return True
    # Subscription-exact: /subscriptions/<guid> - exactly two slash segments
    if s.startswith("/subscriptions/") and s.count("/") == 2:
        return True
    return False
