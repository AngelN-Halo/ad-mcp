# Read-only Active Directory MCP example

This project provides read-only directory lookups. **This is source code, not a production deployment recipe.** The supplied Compose configuration has no published host port and uses a project-local Docker network. Before deployment, add your own authenticated gateway and network access policy; a private network alone is not authorization.

## Configuration

Copy `.env.example` to `.env`; replace all placeholders and keep `.env` out of version control. Use a dedicated, nonprivileged service account with normal authenticated directory read access and no delegated directory management permissions. The code issues LDAP searches and reads only; the account's effective permissions come from your directory ACLs and domain policy. If your environment restricts ordinary users from joining workstations, verify that the same restriction applies to this account. The MCP does not set that policy. Set LDAPS hostnames, naming contexts, and the CA trust file for **your** directory. Require certificate and hostname validation. Do not put credentials, CA files, host inventories, or user exports in Git.

The public example names two configurable, generic people scopes, `AD_PRIMARY_PEOPLE_BASE` and `AD_SECONDARY_PEOPLE_BASE`; account classifications are `primary_person` and `secondary_person`. The sample DNs are fictional. Supply your own private directory mapping. These public labels are intentionally **not** backwards-compatible with any older deployment settings.

## Run and verify

Run `docker compose config` after supplying a local `.env`, then build and start on an access-controlled network. Test only with synthetic or approved accounts. Validate TLS, LDAP read-only behavior, the bind account's effective permissions (including workstation-join restrictions), caller authentication, returned attributes, CSV export controls, and logging/retention before connecting clients. Do not expose the MCP endpoint directly to the internet.

## Available operations

The source exposes health/preflight, identity and group searches, membership queries, and guarded CSV exports. It implements no LDAP writes. Treat query results and downloaded reports as sensitive personal information.
