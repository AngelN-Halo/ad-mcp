# Generic deployment prerequisites

1. Provide a dedicated, nonprivileged directory account with normal authenticated read access and no delegated management permissions; store its credential only in a private secret store or ignored `.env` file. Directory ACLs determine what it can read.
2. Configure your own LDAPS hostnames and naming contexts via environment variables. Use the real certificate authority chain in a locally protected file; never commit certificates or keys.
3. Require TLS certificate and hostname validation. Do not disable checks to work around a trust failure.
4. Require authenticated, authorized client access at a separately configured gateway. This Compose example publishes no host port.
5. Check the account's effective permissions, including your domain's workstation-join restriction. That restriction is a deployment policy, not a feature of this MCP. Verify read-only LDAP behavior and information minimization using synthetic or approved test identities; review logs and CSV retention for PII.

The contents of this repository intentionally do not specify production hosts, directory structure, names, access lists, or reverse proxies.
