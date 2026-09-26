# Contributor guidance

- This project performs read-only directory lookups. Do not add write operations without a separate security review.
- Never commit `.env`, private keys, CA certificates, exports, logs, or real identity test fixtures.
- Keep credentials and LDAP naming contexts in site-local configuration; validate TLS and limit access.
- Authentication, authorization, rate limiting, and audit policy belong in the deployment environment.
- Use synthetic identities in tests and docs. Preserve LDAP escaping, scope checks, and export limits.
