import csv
import datetime as dt
import os
import re
import secrets
import socket
import ssl
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP
from ldap3 import BASE, SUBTREE, SIMPLE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException, LDAPInvalidDnError
from ldap3.utils.dn import parse_dn
from starlette.requests import Request
from starlette.responses import FileResponse, PlainTextResponse, Response


load_dotenv()

mcp = FastMCP("active-directory-readonly")

REPORT_DIRECTORY = Path("/tmp/ad-mcp-reports")
REPORTS: dict[str, dict[str, Any]] = {}

USER_ATTRIBUTES = [
    "distinguishedName", "displayName", "givenName", "sn", "sAMAccountName",
    "userPrincipalName", "mail", "employeeID", "employeeNumber", "department",
    "title", "company", "physicalDeliveryOfficeName", "manager", "whenCreated",
    "whenChanged", "userAccountControl", "accountExpires", "lockoutTime",
    "msDS-User-Account-Control-Computed",
]
USER_SUMMARY_ATTRIBUTES = [
    "distinguishedName", "displayName", "sAMAccountName", "userPrincipalName",
    "mail", "employeeID", "department", "title", "userAccountControl",
    "accountExpires", "lockoutTime", "msDS-User-Account-Control-Computed",
]
GROUP_ATTRIBUTES = [
    "distinguishedName", "cn", "sAMAccountName", "displayName", "mail",
    "description", "groupType", "managedBy", "whenCreated", "whenChanged",
]

# Defense in depth: tools use fixed allowlists, and these names must never be added.
SENSITIVE_ATTRIBUTES = {
    "unicodepwd", "supplementalcredentials", "ntpwdhistory", "dbcspwd",
    "unicodepwd", "msds-managedpassword", "ms-mcs-admpwd", "mslaps-password",
    "mslaps-encryptedpassword", "msfve-recoverypassword",
}

USER_FILTER = "(&(objectCategory=person)(objectClass=user))"
GROUP_FILTER = "(objectCategory=group)"
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"
UAC_DISABLED = 0x0002
UAC_COMPUTED_LOCKOUT = 0x0010
WINDOWS_NEVER_EXPIRES = 9223372036854775807


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def config() -> dict[str, Any]:
    primary_people = os.getenv("AD_PRIMARY_PEOPLE_BASE", "OU=People,DC=example,DC=org")
    secondary_people = os.getenv("AD_SECONDARY_PEOPLE_BASE", "OU=PeopleSecondary,DC=example,DC=org")
    hosts = [h.strip() for h in os.getenv("AD_LDAP_HOSTS", "").split(",") if h.strip()]
    return {
        "hosts": hosts,
        "port": env_int("AD_LDAP_PORT", 636),
        "use_ssl": env_bool("AD_USE_SSL", True),
        "bind_user": os.getenv("AD_BIND_USER", ""),
        "bind_password": os.getenv("AD_BIND_PASSWORD", ""),
        "domain_base": os.getenv("AD_DOMAIN_BASE", "DC=example,DC=org"),
        "primary_people_base": primary_people,
        "secondary_people_base": secondary_people,
        "people_bases": [primary_people, secondary_people],
        "service_base": os.getenv("AD_SERVICE_BASE", "OU=Service Items,DC=example,DC=org"),
        "pam_base": os.getenv("AD_PAM_BASE", "OU=PAM,DC=example,DC=org"),
        "tls_validate": env_bool("AD_TLS_VALIDATE", True),
        "ca_cert_file": os.getenv("AD_CA_CERT_FILE", ""),
        "connect_timeout": env_int("AD_CONNECT_TIMEOUT", 8),
        "receive_timeout": env_int("AD_RECEIVE_TIMEOUT", 30),
        "default_limit": env_int("AD_DEFAULT_LIMIT", 50),
        "max_limit": env_int("AD_MAX_LIMIT", 500),
        "export_max_limit": env_int("AD_EXPORT_MAX_LIMIT", 5000),
        "report_max_rows": env_int("AD_REPORT_MAX_ROWS", 100000),
        "report_ttl_seconds": env_int("AD_REPORT_TTL_SECONDS", 900),
        "public_base_url": os.getenv(
            "AD_PUBLIC_BASE_URL", "https://ad-mcp.example.org"
        ).rstrip("/"),
    }


def escape_filter_value(value: str) -> str:
    replacements = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}
    return "".join(replacements.get(char, char) for char in str(value))


def clamp_limit(limit: int | None, default: int, maximum: int) -> int:
    if limit is None:
        return default
    try:
        return max(1, min(int(limit), maximum))
    except (TypeError, ValueError):
        return default


def _safe_attributes(attributes: list[str]) -> list[str]:
    for attribute in attributes:
        if attribute.lower().split(";", 1)[0] in SENSITIVE_ATTRIBUTES:
            raise ValueError(f"Sensitive AD attribute is prohibited: {attribute}")
    return attributes


def _tls(cfg: dict[str, Any]) -> Tls:
    kwargs: dict[str, Any] = {
        "validate": ssl.CERT_REQUIRED if cfg["tls_validate"] else ssl.CERT_NONE,
        "version": ssl.PROTOCOL_TLS_CLIENT,
    }
    if cfg["ca_cert_file"]:
        kwargs["ca_certs_file"] = cfg["ca_cert_file"]
    return Tls(**kwargs)


def _connect() -> Connection:
    cfg = config()
    if not cfg["hosts"]:
        raise ValueError("AD_LDAP_HOSTS is required")
    if not cfg["bind_user"] or not cfg["bind_password"]:
        raise ValueError("AD_BIND_USER and AD_BIND_PASSWORD are required")
    errors: list[str] = []
    for host in cfg["hosts"]:
        try:
            server = Server(
                host,
                port=cfg["port"],
                use_ssl=cfg["use_ssl"],
                tls=_tls(cfg),
                connect_timeout=cfg["connect_timeout"],
                get_info="ALL",
            )
            return Connection(
                server,
                user=cfg["bind_user"],
                password=cfg["bind_password"],
                authentication=SIMPLE,
                auto_bind=True,
                auto_range=False,
                return_empty_attributes=False,
                raise_exceptions=True,
                receive_timeout=cfg["receive_timeout"],
            )
        except (LDAPException, OSError, ValueError) as exc:
            errors.append(f"{host}: {exc}")
    raise ConnectionError("All configured domain controllers failed: " + " | ".join(errors))


def _json_value(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    return value


def _attributes_to_dict(dn: str, attributes: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {"dn": dn}
    for key, value in attributes.items():
        if key.lower().split(";", 1)[0] in SENSITIVE_ATTRIBUTES:
            continue
        if isinstance(value, list):
            values = [_json_value(v) for v in value]
            item[key] = values[0] if len(values) == 1 else values
        else:
            item[key] = _json_value(value)
    return item


def _response_to_dict(response: dict[str, Any]) -> dict[str, Any]:
    return _attributes_to_dict(response.get("dn", ""), response.get("attributes", {}) or {})


def _error(exc: Exception) -> dict[str, Any]:
    return {"ok": False, "error": str(exc)}


def _search_with_connection(
    conn: Connection,
    bases: list[str],
    search_filter: str,
    attributes: list[str],
    limit: int,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for base in bases:
        remaining = limit - len(entries)
        if remaining <= 0:
            break
        responses = conn.extend.standard.paged_search(
            search_base=base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=_safe_attributes(attributes),
            paged_size=min(remaining, 1000),
            generator=True,
        )
        for response in responses:
            if response.get("type") != "searchResEntry":
                continue
            item = _response_to_dict(response)
            identity = item["dn"].lower()
            if identity not in seen:
                entries.append(item)
                seen.add(identity)
            if len(entries) >= limit:
                break
    return entries


def _search(
    bases: list[str],
    search_filter: str,
    attributes: list[str],
    limit: int,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with _connect() as conn:
            entries = _search_with_connection(conn, bases, search_filter, attributes, limit + 1)
            truncated = len(entries) > limit
            entries = entries[:limit]
            return {
                "ok": True,
                "count": len(entries),
                "limit": limit,
                "truncated": truncated,
                "bases": bases,
                "domain_controller": conn.server.host,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "entries": entries,
            }
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


def _as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, list):
        value = value[0] if value else default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _filetime_to_datetime(value: Any) -> dt.datetime | None:
    ticks = _as_int(value)
    if ticks in {0, WINDOWS_NEVER_EXPIRES}:
        return None
    try:
        return dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=ticks / 10)
    except (OverflowError, ValueError):
        return None


def account_state(user: dict[str, Any]) -> dict[str, Any]:
    uac = _as_int(user.get("userAccountControl"))
    computed = _as_int(user.get("msDS-User-Account-Control-Computed"))
    enabled = not bool(uac & UAC_DISABLED)
    expires_at = _filetime_to_datetime(user.get("accountExpires"))
    expired = expires_at is not None and expires_at <= dt.datetime.now(dt.timezone.utc)
    locked = bool(computed & UAC_COMPUTED_LOCKOUT)
    active = enabled and not expired
    status = "disabled" if not enabled else "expired" if expired else "active"
    return {
        "active": active,
        "status": status,
        "enabled": enabled,
        "expired": expired,
        "locked": locked,
        "account_expires": expires_at.isoformat() if expires_at else None,
    }


def _decorate_user(user: dict[str, Any], source_base: str | None = None) -> dict[str, Any]:
    result = dict(user)
    result["account_state"] = account_state(user)
    dn = str(user.get("dn", "")).lower()
    cfg = config()
    if source_base:
        result["source_base"] = source_base
    elif dn.endswith(cfg["secondary_people_base"].lower()):
        result["account_type"] = "secondary_person"
    elif dn.endswith(cfg["primary_people_base"].lower()):
        result["account_type"] = "primary_person"
    return result


def _exact_identity_filter(value: str) -> str:
    escaped = escape_filter_value(value.strip())
    return (
        "(&(objectCategory=person)(objectClass=user)(|"
        f"(sAMAccountName={escaped})(userPrincipalName={escaped})(mail={escaped})"
        f"(employeeID={escaped})(employeeNumber={escaped})(distinguishedName={escaped})))"
    )


def _name_search_filter(value: str) -> str:
    escaped = escape_filter_value(value.strip())
    return (
        "(&(objectCategory=person)(objectClass=user)(|"
        f"(displayName=*{escaped}*)(cn=*{escaped}*)(sAMAccountName=*{escaped}*)"
        f"(userPrincipalName=*{escaped}*)(mail=*{escaped}*)"
        f"(employeeID={escaped})(employeeNumber={escaped})))"
    )


def _looks_like_dn(value: str, domain_base: str) -> bool:
    try:
        parsed = parse_dn(value, escape=True, strip=True)
        return bool(parsed) and value.lower().endswith(domain_base.lower())
    except (LDAPInvalidDnError, TypeError, ValueError):
        return False


def _looks_like_human_name(value: str, domain_base: str) -> bool:
    candidate = value.strip()
    if not candidate or _looks_like_dn(candidate, domain_base) or "@" in candidate:
        return False
    if re.fullmatch(r"[A-Za-z0-9_.-]+", candidate):
        return False
    return len(candidate.split()) >= 2


def _unescape_dn_value(value: str) -> str:
    output = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            output.extend(char.encode("utf-8"))
            index += 1
            continue
        if index + 2 < len(value) and re.fullmatch(r"[0-9A-Fa-f]{2}", value[index + 1:index + 3]):
            output.append(int(value[index + 1:index + 3], 16))
            index += 3
        elif index + 1 < len(value):
            output.extend(value[index + 1].encode("utf-8"))
            index += 2
        else:
            output.extend(b"\\")
            index += 1
    return output.decode("utf-8", errors="replace")


def _group_from_dn(dn: str) -> dict[str, Any]:
    name: str | None = None
    try:
        parsed = parse_dn(dn, escape=True, strip=True)
        if parsed:
            name = _unescape_dn_value(parsed[0][1])
    except (LDAPInvalidDnError, TypeError, ValueError):
        pass
    return {"name": name, "dn": dn}


def _safe_report_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return (cleaned or "ad-group")[:100]


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _cleanup_expired_reports(now: float | None = None) -> None:
    current = time.time() if now is None else now
    for token, report in list(REPORTS.items()):
        if report["expires_at"] > current:
            continue
        try:
            Path(report["path"]).unlink(missing_ok=True)
        finally:
            REPORTS.pop(token, None)


def _read_group_member_dns(
    conn: Connection,
    group_dn: str,
    limit: int,
) -> dict[str, Any]:
    members: list[str] = []
    start = 0
    complete = False
    while len(members) <= limit:
        requested = f"member;range={start}-{start + 1499}"
        conn.search(group_dn, GROUP_FILTER, BASE, attributes=[requested], size_limit=1)
        if not conn.entries:
            complete = True
            break
        attrs = conn.entries[0].entry_attributes_as_dict
        ranged_key = next(
            (key for key in attrs if key.lower().startswith("member;range=")), None
        )
        if ranged_key is None:
            members.extend(_as_string_list(attrs.get("member")))
            complete = True
            break
        members.extend(_as_string_list(attrs.get(ranged_key)))
        if ranged_key.endswith("-*"):
            complete = True
            break
        start = int(ranged_key.rsplit("-", 1)[-1]) + 1
        if len(members) > limit:
            break

    unique_dns = list(dict.fromkeys(members))
    truncated = len(unique_dns) > limit or not complete
    return {
        "member_dns": unique_dns[:limit],
        "count": min(len(unique_dns), limit),
        "limit": limit,
        "truncated": truncated,
    }


def _resolve_groups(
    conn: Connection,
    query: str,
    cfg: dict[str, Any],
    limit: int = 10,
) -> tuple[list[dict[str, Any]], str]:
    escaped = escape_filter_value(query.strip())
    exact_filter = (
        "(&(objectCategory=group)(|"
        f"(cn={escaped})(sAMAccountName={escaped})(mail={escaped})"
        f"(distinguishedName={escaped})))"
    )
    exact = _search_with_connection(
        conn, [cfg["domain_base"]], exact_filter, GROUP_ATTRIBUTES, limit
    )
    if exact:
        return exact, "exact_identifier"
    contains_filter = (
        "(&(objectCategory=group)(|"
        f"(cn=*{escaped}*)(sAMAccountName=*{escaped}*)(mail=*{escaped}*)"
        f"(description=*{escaped}*)))"
    )
    groups = _search_with_connection(
        conn, [cfg["domain_base"]], contains_filter, GROUP_ATTRIBUTES, limit
    )
    return groups, "name_search"


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return [str(item) for item in values if item]


def _read_direct_memberships(
    conn: Connection,
    user_dn: str,
    limit: int,
) -> dict[str, Any]:
    memberships: list[str] = []
    start = 0
    complete = False
    while len(memberships) <= limit:
        requested = f"memberOf;range={start}-{start + 1499}"
        conn.search(user_dn, USER_FILTER, BASE, attributes=[requested], size_limit=1)
        if not conn.entries:
            raise ValueError("Resolved user could not be read for membership retrieval")
        attrs = conn.entries[0].entry_attributes_as_dict
        ranged_key = next((key for key in attrs if key.lower().startswith("memberof;range=")), None)
        if ranged_key is None:
            memberships.extend(_as_string_list(attrs.get("memberOf")))
            complete = True
            break
        memberships.extend(_as_string_list(attrs.get(ranged_key)))
        if ranged_key.endswith("-*"):
            complete = True
            break
        start = int(ranged_key.rsplit("-", 1)[-1]) + 1
        if len(memberships) > limit:
            break

    unique_dns = list(dict.fromkeys(memberships))
    truncated = len(unique_dns) > limit or not complete
    returned_dns = unique_dns[:limit]
    return {
        "memberships_included": True,
        "membership_type": "direct",
        "membership_source": "memberOf",
        "direct_membership_count": len(returned_dns),
        "memberships_truncated": truncated,
        "membership_limit": limit,
        "primary_group_included": False,
        "primary_group": None,
        "direct_memberships": [_group_from_dn(dn) for dn in returned_dns],
        "memberOf": returned_dns,
    }


def _memberships_not_requested() -> dict[str, Any]:
    return {
        "memberships_included": False,
        "direct_memberships": None,
        "primary_group_included": False,
    }


def _resolve_people(
    conn: Connection,
    query: str,
    cfg: dict[str, Any],
    limit: int = 4,
) -> tuple[list[dict[str, Any]], str]:
    exact = _search_with_connection(
        conn, cfg["people_bases"], _exact_identity_filter(query), USER_SUMMARY_ATTRIBUTES, limit
    )
    if exact:
        return exact, "exact_identifier"
    names = _search_with_connection(
        conn, cfg["people_bases"], _name_search_filter(query), USER_SUMMARY_ATTRIBUTES, limit
    )
    return names, "name_search"


@mcp.tool
def ad_preflight() -> dict[str, Any]:
    """Check non-secret CA, DNS, and configuration prerequisites without binding.

    Use only for configuration or prerequisite diagnosis, not normal person or group searches.
    """
    cfg = config()
    checks: list[dict[str, Any]] = []
    checks.append({"name": "ldap_hosts_configured", "ok": bool(cfg["hosts"]), "hosts": cfg["hosts"]})
    checks.append({"name": "bind_user_configured", "ok": bool(cfg["bind_user"])})
    checks.append({"name": "bind_password_configured", "ok": bool(cfg["bind_password"])})
    ca_ok = bool(cfg["ca_cert_file"] and os.path.isfile(cfg["ca_cert_file"]))
    checks.append({"name": "ca_certificate_present", "ok": ca_ok, "path": cfg["ca_cert_file"] or None})
    checks.append({"name": "tls_validation_enabled", "ok": cfg["tls_validate"]})
    for host in cfg["hosts"]:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, cfg["port"], type=socket.SOCK_STREAM)})
            checks.append({"name": "dns", "host": host, "ok": True, "addresses": addresses})
        except OSError as exc:
            checks.append({"name": "dns", "host": host, "ok": False, "error": str(exc)})
    return {
        "ok": all(check["ok"] for check in checks),
        "ready_to_bind": all(check["ok"] for check in checks),
        "domain_base": cfg["domain_base"],
        "people_bases": cfg["people_bases"],
        "service_base": cfg["service_base"],
        "pam_base": cfg["pam_base"],
        "checks": checks,
    }


@mcp.tool
def ad_health_check() -> dict[str, Any]:
    """Diagnose AD connectivity, TLS, bind, LDAP, RootDSE, and naming-context failures.

    Do not call this merely because a valid search returned zero results.
    """
    cfg = config()
    started = time.monotonic()
    try:
        with _connect() as conn:
            info = conn.server.info
            other = info.other if info else {}
            default_context = (other.get("defaultNamingContext") or [None])[0]
            return {
                "ok": True,
                "domain_controller": conn.server.host,
                "port": cfg["port"],
                "tls_validate": cfg["tls_validate"],
                "configured_domain_base": cfg["domain_base"],
                "discovered_default_naming_context": default_context,
                "naming_context_matches": str(default_context).lower() == cfg["domain_base"].lower(),
                "people_bases": cfg["people_bases"],
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


@mcp.tool
def ad_check_identity_status(value: str) -> dict[str, Any]:
    """Check a person's AD status using an exact identifier or a full human name.

    Exact identifiers are preferred, but a human name is accepted and safely searched within
    the primary and secondary people scopes. Ambiguous names return candidates rather than choosing silently.
    """
    cfg = config()
    query = value.strip()
    if not query:
        return {"ok": False, "error": "value is required"}
    started = time.monotonic()
    try:
        with _connect() as conn:
            raw_users, match_method = _resolve_people(conn, query, cfg)
            users = [_decorate_user(user) for user in raw_users]
            common = {
                "ok": True,
                "count": len(users),
                "domain_controller": conn.server.host,
                "match_method": match_method,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
            if not users:
                likely_name = _looks_like_human_name(query, cfg["domain_base"])
                outside_scope = False
                if not likely_name:
                    outside = _search_with_connection(
                        conn,
                        [cfg["domain_base"]],
                        _exact_identity_filter(query),
                        ["distinguishedName"],
                        1,
                    )
                    outside_scope = bool(outside)
                return {
                    **common,
                    "exists": False,
                    "active": None,
                    "status": "outside_people_scope" if outside_scope else "not_found",
                    "authoritative": not likely_name,
                    "possible_non_person_account": outside_scope,
                    "recommended_tool": "ad_search_users" if likely_name else None,
                    "matches": [],
                }
            return {
                **common,
                "exists": True,
                "status": "ambiguous" if len(users) > 1 else users[0]["account_state"]["status"],
                "active": users[0]["account_state"]["active"] if len(users) == 1 else None,
                "authoritative": len(users) == 1,
                "matches": users,
            }
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


@mcp.tool
def ad_search_users(query: str, limit: int | None = None, include_memberships: bool = False) -> dict[str, Any]:
    """Search people by human name, partial name, or uncertain identity information.

    Use this first for ordinary human names, including complete-looking full names. Set
    include_memberships=true when asked which direct AD groups a person belongs to. Those
    memberships come from memberOf and are direct, not recursive or effective memberships.

    Args:
        query: Human name, partial name, username, email, UPN, or employee identifier.
        limit: Maximum people to return.
        include_memberships: Return complete direct memberOf memberships for each matched user.
    """
    cfg = config()
    q = query.strip()
    if not q:
        return {"ok": False, "error": "query is required"}
    result_limit = clamp_limit(limit, cfg["default_limit"], cfg["max_limit"])
    started = time.monotonic()
    try:
        with _connect() as conn:
            raw_users = _search_with_connection(
                conn,
                cfg["people_bases"],
                _name_search_filter(q),
                USER_SUMMARY_ATTRIBUTES,
                result_limit + 1,
            )
            user_results_truncated = len(raw_users) > result_limit
            users = []
            for raw_user in raw_users[:result_limit]:
                user = _decorate_user(raw_user)
                if include_memberships:
                    try:
                        user.update(_read_direct_memberships(conn, user["dn"], cfg["max_limit"]))
                    except (LDAPException, OSError, ValueError) as exc:
                        user.update({
                            "memberships_included": False,
                            "direct_memberships": None,
                            "membership_error": {
                                "code": "membership_retrieval_failed",
                                "message": str(exc),
                            },
                            "primary_group_included": False,
                        })
                else:
                    user.update(_memberships_not_requested())
                users.append(user)
            return {
                "ok": True,
                "count": len(users),
                "limit": result_limit,
                "truncated": user_results_truncated,
                "user_results_truncated": user_results_truncated,
                "bases": cfg["people_bases"],
                "domain_controller": conn.server.host,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "users": users,
            }
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


@mcp.tool
def ad_get_user_memberships(
    query: str,
    recursive: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    """Return groups to which one resolved person in a configured people scope belongs.

    This is the preferred tool for "Which groups is this person in?" It accepts a human
    name, partial name, username, email, UPN, employee identifier, or user DN. It resolves
    the person internally, so the user does not need to provide a DN. Multiple matches are
    returned as candidates without combining memberships.

    Use recursive=false for direct memberOf memberships. Use recursive=true only for nested,
    inherited, transitive, or effective group-membership requests. This tool does not list
    the members of a group.
    """
    cfg = config()
    q = query.strip()
    if not q:
        return {"ok": False, "error": "query is required"}
    result_limit = clamp_limit(limit, cfg["max_limit"], cfg["export_max_limit"])
    started = time.monotonic()
    try:
        with _connect() as conn:
            raw_users, match_method = _resolve_people(conn, q, cfg)
            candidates = [_decorate_user(user) for user in raw_users]
            if not candidates:
                return {
                    "ok": True,
                    "count": 0,
                    "status": "not_found",
                    "match_method": match_method,
                    "candidates": [],
                    "groups": [],
                    "domain_controller": conn.server.host,
                }
            if len(candidates) > 1:
                return {
                    "ok": True,
                    "count": len(candidates),
                    "status": "ambiguous",
                    "match_method": match_method,
                    "candidates": candidates,
                    "groups": None,
                    "domain_controller": conn.server.host,
                }

            user = candidates[0]
            if not recursive:
                membership = _read_direct_memberships(conn, user["dn"], result_limit)
                return {
                    "ok": True,
                    "status": "found",
                    "match_method": match_method,
                    "user": user,
                    "recursive": False,
                    "count": membership["direct_membership_count"],
                    "truncated": membership["memberships_truncated"],
                    "groups": membership["direct_memberships"],
                    "domain_controller": conn.server.host,
                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                    **membership,
                }

            escaped_dn = escape_filter_value(user["dn"])
            group_filter = f"(&(objectCategory=group)(member:{MATCHING_RULE_IN_CHAIN}:={escaped_dn}))"
            raw_groups = _search_with_connection(
                conn, [cfg["domain_base"]], group_filter, GROUP_ATTRIBUTES, result_limit + 1
            )
            truncated = len(raw_groups) > result_limit
            groups = []
            for group in raw_groups[:result_limit]:
                groups.append({
                    "name": group.get("cn") or _group_from_dn(group["dn"])["name"],
                    "dn": group["dn"],
                })
            return {
                "ok": True,
                "status": "found",
                "match_method": match_method,
                "user": user,
                "recursive": True,
                "membership_type": "transitive",
                "membership_source": f"member:{MATCHING_RULE_IN_CHAIN}",
                "count": len(groups),
                "limit": result_limit,
                "truncated": truncated,
                "primary_group_included": False,
                "groups": groups,
                "domain_controller": conn.server.host,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


@mcp.tool
def ad_search_groups(query: str, limit: int | None = None) -> dict[str, Any]:
    """Search groups across the domain by name, mail, or description."""
    cfg = config()
    q = query.strip()
    if not q:
        return {"ok": False, "error": "query is required"}
    escaped = escape_filter_value(q)
    search_filter = (
        "(&(objectCategory=group)(|"
        f"(cn=*{escaped}*)(sAMAccountName=*{escaped}*)(mail=*{escaped}*)(description=*{escaped}*)))"
    )
    result_limit = clamp_limit(limit, cfg["default_limit"], cfg["max_limit"])
    result = _search([cfg["domain_base"]], search_filter, GROUP_ATTRIBUTES, result_limit)
    if result.get("ok"):
        result["groups"] = result.pop("entries")
    return result


@mcp.tool
def ad_get_group(group_dn: str) -> dict[str, Any]:
    """Get safe metadata for one group by exact distinguished name."""
    cfg = config()
    if not group_dn.strip().lower().endswith(cfg["domain_base"].lower()):
        return {"ok": False, "error": "group_dn must be within the configured domain"}
    try:
        with _connect() as conn:
            conn.search(group_dn, GROUP_FILTER, BASE, attributes=_safe_attributes(GROUP_ATTRIBUTES), size_limit=1)
            group = _attributes_to_dict(conn.entries[0].entry_dn, conn.entries[0].entry_attributes_as_dict) if conn.entries else None
            return {"ok": True, "count": 1 if group else 0, "domain_controller": conn.server.host, "group": group}
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


@mcp.tool
def ad_get_group_members(group_dn: str, limit: int | None = None) -> dict[str, Any]:
    """Enumerate direct group member DNs using AD ranged retrieval for large groups."""
    cfg = config()
    if not group_dn.strip().lower().endswith(cfg["domain_base"].lower()):
        return {"ok": False, "error": "group_dn must be within the configured domain"}
    result_limit = clamp_limit(limit, cfg["default_limit"], cfg["export_max_limit"])
    try:
        with _connect() as conn:
            membership = _read_group_member_dns(conn, group_dn, result_limit)
            return {
                "ok": True,
                "group_dn": group_dn,
                "domain_controller": conn.server.host,
                **membership,
            }
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


@mcp.tool
def ad_export_group_members_csv(group: str) -> dict[str, Any]:
    """Create a short-lived downloadable CSV containing all direct members of an AD group.

    Use this for large group membership reports instead of returning thousands of DNs to the
    model. The group may be supplied as an ordinary name, sAMAccountName, email address, or
    exact DN. The CSV contains friendly member names and exact distinguished names. It is a
    direct-membership report; nested group expansion is not performed.

    If multiple groups match, return candidates and ask the user to choose one. The download
    URL expires automatically and is protected by the same network controls as the MCP site.

    Args:
        group: Group name, partial name, sAMAccountName, email address, or exact group DN.
    """
    cfg = config()
    query = group.strip()
    if not query:
        return {"ok": False, "error": "group is required"}
    started = time.monotonic()
    try:
        with _connect() as conn:
            groups, match_method = _resolve_groups(conn, query, cfg)
            if not groups:
                return {
                    "ok": True,
                    "status": "not_found",
                    "count": 0,
                    "match_method": match_method,
                    "candidates": [],
                }
            if len(groups) > 1:
                return {
                    "ok": True,
                    "status": "ambiguous",
                    "count": len(groups),
                    "match_method": match_method,
                    "candidates": groups,
                }

            resolved_group = groups[0]
            membership = _read_group_member_dns(
                conn, resolved_group["dn"], cfg["report_max_rows"]
            )
            _cleanup_expired_reports()
            REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)
            token = secrets.token_urlsafe(32)
            group_name = str(
                resolved_group.get("cn")
                or resolved_group.get("sAMAccountName")
                or _group_from_dn(resolved_group["dn"])["name"]
                or "ad-group"
            )
            filename = f"{_safe_report_filename(group_name)}-direct-members.csv"
            path = REPORT_DIRECTORY / f"{token}.csv"
            with path.open("w", encoding="utf-8-sig", newline="") as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=["Name", "DistinguishedName"],
                    lineterminator="\n",
                )
                writer.writeheader()
                for member_dn in membership["member_dns"]:
                    parsed = _group_from_dn(member_dn)
                    writer.writerow({
                        "Name": _csv_safe(parsed["name"]),
                        "DistinguishedName": _csv_safe(member_dn),
                    })

            expires_at = time.time() + cfg["report_ttl_seconds"]
            REPORTS[token] = {
                "path": str(path),
                "filename": filename,
                "expires_at": expires_at,
            }
            return {
                "ok": True,
                "status": "ready",
                "group": {
                    "name": group_name,
                    "dn": resolved_group["dn"],
                },
                "membership_type": "direct",
                "count": membership["count"],
                "truncated": membership["truncated"],
                "report_max_rows": cfg["report_max_rows"],
                "download_url": f"{cfg['public_base_url']}/reports/{token}",
                "filename": filename,
                "expires_in_seconds": cfg["report_ttl_seconds"],
                "domain_controller": conn.server.host,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "message": (
                    "The CSV is ready. Share the download link rather than listing all member "
                    "DNs in the conversation."
                ),
            }
    except (LDAPException, OSError, ValueError, ConnectionError) as exc:
        return _error(exc)


@mcp.custom_route("/reports/{token}", methods=["GET"], include_in_schema=False)
async def download_group_report(request: Request) -> Response:
    _cleanup_expired_reports()
    token = request.path_params["token"]
    report = REPORTS.get(token)
    if report is None or not Path(report["path"]).is_file():
        return PlainTextResponse("Report not found or expired", status_code=404)
    return FileResponse(
        report["path"],
        media_type="text/csv; charset=utf-8",
        filename=report["filename"],
        headers={
            "Cache-Control": "no-store, private",
            "X-Content-Type-Options": "nosniff",
        },
    )


@mcp.tool
def ad_find_users_in_group(group_dn: str, recursive: bool = False, limit: int | None = None) -> dict[str, Any]:
    """Find people in a group, optionally including nested group membership."""
    cfg = config()
    if not group_dn.strip().lower().endswith(cfg["domain_base"].lower()):
        return {"ok": False, "error": "group_dn must be within the configured domain"}
    escaped = escape_filter_value(group_dn)
    membership = f"(memberOf:{MATCHING_RULE_IN_CHAIN}:={escaped})" if recursive else f"(memberOf={escaped})"
    search_filter = f"(&{USER_FILTER}{membership})"
    result_limit = clamp_limit(limit, cfg["default_limit"], cfg["max_limit"])
    result = _search(cfg["people_bases"], search_filter, USER_SUMMARY_ATTRIBUTES, result_limit)
    if result.get("ok"):
        result["recursive"] = recursive
        result["users"] = [_decorate_user(user) for user in result.pop("entries")]
    return result


if __name__ == "__main__":
    mcp.run(
        transport=os.getenv("MCP_TRANSPORT", "streamable-http"),
        host=os.getenv("MCP_HOST", "0.0.0.0"),
        port=env_int("MCP_PORT", 8000),
    )
