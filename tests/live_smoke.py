"""Read-only live smoke test. Requires AD environment variables and CA mount."""

import json
import sys

import server


def main() -> None:
    query = sys.argv[1] if len(sys.argv) > 1 else ""
    if not query:
        raise SystemExit("usage: python tests/live_smoke.py <user query>")

    status = server.ad_check_identity_status.fn(query)
    search = server.ad_search_users.fn(query, limit=10, include_memberships=True)
    memberships = server.ad_get_user_memberships.fn(query, recursive=False, limit=500)
    first_search_user = (search.get("users") or [{}])[0]
    summary = {
        "status_ok": status.get("ok"),
        "status": status.get("status"),
        "status_match_method": status.get("match_method"),
        "status_count": status.get("count"),
        "search_ok": search.get("ok"),
        "search_count": search.get("count"),
        "search_user_results_truncated": search.get("user_results_truncated"),
        "search_memberships_included": first_search_user.get("memberships_included"),
        "search_membership_count": first_search_user.get("direct_membership_count"),
        "search_memberships_truncated": first_search_user.get("memberships_truncated"),
        "membership_ok": memberships.get("ok"),
        "membership_status": memberships.get("status"),
        "membership_match_method": memberships.get("match_method"),
        "membership_type": memberships.get("membership_type"),
        "membership_count": memberships.get("count"),
        "membership_truncated": memberships.get("truncated"),
        "primary_group_included": memberships.get("primary_group_included"),
        "sample_group_names": [
            group.get("name") for group in (memberships.get("groups") or [])[:3]
        ],
        "error": status.get("error") or search.get("error") or memberships.get("error"),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
