"""End-to-end smoke test for a running MCP group CSV export."""

import asyncio
import csv
import io
import json
import sys
import urllib.parse
import urllib.request

from fastmcp import Client


async def main() -> None:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://ad-mcp:8000/mcp"
    group = sys.argv[2] if len(sys.argv) > 2 else "Duo-SSO-FTE"
    download_origin = (
        sys.argv[3] if len(sys.argv) > 3 else "http://ad-mcp:8000"
    ).rstrip("/")

    async with Client(endpoint) as client:
        result = await client.call_tool(
            "ad_export_group_members_csv",
            {"group": group},
        )
        data = result.data if hasattr(result, "data") else None

    if not isinstance(data, dict):
        raise RuntimeError("CSV export tool did not return structured data")
    if data.get("status") != "ready":
        print(json.dumps(data, indent=2))
        raise RuntimeError("CSV export was not ready")

    public_url = str(data["download_url"])
    report_path = urllib.parse.urlsplit(public_url).path
    with urllib.request.urlopen(download_origin + report_path, timeout=30) as response:
        payload = response.read()
        response_status = response.status
        content_type = response.headers.get_content_type()

    rows = list(csv.DictReader(io.StringIO(payload.decode("utf-8-sig"))))
    expected_count = int(data["count"])
    if len(rows) != expected_count:
        raise RuntimeError(
            f"CSV row count {len(rows)} did not match tool count {expected_count}"
        )

    print(json.dumps({
        "ok": data.get("ok"),
        "status": data.get("status"),
        "group": (data.get("group") or {}).get("name"),
        "membership_type": data.get("membership_type"),
        "count": expected_count,
        "truncated": data.get("truncated"),
        "filename": data.get("filename"),
        "expires_in_seconds": data.get("expires_in_seconds"),
        "download_url": public_url,
        "download_status": response_status,
        "content_type": content_type,
        "download_bytes": len(payload),
        "csv_rows": len(rows),
        "csv_columns": list(rows[0]) if rows else ["Name", "DistinguishedName"],
    }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
