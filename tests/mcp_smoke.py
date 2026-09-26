"""Smoke-test a running Streamable HTTP MCP endpoint."""

import asyncio
import json
import sys

from fastmcp import Client


async def main() -> None:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://ad-mcp:8000/mcp"
    query = sys.argv[2] if len(sys.argv) > 2 else ""
    async with Client(endpoint) as client:
        tools = await client.list_tools()
        names = sorted(tool.name for tool in tools)
        output = {
            "connected": True,
            "tool_count": len(names),
            "has_user_membership_tool": "ad_get_user_memberships" in names,
            "has_group_csv_export_tool": "ad_export_group_members_csv" in names,
            "tools": names,
        }
        if query:
            result = await client.call_tool(
                "ad_get_user_memberships",
                {"query": query, "recursive": False, "limit": 500},
            )
            data = result.data if hasattr(result, "data") else None
            output["membership_call_returned"] = result is not None
            if isinstance(data, dict):
                output["membership_status"] = data.get("status")
                output["membership_count"] = data.get("count")
                output["membership_truncated"] = data.get("truncated")
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
