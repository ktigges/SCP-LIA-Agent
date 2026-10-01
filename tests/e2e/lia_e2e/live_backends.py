"""Live tool backends. Neither one uses Security Copilot, so neither consumes SCUs.

HuntingBackend
    Runs the real kql/*.kql text through Microsoft Graph Advanced Hunting
    (POST /v1.0/security/runHuntingQuery) after substituting {Param}
    placeholders with the raw argument text, the same way "Save as tool"
    substitutes them. This validates the KQL against the tenant's real tables,
    columns and functions before any MCP tool is created.
    Token: $LIA_GRAPH_TOKEN, otherwise `az account get-access-token`.
    Needs delegated ThreatHunting.Read.All (see tests/e2e/README.md).

McpBackend
    Calls the deployed custom Sentinel MCP collection directly (JSON-RPC over
    streamable HTTP, `tools/call`), which tests the exact tools the plugin will
    import. Token: $LIA_MCP_TOKEN, otherwise `az account get-access-token`
    for the Sentinel Platform Services scope used in the plugin YAML.
"""
import json
import os
import subprocess
import urllib.error
import urllib.request

from .contract import load_contract
from .mock_backend import ToolError

GRAPH_HUNTING_URL = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
SENTINEL_SCOPE = "4500ebfb-89b6-4b14-a480-7f749797bfcd/.default"
AUTH_WORDS = ("forbidden", "unauthorized", "insufficient privileges", "not authorized", "access denied")


def _az_token(args):
    try:
        out = subprocess.run(["az", "account", "get-access-token", *args, "--query", "accessToken", "-o", "tsv"],
                             capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise SystemExit("Azure CLI not found; set the token environment variable instead.")
    if out.returncode != 0:
        raise SystemExit(f"az account get-access-token failed: {out.stderr.strip()}")
    return out.stdout.strip()


def _post(url, token, body, extra_headers=None, timeout=300):
    data = json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    headers.update(extra_headers or {})
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")
    except (urllib.error.URLError, TimeoutError) as e:
        raise ToolError("QueryFailed", f"Network error or timeout: {e}")


def _classify(status, text):
    msg = " ".join(text.split())[:600]
    if status in (401, 403) or any(w in msg.lower() for w in AUTH_WORDS):
        return ToolError("AccessDenied", f"HTTP {status}: {msg}")
    return ToolError("QueryFailed", f"HTTP {status}: {msg}")


class HuntingBackend:
    name = "hunting"

    def __init__(self):
        self.contract = load_contract()
        self.token = os.environ.get("LIA_GRAPH_TOKEN") or _az_token(["--resource", "https://graph.microsoft.com"])

    def render(self, tool, args):
        spec = self.contract.tools[tool]
        text = spec.kql()
        for p in spec.params:
            text = text.replace("{" + p + "}", str(args.get(p, "")))
        # Advanced Hunting rejects nothing in comments, but strip them to keep payloads small.
        return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))

    def call(self, tool, args):
        if tool not in self.contract.tools:
            raise ToolError("QueryFailed", f"Tool '{tool}' is not in the collection")
        status, _, text = _post(GRAPH_HUNTING_URL, self.token, {"Query": self.render(tool, args)})
        if status != 200:
            raise _classify(status, text)
        return json.loads(text).get("results", [])


class McpBackend:
    name = "mcp"

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.token = os.environ.get("LIA_MCP_TOKEN") or _az_token(["--scope", SENTINEL_SCOPE])
        self.session = None
        self._id = 0
        self._initialize()

    def _rpc(self, method, params=None, notify=False):
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            self._id += 1
            body["id"] = self._id
        headers = {"Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        status, resp_headers, text = _post(self.endpoint, self.token, body, headers)
        sid = {k.lower(): v for k, v in resp_headers.items()}.get("mcp-session-id")
        if sid:
            self.session = sid
        if status >= 400:
            raise _classify(status, text)
        if notify or not text.strip():
            return None
        if text.lstrip().startswith("{"):
            msg = json.loads(text)
        else:  # SSE: take the last data: line that parses as a JSON-RPC response
            msg = None
            for line in text.splitlines():
                if line.startswith("data:"):
                    try:
                        cand = json.loads(line[5:].strip())
                    except json.JSONDecodeError:
                        continue
                    if "result" in cand or "error" in cand:
                        msg = cand
            if msg is None:
                raise ToolError("QueryFailed", f"Unparseable MCP response: {text[:300]}")
        if "error" in msg:
            raise _classify(200, json.dumps(msg["error"]))
        return msg["result"]

    def _initialize(self):
        self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "lia-e2e", "version": "1.0"}})
        self._rpc("notifications/initialized", notify=True)

    def list_tools(self):
        return [t["name"] for t in self._rpc("tools/list", {}).get("tools", [])]

    def call(self, tool, args):
        result = self._rpc("tools/call", {"name": tool, "arguments": args})
        texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        if result.get("isError"):
            raise _classify(200, " ".join(texts))
        if isinstance(result.get("structuredContent"), (dict, list)):
            return _rows_from(result["structuredContent"])
        for t in texts:
            try:
                return _rows_from(json.loads(t))
            except json.JSONDecodeError:
                continue
        # Unknown payload shape: hand the raw text to the orchestrator unchanged.
        return [{"RawToolText": "\n".join(texts)}]


def _rows_from(obj):
    """Accept the likely result shapes: list of rows, {results|rows|Results: [...]}, or AH {tables:[...]}."""
    if isinstance(obj, list):
        return obj
    for key in ("results", "rows", "Results", "Rows", "data"):
        if isinstance(obj.get(key), list):
            return obj[key]
    if isinstance(obj.get("tables"), list) and obj["tables"]:
        tbl = obj["tables"][0]
        cols = [c.get("name") or c.get("ColumnName") for c in tbl.get("columns", [])]
        return [dict(zip(cols, r)) for r in tbl.get("rows", [])]
    return [obj]
