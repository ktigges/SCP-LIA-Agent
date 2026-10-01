# LIA - Log Intelligence Assistant (PoC)

LIA is a read-only investigation agent built in Microsoft Security Copilot. Given a specific device, user, or SHA-256 hash and a bounded time window, LIA retrieves telemetry across Microsoft Defender XDR and Microsoft Sentinel using parameterized KQL tools, correlates events, and generates an audit-ready, 10-section SOC investigation report.

For interactive architecture diagrams, visual workflows, and component breakdowns, see the [`docs/`](docs/) directory:
- [Visual Architecture Overview](docs/lia-architecture-visual.html)
- [Interactive Investigation Flow & Deep-Dive Explainer](docs/lia-explainer/index.html)

---

## Repository Structure

```
agent/
  lia-agent.yaml                     # Security Copilot agent manifest
  lia-agent-instructions.txt         # Standalone agent instructions for Build portal
plugins/
  lia-sentinel-mcp-plugin.yaml       # MCP plugin descriptor for Security Copilot
kql/                                 # Parameterized KQL queries (saved as MCP tools)
  normalize-time-window.kql          # Timezone conversion & window validation
  resolve-device.kql                 # Resolves hostnames/IDs to canonical DeviceId
  resolve-user.kql                   # Resolves UPN/SID/ObjectId to AccountObjectId
  get-device-timeline.kql            # Endpoint event timeline for one device
  user-authentication-timeline.kql   # Sign-in and logon timeline for one user
  file-hash-activity.kql             # Cross-device activity for a SHA-256
  related-alerts.kql                 # Correlated Defender and Sentinel alerts
  match-observed-indicators.kql      # Threat intelligence indicator enrichment
  source-coverage.kql                # Table availability and record count checks
schemas/                             # JSON schemas for normalized events & reports
tests/                               # Acceptance criteria and local validation scripts
docs/                                # Visual diagrams, explainers, and runbooks
```

---

## Installation & Setup

### 1. Save KQL Queries as Tools (Defender Advanced Hunting)
In the Microsoft Defender portal, go to **Hunting** -> **Advanced hunting**:
1. Open each file in `kql/`.
2. Select **Save as tool**.
3. Set the tool name to match the file name (e.g. `get_device_timeline`).
4. Assign all 9 tools to a single collection named `LIA`.
5. Set the **Default workspace** to your Sentinel log analytics workspace.
6. Configure the `{Parameter}` placeholders as strings in the tool parameters flyout.

### 2. Configure & Upload the MCP Plugin (Security Copilot)
1. Verify the collection endpoint in `plugins/lia-sentinel-mcp-plugin.yaml`:
   `https://sentinel.microsoft.com/mcp/custom/LIA`
2. In Security Copilot, select the **Sources** icon in the prompt bar -> **Manage sources**.
3. Under **Plugins** -> **Custom**, select **Add plugin** -> **Security Copilot plugin**.
4. Upload `plugins/lia-sentinel-mcp-plugin.yaml` (scoped to yourself or organization).

### 3. Deploy the Custom Agent (Security Copilot Build)
1. In Security Copilot, go to **Build** -> **Start from scratch**.
2. Set the agent display name to `LIA - Log Intelligence Assistant`.
3. In **Instructions**, copy and paste the full contents of `agent/lia-agent-instructions.txt`.
4. In **Tools**, select **Add tool** -> search for **LIA Sentinel MCP Tools** -> select all 9 tools.
5. Select **Publish**.

---

## Running an Investigation

In the Security Copilot chat prompt:

- **Device Investigation (24h max):**
  > `Investigate device KYTIGGES-WS11 on 2026-09-30 between 12:00 and 18:00 America/Denver`

- **User Investigation (24h max):**
  > `Investigate user user@domain.com from 2026-09-30 08:00 to 2026-09-30 17:00 UTC`

- **File Hash Investigation (30-day max):**
  > `Find every device where SHA256 <64-char-hex-hash> was observed from 2026-09-01 to 2026-09-30 UTC`
