"""Generate the Microsoft Sentinel deployment templates.

Run from the repo root:

    python integrations/sentinel/_build.py           # rewrite the templates
    python integrations/sentinel/_build.py --check   # fail if they are stale (CI)

Sources of truth:

* ``src/drosera/telemetry/azure.py`` ``COLUMNS`` -- the table schema and the
  data collection rule's stream declaration. The sink and the Azure side can
  therefore never disagree about a column.
* ``integrations/sentinel/kql/**.kql`` -- every query, kept as plain KQL so an
  analyst can read it, paste it into Log Analytics, or review it in a diff.
* This file -- rule metadata, the workbook layout, and the two playbooks.

Edit those, not the generated JSON under ``deploy/`` and ``playbooks/``.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from drosera.telemetry.azure import COLUMNS, DEFAULT_STREAM  # noqa: E402

TABLE = "DroseraEvents_CL"
OUTPUT_STREAM = f"Custom-{TABLE}"
SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
NS = uuid.UUID("5b3f6f0e-6a53-4f43-9a4a-6f0d8d1c0a11")  # stable ids across rebuilds
MONITORING_METRICS_PUBLISHER = "3913510d-42f4-4e42-8a64-420c390055eb"
SENTINEL_API = (
    "[concat('/subscriptions/', subscription().subscriptionId, "
    "'/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]"
)


def kql(rel: str) -> str:
    return (HERE / "kql" / rel).read_text(encoding="utf-8").strip() + "\n"


def stable_id(name: str) -> str:
    return str(uuid.uuid5(NS, name))


def literal(text: str) -> str:
    """ARM treats any string starting with '[' as an expression. Ours never should."""
    if text.startswith("["):
        raise ValueError(f"literal string would be parsed as an ARM expression: {text[:40]!r}")
    return text


def template(parameters: dict, resources: list, outputs: dict | None = None,
             variables: dict | None = None, description: str = "") -> dict[str, Any]:
    t: dict[str, Any] = {
        "$schema": SCHEMA,
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": description,
            "generator": "integrations/sentinel/_build.py -- do not edit by hand",
        },
        "parameters": parameters,
    }
    if variables:
        t["variables"] = variables
    t["resources"] = resources
    if outputs:
        t["outputs"] = outputs
    return t


# -- ingestion: table, DCE, DCR, role, functions -----------------------------------


def ingestion() -> dict[str, Any]:
    table_columns = [
        {"name": n, "type": "dateTime" if t == "datetime" else t} for n, t in COLUMNS
    ]
    stream_columns = [{"name": n, "type": t} for n, t in COLUMNS]
    dce_id = "[resourceId('Microsoft.Insights/dataCollectionEndpoints', parameters('dceName'))]"
    dcr_id = "[resourceId('Microsoft.Insights/dataCollectionRules', parameters('dcrName'))]"
    ws_id = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
    table_id = (
        "[resourceId('Microsoft.OperationalInsights/workspaces/tables', "
        f"parameters('workspaceName'), '{TABLE}')]"
    )

    functions = []
    for alias, category_name in (("DroseraSessions", "drosera-sessions"),
                                 ("DroseraCanaryHits", "drosera-canary-hits")):
        functions.append({
            "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
            "apiVersion": "2020-08-01",
            "name": f"[concat(parameters('workspaceName'), '/{category_name}')]",
            "dependsOn": [table_id],
            "properties": {
                "category": "Drosera",
                "displayName": alias,
                "functionAlias": alias,
                "query": literal(kql(f"functions/{alias}.kql")),
            },
        })

    return template(
        description=(
            "Drosera -> Microsoft Sentinel ingestion: the DroseraEvents_CL table, a data "
            "collection endpoint and rule for the Logs Ingestion API, an optional Monitoring "
            "Metrics Publisher assignment for the sender, and the DroseraSessions and "
            "DroseraCanaryHits parser functions. Deploy into the workspace's resource group."
        ),
        parameters={
            "workspaceName": {"type": "string", "metadata": {
                "description": "Existing Log Analytics workspace with Microsoft Sentinel enabled."}},
            "location": {"type": "string", "defaultValue": "[resourceGroup().location]", "metadata": {
                "description": "Must be the workspace's region."}},
            "dceName": {"type": "string", "defaultValue": "drosera-dce"},
            "dcrName": {"type": "string", "defaultValue": "drosera-dcr"},
            "principalId": {"type": "string", "defaultValue": "", "metadata": {
                "description": "Object id of the app registration's service principal, or of "
                               "the managed identity, that will send events. Leave empty to "
                               "assign the role yourself."}},
            "principalType": {"type": "string", "defaultValue": "ServicePrincipal",
                              "allowedValues": ["ServicePrincipal", "User", "Group"]},
        },
        resources=[
            {
                "type": "Microsoft.OperationalInsights/workspaces/tables",
                "apiVersion": "2022-10-01",
                "name": f"[concat(parameters('workspaceName'), '/{TABLE}')]",
                "properties": {
                    "plan": "Analytics",
                    "schema": {
                        "name": TABLE,
                        "description": "Drosera honeypot events: one row per request or canary hit.",
                        "columns": table_columns,
                    },
                },
            },
            {
                "type": "Microsoft.Insights/dataCollectionEndpoints",
                "apiVersion": "2022-06-01",
                "name": "[parameters('dceName')]",
                "location": "[parameters('location')]",
                "properties": {"networkAcls": {"publicNetworkAccess": "Enabled"}},
            },
            {
                "type": "Microsoft.Insights/dataCollectionRules",
                "apiVersion": "2022-06-01",
                "name": "[parameters('dcrName')]",
                "location": "[parameters('location')]",
                "dependsOn": [dce_id, table_id],
                "properties": {
                    "description": "Drosera events via the Logs Ingestion API.",
                    "dataCollectionEndpointId": dce_id,
                    "streamDeclarations": {DEFAULT_STREAM: {"columns": stream_columns}},
                    "destinations": {"logAnalytics": [{"workspaceResourceId": ws_id, "name": "sentinel"}]},
                    "dataFlows": [{
                        "streams": [DEFAULT_STREAM],
                        "destinations": ["sentinel"],
                        "transformKql": "source",
                        "outputStream": OUTPUT_STREAM,
                    }],
                },
            },
            {
                "condition": "[not(empty(parameters('principalId')))]",
                "type": "Microsoft.Authorization/roleAssignments",
                "apiVersion": "2022-04-01",
                "scope": "[format('Microsoft.Insights/dataCollectionRules/{0}', parameters('dcrName'))]",
                "name": f"[guid({dcr_id[1:-1]}, parameters('principalId'), '{MONITORING_METRICS_PUBLISHER}')]",
                "dependsOn": [dcr_id],
                "properties": {
                    "roleDefinitionId": (
                        "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
                        f"'{MONITORING_METRICS_PUBLISHER}')]"
                    ),
                    "principalId": "[parameters('principalId')]",
                    "principalType": "[parameters('principalType')]",
                },
            },
            *functions,
        ],
        outputs={
            "endpoint": {"type": "string",
                         "value": f"[reference({dce_id[1:-1]}, '2022-06-01').logsIngestion.endpoint]"},
            "rule_id": {"type": "string", "value": f"[reference({dcr_id[1:-1]}, '2022-06-01').immutableId]"},
            "stream": {"type": "string", "value": DEFAULT_STREAM},
        },
    )


# -- analytics rules -------------------------------------------------------------------

IP = {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "SrcIpAddr"}]}
HOST = {"entityType": "Host", "fieldMappings": [{"identifier": "HostName", "columnName": "Sensor"}]}

RULES: list[dict[str, Any]] = [
    {
        "key": "agent-confirmed",
        "displayName": "Drosera - LLM agent confirmed by comprehension evidence",
        "description": (
            "A client read the honeypot's plain-English notice and acted on it -- returned the "
            "deployment's HMAC-signed ticket, sent the requested purpose header, or followed the "
            "prose instruction. A crawler cannot do this; an LLM agent can. This is evidence "
            "about the software, not a judgement about whoever is running it."
        ),
        "severity": "Medium",
        "tactics": ["Reconnaissance"],
        "techniques": ["T1594", "T1595"],
        "entities": [IP, HOST],
        "details": {"Sessions": "Sessions", "Agency": "MaxAgency", "Signals": "SignalList",
                    "UserAgent": "UserAgent", "TokensBurned": "TokensBurned"},
        "name": "Drosera: LLM agent at {{SrcIpAddr}}",
        "frequency": "PT1H", "period": "PT1H",
    },
    {
        "key": "hostile-agent",
        "displayName": "Drosera - Hostile LLM agent",
        "description": (
            "An LLM-driven client that also probed for secrets, admin paths, path traversal or "
            "injection. Agency and hostility are scored independently; both are high here."
        ),
        "severity": "High",
        "tactics": ["Reconnaissance", "InitialAccess"],
        "techniques": ["T1595", "T1190"],
        "entities": [IP, HOST],
        "details": {"Sessions": "Sessions", "Agency": "MaxAgency", "Hostility": "MaxHostility",
                    "Signals": "SignalList", "Paths": "PathList", "UserAgent": "UserAgent"},
        "name": "Drosera: hostile LLM agent at {{SrcIpAddr}}",
        "frequency": "PT15M", "period": "PT15M",
    },
    {
        "key": "canary-credential-used",
        "displayName": "Drosera - Canary credential used",
        "description": (
            "A planted canary credential was presented to the honeypot or found by drosera "
            "canary scan. The value exists nowhere except inside bait, so this is proof the bait "
            "was read and its contents moved. Canary credentials authenticate nowhere."
        ),
        "severity": "High",
        "tactics": ["CredentialAccess", "Exfiltration"],
        "techniques": ["T1552"],
        "entities": [IP, HOST],
        "details": {"Occurrences": "Occurrences", "Detail": "DetailText", "Location": "LocationList"},
        "name": "Drosera: canary credential used on {{Sensor}}",
        "frequency": "PT15M", "period": "PT15M",
    },
    {
        "key": "canary-file-touched",
        "displayName": "Drosera - Canary file modified or read",
        "description": (
            "A planted canary file changed (or was read, when access-time watching is on). "
            "A hint, not proof: backups, antivirus and indexers touch files too. Correlate with "
            "process and logon activity on the host."
        ),
        "severity": "Medium",
        "tactics": ["CredentialAccess", "Collection"],
        "techniques": ["T1552", "T1005"],
        "entities": [HOST],
        "details": {"File": "FilePath", "Channels": "ChannelList", "Kinds": "KindList"},
        "name": "Drosera: canary file touched on {{Sensor}}",
        "frequency": "PT1H", "period": "PT1H",
    },
    {
        "key": "honeypot-ip-signin",
        "displayName": "Drosera - Honeypot agent address signing in to Entra ID",
        "description": (
            "An address that behaved as an LLM agent, or with high hostility, on the honeypot in "
            "the last 7 days is attempting to sign in to Entra ID. Requires the Microsoft Entra "
            "ID (SigninLogs) connector. High severity when an attempt succeeded."
        ),
        "severity": "Medium",
        "tactics": ["InitialAccess", "CredentialAccess"],
        "techniques": ["T1078", "T1110"],
        "entities": [
            {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "UserPrincipalName"}]},
            {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "IPAddress"}]},
        ],
        "details": {"Attempts": "Attempts", "Successes": "Successes", "Apps": "AppList",
                    "HoneypotVerdicts": "HoneypotVerdictList"},
        "name": "Drosera: honeypot agent address {{IPAddress}} signing in as {{UserPrincipalName}}",
        "severity_column": "Severity",
        "frequency": "PT1H", "period": "P7D",
        "condition": "deploySigninCorrelation",
    },
]


def rule_resource(rule: dict[str, Any]) -> dict[str, Any]:
    override: dict[str, Any] = {"alertDisplayNameFormat": literal(rule["name"])}
    if rule.get("severity_column"):
        override["alertSeverityColumnName"] = rule["severity_column"]
    res: dict[str, Any] = {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": "2023-02-01",
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{stable_id(rule['key'])}')]",
        "kind": "Scheduled",
        "properties": {
            "displayName": rule["displayName"],
            "description": rule["description"],
            "severity": rule["severity"],
            "enabled": True,
            "query": literal(kql(f"rules/{rule['key']}.kql")),
            "queryFrequency": rule["frequency"],
            "queryPeriod": rule["period"],
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": rule["tactics"],
            "techniques": rule["techniques"],
            "entityMappings": rule["entities"],
            "customDetails": rule["details"],
            "alertDetailsOverride": override,
            "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "P1D",
                    "matchingMethod": "AllEntities",
                    "groupByEntities": [],
                    "groupByAlertDetails": [],
                    "groupByCustomDetails": [],
                },
            },
        },
    }
    if rule.get("condition"):
        res = {"condition": f"[parameters('{rule['condition']}')]", **res}
    return res


def analytics() -> dict[str, Any]:
    return template(
        description=(
            "Drosera analytics rules for Microsoft Sentinel. Deploy after ingestion.json, once "
            "DroseraEvents_CL exists -- rule validation fails against a missing table."
        ),
        parameters={
            "workspace": {"type": "string", "metadata": {"description": "Sentinel workspace name."}},
            "deploySigninCorrelation": {"type": "bool", "defaultValue": False, "metadata": {
                "description": "Also deploy the Entra ID sign-in correlation rule. Needs SigninLogs."}},
        },
        resources=[rule_resource(r) for r in RULES],
    )


# -- workbook ----------------------------------------------------------------------------

SENSOR_FILTER = "| where '*' in ({Sensor}) or Sensor in ({Sensor})"
LA = "microsoft.operationalinsights/workspaces"


def q(name: str, title: str, query: str, viz: str, size: int = 0, width: str | None = None,
      extra: dict | None = None) -> dict[str, Any]:
    content: dict[str, Any] = {
        "version": "KqlItem/1.0",
        "query": literal(query.strip()),
        "size": size,
        "title": title,
        "timeContextFromParameter": "TimeRange",
        "queryType": 0,
        "resourceType": LA,
        "visualization": viz,
    }
    content.update(extra or {})
    item: dict[str, Any] = {"type": 3, "content": content, "name": name}
    if width:
        item["customWidth"] = width
    return item


def workbook_content() -> dict[str, Any]:
    events = f"DroseraEvents_CL\n{SENSOR_FILTER}"
    tiles = f"""
let e = {events};
let r = e | where EventType == "request";
union
    (r | summarize Value = dcount(SessionId) | extend Metric = "Sessions", Order = 1),
    (r | where Verdict in ("agent", "hostile_agent") | summarize Value = dcount(SessionId) | extend Metric = "LLM agent sessions", Order = 2),
    (r | where Confidence == "confirmed" | summarize Value = dcount(SessionId) | extend Metric = "Confirmed", Order = 3),
    (r | where Verdict == "hostile_agent" | summarize Value = dcount(SessionId) | extend Metric = "Hostile agents", Order = 4),
    (r | summarize Value = dcount(SrcIpAddr) | extend Metric = "Source addresses", Order = 5),
    (r | summarize t = max(TokensBurned) by SessionId | summarize Value = sum(t) | extend Metric = "Tokens burned", Order = 6),
    (e | where EventType == "canary" | summarize Value = count() | extend Metric = "Canary hits", Order = 7)
| order by Order asc
| project Metric, Value
"""
    timeline = f"""
{events}
| where EventType == "request" and Verdict in ("automation", "agent", "hostile_agent")
| summarize Sessions = dcount(SessionId) by Verdict, bin(TimeGenerated, {{TimeRange:grain}})
"""
    verdicts = f"""
DroseraSessions
{SENSOR_FILTER}
| summarize Sessions = count() by Verdict
| order by Sessions desc
"""
    signals = f"""
{events}
| where EventType == "request" and Verdict != "human"
| mv-expand Signal = SignalIds to typeof(string)
| summarize Sessions = dcount(SessionId) by Signal
| top 15 by Sessions
"""
    sessions = f"""
DroseraSessions
{SENSOR_FILTER}
| where Verdict !in ("human", "unknown")
| extend Rank = case(Confidence == "confirmed", 3, Confidence == "high", 2, Confidence == "medium", 1, 0)
| extend Country = tostring(geo_info_from_ip_address(SrcIpAddr).country)
| order by Rank desc, Agency desc, Requests desc
| project Confidence, Verdict, SrcIpAddr, Country, HttpUserAgent, Requests, Agency = round(Agency, 0),
    Hostility = round(Hostility, 0), TokensBurned, FirstSeen, LastSeen, Signals = strcat_array(Signals, " "), Sensor
| take 500
"""
    agents = f"""
{events}
| where EventType == "request" and Verdict in ("agent", "hostile_agent")
| summarize Sessions = dcount(SessionId), Addresses = dcount(SrcIpAddr), FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated) by HttpUserAgent
| order by Sessions desc
| take 25
"""
    canaries = f"""
DroseraCanaryHits
{SENSOR_FILTER}
| order by TimeGenerated desc
| take 200
"""
    tile_settings = {
        "tileSettings": {
            "titleContent": {"columnMatch": "Metric", "formatter": 1},
            "leftContent": {"columnMatch": "Value", "formatter": 12, "formatOptions": {"palette": "none"},
                            "numberFormat": {"unit": 17, "options": {"style": "decimal", "maximumFractionDigits": 0}}},
            "showBorder": True,
        }
    }
    return {
        "version": "Notebook/1.0",
        "items": [
            {"type": 1, "name": "header", "content": {"json": literal(
                "## Drosera honeypot\n"
                "Sessions and canary hits from Drosera sensors. **Confidence** is the *kind* of "
                "evidence, not a score: *confirmed* means the client returned this deployment's "
                "signed ticket or used a planted credential; *low* is traffic shape alone. "
                "A verdict is not a judgement -- confirm before acting on anything real."
            )}},
            {"type": 9, "name": "parameters", "content": {
                "version": "KqlParameterItem/1.0",
                "style": "pills",
                "queryType": 0,
                "resourceType": LA,
                "parameters": [
                    {
                        "id": stable_id("param-time"), "version": "KqlParameterItem/1.0",
                        "name": "TimeRange", "label": "Time range", "type": 4, "isRequired": True,
                        "value": {"durationMs": 604800000},
                        "typeSettings": {"allowCustom": True, "selectableValues": [
                            {"durationMs": 3600000}, {"durationMs": 86400000}, {"durationMs": 604800000},
                            {"durationMs": 2592000000}, {"durationMs": 7776000000},
                        ]},
                    },
                    {
                        "id": stable_id("param-sensor"), "version": "KqlParameterItem/1.0",
                        "name": "Sensor", "label": "Sensor", "type": 2, "multiSelect": True,
                        "quote": "'", "delimiter": ",",
                        "query": "DroseraEvents_CL | distinct Sensor | order by Sensor asc",
                        "value": ["value::all"],
                        "typeSettings": {"additionalResourceOptions": ["value::all"], "selectAllValue": "*",
                                         "showDefault": False},
                        "timeContext": {"durationMs": 2592000000},
                        "queryType": 0, "resourceType": LA,
                    },
                ],
            }},
            q("tiles", "", tiles, "tiles", size=4, extra=tile_settings),
            q("timeline", "New non-human sessions by verdict", timeline, "timechart"),
            q("verdicts", "Sessions by verdict", verdicts, "piechart", width="40"),
            q("signals", "Top signals (non-human sessions)", signals, "barchart", width="60"),
            q("sessions", "Sessions, strongest evidence first", sessions, "table",
              extra={"gridSettings": {"filter": True, "sortBy": []}}),
            q("agents", "LLM agent user agents", agents, "table", width="50"),
            q("canaries", "Canary hits", canaries, "table", width="50",
              extra={"noDataMessage": "No canary hits. Run drosera canary watch --emit to send them here."}),
        ],
        "fallbackResourceIds": [
            "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
        ],
        "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json",
    }


def workbook() -> dict[str, Any]:
    return template(
        description="Drosera workbook for Microsoft Sentinel. Deploy after ingestion.json.",
        parameters={
            "workspaceName": {"type": "string"},
            "workbookName": {"type": "string", "defaultValue": "Drosera honeypot"},
        },
        variables={"workbookContent": workbook_content()},
        resources=[{
            "type": "Microsoft.Insights/workbooks",
            "apiVersion": "2022-04-01",
            "name": f"[guid(resourceGroup().id, '{stable_id('workbook')}')]",
            "location": "[resourceGroup().location]",
            "kind": "shared",
            "properties": {
                "displayName": "[parameters('workbookName')]",
                "category": "sentinel",
                "version": "1.0",
                "sourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]",
                "serializedData": "[string(variables('workbookContent'))]",
            },
        }],
    )


# -- playbooks -----------------------------------------------------------------------------

TRIGGER = {
    "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
            "body": {"callback_url": "@{listCallbackUrl()}"},
            "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
            "path": "/incident-creation",
        },
    }
}
SENTINEL_HOST = {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}}
GET_IPS = {
    "type": "ApiConnection",
    "runAfter": {},
    "inputs": {
        "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
        "host": SENTINEL_HOST,
        "method": "post",
        "path": "/entities/ip",
    },
}
IP_EXPR = "items('For_each_IP')?['Address']"


def comment(message: str, run_after: dict) -> dict[str, Any]:
    return {
        "type": "ApiConnection",
        "runAfter": run_after,
        "inputs": {
            "body": {"incidentArmId": "@triggerBody()?['object']?['id']", "message": message},
            "host": SENTINEL_HOST,
            "method": "post",
            "path": "/Incidents/Comment",
        },
    }


def playbook(name: str, description: str, parameters: dict, actions: dict) -> dict[str, Any]:
    connection = "[concat('azuresentinel-', parameters('PlaybookName'))]"
    conn_id = "[resourceId('Microsoft.Web/connections', concat('azuresentinel-', parameters('PlaybookName')))]"
    return template(
        description=description,
        parameters={"PlaybookName": {"type": "string", "defaultValue": name}, **parameters},
        resources=[
            {
                "type": "Microsoft.Web/connections",
                "apiVersion": "2016-06-01",
                "name": connection,
                "location": "[resourceGroup().location]",
                "kind": "V1",
                "properties": {
                    "displayName": connection,
                    "customParameterValues": {},
                    "parameterValueType": "Alternative",
                    "api": {"id": SENTINEL_API},
                },
            },
            {
                "type": "Microsoft.Logic/workflows",
                "apiVersion": "2019-05-01",
                "name": "[parameters('PlaybookName')]",
                "location": "[resourceGroup().location]",
                "identity": {"type": "SystemAssigned"},
                "tags": {"hidden-SentinelTemplateName": name, "hidden-SentinelTemplateVersion": "1.0"},
                "dependsOn": [conn_id],
                "properties": {
                    "state": "Enabled",
                    "definition": {
                        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                        "contentVersion": "1.0.0.0",
                        "parameters": {"$connections": {"defaultValue": {}, "type": "Object"}},
                        "triggers": TRIGGER,
                        "actions": {
                            "Entities_-_Get_IPs": GET_IPS,
                            "For_each_IP": {
                                "type": "Foreach",
                                "foreach": "@body('Entities_-_Get_IPs')?['IPs']",
                                "runAfter": {"Entities_-_Get_IPs": ["Succeeded"]},
                                "actions": actions,
                            },
                        },
                        "outputs": {},
                    },
                    "parameters": {"$connections": {"value": {"azuresentinel": {
                        "connectionId": conn_id,
                        "connectionName": connection,
                        "id": SENTINEL_API,
                        "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}},
                    }}}},
                },
            },
        ],
        outputs={"principalId": {"type": "string", "value": (
            "[reference(resourceId('Microsoft.Logic/workflows', parameters('PlaybookName')), "
            "'2019-05-01', 'full').identity.principalId]"
        )}},
    )


# The IP comes from a Sentinel entity, so it is already an address -- but it is still
# stripped of quotes before being placed inside a KQL string literal.
ENRICH_QUERY = """let ip = '@{replace(IP_EXPR, '''', '')}';
let esc = (s: string) { replace_string(replace_string(replace_string(s, "&", "&amp;"), "<", "&lt;"), ">", "&gt;") };
let hits = DroseraEvents_CL
    | where TimeGenerated > ago(30d)
    | where EventType == "request" and SrcIpAddr == ip;
let sigs = toscalar(hits | mv-expand Signal = SignalIds to typeof(string) | summarize make_set(Signal, 40));
hits
| summarize
    FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Requests = count(),
    Sessions = dcount(SessionId), MaxAgency = max(Agency), MaxHostility = max(Hostility),
    TokensBurned = max(TokensBurned),
    VerdictRank = max(case(Verdict == "hostile_agent", 4, Verdict == "agent", 3, Verdict == "automation", 2, Verdict == "unknown", 1, 0)),
    ConfidenceRank = max(case(Confidence == "confirmed", 3, Confidence == "high", 2, Confidence == "medium", 1, 0)),
    UserAgents = make_set(HttpUserAgent, 5), Sensors = make_set(Sensor, 5)
| where Requests > 0
| extend Verdict = tostring(dynamic(["human", "unknown", "automation", "agent", "hostile_agent"])[VerdictRank]),
    Confidence = tostring(dynamic(["low", "medium", "high", "confirmed"])[ConfidenceRank])
| project Message = strcat(
    "<p><b>Drosera honeypot history for ", ip, " (last 30 days)</b></p><p>",
    "Verdict: <b>", Verdict, "</b> &middot; evidence: <b>", Confidence, "</b><br>",
    "Sessions: ", Sessions, " &middot; requests: ", Requests,
    " &middot; max LLM agency: ", round(MaxAgency, 0), " &middot; max hostility: ", round(MaxHostility, 0), "<br>",
    "First seen ", format_datetime(FirstSeen, "yyyy-MM-dd HH:mm"), " UTC &middot; last seen ",
    format_datetime(LastSeen, "yyyy-MM-dd HH:mm"), " UTC<br>",
    "Signals: ", esc(strcat_array(sigs, ", ")), "<br>",
    "User agents: ", esc(strcat_array(UserAgents, " | ")), "<br>",
    "Sensors: ", esc(strcat_array(Sensors, ", ")), "</p>",
    "<p><i>A verdict is not a judgement. Confirm before acting on anything real.</i></p>")
""".replace("IP_EXPR", IP_EXPR)


def enrich_playbook() -> dict[str, Any]:
    actions = {
        "Query_Drosera": {
            "type": "Http",
            "runAfter": {},
            "inputs": {
                "method": "POST",
                "uri": "[concat('https://api.loganalytics.io/v1/workspaces/', parameters('WorkspaceId'), '/query')]",
                "headers": {"Content-Type": "application/json"},
                "body": {"query": ENRICH_QUERY},
                "authentication": {"type": "ManagedServiceIdentity", "audience": "https://api.loganalytics.io"},
            },
        },
        "If_the_address_has_Drosera_history": {
            "type": "If",
            "runAfter": {"Query_Drosera": ["Succeeded"]},
            "expression": {"and": [{"greater": [
                "@length(body('Query_Drosera')?['tables']?[0]?['rows'])", 0]}]},
            "actions": {"Add_comment_to_incident": comment(
                "@{body('Query_Drosera')?['tables']?[0]?['rows']?[0]?[0]}", {})},
            "else": {"actions": {}},
        },
    }
    return playbook(
        "Drosera-Enrich-Incident",
        "On a Sentinel incident, look up each IP entity in DroseraEvents_CL and add the "
        "address's honeypot history -- verdict, evidence class, signals, user agents -- as an "
        "incident comment. The playbook identity needs Log Analytics Reader on the workspace "
        "and Microsoft Sentinel Responder on its resource group.",
        {"WorkspaceId": {"type": "string", "metadata": {
            "description": "Workspace ID (the GUID on the workspace's overview page), not its name."}}},
        actions,
    )


def mde_playbook() -> dict[str, Any]:
    actions = {
        "Submit_Defender_indicator": {
            "type": "Http",
            "runAfter": {},
            "inputs": {
                "method": "POST",
                "uri": "https://api.securitycenter.microsoft.com/api/indicators",
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "indicatorValue": f"@{{{IP_EXPR}}}",
                    "indicatorType": "IpAddress",
                    "action": "[parameters('IndicatorAction')]",
                    "severity": "[parameters('Severity')]",
                    "generateAlert": True,
                    "title": "Drosera honeypot: @{triggerBody()?['object']?['properties']?['title']}",
                    "description": (
                        "Submitted by the Drosera-MDE-Indicator playbook from Microsoft Sentinel "
                        "incident @{triggerBody()?['object']?['properties']?['incidentNumber']}. "
                        "This address interacted with a Drosera honeypot."
                    ),
                    "recommendedActions": (
                        "Review which devices contacted this address and why. A honeypot verdict "
                        "is not a judgement; confirm before blocking anything real."
                    ),
                    "expirationTime": (
                        "[concat('@{addDays(utcNow(), ', string(parameters('ExpirationDays')), ')}')]"
                    ),
                },
                "authentication": {"type": "ManagedServiceIdentity",
                                   "audience": "https://api.securitycenter.microsoft.com"},
            },
        },
        # Action and expiry are read back from Defender's response, not from the ARM
        # parameters, so the comment records what Defender actually accepted.
        "Comment_submitted": comment(
            "<p>Drosera: submitted <b>@{" + IP_EXPR + "}</b> to Defender for Endpoint as an IP "
            "indicator (action @{body('Submit_Defender_indicator')?['action']}, expires "
            "@{body('Submit_Defender_indicator')?['expirationTime']}).</p>",
            {"Submit_Defender_indicator": ["Succeeded"]},
        ),
        "Comment_failed": comment(
            "<p>Drosera: could not submit <b>@{" + IP_EXPR + "}</b> to Defender for Endpoint "
            "(HTTP @{outputs('Submit_Defender_indicator')?['statusCode']}). Check that the "
            "playbook identity holds the Ti.ReadWrite.All application permission.</p>",
            {"Submit_Defender_indicator": ["Failed", "TimedOut"]},
        ),
    }
    return playbook(
        "Drosera-MDE-Indicator",
        "On a Sentinel incident, submit each IP entity to Microsoft Defender for Endpoint as a "
        "custom indicator (Audit by default) and comment on the incident. Network indicators "
        "govern connections from your devices: in Audit mode they alert when any managed device "
        "contacts the same infrastructure. They do not stop inbound traffic to your site. "
        "The playbook identity needs the WindowsDefenderATP Ti.ReadWrite.All application "
        "permission and Microsoft Sentinel Responder.",
        {
            "IndicatorAction": {"type": "string", "defaultValue": "Audit",
                                "allowedValues": ["Audit", "Warn", "Block"]},
            "Severity": {"type": "string", "defaultValue": "Medium",
                         "allowedValues": ["Informational", "Low", "Medium", "High"]},
            "ExpirationDays": {"type": "int", "defaultValue": 30, "minValue": 1, "maxValue": 365},
        },
        actions,
    )


# -- main ----------------------------------------------------------------------------------

OUTPUTS = {
    "deploy/ingestion.json": ingestion,
    "deploy/analytics-rules.json": analytics,
    "deploy/workbook.json": workbook,
    "playbooks/Drosera-Enrich-Incident/azuredeploy.json": enrich_playbook,
    "playbooks/Drosera-MDE-Indicator/azuredeploy.json": mde_playbook,
}


def check_expressions(node: Any, where: str) -> None:
    """Cheap ARM expression lint: bracketed, and single quotes balanced.

    ARM string literals escape a quote by doubling it, so a well-formed expression
    always has an even number of them. An odd count means a Logic App ``items('x')``
    or similar leaked into an ARM literal unescaped -- a deployment-time failure.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            check_expressions(v, f"{where}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            check_expressions(v, f"{where}[{i}]")
    elif (
        isinstance(node, str) and node.startswith("[") and not node.startswith("[[")
        and (not node.endswith("]") or node.count("'") % 2)
    ):
        raise ValueError(f"malformed ARM expression at {where}: {node[:80]!r}")


def render_all() -> dict[str, str]:
    out = {}
    for rel, fn in OUTPUTS.items():
        doc = fn()
        check_expressions(doc, rel)
        out[rel] = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for rel, text in render_all().items():
        path = HERE / rel
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        if check:
            stale.append(rel)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote integrations/sentinel/{rel}")
    if stale:
        print("stale Sentinel templates -- run python integrations/sentinel/_build.py:")
        for rel in stale:
            print(f"  integrations/sentinel/{rel}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
