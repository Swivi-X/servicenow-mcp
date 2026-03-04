# CLAUDE.md — ServiceNow MCP Server

## Project Overview

This is a **Model Completion Protocol (MCP) server** that bridges Claude and ServiceNow. It exposes ServiceNow table operations as MCP tools that Claude can call. The server is a fork of [osomai/servicenow-mcp](https://github.com/osomai/servicenow-mcp) with Mashgin-specific CSM (Customer Service Management) tools added.

## Quick Start

```bash
# Install
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Configure (.env already exists with Mashgin credentials)
# SERVICENOW_INSTANCE_URL, SERVICENOW_USERNAME, SERVICENOW_PASSWORD, SERVICENOW_AUTH_TYPE

# Run MCP server (stdio mode, for Claude Desktop / Claude Code)
servicenow-mcp

# Run MCP server (SSE mode, for web clients)
servicenow-mcp-sse --port 8080

# Run tests
python -m pytest tests/test_case_tools.py tests/test_csm_tools.py -v
python -m pytest tests/ --ignore=tests/test_catalog_resources.py --ignore=tests/test_changeset_resources.py --ignore=tests/test_script_include_resources.py -v
```

## Architecture

```
src/servicenow_mcp/
├── cli.py                  # Entry point: loads .env, parses args, starts stdio server
├── server.py               # ServiceNowMCP class: registers MCP handlers, routes tool calls
├── server_sse.py           # SSE (HTTP) transport alternative
├── auth/
│   └── auth_manager.py     # AuthManager: handles Basic/OAuth/API Key auth headers
├── tools/                  # Each file = one domain of tools
│   ├── __init__.py         # Re-exports all tool functions
│   ├── case_tools.py       # Basic CSM case tools (list, get, search)
│   ├── csm_tools.py        # Mashgin CSM tools (accounts, locations, products, case correlation)
│   ├── incident_tools.py   # Incident CRUD
│   ├── catalog_tools.py    # Service Catalog
│   └── ...                 # change, workflow, knowledge, user, story, epic, project tools
├── utils/
│   ├── config.py           # ServerConfig, AuthConfig Pydantic models
│   └── tool_utils.py       # Central registry: get_tool_definitions() → Dict[name, (func, params, type, desc, serialization)]
└── resources/              # MCP resource handlers (catalog, changeset, script)

config/
└── tool_packages.yaml      # Controls which tools are exposed per package (MCP_TOOL_PACKAGE env var)

tests/
├── test_case_tools.py      # Tests for basic case tools
├── test_csm_tools.py       # Tests for Mashgin CSM tools
└── ...                     # Other domain test files
```

## How Tools Work

1. **Define** a Pydantic params model + implementation function in `tools/<domain>_tools.py`
2. **Register** in `tools/__init__.py` (import + `__all__`)
3. **Register** in `utils/tool_utils.py` (import params + function, add to `get_tool_definitions()` dict)
4. **Add** to `config/tool_packages.yaml` in relevant packages
5. **Test** in `tests/test_<domain>_tools.py` using `@patch('...requests.get')` mocks

Every tool function has the signature: `func(config: ServerConfig, auth_manager: AuthManager, params: ParamsModel) -> dict`

The server calls `serialize_tool_output()` to convert the dict to JSON for MCP transport.

## Key Design Decisions

### CSM Table Access Workaround
The `sn_customerservice_case` table returns 401 directly. All case queries go through the `task` table filtered by `sys_class_name=sn_customerservice_case`. This works but drops CSM-specific foreign key fields (account, product, sold_product, location, custom u_ fields).

### Case Correlation via Text Search
`get_cases_by_account`, `get_cases_by_location`, `get_cases_by_product`, `get_cases_by_integration` currently search `short_description`/`description` with LIKE queries. When CSM table access is granted, swap to structured foreign key queries without changing the tool API.

### Reference Data Tables (work today, structured)
- `customer_account` — 540 records (Aramark, Levy, Circle K, Sodexo, etc.)
- `cmn_location` — 5,187 records (venue stands, stores, cafes)
- `sn_install_base_sold_product` — 905 records (Kiosk, Origin, Cloud, Creator, Byte, MashCash, Mobile, Fleet)

### AuthManager Construction
`AuthManager` takes `AuthConfig` (not `ServerConfig`). When calling tools directly in scripts:
```python
auth_config = AuthConfig(type=AuthType.BASIC, basic=BasicAuthConfig(...))
config = ServerConfig(instance_url=..., auth=auth_config)
auth = AuthManager(auth_config, instance_url=config.instance_url)
result = some_tool(config, auth, SomeParams(...))
```

## Tool Packages

Set `MCP_TOOL_PACKAGE` env var to load a subset. Default is `full`. Key packages:
- `customer_service` — case tools + CSM tools + user lookup
- `service_desk` — incident tools + user/knowledge lookup
- `full` — everything

## Testing

```bash
# Run all safe tests (some test files have pre-existing failures unrelated to CSM)
python -m pytest tests/ --ignore=tests/test_catalog_resources.py --ignore=tests/test_changeset_resources.py --ignore=tests/test_script_include_resources.py -v

# Known pre-existing failures in: test_knowledge_base.py, test_server_catalog.py, test_server_workflow.py, test_change_tools.py (swapped params), test_workflow_tools.py
```

## Mashgin Business Context

Mashgin makes self-checkout kiosks. Key entities in ServiceNow:
- **Products**: Kiosk, Origin, Cloud, Creator, Byte, MashCash, Mobile, Fleet
- **Integrations/Vendors**: Shift4, Ingenico, Glory, FreedomPay, Aurus, PDI, Micros, Eatec, CBORD, Stuzo
- **Major accounts**: Aramark, Levy Restaurants, Circle K, Sodexo
- **Case format**: short_description typically follows `Account | Location | Product/Issue` pattern (e.g. "Aramark | Wrigley Field | Shift4 Inquiry")
