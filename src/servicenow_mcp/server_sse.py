"""
ServiceNow MCP Server — SSE (HTTP) transport with OAuth 2.0 client credentials auth.

Endpoints:
  GET  /health                                — unauthenticated health check
  GET  /.well-known/oauth-authorization-server — OAuth 2.0 metadata discovery
  POST /token                                 — OAuth 2.0 client_credentials token exchange
  GET  /sse                                   — authenticated SSE stream  (Bearer token)
  POST /messages/                             — authenticated message post (Bearer token)

Auth flow for Claude Desktop "Add custom connector":
  1. Claude reads /.well-known/oauth-authorization-server to find the token endpoint
  2. Claude POSTs client_id + client_secret to /token
  3. Server validates credentials and returns an access_token
  4. Claude uses the access_token as Bearer token for /sse and /messages/
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Dict, Optional, Union
from urllib.parse import parse_qs

import uvicorn
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from servicenow_mcp.server import ServiceNowMCP
from servicenow_mcp.utils.config import (
    AuthConfig,
    AuthType,
    BasicAuthConfig,
    OAuthConfig,
    ServerConfig,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Health-check endpoint (unauthenticated)
# ---------------------------------------------------------------------------

async def handle_health(request: Request) -> Response:
    """Return a simple health-check response for Docker / load-balancer probes."""
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# OAuth 2.0 discovery + token endpoint
# ---------------------------------------------------------------------------

# Will be set at startup from env vars
_oauth_config: Dict[str, Optional[str]] = {
    "client_id": None,
    "client_secret": None,
    "auth_token": None,
    "issuer_url": None,
}


def _generate_access_token(auth_token: str) -> str:
    """Generate a deterministic access token derived from the MCP_AUTH_TOKEN.

    This way the Bearer middleware can validate it without storing extra state.
    We simply use the auth_token itself as the access token.
    """
    return auth_token


async def handle_oauth_metadata(request: Request) -> Response:
    """RFC 8414 — OAuth 2.0 Authorization Server Metadata."""
    issuer = _oauth_config["issuer_url"] or str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": issuer,
        "token_endpoint": f"{issuer}/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "grant_types_supported": ["client_credentials"],
        "response_types_supported": [],
        "scopes_supported": ["mcp:tools"],
    })


async def handle_token(request: Request) -> Response:
    """OAuth 2.0 token endpoint — client_credentials grant only."""
    client_id = _oauth_config["client_id"]
    client_secret = _oauth_config["client_secret"]
    auth_token = _oauth_config["auth_token"]

    # If OAuth is not configured, return an error
    if not client_id or not client_secret or not auth_token:
        return JSONResponse(
            {"error": "server_error", "error_description": "OAuth not configured on server"},
            status_code=500,
        )

    # Parse the request body (application/x-www-form-urlencoded)
    body = await request.body()
    try:
        # Try form-encoded first
        params = parse_qs(body.decode("utf-8"))
        provided_grant = params.get("grant_type", [None])[0]
        provided_id = params.get("client_id", [None])[0]
        provided_secret = params.get("client_secret", [None])[0]
    except Exception:
        # Try JSON body as fallback
        try:
            data = json.loads(body)
            provided_grant = data.get("grant_type")
            provided_id = data.get("client_id")
            provided_secret = data.get("client_secret")
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Could not parse request body"},
                status_code=400,
            )

    # Also check Authorization: Basic header (client_secret_basic method)
    if not provided_id or not provided_secret:
        import base64
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                provided_id, provided_secret = decoded.split(":", 1)
            except Exception:
                pass

    # Validate grant type
    if provided_grant != "client_credentials":
        return JSONResponse(
            {"error": "unsupported_grant_type", "error_description": "Only client_credentials is supported"},
            status_code=400,
        )

    # Validate client credentials (constant-time comparison)
    if not provided_id or not provided_secret:
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Missing client_id or client_secret"},
            status_code=401,
            headers={"WWW-Authenticate": "Basic"},
        )

    id_valid = secrets.compare_digest(provided_id, client_id)
    secret_valid = secrets.compare_digest(provided_secret, client_secret)

    if not id_valid or not secret_valid:
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Invalid client credentials"},
            status_code=401,
            headers={"WWW-Authenticate": "Basic"},
        )

    # Issue access token
    access_token = _generate_access_token(auth_token)
    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 86400,  # 24 hours (token doesn't actually expire, but spec requires it)
        "scope": "mcp:tools",
    })


# ---------------------------------------------------------------------------
# Bearer-token authentication middleware
# ---------------------------------------------------------------------------

# Paths that are allowed without authentication
_PUBLIC_PATHS = frozenset({"/health", "/.well-known/oauth-authorization-server", "/token"})


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that enforces ``Authorization: Bearer <token>``
    on every request except explicitly public paths.

    The expected token is read once from the ``MCP_AUTH_TOKEN`` env var at
    startup.  If the env var is **not set**, the middleware is effectively
    disabled (all requests are allowed) so that local development still
    works out of the box.
    """

    def __init__(self, app, token: Optional[str] = None):
        super().__init__(app)
        self.token = token

    async def dispatch(self, request: Request, call_next):
        # Allow public endpoints through without auth
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        # If no token configured, skip auth (local dev mode)
        if not self.token:
            return await call_next(request)

        # Extract and validate the Bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "Missing or malformed Authorization header"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        provided_token = auth_header[7:]  # strip "Bearer "
        if not secrets.compare_digest(provided_token, self.token):
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response


# ---------------------------------------------------------------------------
# Starlette app factory
# ---------------------------------------------------------------------------

def create_starlette_app(
    mcp_server: Server,
    *,
    debug: bool = False,
    auth_token: Optional[str] = None,
) -> Starlette:
    """Create a Starlette application that serves the MCP server over SSE."""
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,  # noqa: SLF001
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                mcp_server.create_initialization_options(),
            )

    return Starlette(
        debug=debug,
        routes=[
            Route("/health", endpoint=handle_health),
            Route("/.well-known/oauth-authorization-server", endpoint=handle_oauth_metadata),
            Route("/token", endpoint=handle_token, methods=["POST"]),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
        middleware=[
            Middleware(SecurityHeadersMiddleware),
            Middleware(BearerAuthMiddleware, token=auth_token),
        ],
    )


# ---------------------------------------------------------------------------
# SSE server subclass (kept for backward compat)
# ---------------------------------------------------------------------------

class ServiceNowSSEMCP(ServiceNowMCP):
    """ServiceNow MCP Server — SSE transport variant."""

    def __init__(self, config: Union[Dict, ServerConfig]):
        super().__init__(config)

    def start(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        auth_token: Optional[str] = None,
        debug: bool = False,
    ):
        starlette_app = create_starlette_app(
            self.mcp_server,
            debug=debug,
            auth_token=auth_token,
        )
        uvicorn.run(starlette_app, host=host, port=port)


# ---------------------------------------------------------------------------
# Factory (kept for backward compat)
# ---------------------------------------------------------------------------

def create_servicenow_mcp(instance_url: str, username: str, password: str):
    """Create a ServiceNow MCP server with basic auth (legacy helper)."""
    auth_config = AuthConfig(
        type=AuthType.BASIC,
        basic=BasicAuthConfig(username=username, password=password),
    )
    config = ServerConfig(instance_url=instance_url, auth=auth_config)
    return ServiceNowSSEMCP(config)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Run ServiceNow MCP SSE-based server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    args = parser.parse_args()

    instance_url = os.getenv("SERVICENOW_INSTANCE_URL")
    if not instance_url:
        raise SystemExit("SERVICENOW_INSTANCE_URL env var is required")

    auth_type = os.getenv("SERVICENOW_AUTH_TYPE", "basic").lower()

    if auth_type == "oauth":
        client_id = os.getenv("SERVICENOW_CLIENT_ID")
        client_secret = os.getenv("SERVICENOW_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise SystemExit("SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET are required for OAuth")
        token_url = os.getenv("SERVICENOW_TOKEN_URL", f"{instance_url}/oauth_token.do")
        auth_config = AuthConfig(
            type=AuthType.OAUTH,
            oauth=OAuthConfig(
                client_id=client_id,
                client_secret=client_secret,
                token_url=token_url,
                username=os.getenv("SERVICENOW_USERNAME"),
                password=os.getenv("SERVICENOW_PASSWORD"),
            ),
        )
    else:
        # Default: basic auth
        username = os.getenv("SERVICENOW_USERNAME")
        password = os.getenv("SERVICENOW_PASSWORD")
        if not username or not password:
            raise SystemExit("SERVICENOW_USERNAME and SERVICENOW_PASSWORD are required for basic auth")
        auth_config = AuthConfig(
            type=AuthType.BASIC,
            basic=BasicAuthConfig(username=username, password=password),
        )

    config = ServerConfig(instance_url=instance_url, auth=auth_config)
    mcp_auth_token = os.getenv("MCP_AUTH_TOKEN")
    debug_mode = os.getenv("SERVICENOW_DEBUG", "false").lower() == "true"

    # --- Configure OAuth 2.0 for MCP clients ---
    mcp_client_id = os.getenv("MCP_CLIENT_ID")
    mcp_client_secret = os.getenv("MCP_CLIENT_SECRET")
    mcp_issuer_url = os.getenv("MCP_ISSUER_URL")

    _oauth_config["client_id"] = mcp_client_id
    _oauth_config["client_secret"] = mcp_client_secret
    _oauth_config["auth_token"] = mcp_auth_token
    _oauth_config["issuer_url"] = mcp_issuer_url

    if mcp_auth_token:
        logger.info("Bearer token authentication ENABLED for MCP clients")
        if mcp_client_id and mcp_client_secret:
            logger.info("OAuth 2.0 client_credentials flow ENABLED (token endpoint at /token)")
        else:
            logger.warning(
                "MCP_CLIENT_ID / MCP_CLIENT_SECRET not set — "
                "OAuth token endpoint disabled. Clients must provide Bearer token directly."
            )
    else:
        logger.warning(
            "MCP_AUTH_TOKEN not set — SSE server is UNAUTHENTICATED. "
            "Set MCP_AUTH_TOKEN for production deployments."
        )

    server = ServiceNowSSEMCP(config)
    server.start(host=args.host, port=args.port, auth_token=mcp_auth_token, debug=debug_mode)


if __name__ == "__main__":
    main()
