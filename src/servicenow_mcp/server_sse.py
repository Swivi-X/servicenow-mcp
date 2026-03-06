"""
ServiceNow MCP Server — SSE (HTTP) transport with Bearer token authentication.

Endpoints:
  GET  /health     — unauthenticated health check (for Docker/LB probes)
  GET  /sse        — authenticated SSE stream  (requires Authorization: Bearer <token>)
  POST /messages/  — authenticated message post (requires Authorization: Bearer <token>)
"""

import argparse
import logging
import os
import secrets
from typing import Dict, Optional, Union

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
# Bearer-token authentication middleware
# ---------------------------------------------------------------------------

# Paths that are allowed without authentication
_PUBLIC_PATHS = frozenset({"/health"})


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

    if mcp_auth_token:
        logger.info("Bearer token authentication ENABLED for MCP clients")
    else:
        # If a Cloudflare tunnel token is set, we're likely in production — refuse to start without auth
        if os.getenv("CLOUDFLARE_TUNNEL_TOKEN"):
            raise SystemExit(
                "FATAL: MCP_AUTH_TOKEN is required when CLOUDFLARE_TUNNEL_TOKEN is set. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        logger.warning(
            "MCP_AUTH_TOKEN not set — SSE server is UNAUTHENTICATED. "
            "Set MCP_AUTH_TOKEN for production deployments."
        )

    server = ServiceNowSSEMCP(config)
    server.start(host=args.host, port=args.port, auth_token=mcp_auth_token, debug=debug_mode)


if __name__ == "__main__":
    main()
