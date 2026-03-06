"""
ServiceNow MCP Server — SSE (HTTP) transport with OAuth 2.0 authorization_code + PKCE.

Endpoints:
  GET  /health                                    — unauthenticated health check
  GET  /.well-known/oauth-protected-resource      — RFC 9470 protected resource metadata
  GET  /.well-known/oauth-authorization-server    — RFC 8414 authorization server metadata
  GET  /authorize                                 — OAuth 2.0 authorization (auto-approves valid clients)
  POST /token                                     — OAuth 2.0 token exchange (auth code + PKCE)
  GET  /sse                                       — authenticated SSE stream  (Bearer token)
  POST /messages/                                 — authenticated message post (Bearer token)

Auth flow for Cowork "Add custom connector":
  1. Cowork POSTs to /sse → gets 401
  2. Cowork reads /.well-known/oauth-protected-resource to find the auth server
  3. Cowork reads /.well-known/oauth-authorization-server to find authorize + token endpoints
  4. Cowork redirects to /authorize with code_challenge (PKCE S256)
  5. Server validates client_id, stores code_challenge, returns auth code via redirect
  6. Cowork POSTs to /token with auth code + code_verifier
  7. Server validates PKCE, returns access_token
  8. Cowork uses access_token as Bearer token for /sse and /messages/
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Dict, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse

import uvicorn
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
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
# OAuth 2.0 configuration (set at startup)
# ---------------------------------------------------------------------------

_oauth_config: Dict[str, Optional[str]] = {
    "client_id": None,
    "client_secret": None,
    "auth_token": None,
    "issuer_url": None,
}

# In-memory store for pending authorization codes
# Maps: auth_code -> {"code_challenge": str, "redirect_uri": str, "client_id": str, "expires": float}
_pending_codes: Dict[str, dict] = {}

# Cleanup codes older than 10 minutes
_CODE_LIFETIME = 600


def _cleanup_expired_codes():
    """Remove expired authorization codes."""
    now = time.time()
    expired = [code for code, data in _pending_codes.items() if data["expires"] < now]
    for code in expired:
        del _pending_codes[code]


def _get_issuer(request: Request) -> str:
    """Get the issuer URL from config or request."""
    return _oauth_config["issuer_url"] or str(request.base_url).rstrip("/")


# ---------------------------------------------------------------------------
# RFC 9470 — Protected Resource Metadata
# ---------------------------------------------------------------------------

async def handle_protected_resource(request: Request) -> Response:
    """Tell the client where to find our authorization server."""
    issuer = _get_issuer(request)
    return JSONResponse({
        "resource": issuer,
        "authorization_servers": [issuer],
    })


# Also handle the path-suffixed variant that Cowork tries first
async def handle_protected_resource_sse(request: Request) -> Response:
    """Same as above, for /.well-known/oauth-protected-resource/sse."""
    return await handle_protected_resource(request)


# ---------------------------------------------------------------------------
# RFC 8414 — OAuth 2.0 Authorization Server Metadata
# ---------------------------------------------------------------------------

async def handle_oauth_metadata(request: Request) -> Response:
    """Authorization server metadata discovery."""
    issuer = _get_issuer(request)
    return JSONResponse({
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp:tools", "claudeai"],
    })


# ---------------------------------------------------------------------------
# /authorize — Authorization endpoint (auto-approves valid clients)
# ---------------------------------------------------------------------------

async def handle_authorize(request: Request) -> Response:
    """OAuth 2.0 authorization endpoint with PKCE support.

    Since this is a machine-to-machine MCP server (not a user-facing app),
    we auto-approve requests from valid client_ids without showing a consent page.
    """
    params = dict(request.query_params)

    response_type = params.get("response_type")
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method", "S256")
    state = params.get("state")

    # Validate required params
    if response_type != "code":
        return JSONResponse(
            {"error": "unsupported_response_type", "error_description": "Only 'code' is supported"},
            status_code=400,
        )

    if not client_id:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing client_id"},
            status_code=400,
        )

    if not redirect_uri:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing redirect_uri"},
            status_code=400,
        )

    if not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing code_challenge (PKCE required)"},
            status_code=400,
        )

    if code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Only S256 code_challenge_method supported"},
            status_code=400,
        )

    # Validate client_id matches configured one (if configured)
    configured_client_id = _oauth_config["client_id"]
    if configured_client_id:
        if not secrets.compare_digest(client_id, configured_client_id):
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Unknown client_id"},
                status_code=401,
            )

    # Validate redirect_uri (must be HTTPS or localhost)
    parsed_redirect = urlparse(redirect_uri)
    if parsed_redirect.scheme not in ("https", "http"):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid redirect_uri scheme"},
            status_code=400,
        )

    # Clean up expired codes
    _cleanup_expired_codes()

    # Generate authorization code
    auth_code = secrets.token_urlsafe(48)
    _pending_codes[auth_code] = {
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "expires": time.time() + _CODE_LIFETIME,
    }

    # Redirect back to the client with the auth code
    redirect_params = {"code": auth_code}
    if state:
        redirect_params["state"] = state

    separator = "&" if "?" in redirect_uri else "?"
    redirect_url = f"{redirect_uri}{separator}{urlencode(redirect_params)}"

    logger.info("OAuth: issued authorization code for client_id=%s, redirecting to %s",
                client_id[:8] + "...", parsed_redirect.netloc)

    return RedirectResponse(url=redirect_url, status_code=302)


# ---------------------------------------------------------------------------
# /token — Token endpoint (authorization_code + PKCE exchange)
# ---------------------------------------------------------------------------

async def handle_token(request: Request) -> Response:
    """OAuth 2.0 token endpoint — authorization_code with PKCE."""
    auth_token = _oauth_config["auth_token"]

    if not auth_token:
        return JSONResponse(
            {"error": "server_error", "error_description": "OAuth not configured (MCP_AUTH_TOKEN not set)"},
            status_code=500,
        )

    # Parse form-encoded body
    body = await request.body()
    try:
        params = parse_qs(body.decode("utf-8"))
    except Exception:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Could not parse request body"},
            status_code=400,
        )

    grant_type = (params.get("grant_type") or [None])[0]
    code = (params.get("code") or [None])[0]
    redirect_uri = (params.get("redirect_uri") or [None])[0]
    code_verifier = (params.get("code_verifier") or [None])[0]
    provided_client_id = (params.get("client_id") or [None])[0]
    provided_client_secret = (params.get("client_secret") or [None])[0]

    # Also support client_secret_basic
    if not provided_client_id or not provided_client_secret:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                provided_client_id, provided_client_secret = decoded.split(":", 1)
            except Exception:
                pass

    # Support both authorization_code and client_credentials
    if grant_type == "client_credentials":
        return await _handle_client_credentials(provided_client_id, provided_client_secret)

    if grant_type != "authorization_code":
        return JSONResponse(
            {"error": "unsupported_grant_type",
             "error_description": "Supported: authorization_code, client_credentials"},
            status_code=400,
        )

    # Validate authorization code
    if not code:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing authorization code"},
            status_code=400,
        )

    _cleanup_expired_codes()

    pending = _pending_codes.pop(code, None)
    if not pending:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
            status_code=400,
        )

    # Validate redirect_uri matches
    if redirect_uri and redirect_uri != pending["redirect_uri"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            status_code=400,
        )

    # Validate PKCE code_verifier
    if not code_verifier:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing code_verifier (PKCE required)"},
            status_code=400,
        )

    # S256: code_challenge = BASE64URL(SHA256(code_verifier))
    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )

    if not secrets.compare_digest(expected_challenge, pending["code_challenge"]):
        logger.warning("OAuth: PKCE verification failed for client_id=%s", pending["client_id"][:8] + "...")
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            status_code=400,
        )

    # Issue access token
    logger.info("OAuth: issued access token for client_id=%s", pending["client_id"][:8] + "...")
    return JSONResponse({
        "access_token": auth_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "scope": "mcp:tools",
    })


async def _handle_client_credentials(client_id: Optional[str], client_secret: Optional[str]) -> Response:
    """Handle client_credentials grant (for non-Cowork clients)."""
    configured_id = _oauth_config["client_id"]
    configured_secret = _oauth_config["client_secret"]
    auth_token = _oauth_config["auth_token"]

    if not configured_id or not configured_secret or not auth_token:
        return JSONResponse(
            {"error": "server_error", "error_description": "OAuth client_credentials not configured"},
            status_code=500,
        )

    if not client_id or not client_secret:
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Missing client_id or client_secret"},
            status_code=401,
        )

    if not (secrets.compare_digest(client_id, configured_id) and
            secrets.compare_digest(client_secret, configured_secret)):
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Invalid client credentials"},
            status_code=401,
        )

    return JSONResponse({
        "access_token": auth_token,
        "token_type": "bearer",
        "expires_in": 86400,
        "scope": "mcp:tools",
    })


# ---------------------------------------------------------------------------
# Bearer-token authentication middleware
# ---------------------------------------------------------------------------

# Paths/prefixes allowed without authentication
_PUBLIC_PATHS = frozenset({
    "/health",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/sse",
    "/authorize",
    "/token",
})


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

        # Handle OPTIONS preflight requests
        if request.method == "OPTIONS":
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
            Route("/.well-known/oauth-protected-resource/sse", endpoint=handle_protected_resource_sse),
            Route("/.well-known/oauth-protected-resource", endpoint=handle_protected_resource),
            Route("/.well-known/oauth-authorization-server", endpoint=handle_oauth_metadata),
            Route("/authorize", endpoint=handle_authorize),
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
        if mcp_client_id:
            logger.info("OAuth 2.0 authorization_code + PKCE flow ENABLED")
            logger.info("  Discovery: /.well-known/oauth-authorization-server")
            logger.info("  Authorize: /authorize")
            logger.info("  Token:     /token")
        else:
            logger.warning(
                "MCP_CLIENT_ID not set — OAuth auto-approve disabled. "
                "Any client_id will be accepted for authorization."
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
