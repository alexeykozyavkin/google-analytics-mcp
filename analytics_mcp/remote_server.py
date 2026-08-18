#!/usr/bin/env python

"""Railway entry point for the Google Analytics MCP server.

This module keeps the upstream stdio entry point intact and exposes the same
low-level MCP server over Streamable HTTP at ``/mcp``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import secrets
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

import analytics_mcp.coordinator as coordinator

_CREDENTIALS_VARIABLE = "GOOGLE_APPLICATION_CREDENTIALS_BASE64"
_CREDENTIALS_PATH = Path(tempfile.gettempdir()) / "google-credentials.json"
_AUTH0_SCOPE = "analytics:read"
_OAUTH_METADATA_PATH = "/.well-known/oauth-protected-resource"


@dataclass(frozen=True)
class Auth0Configuration:
    """Validated Auth0 settings for the remote MCP resource server."""

    issuer: str
    audience: str
    scope: str
    resource_metadata_url: str


def get_auth0_configuration() -> Auth0Configuration | None:
    """Load Auth0 settings, requiring a complete configuration when present."""

    domain = os.environ.get("AUTH0_DOMAIN", "").strip()
    audience = os.environ.get("AUTH0_AUDIENCE", "").strip().rstrip("/")
    if not domain and not audience:
        return None
    if not domain or not audience:
        raise RuntimeError(
            "Set both AUTH0_DOMAIN and AUTH0_AUDIENCE to enable OAuth."
        )

    domain = domain.removeprefix("https://").removeprefix("http://").strip("/")
    if not domain or "/" in domain:
        raise RuntimeError(
            "AUTH0_DOMAIN must be a hostname such as tenant.us.auth0.com."
        )
    if not audience.startswith("https://"):
        raise RuntimeError("AUTH0_AUDIENCE must be an absolute HTTPS URL.")

    scope = os.environ.get("AUTH0_SCOPE", _AUTH0_SCOPE).strip()
    if not scope or " " in scope:
        raise RuntimeError("AUTH0_SCOPE must contain exactly one OAuth scope.")

    resource_url = (
        os.environ.get("MCP_PUBLIC_URL", audience).strip().rstrip("/")
    )
    if not resource_url.startswith("https://"):
        raise RuntimeError("MCP_PUBLIC_URL must be an absolute HTTPS URL.")

    return Auth0Configuration(
        issuer=f"https://{domain}/",
        audience=audience,
        scope=scope,
        resource_metadata_url=f"{resource_url}{_OAUTH_METADATA_PATH}",
    )


def configure_google_credentials() -> None:
    """Materialize base64-encoded Railway credentials into a private file.

    Local development can continue to use GOOGLE_APPLICATION_CREDENTIALS with
    an existing file. Railway should use GOOGLE_APPLICATION_CREDENTIALS_BASE64
    so the service-account key never enters the repository or image.
    """

    existing_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if existing_path:
        if not Path(existing_path).is_file():
            raise RuntimeError(
                "GOOGLE_APPLICATION_CREDENTIALS does not point to a file."
            )
        return

    encoded = os.environ.get(_CREDENTIALS_VARIABLE)
    if not encoded:
        raise RuntimeError(
            f"Set {_CREDENTIALS_VARIABLE} to the base64-encoded service-account JSON."
        )

    try:
        compact_value = "".join(encoded.split())
        decoded = base64.b64decode(compact_value, validate=True)
        credentials = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"{_CREDENTIALS_VARIABLE} is not valid base64-encoded JSON."
        ) from exc

    if not isinstance(credentials, dict):
        raise RuntimeError(
            "The decoded Google credentials must be a JSON object."
        )

    required_fields = {"type", "project_id", "private_key", "client_email"}
    missing_fields = sorted(required_fields.difference(credentials))
    if credentials.get("type") != "service_account" or missing_fields:
        details = (
            f" Missing fields: {', '.join(missing_fields)}."
            if missing_fields
            else ""
        )
        raise RuntimeError(
            "The decoded Google credentials must describe a service account."
            + details
        )

    _CREDENTIALS_PATH.write_bytes(decoded)
    _CREDENTIALS_PATH.chmod(0o600)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(_CREDENTIALS_PATH)
    os.environ.setdefault("GOOGLE_CLOUD_PROJECT", credentials["project_id"])


def validate_remote_access_configuration() -> None:
    """Prevent accidental publication of an unprotected Analytics endpoint."""

    if get_auth0_configuration():
        return

    if os.environ.get("MCP_AUTH_TOKEN"):
        return

    if os.environ.get("ALLOW_UNAUTHENTICATED_MCP", "").lower() == "true":
        return

    raise RuntimeError(
        "Set AUTH0_DOMAIN and AUTH0_AUDIENCE, set MCP_AUTH_TOKEN, or explicitly "
        "set ALLOW_UNAUTHENTICATED_MCP=true for short-lived testing only."
    )


async def health(_: Request) -> JSONResponse:
    """Return a credential-free readiness response for Railway."""

    return JSONResponse({"status": "ok", "service": "analytics-mcp"})


async def oauth_protected_resource(_: Request) -> JSONResponse:
    """Advertise Auth0 metadata according to RFC 9728."""

    configuration = get_auth0_configuration()
    if not configuration:
        return JSONResponse(
            {"error": "oauth_not_configured"},
            status_code=404,
        )

    return JSONResponse(
        {
            "resource": configuration.audience,
            "authorization_servers": [configuration.issuer],
            "scopes_supported": [configuration.scope],
            "bearer_methods_supported": ["header"],
            "resource_name": "Google Analytics MCP",
        }
    )


class Auth0TokenVerifier:
    """Verify Auth0 access tokens with cached RS256 signing keys."""

    def __init__(self, configuration: Auth0Configuration):
        self.configuration = configuration
        self.jwks_client = PyJWKClient(
            f"{configuration.issuer}.well-known/jwks.json"
        )

    async def verify(
        self, token: str
    ) -> tuple[dict[str, Any], set[str]] | None:
        """Return verified claims and scopes, or None for an invalid token."""

        try:
            signing_key = await asyncio.to_thread(
                self.jwks_client.get_signing_key_from_jwt,
                token,
            )
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.configuration.audience,
                issuer=self.configuration.issuer,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
        except (InvalidTokenError, PyJWKClientError):
            return None

        scopes: set[str] = set()
        scope_claim = claims.get("scope", "")
        if isinstance(scope_claim, str):
            scopes.update(scope_claim.split())
        elif isinstance(scope_claim, list):
            scopes.update(str(value) for value in scope_claim)

        permissions_claim = claims.get("permissions", [])
        if isinstance(permissions_claim, list):
            scopes.update(str(value) for value in permissions_claim)

        return claims, scopes


class RemoteAuthMiddleware:
    """Protect MCP routes with Auth0 OAuth or a static bearer token."""

    def __init__(self, app: ASGIApp):
        self.app = app
        self.auth0_configuration = get_auth0_configuration()
        self.auth0_verifier = (
            Auth0TokenVerifier(self.auth0_configuration)
            if self.auth0_configuration
            else None
        )

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or path in {
            "/health",
            _OAUTH_METADATA_PATH,
            f"{_OAUTH_METADATA_PATH}/mcp",
        }:
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        supplied_header = headers.get("authorization", "")

        if self.auth0_configuration and self.auth0_verifier:
            if not supplied_header.lower().startswith("bearer "):
                await self._send_auth0_error(
                    scope,
                    receive,
                    send,
                    status_code=401,
                    error="invalid_token",
                    description="Authentication required",
                )
                return

            verification = await self.auth0_verifier.verify(supplied_header[7:])
            if not verification:
                await self._send_auth0_error(
                    scope,
                    receive,
                    send,
                    status_code=401,
                    error="invalid_token",
                    description="The access token is invalid or expired",
                )
                return

            claims, scopes = verification
            if self.auth0_configuration.scope not in scopes:
                await self._send_auth0_error(
                    scope,
                    receive,
                    send,
                    status_code=403,
                    error="insufficient_scope",
                    description=(
                        f"Required scope: {self.auth0_configuration.scope}"
                    ),
                )
                return

            scope["auth0.claims"] = claims
            await self.app(scope, receive, send)
            return

        expected_token = os.environ.get("MCP_AUTH_TOKEN")
        if not expected_token:
            await self.app(scope, receive, send)
            return

        expected_header = f"Bearer {expected_token}"
        if not secrets.compare_digest(supplied_header, expected_header):
            response = JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    async def _send_auth0_error(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        status_code: int,
        error: str,
        description: str,
    ) -> None:
        """Return an OAuth challenge that ChatGPT can discover."""

        configuration = self.auth0_configuration
        if not configuration:
            raise RuntimeError("Auth0 error requested without Auth0 settings.")

        challenge = (
            "Bearer "
            f'resource_metadata="{configuration.resource_metadata_url}", '
            f'scope="{configuration.scope}", '
            f'error="{error}", '
            f'error_description="{description}"'
        )
        response = JSONResponse(
            {"error": error, "error_description": description},
            status_code=status_code,
            headers={"WWW-Authenticate": challenge},
        )
        await response(scope, receive, send)


class StreamableHTTPASGIApp:
    """Adapt the session manager's ASGI handler for a Starlette route."""

    def __init__(self, manager: StreamableHTTPSessionManager):
        self.manager = manager

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        await self.manager.handle_request(scope, receive, send)


session_manager = StreamableHTTPSessionManager(
    app=coordinator.app,
    json_response=True,
    stateless=True,
)


def configure_tool_security_schemes() -> None:
    """Advertise OAuth requirements on tools when Auth0 is configured."""

    configuration = get_auth0_configuration()
    if not configuration:
        return

    security_schemes = [{"type": "oauth2", "scopes": [configuration.scope]}]
    for tool in coordinator.mcp_tools:
        tool.securitySchemes = security_schemes
        metadata = dict(tool.meta or {})
        metadata["securitySchemes"] = security_schemes
        tool.meta = metadata


configure_tool_security_schemes()


@asynccontextmanager
async def lifespan(_: Starlette):
    """Run the MCP session manager for the ASGI application's lifetime."""

    async with session_manager.run():
        yield


starlette_app = Starlette(
    routes=[
        Route("/health", endpoint=health, methods=["GET"]),
        Route(
            _OAUTH_METADATA_PATH,
            endpoint=oauth_protected_resource,
            methods=["GET"],
        ),
        Route(
            f"{_OAUTH_METADATA_PATH}/mcp",
            endpoint=oauth_protected_resource,
            methods=["GET"],
        ),
        Route(
            "/mcp",
            endpoint=StreamableHTTPASGIApp(session_manager),
            methods=["GET", "POST", "DELETE"],
        ),
    ],
    lifespan=lifespan,
)
app = RemoteAuthMiddleware(starlette_app)


def run_remote_server() -> None:
    """Start the Railway-compatible Streamable HTTP server."""

    configure_google_credentials()
    validate_remote_access_configuration()
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=True)


if __name__ == "__main__":
    run_remote_server()
