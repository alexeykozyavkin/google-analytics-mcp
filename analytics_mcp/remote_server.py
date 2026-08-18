#!/usr/bin/env python

"""Railway entry point for the Google Analytics MCP server.

This module keeps the upstream stdio entry point intact and exposes the same
low-level MCP server over Streamable HTTP at ``/mcp``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

import analytics_mcp.coordinator as coordinator

_CREDENTIALS_VARIABLE = "GOOGLE_APPLICATION_CREDENTIALS_BASE64"
_CREDENTIALS_PATH = Path(tempfile.gettempdir()) / "google-credentials.json"


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

    if os.environ.get("MCP_AUTH_TOKEN"):
        return

    if os.environ.get("ALLOW_UNAUTHENTICATED_MCP", "").lower() == "true":
        return

    raise RuntimeError(
        "Set MCP_AUTH_TOKEN, or explicitly set ALLOW_UNAUTHENTICATED_MCP=true "
        "for short-lived testing only."
    )


async def health(_: Request) -> JSONResponse:
    """Return a credential-free readiness response for Railway."""

    return JSONResponse({"status": "ok", "service": "analytics-mcp"})


class BearerAuthMiddleware:
    """Require the configured static bearer token for MCP requests."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http" or scope.get("path") == "/health":
            await self.app(scope, receive, send)
            return

        expected_token = os.environ.get("MCP_AUTH_TOKEN")
        if not expected_token:
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        supplied_header = headers.get("authorization", "")
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


@asynccontextmanager
async def lifespan(_: Starlette):
    """Run the MCP session manager for the ASGI application's lifetime."""

    async with session_manager.run():
        yield


starlette_app = Starlette(
    routes=[
        Route("/health", endpoint=health, methods=["GET"]),
        Route(
            "/mcp",
            endpoint=StreamableHTTPASGIApp(session_manager),
            methods=["GET", "POST", "DELETE"],
        ),
    ],
    lifespan=lifespan,
)
app = BearerAuthMiddleware(starlette_app)


def run_remote_server() -> None:
    """Start the Railway-compatible Streamable HTTP server."""

    configure_google_credentials()
    validate_remote_access_configuration()
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=True)


if __name__ == "__main__":
    run_remote_server()
