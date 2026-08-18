"""Test cases for the Railway remote server authentication."""

import os
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from analytics_mcp import remote_server


class TestAuth0Configuration(unittest.TestCase):
    """Tests Auth0 environment validation."""

    def test_loads_complete_configuration(self):
        """A domain and audience produce MCP OAuth metadata settings."""

        with mock.patch.dict(
            os.environ,
            {
                "AUTH0_DOMAIN": "tenant.us.auth0.com",
                "AUTH0_AUDIENCE": "https://example.up.railway.app/",
            },
            clear=True,
        ):
            configuration = remote_server.get_auth0_configuration()

        self.assertIsNotNone(configuration)
        self.assertEqual(
            configuration.issuer,
            "https://tenant.us.auth0.com/",
        )
        self.assertEqual(
            configuration.audience,
            "https://example.up.railway.app",
        )
        self.assertEqual(configuration.scope, "analytics:read")

    def test_rejects_partial_configuration(self):
        """OAuth cannot start with only one Auth0 setting."""

        with mock.patch.dict(
            os.environ,
            {"AUTH0_DOMAIN": "tenant.us.auth0.com"},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                remote_server.get_auth0_configuration()


class TestRemoteAuthMiddleware(unittest.TestCase):
    """Tests JWT validation and OAuth challenges."""

    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    def _make_token(self, scope: str) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": "https://tenant.us.auth0.com/",
                "aud": "https://example.up.railway.app",
                "sub": "auth0|test-user",
                "iat": now,
                "exp": now + 300,
                "scope": scope,
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    def test_requires_valid_token_and_scope(self):
        """Missing or under-scoped tokens fail before reaching MCP."""

        async def endpoint(_):
            return JSONResponse({"ok": True})

        application = Starlette(routes=[Route("/mcp", endpoint)])
        with mock.patch.dict(
            os.environ,
            {
                "AUTH0_DOMAIN": "tenant.us.auth0.com",
                "AUTH0_AUDIENCE": "https://example.up.railway.app",
                "AUTH0_SCOPE": "analytics:read",
            },
            clear=True,
        ):
            middleware = remote_server.RemoteAuthMiddleware(application)
            middleware.auth0_verifier.jwks_client.get_signing_key_from_jwt = (
                lambda _: SimpleNamespace(key=self.private_key.public_key())
            )

            with TestClient(middleware) as client:
                missing = client.get("/mcp")
                wrong_scope = client.get(
                    "/mcp",
                    headers={
                        "Authorization": (
                            f"Bearer {self._make_token('other:read')}"
                        )
                    },
                )
                valid = client.get(
                    "/mcp",
                    headers={
                        "Authorization": (
                            f"Bearer {self._make_token('analytics:read')}"
                        )
                    },
                )

        self.assertEqual(missing.status_code, 401)
        self.assertIn(
            "resource_metadata=",
            missing.headers["www-authenticate"],
        )
        self.assertEqual(wrong_scope.status_code, 403)
        self.assertEqual(valid.status_code, 200)


if __name__ == "__main__":
    unittest.main()
