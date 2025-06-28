"""Example token verifier implementation using OAuth 2.0 Token Introspection (RFC 7662)."""

import logging
import base64
import json
from typing import Dict, Any, Optional

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.shared.auth_utils import check_resource_allowed, resource_url_from_server_url

logger = logging.getLogger(__name__)

class LocalTokenVerifier(TokenVerifier):
    """

    Validate access token locally but getting public keys from JWKS endpoint
    """
    def __init__(
        self,
        jwks_endpoint: str,
        server_url: str,
        validate_resource: bool = False,
    ):
        self.jwks_endpoint = jwks_endpoint
        self.serer_url = server_url
        self.validate_resource = validate_resource
        self.resource_url = resource_url_from_server_url(server_url) 

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify JWT token locally using JWKS endpoint."""
        import httpx
        import jwt

        # Parse the JWT token to extract header and payload
        try:
            # Decode without verification to get header and payload
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError as e:
            logger.warning(f"Failed to parse JWT token: {e}")
            return None

        # Extract kid from header
        kid = unverified_header.get("kid")
        if not kid:
            logger.warning("JWT token missing 'kid' claim in header")
            return None

        # Fetch JWKS from endpoint
        timeout = httpx.Timeout(10.0, connect=5.0)
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=True,  # Enforce SSL verification
        ) as client:
            try:
                response = await client.get(self.jwks_endpoint)
                if response.status_code != 200:
                    logger.warning(f"JWKS endpoint returned status {response.status_code}")
                    return None

                jwks_data = response.json()
            except Exception as e:
                logger.warning(f"Failed to get JWKS: {e}")
                return None

        # Find the public key by kid
        public_key = None
        for key in jwks_data.get("keys", []):
            if key.get("kid") == kid:
                public_key = key
                break

        if not public_key:
            logger.warning(f"Public key with kid '{kid}' not found in JWKS")
            return None

        # Verify the token signature
        try:
            # Convert JWK to PEM format for verification
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.primitives import serialization
            import json

            # Handle RSA keys
            if public_key.get("kty") == "RSA":
                n = int.from_bytes(base64.urlsafe_b64decode(public_key["n"] + "=="), "big")
                e = int.from_bytes(base64.urlsafe_b64decode(public_key["e"] + "=="), "big")
                public_numbers = rsa.RSAPublicNumbers(e, n)
                public_key_obj = public_numbers.public_key()
                pem_key = public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            # Handle EC keys
            elif public_key.get("kty") == "EC":
                x = int.from_bytes(base64.urlsafe_b64decode(public_key["x"] + "=="), "big")
                y = int.from_bytes(base64.urlsafe_b64decode(public_key["y"] + "=="), "big")
                curve_name = public_key.get("crv", "P-256")
                if curve_name == "P-256":
                    curve = ec.SECP256R1()
                elif curve_name == "P-384":
                    curve = ec.SECP384R1()
                elif curve_name == "P-521":
                    curve = ec.SECP521R1()
                else:
                    logger.warning(f"Unsupported EC curve: {curve_name}")
                    return None
                
                public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
                public_key_obj = public_numbers.public_key()
                pem_key = public_key_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            else:
                logger.warning(f"Unsupported key type: {public_key.get('kty')}")
                return None

            # Verify the token
            payload = jwt.decode(
                token,
                pem_key,
                algorithms=["RS256", "ES256"],  # Common algorithms, adjust as needed
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": False,  # We'll handle audience validation separately
                }
            )

            # RFC 8707 resource validation (only when validate_resource is True)
            if self.validate_resource and not self._validate_resource(payload):
                logger.warning(f"Token resource validation failed. Expected: {self.resource_url}")
                return None

            return AccessToken(
                token=token,
                client_id=payload.get("client_id", payload.get("azp", "unknown")),
                scopes=payload.get("scope", ""),
                expires_at=payload.get("exp"),
                resource=payload.get("aud"),  # Include resource in token
            )

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidSignatureError:
            logger.warning("JWT token signature is invalid")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT token validation failed: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error during JWT verification: {e}")
            return None

    def _validate_resource(self, token_data: dict) -> bool:
        """Validate token was issued for this resource server."""
        if not self.server_url or not self.resource_url:
            return False  # Fail if strict validation requested but URLs missing

        # Check 'aud' claim first (standard JWT audience)
        aud = token_data.get("aud")
        if isinstance(aud, list):
            for audience in aud:
                if self._is_valid_resource(audience):
                    return True
            return False
        elif aud:
            return self._is_valid_resource(aud)

        # No resource binding - invalid per RFC 8707
        return False

    def _is_valid_resource(self, resource: str) -> bool:
        """Check if resource matches this server using hierarchical matching."""
        if not self.resource_url:
            return False

        return check_resource_allowed(requested_resource=self.resource_url, configured_resource=resource)


class IntrospectionTokenVerifier(TokenVerifier):
    """Example token verifier that uses OAuth 2.0 Token Introspection (RFC 7662).

    This is a simple example implementation for demonstration purposes.
    Production implementations should consider:
    - Connection pooling and reuse
    - More sophisticated error handling
    - Rate limiting and retry logic
    - Comprehensive configuration options
    """

    def __init__(
        self,
        introspection_endpoint: str,
        server_url: str,
        client_id: str,
        client_secret: str,
        validate_resource: bool = False,
    ):
        self.introspection_endpoint = introspection_endpoint
        self.server_url = server_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.validate_resource = validate_resource
        self.resource_url = resource_url_from_server_url(server_url)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify token via introspection endpoint."""
        import httpx

        # Validate URL to prevent SSRF attacks
        if not self.introspection_endpoint.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            logger.warning(f"Rejecting introspection endpoint with unsafe scheme: {self.introspection_endpoint}")
            return None

        # Configure secure HTTP client
        timeout = httpx.Timeout(10.0, connect=5.0)
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=True,  # Enforce SSL verification
        ) as client:
            try:
                credentials = base64.b64encode(f'{self.client_id}:{self.client_secret}'.encode()).decode('utf-8')
                response = await client.post(
                    self.introspection_endpoint,
                    data={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Basic {credentials}"},
                )

                if response.status_code != 200:
                    logger.debug(f"Token introspection returned status {response.status_code}")
                    return None

                data = response.json()
                if not data.get("active", False):
                    return None

                # RFC 8707 resource validation (only when --oauth-strict is set)
                if self.validate_resource and not self._validate_resource(data):
                    logger.warning(f"Token resource validation failed. Expected: {self.resource_url}")
                    return None

                return AccessToken(
                    token=token,
                    client_id=data.get("client_id", "unknown"),
                    scopes=data.get("scope", "").split() if data.get("scope") else [],
                    expires_at=data.get("exp"),
                    resource=data.get("aud"),  # Include resource in token
                )
            except Exception as e:
                logger.warning(f"Token introspection failed: {e}")
                return None

    def _validate_resource(self, token_data: dict) -> bool:
        """Validate token was issued for this resource server."""
        if not self.server_url or not self.resource_url:
            return False  # Fail if strict validation requested but URLs missing

        # Check 'aud' claim first (standard JWT audience)
        aud = token_data.get("aud")
        if isinstance(aud, list):
            for audience in aud:
                if self._is_valid_resource(audience):
                    return True
            return False
        elif aud:
            return self._is_valid_resource(aud)

        # No resource binding - invalid per RFC 8707
        return False

    def _is_valid_resource(self, resource: str) -> bool:
        """Check if resource matches this server using hierarchical matching."""
        if not self.resource_url:
            return False

        return check_resource_allowed(requested_resource=self.resource_url, configured_resource=resource)
