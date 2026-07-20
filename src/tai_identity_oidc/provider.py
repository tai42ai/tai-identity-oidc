"""Validate-only OIDC identity provider.

Resolves an issuer-minted JWT presented on an API call to an authenticated
identity: a cheap structural gate claims JWT-shaped tokens (non-JWT credentials
fall through the provider chain untouched), the token is verified against the
issuer's JWKS via :mod:`tai_kit.net.jwt`, and the verified claims become the
identity. The subject is namespaced ``idp:{issuer}:{sub}`` so an issuer subject
never collides with an account, key, or login-subject id in the shared policy
namespace.

This provider VALIDATES only. It implements the base
:class:`tai_contract.access_control.identity.IdentityProvider` ABC — deliberately
NOT :class:`ApiKeyIdentityProvider`: it mints no keys and holds no state, so the
skeleton's key-minting surface refuses it loudly. An issuer-authenticated subject
with no operator-provisioned policy resolves to the empty ``AccessPolicy`` and is
denied on every protected route (deny-by-default; there is no auto-provision or
default-policy path).

The provider registers itself as the ``"identity-oidc"`` identity provider in the
contract's module-level registry at import, with no app handle involved.
"""

from __future__ import annotations

import asyncio
import logging

from pydantic import Field
from pydantic_settings import SettingsConfigDict
from tai_contract.access_control import OWNER_USER_ID_CLAIM
from tai_contract.access_control.identity import (
    AuthIdentity,
    IdentityProvider,
    IdentityProviderSettings,
)
from tai_contract.access_control.registry import register_identity_provider
from tai_kit.net.jwt import JwksCache, JwtVerifyError, fetch_discovery, looks_like_jwt, verify_jwt
from tai_kit.settings import TaiBaseSettings

logger = logging.getLogger(__name__)

# A kid the issuer's live JWKS will not carry, used by the healthcheck to force a
# real JWKS fetch: a successful fetch that simply lacks this kid proves the JWKS
# is reachable and well-formed (the reachability signal we want), while a
# transport/parse/size failure raises and fails the boot probe.
_HEALTHCHECK_PROBE_KID = "__identity_oidc_healthcheck_probe__"


class OidcIdentitySettings(TaiBaseSettings):
    """``TAI_IDENTITY_OIDC_*`` config for the validate-only OIDC provider.

    ``issuer`` and ``audience`` are REQUIRED — each is ``| None`` at the model
    level (so the settings load cleanly when the process does not run this
    provider) and enforced loudly at provider construction, where a missing one
    raises naming its env var. ``allowed_algs`` is an explicit allowlist (never
    "any"): ``alg=none`` and symmetric downgrades are rejected by construction
    because the kit verifier checks it before any key lookup.
    """

    model_config = SettingsConfigDict(env_prefix="TAI_IDENTITY_OIDC_")

    issuer: str | None = None
    audience: str | None = None
    # An empty allowlist would reject every token — a misconfiguration, so it is
    # refused loudly at load rather than silently denying everything.
    allowed_algs: tuple[str, ...] = Field(default=("RS256",), min_length=1)
    claim: str = "sub"
    jwks_ttl_seconds: float = 3600.0


def _require(value: str | None, env_name: str) -> str:
    """Return ``value``, or raise loudly naming the env var when it is unset."""
    if not value:
        raise ValueError(f"{env_name} is required for the OIDC identity provider.")
    return value


class OidcIdentityProvider(IdentityProvider):
    """Validate an issuer-minted JWT against the issuer's JWKS.

    Implements the base :class:`IdentityProvider` ABC, NOT
    :class:`ApiKeyIdentityProvider`: this is the member that proves the
    mint-capability gate — the skeleton's key-minting surface raises for it —
    so it exposes no ``provision``/``revoke``/``list_identities`` surface.

    The registry factory hands this provider the skeleton's AC settings object
    (:class:`IdentityProviderSettings`). This provider reads its OWN
    ``TAI_IDENTITY_OIDC_*`` env config at construction and uses NOTHING from the
    injected object beyond accepting it: it holds no state and reaches no injected
    store, so it inherits the base ``readiness_targets`` empty tuple (the boot
    probe's ``healthcheck`` is the issuer-reachability check) and needs no
    ``settings.redis``.
    """

    def __init__(self, settings: IdentityProviderSettings) -> None:
        # The injected AC settings object satisfies the factory contract but is
        # unused — this provider's configuration is its OWN env namespace. A
        # missing required issuer/audience raises a loud settings error here.
        self._settings = OidcIdentitySettings()
        self._issuer = _require(self._settings.issuer, "TAI_IDENTITY_OIDC_ISSUER")
        self._audience = _require(self._settings.audience, "TAI_IDENTITY_OIDC_AUDIENCE")
        # Discovery is async and the JWKS uri is only known after it, so the cache
        # is built lazily on first use under a lock (concurrent first callers
        # collapse behind one discovery fetch).
        self._jwks: JwksCache | None = None
        self._discovery_lock = asyncio.Lock()

    async def _jwks_cache(self) -> JwksCache:
        if self._jwks is not None:
            return self._jwks
        async with self._discovery_lock:
            if self._jwks is None:
                discovery = await fetch_discovery(self._issuer)
                self._jwks = JwksCache(discovery.jwks_uri, ttl_seconds=self._settings.jwks_ttl_seconds)
            return self._jwks

    async def validate_token(self, token: str) -> AuthIdentity | None:
        # Cheap structural gate: a non-JWT credential (an ``sk-…`` key, a
        # ``tai-sess-…`` session token) is not ours — return ``None`` so it falls
        # through the provider chain with no verification attempt and no fetch.
        if not looks_like_jwt(token):
            return None

        # A JWT-shaped token that fails verification is an attack or a
        # misconfiguration, never someone else's credential: verify_jwt raises a
        # typed error, which propagates so the request denies (fail-closed).
        jwks = await self._jwks_cache()
        claims = await verify_jwt(
            token,
            jwks=jwks,
            issuer=self._issuer,
            audience=self._audience,
            allowed_algs=self._settings.allowed_algs,
        )

        # Reserved-claim strip (defense-in-depth): drop any ``owner_user_id`` the
        # issuer may have emitted before the claims become the identity. That claim
        # is authoritative ONLY from the key-mint path; the skeleton verifier's
        # central strip already removes it for every non-mintable provider, so this
        # is belt-and-suspenders — a non-mintable provider that copies external
        # claims should still not carry attacker/issuer-controlled owner data.
        claims = {name: value for name, value in claims.items() if name != OWNER_USER_ID_CLAIM}

        if self._settings.claim not in claims:
            # A verified token missing the configured subject claim is a
            # misconfiguration, never a silent guest — raise so it is visible.
            raise ValueError(
                f"Verified token from issuer {self._issuer!r} has no "
                f"{self._settings.claim!r} claim to map to a user id."
            )

        # Namespace the subject: the raw issuer ``sub`` shares the single flat
        # policy user_id namespace with account, key, and login-subject ids, so a
        # bare sub could inherit another principal's policy. The ``idp:{issuer}:``
        # prefix fences issuer subjects into their own namespace; operators
        # pre-provision policy under this namespaced id.
        user_id = f"idp:{self._issuer}:{claims[self._settings.claim]}"
        return AuthIdentity(user_id=user_id, claims=claims)

    async def healthcheck(self) -> None:
        # Prove the issuer's discovery + JWKS are reachable and well-formed at
        # boot, so a broken issuer fails startup loudly rather than the first
        # authenticated request. fetch_discovery validates the discovery document
        # and the issuer-match; get_key forces a real JWKS fetch. A sentinel kid
        # the live JWKS legitimately lacks is NOT a health failure — the JWKS was
        # fetched and parsed — so the unknown-kid verify error is swallowed; a
        # transport/parse/size failure (JwksFetchError) propagates and fails boot.
        discovery = await fetch_discovery(self._issuer)
        probe_cache = JwksCache(discovery.jwks_uri, ttl_seconds=self._settings.jwks_ttl_seconds)
        probe_alg = self._settings.allowed_algs[0]
        try:
            await probe_cache.get_key(_HEALTHCHECK_PROBE_KID, probe_alg)
        except JwtVerifyError:
            return


# Module-level registration: the plugin registers itself as "identity-oidc" in the
# contract's direct-import registry at its own import, with no ``tai_app`` handle
# involved. The factory is the class itself — ``OidcIdentityProvider(settings)``
# builds a live provider from the injected settings shape.
register_identity_provider("identity-oidc", OidcIdentityProvider)
