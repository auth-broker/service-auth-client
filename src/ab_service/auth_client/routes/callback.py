"""Handle Login Callback."""

from typing import Annotated

from ab_core.auth_client.oauth2.client import OAuth2Client
from ab_core.auth_client.oauth2.client.pkce import PKCEOAuth2Client
from ab_core.auth_client.oauth2.client.standard import StandardOAuth2Client
from ab_core.auth_client.oauth2.schema.exchange import (
    OAuth2ExchangeFromRedirectUrlRequest,
    PKCEExchangeFromRedirectUrlRequest,
)
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.cache.caches.base import CacheSession
from ab_core.cache.session_context import cache_session_sync
from ab_core.dependency import Depends
from fastapi import APIRouter, Request

router = APIRouter(prefix="/callback", tags=["Auth"])


@router.get("", response_model=OAuth2Token)
async def callback(
    request: Request,
    auth_client: Annotated[OAuth2Client, Depends(OAuth2Client, persist=True)],
    cache_session: Annotated[CacheSession, Depends(cache_session_sync, persist=True)],
):
    """Exchange the authorization code for tokens using the full redirect URL.

    For PKCE, the verifier is auto-fetched from cache via `state` (or falls back to the verifier
    included in the /login response if the caller passes it back).
    """
    redirect_url = str(request.url)

    if isinstance(auth_client, PKCEOAuth2Client):
        exch = PKCEExchangeFromRedirectUrlRequest(
            redirect_url=redirect_url,
            enforce_redirect_uri_match=True,  # optional, validates against client.config.redirect_uri
            expected_state=None,  # set to a value you stored server-side if you want CSRF check here
            code_verifier=None,  # prefer cache lookup by state; pass fallback if you kept it client-side
            delete_after=True,
        )
        return auth_client.exchange_from_redirect_url(exch, cache_session=cache_session)

    elif isinstance(auth_client, StandardOAuth2Client):
        exch = OAuth2ExchangeFromRedirectUrlRequest(
            redirect_url=redirect_url,
            enforce_redirect_uri_match=True,
            expected_state=None,
            delete_after=True,  # no-op for standard, but field exists for parity
        )
        return auth_client.exchange_from_redirect_url(exch, cache_session=cache_session)

    raise TypeError(f"Unsupported OAuth2 client type: {type(auth_client).__name__}")
