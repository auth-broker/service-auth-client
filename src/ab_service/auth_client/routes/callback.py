"""Handle Login Callback."""

from typing import Annotated

from ab_core.auth_client.oauth2.client import OAuth2Client
from ab_core.auth_client.oauth2.client.pkce import PKCEOAuth2Client
from ab_core.auth_client.oauth2.client.standard import StandardOAuth2Client
from ab_core.auth_client.oauth2.schema.exchange import (
    OAuth2ExchangeFromRedirectUrlRequest,
    PKCEExchangeFromRedirectUrlRequest,
)
from ab_core.auth_client.oauth2.schema.token import OAuth2TokenExposed
from ab_core.cache.caches.base import CacheSession
from ab_core.cache.session_context import cache_session_sync
from ab_core.dependency import Depends
from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from pydantic import SecretStr

router = APIRouter(prefix="/callback", tags=["Auth"])


@router.get("", response_model=OAuth2TokenExposed)
async def callback(
    request: Request,
    auth_client: Annotated[OAuth2Client, Depends(OAuth2Client, persist=True)],
    cache_session: Annotated[CacheSession, Depends(cache_session_sync, persist=True)],
    redirect_url: str | None = None,
):
    redirect_url = redirect_url or str(request.url)

    if isinstance(auth_client, PKCEOAuth2Client):
        exch = PKCEExchangeFromRedirectUrlRequest(
            redirect_url=redirect_url,
            enforce_redirect_uri_match=True,
            expected_state=None,
            code_verifier=None,
            delete_after=True,
        )
        token = auth_client.exchange_from_redirect_url(exch, cache_session=cache_session)

    elif isinstance(auth_client, StandardOAuth2Client):
        exch = OAuth2ExchangeFromRedirectUrlRequest(
            redirect_url=redirect_url,
            enforce_redirect_uri_match=True,
            expected_state=None,
            delete_after=True,
        )
        token = auth_client.exchange_from_redirect_url(exch, cache_session=cache_session)

    else:
        raise TypeError(f"Unsupported OAuth2 client type: {type(auth_client).__name__}")

    # Unmask SecretStr *only for the HTTP response*
    return jsonable_encoder(
        token.model_dump(mode="python"),
        custom_encoder={SecretStr: lambda s: s.get_secret_value()},
    )
