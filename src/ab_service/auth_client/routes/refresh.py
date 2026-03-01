"""Handle Refresh Token."""

from typing import Annotated

from ab_core.auth_client.oauth2.client import OAuth2Client
from ab_core.auth_client.oauth2.client.pkce import PKCEOAuth2Client
from ab_core.auth_client.oauth2.client.standard import StandardOAuth2Client
from ab_core.auth_client.oauth2.schema.refresh import RefreshTokenRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2TokenExposed
from ab_core.cache.caches.base import CacheAsyncSession
from ab_core.cache.session_context import cache_session_async
from ab_core.dependency import Depends
from fastapi import APIRouter
from fastapi import Depends as FDepends
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, SecretStr

router = APIRouter(prefix="/refresh", tags=["Auth"])


@router.post("", response_model=OAuth2TokenExposed)
async def refresh_token(
    request: RefreshTokenRequest,
    auth_client: Annotated[OAuth2Client, Depends(OAuth2Client, persist=True)],
):
    # Both Standard + PKCE clients typically support refresh. If your PKCE client
    # delegates to the same token endpoint, this will work the same.
    token = await auth_client.refresh_async(request)

    # Unmask SecretStr *only for the HTTP response*
    return jsonable_encoder(
        token.model_dump(mode="python"),
        custom_encoder={SecretStr: lambda s: s.get_secret_value()},
    )
