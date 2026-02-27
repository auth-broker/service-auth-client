"""Generate login url."""

from typing import Annotated

from ab_core.auth_client.oauth2.client import OAuth2Client
from ab_core.auth_client.oauth2.client.pkce import PKCEOAuth2Client
from ab_core.auth_client.oauth2.client.standard import StandardOAuth2Client
from ab_core.auth_client.oauth2.schema.authorize import (
    AuthorizeResponse,
    OAuth2BuildAuthorizeRequest,
    PKCEBuildAuthorizeRequest,
)
from ab_core.cache.caches.base import CacheAsyncSession
from ab_core.cache.session_context import cache_session_async  # your DI dep that yields a session
from ab_core.dependency import Depends
from fastapi import APIRouter, Request
from fastapi import Depends as FDepends

router = APIRouter(prefix="/login", tags=["Auth"])


@router.get("", response_model=AuthorizeResponse)
async def get_login_url(
    request: Request,
    auth_client: Annotated[OAuth2Client, Depends(OAuth2Client, persist=True)],
    cache_session: Annotated[CacheAsyncSession, FDepends(cache_session_async)],
    scope: str = "openid email profile",
    response_type: str = "code",
    identity_provider: str | None = "Google",
):
    # Known keys you explicitly model in the signature
    reserved_keys = {"scope", "response_type", "identity_provider"}

    # Everything else becomes app_context (first value only)
    qp = dict(request.query_params)
    app_context = {k: v for k, v in qp.items() if k not in reserved_keys}

    extra = {"identity_provider": identity_provider} if identity_provider else None

    if isinstance(auth_client, PKCEOAuth2Client):
        req = PKCEBuildAuthorizeRequest(
            scope=scope,
            response_type=response_type,
            extra_params=extra,
            pkce=None,
            app_context=app_context,
        )

    elif isinstance(auth_client, StandardOAuth2Client):
        req = OAuth2BuildAuthorizeRequest(
            scope=scope,
            response_type=response_type,
            extra_params=extra,
            app_context=app_context,
        )

    else:
        raise TypeError(f"Unsupported OAuth2 client type: {type(auth_client).__name__}")

    return await auth_client.build_authorize_request_async(req, cache_session=cache_session)
