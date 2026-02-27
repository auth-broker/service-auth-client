"""Generate login url (POST with explicit app_context)."""

from typing import Annotated, Any

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
from fastapi import APIRouter
from fastapi import Depends as FDepends
from pydantic import BaseModel, Field

router = APIRouter(prefix="/login", tags=["Auth"])


class LoginRequest(BaseModel):
    scope: str = "openid email profile"
    response_type: str = "code"
    identity_provider: str | None = "Google"

    # Explicit, documented, structured context for downstream use (e.g. return_to, tenant, etc.)
    app_context: dict[str, Any] = Field(
        default_factory=dict,
        description="Opaque key/value context to carry through the auth flow (stored server-side).",
        examples=[{"return_to": "/dashboard", "tenant": "acme"}],
    )


@router.post("", response_model=AuthorizeResponse)
async def get_login_url(
    request: LoginRequest,
    auth_client: Annotated[OAuth2Client, Depends(OAuth2Client, persist=True)],
    cache_session: Annotated[CacheAsyncSession, FDepends(cache_session_async)],
):
    extra = {"identity_provider": request.identity_provider} if request.identity_provider else None

    if isinstance(auth_client, PKCEOAuth2Client):
        req = PKCEBuildAuthorizeRequest(
            scope=request.scope,
            response_type=request.response_type,
            extra_params=extra,
            pkce=None,
            app_context=request.app_context,
        )

    elif isinstance(auth_client, StandardOAuth2Client):
        req = OAuth2BuildAuthorizeRequest(
            scope=request.scope,
            response_type=request.response_type,
            extra_params=extra,
            app_context=request.app_context,
        )

    else:
        raise TypeError(f"Unsupported OAuth2 client type: {type(auth_client).__name__}")

    return await auth_client.build_authorize_request_async(req, cache_session=cache_session)
