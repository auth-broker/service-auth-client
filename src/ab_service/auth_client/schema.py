"""Schema for token request."""

from pydantic import BaseModel


class TokenRequest(BaseModel):
    """Schema for token request."""

    token: str
