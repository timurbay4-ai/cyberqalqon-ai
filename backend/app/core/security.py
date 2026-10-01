"""Optional bearer-token guards for event data and Wazuh ingestion."""

from secrets import compare_digest
from typing import Annotated

from fastapi import Header

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError


def _verify_bearer_token(authorization: str | None, expected: str | None) -> None:
    if expected is None:
        return
    scheme, separator, token = (authorization or "").partition(" ")
    valid = separator == " " and scheme.lower() == "bearer" and compare_digest(token, expected)
    if not valid:
        raise AuthenticationError()


def require_api_auth(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    _verify_bearer_token(authorization, get_settings().api_access_token)


def require_wazuh_auth(
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    _verify_bearer_token(authorization, get_settings().wazuh_ingest_token)
