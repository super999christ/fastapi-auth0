import json
import logging
import os
from typing import Optional, Dict, List, Type
import urllib.parse
import urllib.request

from jose import jwt  # type: ignore
from fastapi import HTTPException, Depends, Request
from fastapi.security import SecurityScopes, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security import OAuth2, OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer, OpenIdConnect
from fastapi.openapi.models import OAuthFlows, OAuthFlowImplicit
from pydantic import BaseModel, Field, ValidationError
from typing_extensions import TypedDict


logger = logging.getLogger('fastapi_auth0')

auth0_rule_namespace: str = os.getenv('AUTH0_RULE_NAMESPACE', 'https://github.com/super999christ/fastapi-auth0')


class Auth0UnauthenticatedException(HTTPException):
    def __init__(self, detail: str, **kwargs):
        """Returns HTTP 401"""
        super().__init__(401, detail, **kwargs)

class Auth0UnauthorizedException(HTTPException):
    def __init__(self, detail: str, **kwargs):
        """Returns HTTP 403"""
        super().__init__(403, detail, **kwargs)

class HTTPAuth0Error(BaseModel):
    detail: str

unauthenticated_response: Dict = {401: {'model': HTTPAuth0Error}}
unauthorized_response:    Dict = {403: {'model': HTTPAuth0Error}}
security_responses:       Dict = {**unauthenticated_response, **unauthorized_response}


class Auth0User(BaseModel):
    id:                          str = Field(..., alias='sub')
    permissions: Optional[List[str]] = None
    email:             Optional[str] = Field(None, alias=f'{auth0_rule_namespace}/email')  # type: ignore [literal-required]


class Auth0HTTPBearer(HTTPBearer):
    async def __call__(self, request: Request):
        return await super().__call__(request)

