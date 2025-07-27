# SPDX-FileCopyrightText: Copyright (c) 2024-2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pydantic import Field
from pydantic import field_validator

from aiq.authentication.exceptions.auth_code_grant_exceptions import AuthCodeGrantConfigClientIDFieldError
from aiq.authentication.exceptions.auth_code_grant_exceptions import AuthCodeGrantConfigClientSecretFieldError
from aiq.authentication.exceptions.auth_code_grant_exceptions import AuthCodeGrantConfigScopeFieldError
from aiq.data_models.authentication import AuthenticationBaseConfig
from aiq.data_models.authentication import AuthenticationEndpoint
from aiq.front_ends.fastapi.fastapi_front_end_config import FastApiFrontEndConfig


class OAuth2AuthorizationCodeFlowConfig(AuthenticationBaseConfig, name="oauth2_authorization_code"):
    client_id: str = Field(description="The client ID for OAuth 2.0 authentication.")
    client_secret: str = Field(description="The secret associated with the client_id.")
    scopes: list[str] = Field(description="The space-delimited scopes for OAuth 2.0 authentication.",
                              default_factory=list)
    authorization_url: str = Field(description="The authorization URL for OAuth 2.0 authentication.")
    token_url: str = Field(description="The token URL for OAuth 2.0 authentication.")
    client_server_url: str = Field(description="The base url of the API server instance. "
                                   "This is needed to properly construct the redirect uri i.e: http://localhost:8000")
    audience: str | None = Field(default=None, description="The resource server the token is intended for.")
    response_type: str | None = Field(default="code", description="The response type for OAuth 2.0 authentication.")
    prompt: str | None = Field(default="consent", description="The prompt for OAuth 2.0 authentication.")
    access_type: str | None = Field(default="offline", description="The access type for OAuth 2.0 authentication.")
    use_pkce: bool = Field(default=False,
                           description="Whether to use PKCE (Proof Key for Code Exchange) in the OAuth 2.0 flow.")
    extra_authorization_params: dict[str, str] = Field(default_factory=dict,
                                                       description="Extra parameters for the authorization URL.")

    @property
    def redirect_uri(self) -> str:
        auth_path = FastApiFrontEndConfig().authorization.path
        redirect_path = AuthenticationEndpoint.REDIRECT_URI.value
        return f"{self.client_server_url}{auth_path}{redirect_path}"

    @field_validator('client_secret')
    @classmethod
    def validate_client_secret(cls, value: str) -> str:
        """
        Validate client_secret field value.
        """
        if not value:
            raise AuthCodeGrantConfigClientSecretFieldError('value_missing',
                                                            'client_secret is required for OAuth 2.0 authentication.')

        # Check for minimum length
        if len(value) < 16:
            raise AuthCodeGrantConfigClientSecretFieldError(
                'value_too_short',
                'client_secret must be at least 16 characters long, ensuring a minimum of 128 bits of entropy.'
                'Got: {length} characters', {
                    'length': len(value), 'minimum_length': 16
                })

        return value

    @field_validator('client_id')
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        """
        Validate client_id field value.
        """
        if not value:
            raise AuthCodeGrantConfigClientIDFieldError('value_missing',
                                                        'client_id is required for OAuth 2.0 authentication')

        # Check for whitespace
        if len(value.strip()) != len(value):
            raise AuthCodeGrantConfigClientIDFieldError('whitespace_found',
                                                        'client_id cannot have leading or trailing whitespace')

        return value

    @field_validator('scopes')
    @classmethod
    def validate_scope(cls, value: list[str]) -> list[str]:
        """
        Validate scope field value.
        """
        if not value:
            raise AuthCodeGrantConfigScopeFieldError('value_missing', 'At least one scope is required')

        # Check for empty scope
        empty_scopes = [scope for scope in value if not scope]
        if empty_scopes:
            raise AuthCodeGrantConfigScopeFieldError('value_empty',
                                                     'Scopes cannot be empty', {'empty_scopes': empty_scopes})

        # Check for whitespace
        whitespace_scopes = [scope for scope in value if scope and not scope.strip()]
        if whitespace_scopes:
            raise AuthCodeGrantConfigScopeFieldError('whitespace_found',
                                                     'Scopes cannot contain only whitespace',
                                                     {'whitespace_scopes': whitespace_scopes})

        # Check for overly broad or dangerous scopes
        dangerous_scopes = {'*', 'all', 'root', 'admin', 'superuser'}
        found_dangerous = set(value) & dangerous_scopes
        if found_dangerous:
            raise AuthCodeGrantConfigScopeFieldError(
                'value_too_broad',
                'Overly broad scopes detected. Follow principle of least privilege.'
                'Dangerous scopes: {dangerous_scopes}', {'dangerous_scopes': list(found_dangerous)})

        # Check for duplicate scopes
        if len(value) != len(set(value)):
            duplicates = [scope for scope in set(value) if value.count(scope) > 1]
            raise AuthCodeGrantConfigScopeFieldError('duplicate_found',
                                                     'Duplicate scope found: {duplicates}', {'duplicates': duplicates})

        return value
