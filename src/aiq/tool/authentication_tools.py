# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

import logging

from pydantic import Field

from aiq.authentication.interfaces import AuthenticationClientBase
from aiq.builder.builder import Builder
from aiq.builder.function_info import FunctionInfo
from aiq.cli.register_workflow import register_function
from aiq.data_models.authentication import AuthResult
from aiq.data_models.authentication import HTTPMethod
from aiq.data_models.authentication import HTTPResponse
from aiq.data_models.component_ref import AuthenticationRef
from aiq.data_models.function import FunctionBaseConfig
from aiq.tool.authenticated_request import make_authenticated_request

logger = logging.getLogger(__name__)


class AuthTool(FunctionBaseConfig, name="auth_tool"):
    """Authenticate to any registered API provider using OAuth2 authorization flow with browser consent handling."""
    auth_provider: AuthenticationRef = Field(description="Reference to the authentication provider "
                                             "to use for authentication.")


@register_function(config_type=AuthTool)
async def auth_tool(config: AuthTool, builder: Builder):
    """
    Uses HTTP Basic authentication to authenticate to any registered API provider.
    """
    basic_auth_client: AuthenticationClientBase = await builder.get_authentication(config.auth_provider)

    async def _arun(user_id: str) -> AuthResult:
        try:
            # Perform authentication (this will invoke the user authentication callback)
            auth_context: AuthResult = await basic_auth_client.authenticate(user_id=user_id)

            if not auth_context or not auth_context.credentials:
                raise RuntimeError(f"Failed to authenticate user: {user_id}: Invalid credentials")

            return auth_context

        except Exception as e:
            logger.exception("HTTP Basic authentication failed", exc_info=True)
            raise RuntimeError(f"HTTP Basic authentication for '{user_id}' failed: {str(e)}")

    yield FunctionInfo.from_fn(_arun, description="Perform authentication with a given user ID.")


class AuthenticatedRequestTool(FunctionBaseConfig, name="authenticated_request_tool"):
    """Make authenticated HTTP requests using an authentication provider."""
    auth_provider: AuthenticationRef = Field(description="Reference to the authentication provider "
                                             "to use for authentication.")
    url: str = Field(description="URL to make the request to")
    method: str | HTTPMethod = Field(default=HTTPMethod.GET, description="Default HTTP method")
    headers: str | dict | None = Field(default=None, description="Default headers")
    params: str | dict | None = Field(default=None, description="Default query parameters")
    body_data: str | dict | None = Field(default=None, description="Default request body")
    timeout: int = Field(default=30, description="Default timeout in seconds for HTTP requests")
    user_id: str = Field(default="default", description="Default user ID to use for authentication")


@register_function(config_type=AuthenticatedRequestTool)
async def authenticated_request_tool(config: AuthenticatedRequestTool, builder: Builder):
    """
    Makes authenticated HTTP requests using the configured authentication provider.
    """
    auth_client: AuthenticationClientBase = await builder.get_authentication(config.auth_provider)

    async def _arun(user_id: str) -> str:
        try:
            # Make the authenticated request using the standalone function
            response: HTTPResponse = await make_authenticated_request(url=config.url,
                                                                      auth_client=auth_client,
                                                                      method=config.method,
                                                                      headers=config.headers,
                                                                      params=config.params,
                                                                      body_data=config.body_data,
                                                                      user_id=config.user_id,
                                                                      timeout=config.timeout)

            # Convert HTTPResponse to JSON string for agent compatibility
            return response.model_dump_json(indent=2)

        except Exception as e:
            logger.exception("Authenticated request failed", exc_info=True)
            return f"Authenticated request failed: {str(e)}"

    yield FunctionInfo.from_fn(_arun,
                               description="Make authenticated HTTP requests using the configured auth provider. "
                               "Automatically handles authentication, credential refresh, and applies proper "
                               "authentication headers/parameters to requests.")
