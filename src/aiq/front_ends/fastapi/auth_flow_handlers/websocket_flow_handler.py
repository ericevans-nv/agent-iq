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

import asyncio
from dataclasses import dataclass
from dataclasses import field

import pkce
from authlib.integrations.httpx_client import AsyncOAuth2Client

from aiq.authentication.interfaces import FlowHandlerBase
from aiq.authentication.oauth2.authorization_code_flow_config import OAuth2AuthorizationCodeFlowConfig
from aiq.authentication.oauth2.respone_manager import ResponseManager
from aiq.data_models.authentication import AuthenticatedContext
from aiq.data_models.authentication import AuthFlowType
from aiq.data_models.interactive import _HumanPromptOAuthConsent
from aiq.front_ends.fastapi.fastapi_front_end_controller import _FastApiFrontEndController


@dataclass
class Auth_Code_Cred:
    event: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    access_token: dict | None = None
    expires: int | None = None
    token_type: str | None = None
    refresh_token: str | None = None
    error: Exception | None = None
    challenge: str | None = None
    verifier: str | None = None


class WebSocketAuthenticationFlowHandler(FlowHandlerBase):
    _flows: dict[str, Auth_Code_Cred] = {}
    _configs: dict[str, OAuth2AuthorizationCodeFlowConfig] = {}
    _oauth_client: dict[str, AsyncOAuth2Client] = {}
    _server_controller: _FastApiFrontEndController | None = None
    _server_lock: asyncio.Lock = asyncio.Lock()
    _active_flows: int = 0
    web_socket = None

    @staticmethod
    async def authenticate(config: OAuth2AuthorizationCodeFlowConfig, method: AuthFlowType) -> AuthenticatedContext:
        if method == AuthFlowType.OAUTH2_AUTHORIZATION_CODE:
            return await WebSocketAuthenticationFlowHandler._handle_oauth2_auth_code_flow(config)

        raise NotImplementedError(f"Authentication method '{method}' is not supported by the websocket frontend.")

    @staticmethod
    async def _handle_oauth2_auth_code_flow(config: OAuth2AuthorizationCodeFlowConfig) -> AuthenticatedContext:
        import httpx

        oauth_credentials = Auth_Code_Cred()

        client = AsyncOAuth2Client(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=config.redirect_uri,
            token_endpoint_auth_method="none" if config.use_pkce else "client_secret_post",
            scope=" ".join(config.scopes) if config.scopes else None,
            token_endpoint=config.token_url,
            code_challenge_method='S256' if config.use_pkce else None,
        )

        if config.use_pkce:
            verifier, challenge = pkce.generate_pkce_pair()
            oauth_credentials.verifier = verifier
            oauth_credentials.challenge = challenge

        authorization_url, state = client.create_authorization_url(
            url=config.authorization_url,
            response_type=config.response_type or "code",
            audience=config.audience,
            prompt=config.prompt or "consent",
            access_type=config.access_type,  # optional
            code_verifier=oauth_credentials.verifier if config.use_pkce else None,
            code_challenge=oauth_credentials.challenge if config.use_pkce else None,
            code_challenge_method="S256" if config.use_pkce else None,
            extra_params=config.extra_authorization_params or {}
        )

        async with WebSocketAuthenticationFlowHandler._server_lock:
            WebSocketAuthenticationFlowHandler._active_flows += 1
            WebSocketAuthenticationFlowHandler._flows[state] = oauth_credentials
            WebSocketAuthenticationFlowHandler._configs[state] = config
            WebSocketAuthenticationFlowHandler._oauth_client[state] = client

        if WebSocketAuthenticationFlowHandler.web_socket is None:
            raise RuntimeError("WebSocket instance is not available for handling authentication.")

        # Initiates the OAuth 2.0 Authorization Code Grant flow by sending the authorization request.
        async with httpx.AsyncClient() as client:
            response = await client.get(authorization_url, timeout=10.0)

        # Handles the response from the authorization request.
        if response.status_code != 302:
            await ResponseManager().process_http_response(response)
        else:
            redirect_location_header: str | None = response.headers.get("Location")
            await WebSocketAuthenticationFlowHandler.web_socket.message_handler.create_websocket_message(
                _HumanPromptOAuthConsent(text=redirect_location_header))

        try:
            await asyncio.wait_for(oauth_credentials.event.wait(), timeout=300)
        except asyncio.TimeoutError as e:
            raise RuntimeError("Authentication flow timed out after 5 minutes.") from e
        finally:
            async with WebSocketAuthenticationFlowHandler._server_lock:
                if state in WebSocketAuthenticationFlowHandler._flows:
                    del WebSocketAuthenticationFlowHandler._flows[state]
                WebSocketAuthenticationFlowHandler._active_flows -= 1

        if oauth_credentials.error:
            raise RuntimeError(f"Authentication failed: {oauth_credentials.error}") from oauth_credentials.error

        if not oauth_credentials.access_token:
            raise RuntimeError("Authentication failed: Did not receive token.")

        return AuthenticatedContext(
            metadata={
                "access_token": oauth_credentials.access_token,
                "token_type": oauth_credentials.token_type,
                "expires": oauth_credentials.expires,
                "refresh_token": oauth_credentials.refresh_token
            })
