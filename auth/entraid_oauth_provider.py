import httpx
import time
import logging
from typing import Optional
import secrets
import urllib.parse
from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    AuthorizationParams,
    AuthorizationCode,
    RefreshToken,
    AccessToken,
    OAuthClientInformationFull,
    OAuthToken,    
    AuthorizeError,
    TokenError, 
    construct_redirect_uri
)
from pydantic import AnyHttpUrl

from auth.auth_utilities import generate_code_challenge, generate_code_verifier, Scope

logger = logging.getLogger(__name__)

class EntraIDOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, redirect_uri: str, scope: Scope = Scope("user.read")):
        logger.debug("EntraIDOAuthProvider.__init__ called")        
        self.tenant_id = tenant_id
        self.client_id = client_id        
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.authority = f"https://login.microsoftonline.com/{tenant_id}/"
        self.token_endpoint = f"{self.authority}/oauth2/v2.0/token"
        self.authorization_endpoint = f"{self.authority}/oauth2/v2.0/authorize"
        self.scope = scope
        # You may want to use a persistent store for these in production        
        self.clients: dict[str, OAuthClientInformationFull] = {} # in-memory store for client information
        #todo: none of these in-memory stores are persistent, they are just for testing
        # No expiration or cleanup logic is implemented here
        self.state_mapping: dict[str, dict[str, str]] = {}
        self.AUTHORIZATION_CODES = {} #Temp store for authorization codes to used by MCP clients performing the authorization code flow
        self.ENTRAID_TOKENS = {} # Temp store for tokens received from Entra ID (Capable of accessing Azure resources)
        self.TOKEN_MAPPING = {} # Temp store for mapping Entra ID tokens to MCP tokens (MCP Clients (like agents) can use these tokens to access the MCP Server)
        self.TOKENS = {} # Temp store for MCP tokens (MCP Clients can use these tokens to access the MCP Server)

    # This method is not a part of the OAuthAuthorizationServerProvider OAuth2 flow
    def get_entra_id_token(self, token: str) -> Optional[OAuthToken]:        
        # Retrieve the Entra ID token from the mapping
        return self.TOKEN_MAPPING.get(token)
    
    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        logger.debug("EntraIDOAuthProvider.get_client called")
        return self.clients.get(client_id)
    
    # This method is not a part of the OAuthAuthorizationServerProvider OAuth2 flow
    def get_client_info_from_state(self, state: str) -> dict[str, str]:
        client_id = self.state_mapping.get(state, {}).get("client_id")
        redirect_uri = self.state_mapping.get(state, {}).get("redirect_uri")
        
        if not client_id or not redirect_uri:
            # Log the error and raise an exception
            logger.error(f"Invalid state parameter: {state}, client_id: {client_id}, redirect_uri: {redirect_uri}")        
            raise ValueError("Invalid state parameter")
        
        logger.debug(f"Client ID found for state {state}: {client_id}")        
        return {
            "client_id": client_id,
            "redirect_uri": redirect_uri}
            

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        logger.debug("EntraIDOAuthProvider.register_client called")
        # Register a new client in the in-memory store, does not register with Entra ID
        if client_info.client_id in self.clients:
            raise ValueError("Client already registered")
        self.clients[client_info.client_id] = client_info
        logger.info(f"Client {client_info.client_id} registered with redirect URIs: {client_info.redirect_uris}")
        

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        logger.debug("EntraIDOAuthProvider.authorize called")
        # if state is not provided, generate a new state
        if not params.state:
            params.state = secrets.token_urlsafe(16)
        # Store the state mapping
        state = params.state
        if not state:
            raise AuthorizeError(error="invalid_request", error_description="Missing state parameter")

        # Generate a code verifier and challenge
        code_verifier = generate_code_verifier() # Though one was already provided, we generate a new one for the redirect to Entra ID. This allows us to use our private code_verifier for the token exchange later.
        code_challenge = generate_code_challenge(code_verifier)        
        #store original request from client to relay in last step of exchange
        self.state_mapping[params.state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge, #original from client
            "code_verifier": code_verifier, # internally generated, needed for delegated token exchange later
            "redirect_uri_provided_explicitly": True,
            "client_id": client.client_id,
        }

        # Construct the Azure Entra ID authorization URL
        query = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": self.scope.as_string(),
            "state": params.state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        
        url = f"{self.authorization_endpoint}?{urllib.parse.urlencode(query)}"        
        return url

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> Optional[AuthorizationCode]:
        logger.debug("EntraIDOAuthProvider.load_authorization_code called")
        # In production, retrieve from persistent store
        return self.AUTHORIZATION_CODES.get(authorization_code)       
              

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        logger.debug("EntraIDOAuthProvider.exchange_authorization_code called")
        if authorization_code.code not in self.AUTHORIZATION_CODES:
            raise ValueError("Invalid authorization code")        

        # Use authorization code to get tokens
        entra_token = self.ENTRAID_TOKENS[f"{authorization_code.code}{authorization_code.client_id}{authorization_code.code_challenge}"]
        
        #raise error if token is expired or missing
        if not entra_token:
            logger.error("Entra ID token not found")
            raise TokenError(error="invalid_grant", error_description="Invalid or expired token")
        if entra_token.expires_in < time.time():
            logger.error("Entra ID token expired")
            raise TokenError(error="invalid_grant", error_description="Token expired")
        
        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.TOKENS[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )        

        self.TOKEN_MAPPING[mcp_token] = entra_token
        del self.AUTHORIZATION_CODES[authorization_code.code]        
        # Return the MCP token
        return OAuthToken(
            access_token=mcp_token,
            refresh_token="",
            expires_in=self.TOKENS[mcp_token].expires_at,
            token_type="bearer",
            scope=Scope.from_list(authorization_code.scopes).as_string(), #may need to be adjusted, Is this the correct scope?
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> Optional[RefreshToken]:
        logger.debug("EntraIDOAuthProvider.load_refresh_token called")
        raise NotImplementedError("TODO: Implement loading refresh token from persistent store")

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        logger.debug("EntraIDOAuthProvider.exchange_refresh_token called")
        raise NotImplementedError("TODO: Implement exchange refresh token for new access token")

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        logger.debug("EntraIDOAuthProvider.load_access_token called")
        return self.TOKENS.get(token)                

    async def revoke_token(self, token):
        logger.debug("EntraIDOAuthProvider.revoke_token called")
        # Remove from in-memory store (in production, revoke in DB or with Azure if possible)
        self.TOKEN_MAPPING.pop(token, None)
        self.ENTRAID_TOKENS.pop(token, None)

      

    async def handle_callback(self, code: str, state: str):
        logger.debug("EntraIDOAuthProvider.handle_callback called")
        # Retrieve state data from mapping
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise Exception("Invalid state parameter")  # Replace with HTTPException if needed
        

        #exchange code for tokens
        # In production, validate the code and state
        # with Azure and store the tokens securely

        data = {
            "client_id": self.client_id,
            "scope": self.scope.as_string(),
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
            "client_secret": self.client_secret,
            "code_verifier": state_data["code_verifier"],  # PKCE: code_verifier, internally generated uring authorize redirect          
        }

        async with httpx.AsyncClient() as client_http:            
            resp = await client_http.post(self.token_endpoint, data=data)            
            if resp.status_code != 200:
                logger.error(f"Token error response: {resp.text}")
                raise TokenError(error="invalid_grant", error_description=resp.text)
            token_data = resp.json()            
        
        access_token = AccessToken(
            token=token_data["access_token"],
            client_id=self.client_id,
            scopes=self.scope.as_list(),
            expires_at=int(time.time()) + token_data.get("expires_in", 3600),
        )
        refresh_token = RefreshToken(
            token=token_data.get("refresh_token", ""),
            client_id=self.client_id,
            scopes=self.scope.as_list(),
            expires_at=None,
        )


        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = (
            state_data["redirect_uri_provided_explicitly"] == True
        )
        client_id = state_data["client_id"]

        # Create MCP authorization code
        new_code = f"mcp_{secrets.token_hex(16)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=self.scope.as_list(),
            code_challenge=code_challenge,
        )
        self.AUTHORIZATION_CODES[new_code] = auth_code        
        self.ENTRAID_TOKENS[f"{new_code}{client_id}{code_challenge}"] = OAuthToken(
            access_token=access_token.token,
            refresh_token=refresh_token.token,
            expires_in= int(time.time()) + int(token_data.get("expires_in")),
            token_type=token_data.get("token_type").lower(),
            scope=token_data.get("scope", ""),
        )

        #remove state from mapping
        # This is a simple cleanup; in production, consider using a more robust method
        # to manage state (e.g., expiration, database storage)
        del self.state_mapping[state]
        # Return extracted data for further processing or debugging
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)
