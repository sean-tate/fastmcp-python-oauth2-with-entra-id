# Auth related imports
from urllib.parse import urlparse
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response, HTMLResponse
from mcp.server.auth.settings import  AuthSettings, ClientRegistrationOptions
from mcp.server.auth.middleware.auth_context import get_access_token

from auth.auth_utilities import ConsentCookieReader, HashSignatureUtility, Scope
from auth.consent_dialog import ConsentDialog
from auth.entraid_auth_settings import EntraIdAuthSettings
from auth.entraid_oauth_provider import EntraIDOAuthProvider
#end auth related imports

from fastmcp import FastMCP
import logging

from tools.azure_user_info_utility import EntraUserInfo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
auth_settings = EntraIdAuthSettings()
target_scope = Scope("user.read")
hashing_util = HashSignatureUtility(auth_settings.auth_hash_key)
entra_auth = EntraIDOAuthProvider(
    tenant_id=auth_settings.auth_tenant_id,
    client_id=auth_settings.auth_client_id,    
    client_secret=auth_settings.auth_client_secret,
    redirect_uri=auth_settings.auth_redirect_uri,
    scope=target_scope,    
)


mcp = FastMCP("azure_user_mcp_server", auth_server_provider=entra_auth, auth=AuthSettings(
         issuer_url="http://localhost:8000",
           client_registration_options=ClientRegistrationOptions(enabled=True)
            ))


@mcp.custom_route("/auth/consent", methods=["GET"])
async def consent_handler(request: Request) -> Response:    
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or not state:
        raise HTTPException(400, "Missing code, or state parameter")

    mcp_client_redirect_info = entra_auth.get_client_info_from_state(state)
    client_id = mcp_client_redirect_info.get("client_id") if mcp_client_redirect_info else None
    redirect_uri = mcp_client_redirect_info.get("redirect_uri") if mcp_client_redirect_info else None
    client_metadata = await entra_auth.get_client(client_id) if client_id else None

    if not client_id or not redirect_uri or not client_metadata:
        raise HTTPException(400, "Invalid client metadata")
    
    consent = ConsentDialog(
        mcp_server_name=mcp.name,
        application_name=client_metadata.client_name if client_metadata else "Unknown Application",
        application_website=urlparse(redirect_uri).netloc,
        application_id=client_id,
        server_redirect_uri=auth_settings.auth_redirect_uri,
        client_redirect_uri=redirect_uri,
        scopes=target_scope.as_string(),
        authorization_code=code,
        state=state,
        auth_key=auth_settings.auth_hash_key
    )

    return HTMLResponse(
        content=consent.generate_html(),
        media_type="text/html"
    )


@mcp.custom_route("/auth/callback", methods=["GET"])
async def callback_handler(request: Request) -> Response:    
    """Handle Entra Id OAuth callback."""
    logger.debug("Callback handler called")
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or not state:
        raise HTTPException(400, "Missing code or state parameter")

    try:
        #check for consent cookie
        consent_coookie_data = ConsentCookieReader.get_consent_from_request(request.headers, 
                                                     auth_key=auth_settings.auth_hash_key)        
        
        is_valid_constent_cookie = False

        if consent_coookie_data:
            # Validate the consent cookie
            client_metadata = entra_auth.get_client_info_from_state(state)            
            # Check if consent cookie contains the application ID, redirect URI, scopes, authorization code, and state and that they match the request parameters
            is_valid_constent_cookie = (
                consent_coookie_data.get("application_id") == client_metadata.get("client_id") and
                consent_coookie_data.get("redirect_uri") == client_metadata.get("redirect_uri") and
                consent_coookie_data.get("scopes") == target_scope.as_string()                
            )

        if not is_valid_constent_cookie:
            logger.info("Consent cookie not found, redirecting to consent page")
            # Redirect to consent page
            redirect_uri = f"/auth/consent?code={code}&state={state}"
            return RedirectResponse(status_code=302, url=redirect_uri)
        else:
            logger.info("Consent cookie found, proceeding with callback handling")
            redirect_uri = await entra_auth.handle_callback(code, state)        
            return RedirectResponse(status_code=302, url=redirect_uri)   
         
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": f"Unexpected error, {e}",
            },
        )

@mcp.tool()
def get_user_name() -> str:
    """this is a tool to get my user name from the Entra ID."""
    try:
        # Get the access token from the MCP server for current authenticated user
        mcp_server_access_token = get_access_token()
        # Use the Entra ID OAuth provider to get the Entra ID access token          
        entra_id_access_token = entra_auth.get_entra_id_token(mcp_server_access_token.token)        
        if not entra_id_access_token:
            raise Exception("Failed to get Entra ID access token")

        userInfo = EntraUserInfo(bearer_token=entra_id_access_token.access_token)
        user_name = userInfo.get_user_name()
        if user_name:
            return f"User name is {user_name}"
        else:
            return "User name not found"
    except Exception as e:
        logger.error(f"Error getting user name: {e}")
        return "Error getting user name"


if __name__ == "__main__":
    logger.info("Starting MCP server...")
    mcp.run(transport="sse")
