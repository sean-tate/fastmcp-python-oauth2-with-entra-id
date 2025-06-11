# Auth related imports
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.auth.middleware.auth_context import get_access_token

from auth.auth_utilities import Scope
from auth.entraid_auth_settings import EntraIdAuthSettings
from auth.entraid_oauth_provider import EntraIDOAuthProvider

# end auth related imports

from fastmcp import FastMCP
import logging

from tools.azure_user_info_utility import EntraUserInfo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
auth_settings = EntraIdAuthSettings()
target_scope = Scope("user.read")
entra_auth = EntraIDOAuthProvider(
    tenant_id=auth_settings.auth_tenant_id,
    client_id=auth_settings.auth_client_id,
    redirect_uri=auth_settings.auth_redirect_uri,
    scope=target_scope,
)

mcp = FastMCP(
    "azure_user_mcp_server",
    auth_server_provider=entra_auth,
    auth=AuthSettings(
        issuer_url="http://localhost:8000",
        client_registration_options=ClientRegistrationOptions(enabled=True),
    ),
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
        redirect_uri = await entra_auth.handle_callback(code, state)
        print(f"Redirect URI: {redirect_uri}")
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
