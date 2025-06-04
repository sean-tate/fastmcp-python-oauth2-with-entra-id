import secrets
from pydantic_settings import BaseSettings
from typing import Any, ClassVar

class EntraIdAuthSettings(BaseSettings):
    """
    For this to work, you need an .env file in the root of the project with the following variables:     
    AUTH_TENANT_ID=your-tenant-id
    AUTH_CLIENT_ID=your-client-id
    (Optional) AUTH_AUTHORITY=login.microsoftonline.com
    """

    auth_authority: str = "login.microsoftonline.com"  # AZURE_CHINA = "login.chinacloudapi.cn", AZURE_GERMANY = "login.microsoftonline.de", AZURE_GOVERNMENT = "login.microsoftonline.us", AZURE_PUBLIC_CLOUD = "login.microsoftonline.com" 
    auth_tenant_id: str  
    auth_client_id: str 
    auth_client_secret: str = ""  # This should be set in the environment or .env file   
    auth_redirect_uri: str = "http://localhost:8000/auth/callback"  # This should be the redirect URI of your this MCP server  
    auth_hash_key: str = secrets.token_hex(32)  #  WARNING: This should be set in the environment or .env file, otherwise it will generate a new key every time the server starts, which is not suitable for production use.   
    AUTH_VERSION: ClassVar[str] = "v2.0"    
    
    class Config:
        env_file = ".env"
        extra = "ignore"