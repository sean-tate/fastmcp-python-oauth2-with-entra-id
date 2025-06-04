import os
import re
import time

from auth.auth_utilities import ConsentCookieGenerator, ConsentCookieReader, HashSignatureUtility


class ConsentDialog:
    """
    Class to generate consent dialog HTML by replacing tokens in the template file.
    """
    def __init__(self, 
                mcp_server_name: str,
                application_name: str,
                application_website: str,
                application_id: str,
                server_redirect_uri: str,
                client_redirect_uri: str,
                scopes: str,
                authorization_code: str,
                state: str,
                auth_key: str = None):
        """
        Initialize the ConsentDialog with values to replace tokens in the HTML template.
        
        Args:
            mcp_server_name: Name of the MCP server
            application_name: Name of the application requesting access
            application_id: ID of the application
            redirect_uri: URI to redirect after consent
            scopes: Scopes requested by the application
            authorization_code: Authorization code for OAuth flow
            state: State parameter for OAuth flow
        """
        self.mcp_server_name = mcp_server_name
        self.application_name = application_name
        self.application_website = application_website
        self.application_id = application_id
        self.server_redirect_uri = server_redirect_uri
        self.client_redirect_uri = client_redirect_uri
        self.scopes = scopes
        self.authorization_code = authorization_code
        self.state = state                
        self.hashing_util = HashSignatureUtility(auth_key)
        
        # Get the template file path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.template_path = os.path.join(current_dir, "html", "consent_dialog_page.html")
        
    def generate_html(self) -> str:
        """
        Generate the HTML content by replacing all tokens in the template.
        
        Returns:
            str: The HTML content with all tokens replaced
        """
        try:
            with open(self.template_path, "r") as file:
                template = file.read()

            # Generate the consent cookie
            max_age = (int(time.time()) + 2592000)   # Default to 30 days
            
            cookie_generator = ConsentCookieGenerator(
                application_id=self.application_id,
                redirect_uri=self.client_redirect_uri,
                scopes=self.scopes,
                authorization_code=self.authorization_code,
                state=self.state,               
                auth_key=self.hashing_util._key,
                cookie_max_age=max_age
            )

            cookie_value = cookie_generator.generate_cookie()
            # Replace all tokens in a single pass
            replacements = {
                "{{MCP_SERVER_NAME}}": self.mcp_server_name,
                "{{APPLICATION_NAME}}": self.application_name,
                "{{APPLICATION_WEBSITE}}": self.application_website,
                "{{APPLICATION_ID}}": self.application_id,
                "{{CLIENT_REDIRECT_URI}}": self.client_redirect_uri,
                "{{SERVER_REDIRECT_URI}}": self.server_redirect_uri,
                "{{REDIRECT_URI}}": self.client_redirect_uri,
                "{{SCOPES}}": self.scopes,
                "{{AUTHORIZATION_CODE}}": self.authorization_code,
                "{{STATE}}": self.state,
                "{{COOKIE_DATA}}": f"{ConsentCookieReader.CONSENT_COOKIE_NAME}={cookie_value}; path=/; max-age={max_age}" #expires in 30 days
            }

            # Create regex pattern that matches any of the tokens
            pattern = re.compile('|'.join(re.escape(key) for key in replacements.keys()))
            # Replace all tokens in a single pass
            html_content = pattern.sub(lambda match: replacements[match.group(0)], template)
            return html_content
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Template file not found at {self.template_path}")
        except Exception as e:
            raise Exception(f"Error generating consent dialog HTML: {str(e)}")
    
    def save_html(self, output_path: str) -> None:
        """
        Generate the HTML and save it to the specified path.
        
        Args:
            output_path: Path where to save the generated HTML
        """
        html_content = self.generate_html()
        
        with open(output_path, "w") as file:
            file.write(html_content)
