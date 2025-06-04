import os
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
                redirect_uri: str,
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
        self.redirect_uri = redirect_uri
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
                
            # Replace all tokens
            html_content = template.replace("{{MCP_SERVER_NAME}}", self.mcp_server_name)
            html_content = html_content.replace("{{APPLICATION_NAME}}", self.application_name)
            html_content = html_content.replace("{{APPLICATION_WEBSITE}}", self.application_website)
            html_content = html_content.replace("{{APPLICATION_ID}}", self.application_id)
            html_content = html_content.replace("{{REDIRECT_URI}}", self.redirect_uri)
            html_content = html_content.replace("{{SCOPES}}", self.scopes)
            html_content = html_content.replace("{{AUTHORIZATION_CODE}}", self.authorization_code)
            html_content = html_content.replace("{{STATE}}", self.state)

            max_age = (int(time.time()) + 2592000)   # Default to 30 days
            cookie_generator = ConsentCookieGenerator(
                application_id=self.application_id,
                redirect_uri=self.redirect_uri,
                scopes=self.scopes,
                authorization_code=self.authorization_code,
                state=self.state,               
                auth_key=self.hashing_util._key,
                cookie_max_age=max_age
            )

            cookie_value = cookie_generator.generate_cookie()
            html_content = html_content.replace("{{COOKIE_DATA}}", f"{ConsentCookieReader.CONSENT_COOKIE_NAME}={cookie_value}; path=/; max-age={max_age}") #expired in 30 days
            
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


# Example usage:
if __name__ == "__main__":
    consent = ConsentDialog(
        mcp_server_name="Mini MCP Server",
        application_name="claudeai",
        application_id="85de8714-cfd3-40c6-bec0-130b588d280e",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        scopes="User.Read",
        authorization_code="AUTH_CODE_12345",
        state="STATE_67890"
    )
    
    # Get the HTML as a string
    html = consent.generate_html()
    print("HTML generated successfully!")
    
    # Or save to a file
    # consent.save_html("output_consent_dialog.html")