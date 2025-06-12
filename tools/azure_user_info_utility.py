"""Accepts a bearertoken and returns the user information from Azure AD."""

import requests
from typing import Dict, Optional
import logging


class EntraUserInfo:
    """Class to retrieve user information from Microsoft Entra ID using bearer token."""

    def __init__(self, bearer_token: str):
        """
        Initialize with bearer token.

        Args:
            bearer_token (str): The Entra ID bearer token
        """
        self.bearer_token = bearer_token
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }
        self.logger = logging.getLogger(__name__)

    def get_current_user(self) -> Optional[Dict]:
        """
        Retrieve current user information from Entra ID.

        Returns:
            Dict: User information including displayName, userPrincipalName, etc.
            None: If request fails
        """
        try:
            response = requests.get(f"{self.base_url}/me", headers=self.headers, timeout=30)

            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(
                    f"Failed to get user info. Status: {response.status_code}, Response: {response.text}"
                )
                return None

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {str(e)}")
            return None

    def get_user_name(self) -> Optional[str]:
        """
        Get the display name of the current user.

        Returns:
            str: User's display name
            None: If request fails or name not found
        """
        user_info = self.get_current_user()
        if user_info:
            return user_info.get("displayName")
        return None

    def get_user_email(self) -> Optional[str]:
        """
        Get the email/UPN of the current user.

        Returns:
            str: User's email/userPrincipalName
            None: If request fails or email not found
        """
        user_info = self.get_current_user()
        if user_info:
            return user_info.get("userPrincipalName") or user_info.get("mail")
        return None


# Example usage
# if __name__ == "__main__":
#     # Example usage (replace with actual token)
#     token = "your_bearer_token_here"
#     user_info_client = EntraUserInfo(token)

#     # Get user name
#     name = user_info_client.get_user_name()
#     print(f"User name: {name}")

#     # Get full user info
#     full_info = user_info_client.get_current_user()
#     if full_info:
#         print(f"Full user info: {full_info}")
