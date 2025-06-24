import base64
import hashlib
import os
import secrets
import json
import time


def generate_code_verifier():
    """Generate a cryptographically random code verifier."""
    return secrets.token_urlsafe(64)  # Generates a URL-safe random string


def generate_code_challenge(code_verifier):
    """Generate the code challenge using SHA-256 encoding."""
    sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode()


class Scope:
    """Class to represent a set of scopes."""

    def __init__(self, scopes: str):
        """
        :param scopes: Space-separated string of scopes (e.g., "user.read email profile")
        """
        self._scopes_str = scopes.strip()

    def as_string(self) -> str:
        """Return the scopes as a space-separated string."""
        return self._scopes_str

    def as_list(self) -> list[str]:
        """Return the scopes as a list of strings."""
        return self._scopes_str.split() if self._scopes_str else []

    @staticmethod
    def from_list(scopes_list: list[str]) -> str:
        """Return a space-separated string from a list of scopes."""
        return Scope(" ".join(scopes_list or []))

    def __repr__(self):
        return f"Scope(scopes={self._scopes_str!r})"

class HashSignatureUtility:
    """Class to generate one-way hash digests from a key and dictionary."""
    
    def __init__(self, key: str):
        """
        Initialize with a string key for hashing.
        
        :param key: String to use as a salt/key in the hash generation
        """
        self._key = key
    
    def generate_hash(self, data_dict: dict) -> str:
        """
        Generate a one-way hash digest using the key as a salt and provided dictionary.
        
        :param data_dict: Dictionary to hash
        :return: URL-safe base64 encoded hash digest
        """
        # Convert dictionary to a sorted JSON string for consistent hashing
        serialized_data = json.dumps(data_dict, sort_keys=True)
        
        # Create a hash object and update it with the key first (as a salt)
        hash_obj = hashlib.sha256()
        hash_obj.update(self._key.encode())
        
        # Then update with the serialized data
        hash_obj.update(serialized_data.encode())
        
        # Get the digest
        hash_digest = hash_obj.digest()
        
        # Return URL-safe base64 encoded hash (with padding removed)
        return base64.urlsafe_b64encode(hash_digest).rstrip(b'=').decode()
    
    def verify_hash(self, data_dict: dict, hash_to_verify: str) -> bool:
        """
        Verify if the provided dictionary matches the given hash.
        
        :param data_dict: Dictionary to check against the hash
        :param hash_to_verify: Hash string to verify against
        :return: True if the dictionary generates the same hash, False otherwise
        """
        # Generate hash from the provided dictionary        
        computed_hash = self.generate_hash(data_dict)        
        
        # Compare the computed hash with the provided hash
        return computed_hash == hash_to_verify
    
    def __repr__(self):
        return f"HashGenerator(key={self._key!r})"
    

class ConsentCookieGenerator:
    """Class to generate a consent cookie."""
    
    def __init__(self):
        """Initialize the ConsentCookieGenerator."""
        pass

    @staticmethod
    def generate_cookie(application_id: str, 
                       redirect_uri: str, 
                       scopes: str, 
                       cookie_max_age: int, 
                       auth_key: str = None) -> str:
        """
        Generate a consent cookie string.
        
        :param application_id: ID of the application
        :param redirect_uri: URI to redirect after consent
        :param scopes: Scopes requested by the application
        :param authorization_code: Authorization code for OAuth flow
        :param state: State parameter for OAuth flow
        :param cookie_max_age: Max age of the cookie in seconds
        :param auth_key: Authentication key for hashing
        :return: Consent cookie string
        """
        # Create a dictionary with the consent data
        consent_data = {
            "application_id": application_id,
            "redirect_uri": redirect_uri,
            "scopes": scopes,
            "expires_on": cookie_max_age
        }
        
        hashing_util = HashSignatureUtility(auth_key)
        signature = hashing_util.generate_hash(consent_data)
        consent_data['signature'] = signature
        # Convert to JSON and encode as base64
        consent_json = json.dumps(consent_data)
        return base64.urlsafe_b64encode(consent_json.encode()).decode()


class ConsentCookieReader:
    """Class to read and parse consent cookies from requests."""
    
    CONSENT_COOKIE_NAME = "mcp_oauth_consent"  # Default name for the consent cookie
    
    @staticmethod
    def extract_cookies(headers: dict) -> dict:
        """
        Extract cookies from request headers.
        
        :param headers: Dictionary containing request headers
        :return: Dictionary of cookies (name: value)
        """
        cookies = {}
        cookie_header = headers.get('cookie', '')
        
        if not cookie_header:
            return cookies
            
        cookie_parts = cookie_header.split(';')
        for part in cookie_parts:
            if '=' in part:
                name, value = part.strip().split('=', 1)
                cookies[name] = value
                
        return cookies
    
    @staticmethod
    def parse_consent_cookie(cookie_value: str) -> dict:
        """
        Parse the consent cookie value.
        
        :param cookie_value: Base64 encoded cookie value
        :return: Dictionary containing the consent data
        """
        try:
            # Decode base64 to get JSON string
            decoded_bytes = base64.urlsafe_b64decode(cookie_value + '=' * (4 - len(cookie_value) % 4))
            consent_json = decoded_bytes.decode('utf-8')
            
            # Parse JSON to get dictionary
            consent_data = json.loads(consent_json)            
            return consent_data
        except Exception as e:
            # Return empty dict if parsing fails
            return {}
    
    @staticmethod
    def is_consent_cookie_valid(consent_data: dict, auth_key: str) -> bool:
        """
        Check if the consent cookie is valid and not expired.
        
        :param consent_data: Dictionary containing the consent data
        :return: True if valid, False otherwise
        """
        if not consent_data:
            return False
            
        # Check if required fields exist
        required_fields = ['application_id', 'redirect_uri', 'scopes', 'expires_on', 'signature']
                         
        if not all(field in consent_data for field in required_fields):            
            return False
        
        # Verify the signature
        hashing_util = HashSignatureUtility(auth_key)
        consent_data_copy = consent_data.copy()
        consent_data_copy.pop('signature', None)
        if not hashing_util.verify_hash(consent_data_copy, consent_data['signature']):            
            return False
            
        # Check if expired
        current_time = int(time.time())        
        expires_on = consent_data.get('expires_on', 0)                      
        return current_time < expires_on
    
    @classmethod
    def get_consent_from_request(cls, headers: dict, auth_key:str, cookie_name: str = None) -> dict:
        """
        Get and parse the consent cookie from request headers.
        
        :param headers: Dictionary containing request headers
        :param cookie_name: Optional custom cookie name
        :return: Dictionary containing the consent data or empty dict if not found/valid
        """
        cookie_name = cookie_name or cls.CONSENT_COOKIE_NAME
        cookies = cls.extract_cookies(headers)
        
        if cookie_name not in cookies:            
            return {}
            
        consent_data = cls.parse_consent_cookie(cookies[cookie_name])
        
        if not cls.is_consent_cookie_valid(consent_data, auth_key=auth_key):            
            return {}
            
        return consent_data
