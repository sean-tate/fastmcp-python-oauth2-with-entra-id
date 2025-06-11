import base64
import hashlib
import secrets


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
