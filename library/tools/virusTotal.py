from library.shared.HTTPClient import HTTPClient
import os

class VirusTotal:
    """Wrapper for VirusTotal API to retrieve IP-related information."""
    def __init__(self, value: str):
        self.value = value.strip()
        self.base_url = "https://www.virustotal.com/api/v3"
        VT_API_KEY = os.getenv("VT_API_KEY")

        if not VT_API_KEY:
            raise RuntimeError("VT_API_KEY environment variable not set")
        else:
            self.api_key = VT_API_KEY

        self.data = None        # Raw Response object
        self._json_data = None  # Parsed JSON
        self.fetch()

    def fetch(self) -> bool:
        """
        Fetch IP data from VirusTotal API.
        Returns True if successful, False on failure.
        """
        client = HTTPClient(base_url=self.base_url, headers={
            "accept": "application/json",
            "x-apikey": self.api_key
        })

        try:
            self.data = client.get(f"/ip_addresses/{self.value}")
            self._json_data = self.data.json()
            return True
        except Exception:
            self.data = None
            self._json_data = None
            return False

    def _get_attr(self, *keys, default=None):
        """
        Helper method to safely traverse nested JSON attributes.
        """
        d = self._json_data or {}
        for key in keys:
            d = d.get(key, {})
        return d or default

    def asn(self) -> str | None:
        """Return the ASN attribute, or None if missing."""
        return self._get_attr("data", "attributes", "asn")
    

    def owner(self) -> str | None:
        """Return the country attribute, or None if missing."""
        if not self.data:
            return None 
        
        # Safely traverse the nested dictionary 
        return ( 
            self._get_attr("data", "attributes", "as_owner") )



    def country(self) -> str | None:
        """Return the country attribute, or None if missing."""
        if not self.data:
            return None 
        
        # Safely traverse the nested dictionary 
        return ( 
            self._json_data.get("data", {}).get("attributes", {}).get("country") )

    def score(self) -> str:
        """Return the malicious/harmless votes as 'malicious/suspicious/harmless' string."""
        malicious = self._get_attr("data", "attributes", "last_analysis_stats", "malicious", default="-")
        suspicious = self._get_attr("data", "attributes", "last_analysis_stats", "suspicious", default="-")
        harmless = self._get_attr("data", "attributes", "last_analysis_stats", "harmless", default="-")
        return f"{malicious}/{suspicious}/{harmless}"
