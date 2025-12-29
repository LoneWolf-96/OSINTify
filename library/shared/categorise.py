import ipaddress
import re

from library.tools.shodan import Shodan
from library.tools.virusTotal import VirusTotal

class Categorise:
    _hash_patterns = {
        "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
        "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
        "SHA224": re.compile(r"^[a-fA-F0-9]{56}$"),
        "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
        "SHA384": re.compile(r"^[a-fA-F0-9]{96}$"),
        "SHA512": re.compile(r"^[a-fA-F0-9]{128}$"),
    }

    def __init__(self, value: str):
        self.value = value.strip()
        self.type = None
        self.detail = None

        self.categorise()

    def categorise(self) -> None:
        """Determine the type of IOC."""
        if self.is_ipv4():
            self.type = "IP"
            self.classify_ipv4()
        elif self.is_hash():
            self.type = "HASH"
            self.virusTotal = VirusTotal(self.value, type="HASH")
        else:
            self.type = "unknown"
    
    def is_hash(self) -> str | bool:
        for name, pattern in self._hash_patterns.items():
            if pattern.fullmatch(self.value):
                self.detail = name
                return True
        return False

    def is_ipv4(self) -> bool:
        try:
            ipaddress.IPv4Address(self.value)
            return True
        except ValueError:
            return False

    def classify_ipv4(self):
        ip = ipaddress.IPv4Address(self.value)

        if ip.is_loopback:
            self.detail = "loopback"
            self.virusTotal = None
            self.shodan = None
        elif ip.is_private:
            self.detail = "private"
            self.virusTotal = None
            self.shodan = None
        elif ip.is_link_local:
            self.detail = "link-local"
            self.shodan = None
            self.virusTotal = None
        elif ip.is_multicast:
            self.detail = "multicast"
            self.shodan = None
            self.virusTotal = None
        elif ip.is_reserved:
            self.ipv4_detailtype = "reserved"
            self.shodan = None
            self.virusTotal = None
        elif ip.is_unspecified:
            self.detail = "unspecified"
            self.shodan = None
            self.virusTotal = None
        elif ip.is_global:
            self.detail = "public"
            self.virusTotal = VirusTotal(self.value, type="IP")
            self.shodan = Shodan(self.value)
        else:
            self.detail = "unknown"
