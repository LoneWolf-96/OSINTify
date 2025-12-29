from library.shared.HTTPClient import HTTPClient
import os 

class Shodan:
    def __init__(self, value: str):
        self.value = value.strip()
        self._base_url = "https://api.shodan.io/"
        SHO_API_KEY = os.getenv("SHO_API_KEY")

        if not SHO_API_KEY:
            raise RuntimeError("SHO_API_KEY environment variable not set")
        else:
            self.key = SHO_API_KEY

        self.is_known()

    def is_known(self) -> bool:
        webClient = HTTPClient(base_url=self._base_url)
        try:
            self.data = webClient.request(method="GET",
                               endpoint=f"shodan/host/{self.value}",
                               params={"key": self.key})
            return True
        except:
            return False
    
    def exposed_ports(self) -> list: # pyright: ignore[reportUnknownParameterType]
        if not self.data:
            return []

        # Convert Response -> dict
        json_data = self.data.json()
        port_list = json_data.get("ports", [])
        # Safely access "ports"
        if (len(port_list) >=6):
            return ["< 6 ports"]
        else:
            return json_data.get("ports", [])
