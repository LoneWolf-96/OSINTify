import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    def __init__(
        self,
        base_url: str | None = None,
        headers: dict | None = None,
        timeout: int = 10,
        retries: int = 3,
        backoff_factor: float = 0.5,
        verify_ssl: bool = True,
        proxies: dict | None = None,
    ):
        self.base_url = base_url.rstrip("/") if base_url else None
        self.timeout = timeout

        self.session = requests.Session()
        self.session.verify = verify_ssl

        if headers:
            self.session.headers.update(headers)

        if proxies:
            self.session.proxies.update(proxies)

        retry_strategy = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _build_url(self, endpoint: str) -> str:
        if endpoint.startswith("http"):
            return endpoint
        if not self.base_url:
            raise ValueError("No base_url set and endpoint is not absolute")
        return f"{self.base_url}/{endpoint.lstrip('/')}"

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        json: dict | None = None,
        headers: dict | None = None,
    ) -> requests.Response:
        url = self._build_url(endpoint)

        response = self.session.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            timeout=self.timeout,
        )

        response.raise_for_status()
        return response

    # Convenience methods
    def get(self, endpoint: str, **kwargs) -> requests.Response:
        return self.request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs) -> requests.Response:
        return self.request("POST", endpoint, **kwargs)

    def put(self, endpoint: str, **kwargs) -> requests.Response:
        return self.request("PUT", endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs) -> requests.Response:
        return self.request("DELETE", endpoint, **kwargs)

    def close(self):
        self.session.close()
