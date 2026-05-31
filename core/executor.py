import httpx


class RequestExecutor:
    def __init__(self, timeout: int = 120, max_retries: int = 2):
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout, connect=30.0),
                follow_redirects=True,
            )
        return self._client

    def execute(self, request_kwargs: dict) -> httpx.Response:
        client = self._get_client()
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                response = client.request(**request_kwargs)
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code < 500:
                    raise
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_error = e

        raise last_error

    def execute_stream(self, request_kwargs: dict) -> httpx.Response:
        client = self._client or self._get_client()
        request_kwargs.setdefault("method", "POST")
        request = client.build_request(**request_kwargs)
        return client.send(request, stream=True)

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
