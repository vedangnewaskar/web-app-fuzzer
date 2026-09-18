import time

import aiohttp

from fuzzer.core.models import BODY_SNIPPET_LIMIT, HTTPResult


class HTTPClient:

    def __init__(self, timeout=10, follow_redirects=True):
        self.timeout = timeout
        self.follow_redirects = follow_redirects

    async def request(self, method, url):

        timeout = aiohttp.ClientTimeout(
            total=self.timeout
        )

        async with aiohttp.ClientSession(
            timeout=timeout
        ) as session:

            start_time = time.perf_counter()

            async with session.request(
                method,
                url,
                allow_redirects=self.follow_redirects
            ) as response:

                body = await response.read()

                end_time = time.perf_counter()

                # Decoded snippet only, for keyword/signature checks downstream
                # (calibration, confidence scoring, traversal confirmation).
                # Never stored past BODY_SNIPPET_LIMIT chars, and decoding
                # failures fall back to an empty snippet rather than crashing
                # the scan.
                try:
                    body_snippet = body[:BODY_SNIPPET_LIMIT].decode(
                        response.get_encoding() if hasattr(response, "get_encoding") else "utf-8",
                        errors="ignore",
                    )
                except (LookupError, UnicodeDecodeError):
                    body_snippet = body[:BODY_SNIPPET_LIMIT].decode("utf-8", errors="ignore")

                return HTTPResult(
                    url=url,
                    method=method,
                    status_code=response.status,
                    response_length=len(body),
                    response_time=end_time - start_time,
                    headers=dict(response.headers),
                    body_snippet=body_snippet,
                    resolved_url=str(response.url),
                    location_header=response.headers.get("Location"),
                )