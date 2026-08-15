import time

import aiohttp

from fuzzer.core.models import HTTPResult


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

                return HTTPResult(
                    url=url,
                    method=method,
                    status_code=response.status,
                    response_length=len(body),
                    response_time=end_time - start_time,
                    headers=dict(response.headers)
                )