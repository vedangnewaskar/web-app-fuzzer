import asyncio

from fuzzer.core.http_client import HTTPClient


async def main():

    client = HTTPClient()

    result = await client.request(
        "GET",
        "http://127.0.0.1:8000/"
    )

    print("URL:", result.url)
    print("Method:", result.method)
    print("Status:", result.status_code)
    print("Length:", result.response_length)
    print("Time:", result.response_time)
    print("Headers:", result.headers)


asyncio.run(main())