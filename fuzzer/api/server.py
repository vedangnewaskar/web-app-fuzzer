"""
Minimal HTTP API so the React frontend can trigger scans and read results.

Built on aiohttp.web — aiohttp is already a project dependency (used by
HTTPClient), so this adds zero new dependencies. Not a rewrite of the
scan engine: this module only adapts run_directory_scan /
run_traversal_scan to HTTP requests and shapes the JSON response as
{"results": [...]}, matching what reporting/logger.py already produces.

Run with:  python -m fuzzer.api.server
"""
import asyncio
from dataclasses import asdict

from aiohttp import web

from fuzzer.config.loader import load_config
from fuzzer.core.http_client import HTTPClient
from fuzzer.discovery.calibration import calibrate
from fuzzer.discovery.directories import run_directory_scan
from fuzzer.discovery.mutations import run_mutation_scan
from fuzzer.discovery.recursion import run_recursive_scan
from fuzzer.discovery.traversal import run_traversal_scan

routes = web.RouteTableDef()


async def _maybe_mutate(target: str, results, client: HTTPClient, config: dict, body: dict, concurrency: int):
    """Shared by both scan branches below: Module 3 is a second-wave
    pass over whatever the first pass (recursive or flat) found."""
    if not body.get("mutate", False):
        return results
    mutation_results = await run_mutation_scan(
        target, results, client=client, concurrency=concurrency,
        confidence_threshold=config["mutation"]["confidence_threshold"],
        max_mutations_per_result=config["mutation"]["max_mutations_per_result"],
        max_total_requests=config["mutation"]["max_total_requests"],
        weights=config["scoring"]["weights"], thresholds=config["scoring"]["thresholds"],
        years=config["mutation"]["years"],
    )
    return results + mutation_results


@routes.post("/api/scan")
async def scan_handler(request: web.Request) -> web.Response:
    body = await request.json()
    target = body.get("target")
    if not target:
        return web.json_response({"error": "target is required"}, status=400)

    mode = body.get("mode", "dirs")
    config = load_config()
    concurrency = body.get("concurrency", config["scan"]["threads"])

    client = HTTPClient(
        timeout=config["scan"]["timeout"],
        follow_redirects=config["scan"]["follow_redirects"],
    )

    if mode == "traversal":
        param = body.get("param", "file")
        results = await run_traversal_scan(
            target, param=param, client=client, concurrency=concurrency,
            confidence_by_confirmation=config["traversal"]["confidence_by_confirmation"],
        )
        return web.json_response({"results": [asdict(r) for r in results]})

    wordlist = body.get("wordlist", config["wordlists"]["directories"])

    if body.get("recursive", False):
        results = await run_recursive_scan(
            target, wordlist, client=client, concurrency=concurrency,
            max_depth=body.get("max_depth", config["recursion"]["max_depth"]),
            recurse_confidence_threshold=config["recursion"]["recurse_confidence_threshold"],
            max_total_requests=config["recursion"]["max_total_requests"],
            weights=config["scoring"]["weights"], thresholds=config["scoring"]["thresholds"],
        )
        results = await _maybe_mutate(target, results, client, config, body, concurrency)
        return web.json_response({"results": [asdict(r) for r in results]})

    baseline = await calibrate(
        target,
        client=client,
        probe_count=config["calibration"]["probe_count"],
        length_tolerance=config["calibration"]["length_tolerance"],
    )
    results = await run_directory_scan(
        target, wordlist, client=client, concurrency=concurrency,
        baseline=baseline, auto_calibrate=False,
        weights=config["scoring"]["weights"], thresholds=config["scoring"]["thresholds"],
    )
    results = await _maybe_mutate(target, results, client, config, body, concurrency)

    # "calibration" is a sibling key, not folded into individual results,
    # so existing frontend code reading only `data.results` is unaffected.
    return web.json_response({
        "results": [asdict(r) for r in results],
        "calibration": {
            "classification": baseline.classification,
            "is_consistent": baseline.is_consistent,
            "status_code": baseline.status_code,
            "length": baseline.length,
        },
    })


@routes.get("/api/health")
async def health_handler(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def _cors_middleware_factory():
    @web.middleware
    async def cors_middleware(request: web.Request, handler):
        if request.method == "OPTIONS":
            response = web.Response()
        else:
            response = await handler(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response
    return cors_middleware


def create_app() -> web.Application:
    app = web.Application(middlewares=[_cors_middleware_factory()])
    app.add_routes(routes)
    # Preflight OPTIONS for the frontend dev server (different port).
    app.router.add_route("OPTIONS", "/api/scan", lambda r: web.Response())
    return app


def main() -> None:
    app = create_app()
    web.run_app(app, host="127.0.0.1", port=8080)


if __name__ == "__main__":
    main()
