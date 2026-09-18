"""
CLI entry point: `python -m fuzzer --target http://127.0.0.1:8000 --mode dirs`

Wires together: config -> HTTPClient -> discovery scan -> reporting output.
This is the same pipeline the API server (fuzzer/api/server.py) drives, so
CLI and API stay behaviorally consistent.
"""
import asyncio

from fuzzer.cli.parser import build_arg_parser
from fuzzer.config.loader import load_config
from fuzzer.core.http_client import HTTPClient
from fuzzer.discovery.calibration import calibrate
from fuzzer.discovery.directories import run_directory_scan
from fuzzer.discovery.mutations import run_mutation_scan
from fuzzer.discovery.recursion import run_recursive_scan
from fuzzer.discovery.traversal import run_traversal_scan
from fuzzer.reporting.logger import print_summary, save_results


async def run(args) -> None:
    config = load_config(args.config)

    target = args.target or config["target"]["url"]
    mode = args.mode or config["scan"]["mode"]
    concurrency = args.concurrency or config["scan"]["threads"]
    wordlist = args.wordlist or config["wordlists"]["directories"]
    output_path = args.output or config["output"]["file"]

    client = HTTPClient(
        timeout=config["scan"]["timeout"],
        follow_redirects=config["scan"]["follow_redirects"],
    )

    if mode == "traversal":
        results = await run_traversal_scan(
            target, client=client, concurrency=concurrency,
            confidence_by_confirmation=config["traversal"]["confidence_by_confirmation"],
        )
    elif args.recursive:
        results = await run_recursive_scan(
            target, wordlist, client=client, concurrency=concurrency,
            max_depth=args.max_depth or config["recursion"]["max_depth"],
            recurse_confidence_threshold=config["recursion"]["recurse_confidence_threshold"],
            max_total_requests=config["recursion"]["max_total_requests"],
            weights=config["scoring"]["weights"], thresholds=config["scoring"]["thresholds"],
        )
    else:
        baseline = await calibrate(
            target,
            client=client,
            probe_count=config["calibration"]["probe_count"],
            length_tolerance=config["calibration"]["length_tolerance"],
        )
        print(f"[calibration] {baseline.classification} "
              f"(status={baseline.status_code}, length~{baseline.length}, consistent={baseline.is_consistent})\n")
        results = await run_directory_scan(
            target, wordlist, client=client, concurrency=concurrency,
            baseline=baseline, auto_calibrate=False,
            weights=config["scoring"]["weights"], thresholds=config["scoring"]["thresholds"],
        )

    if mode != "traversal" and args.mutate:
        mutation_results = await run_mutation_scan(
            target, results, client=client, concurrency=concurrency,
            confidence_threshold=config["mutation"]["confidence_threshold"],
            max_mutations_per_result=config["mutation"]["max_mutations_per_result"],
            max_total_requests=config["mutation"]["max_total_requests"],
            weights=config["scoring"]["weights"], thresholds=config["scoring"]["thresholds"],
            years=config["mutation"]["years"],
        )
        if mutation_results:
            print(f"[mutation] {len(mutation_results)} mutated paths tried\n")
        results = results + mutation_results

    print_summary(results)
    save_results(results, output_path)


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
