"""Argument parsing for `python -m fuzzer`."""
import argparse


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fuzzer",
        description="Web application fuzzer / directory & traversal scanner.",
    )
    parser.add_argument("--target", help="Target base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--mode", choices=["dirs", "traversal"], help="Scan mode")
    parser.add_argument("--config", help="Path to YAML config file", default=None)
    parser.add_argument("--wordlist", help="Override the directories wordlist path")
    parser.add_argument("--output", help="Override the output JSON path")
    parser.add_argument("--concurrency", type=int, help="Max concurrent requests")
    parser.add_argument("--recursive", action="store_true", help="Recursively fuzz discovered directories (Module 6)")
    parser.add_argument("--max-depth", type=int, help="Max recursion depth when --recursive is set")
    parser.add_argument("--mutate", action="store_true", help="Generate filename mutations of confident file findings (Module 3)")
    return parser
