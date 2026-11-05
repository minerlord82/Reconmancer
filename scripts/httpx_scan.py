#!/usr/bin/env python3

from __future__ import annotations

import argparse

from reconmancer.engines.httpx.runner import (
    run_httpx,
)


def main():

    parser = argparse.ArgumentParser(description=("Run Reconmancer HTTPX recon"))

    parser.add_argument(
        "project",
        help="Reconmancer project slug",
    )

    parser.add_argument(
        "--rate-limit",
        type=int,
        default=10,
    )

    parser.add_argument(
        "--redirect-depth",
        type=int,
        default=10,
    )

    args = parser.parse_args()

    print()
    print("Reconmancer HTTPX")
    print("=================")
    print()

    print(f"Project: {args.project}")

    print(f"Rate limit: {args.rate_limit}/sec")

    print(f"Redirect depth: {args.redirect_depth}")

    print()

    run_id = run_httpx(
        args.project,
        rate_limit=args.rate_limit,
        max_redirect_depth=(args.redirect_depth),
    )

    print()
    print(f"Finished: {run_id}")


if __name__ == "__main__":
    main()
