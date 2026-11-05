#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from reconmancer.core.projects import create_project


HOME = Path("/opt/reconmancer")


def main():

    parser = argparse.ArgumentParser(description=("Create a Reconmancer project"))

    parser.add_argument(
        "name",
        help="Human-readable project name",
    )

    parser.add_argument(
        "slug",
        help="Directory-safe project identifier",
    )

    parser.add_argument(
        "--disk-limit",
        type=float,
        default=10.0,
        help="Project disk limit in GB",
    )

    args = parser.parse_args()

    project = create_project(
        home=HOME,
        name=args.name,
        slug=args.slug,
        disk_limit_gb=args.disk_limit,
    )

    print()
    print("Reconmancer project created")
    print("============================")
    print()
    print(f"Name: {args.name}")
    print(f"Slug: {args.slug}")
    print(f"Path: {project}")
    print()


if __name__ == "__main__":
    main()
