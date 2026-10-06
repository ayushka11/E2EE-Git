#!/usr/bin/env python3

from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal SGitLine learning client")
    parser.add_argument("command", choices=["status", "init"])
    parser.add_argument("--dir", default=".")
    args = parser.parse_args()
    print(f"{args.command} {args.dir}")


if __name__ == "__main__":
    main()
