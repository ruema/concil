#!/usr/bin/env python3
import logging
import os
import sys

from concil.run import join


def main():
    if len(sys.argv) <= 1:
        print("Usage: concil_join.py pid args")
        return
    args = sys.argv[1:]
    if args[0] == "--debug":
        logging.basicConfig(level=logging.DEBUG)
        args = args[1:]
    else:
        logging.basicConfig(level=logging.WARNING)

    pid = args[0]
    join(int(pid), args[1:])


if __name__ == "__main__":
    main()
