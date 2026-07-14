#!/usr/bin/env python3
"""Backwards-compatible entry point: ``python3 adwshound.py …``"""
import sys
from adwshound.cli import main

if __name__ == "__main__":
    sys.exit(main())
