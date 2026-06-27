#!/usr/bin/env python3
"""Compatibility launcher for Java_RMiJmx_Exposure_Scanner.py."""

import runpy
from pathlib import Path


if __name__ == "__main__":
    runpy.run_path(
        str(Path(__file__).with_name("Java_RMiJmx_Exposure_Scanner.py")),
        run_name="__main__",
    )
