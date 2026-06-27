#!/usr/bin/env python3
"""Start the Security Audit Tool."""

import sys
from audit_tool import main


if __name__ == "__main__":
    if len(sys.argv) == 1:
        from gui import launch_gui

        raise SystemExit(launch_gui())
    raise SystemExit(main())
