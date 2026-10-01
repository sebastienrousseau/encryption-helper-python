# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Entry point for ``python -m encryption_helper_mcp``."""

from __future__ import annotations

from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
