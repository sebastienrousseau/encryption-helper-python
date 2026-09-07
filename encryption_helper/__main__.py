"""Entry point for ``python -m encryption_helper``.

All behaviour lives in :mod:`encryption_helper.cli`; this module only wires the
process exit status to the command's return code.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
