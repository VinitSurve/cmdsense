"""Allow ``python -m cmdsense``."""

import sys

from cmdsense.cli import main

if __name__ == "__main__":
    sys.exit(main())
