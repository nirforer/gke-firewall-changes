"""Output helpers for terminal status messages."""

import sys


class Colors:
    def __init__(self, enabled: bool):
        if enabled:
            self.RED = "\033[0;31m"
            self.YELLOW = "\033[1;33m"
            self.GREEN = "\033[0;32m"
            self.CYAN = "\033[0;36m"
            self.BOLD = "\033[1m"
            self.NC = "\033[0m"
        else:
            self.RED = self.YELLOW = self.GREEN = self.CYAN = self.BOLD = self.NC = ""


# Module-level state, set by main()
C = Colors(enabled=False)
VERBOSE = False


def status(msg: str):
    print(f"  {msg}", file=sys.stderr)


def detail(msg: str):
    if VERBOSE:
        print(f"  {msg}", file=sys.stderr)


def progress_error(msg: str):
    print(f"  {C.YELLOW}! {msg}{C.NC}", file=sys.stderr)
