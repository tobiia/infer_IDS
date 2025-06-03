# we are going to get the pcap into flows
# using zeek
# we can filter for specific protocols: 

# iterate over every row, inserting them into the database

import os
import subprocess
import sys

import os
import sys
import shutil
from pathlib import Path


def get_zeek_path(process_name = "zeek"):
    if sys.platform.startswith("win"):
        raise RuntimeError("This resolver is for Linux/macOS only. Use WSL for Zeek on Windows.")

    # PATH lookup
    found = shutil.which(process_name)
    if found:
        return str(Path(found).resolve())

    # fallbacks
    candidates = [
        Path("/opt/zeek/bin") / process_name,       # linux
        Path("/usr/local/bin") / process_name,      # homebrew/manual installs
        Path("/usr/bin") / process_name,
        Path("/usr/sbin") / process_name,
        Path("/opt/homebrew/bin") / process_name,   # Apple Silicon Homebrew
        Path("/usr/local/sbin") / process_name,
    ]

    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK): # access = executable
            return str(p.resolve()) # path = path.replace("\\", "/") if win?

    raise FileNotFoundError(
        "Could not find Zeek executable. Install Zeek and ensure `zeek` is on PATH, "
        "or set ZEEK_PATH=/full/path/to/zeek."
    )