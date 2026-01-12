import os
import sys
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List
from config import Config


def get_path(process_name: str = "zeek") -> Path:
    if sys.platform.startswith("win"):
        raise RuntimeError("This resolver is for Linux/macOS only. Use WSL for Zeek on Windows.")

    # PATH lookup
    found = shutil.which(process_name)
    if found:
        return Path(found).resolve()

    # fallbacks
    candidates = [
        Path("/opt/zeek/bin") / process_name,       # linux
        Path("/usr/local/bin") / process_name,      # homebrew/manual installs
        Path("/usr/bin") / process_name,
        Path("/usr/sbin") / process_name,
        Path("/opt/homebrew/bin") / process_name,   # apple silicon Homebrew
        Path("/usr/local/sbin") / process_name,
    ]

    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK): # access = executable
            return p.resolve()

    raise FileNotFoundError(
        "Could not find Zeek executable. Install Zeek and ensure `zeek` is on PATH"
    )

def run(args: List[str], out_dir: Path) -> Path | None:
    try:
        output = subprocess.run(args,
                                    cwd=out_dir,
                                    capture_output=True,
                                    text=True,
                                    check=True)
        return out_dir
    except subprocess.CalledProcessError as e:
        print(f"Zeek command could not be ran")
        print(e.stderr)
    return None

def generate_logs(pcap_path: Path) -> Path | None:
    now = datetime.now().strftime("%d%m%y_%H%M%S")
    out_dir = Config.RUNS_DIR / now
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir = out_dir.resolve()

    args = [
        str(get_path()),
        "-b",
        "-r",
        str(pcap_path),
        str(Config.SETUP_DIR / "filter.zeek")
    ]
    return run(args, out_dir)


def process_file(file_path: Path) -> Path | None:
    return generate_logs(file_path)
