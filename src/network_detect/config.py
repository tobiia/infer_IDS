from pathlib import Path
from dataclasses import dataclass

@dataclass
class Config:
    PROJECT_ROOT = Path(__file__).parent
    # CONFIG_DIR = PROJECT_ROOT / "config"
    # SETTINGS_FILE = CONFIG_DIR / "settings.json"
    GUI_DIR = PROJECT_ROOT / "gui"
    TRAIN_DIR = PROJECT_ROOT / "training"
    RUNS_DIR = PROJECT_ROOT / "runs"
    SETUP_DIR = PROJECT_ROOT / "setup"
    
    # REVIEW delete this once file dialog done
    PCAP_PATH = Path.home() / "network_detect" / "data" / "botnet.pcap"