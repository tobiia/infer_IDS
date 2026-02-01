from pathlib import Path
from dataclasses import dataclass

@dataclass
class Config:
    PROJECT_ROOT = Path(__file__).parent
    MODEL_DIR = PROJECT_ROOT / "models"
    SETUP_DIR = PROJECT_ROOT / "setup"
    DATA_DIR  = PROJECT_ROOT.parent.parent / "data"
    CONFIG_DIR = Path.home() / ".infer-ids"
    
    # REVIEW delete this once file dialog done
    # figure out alternative to tkinter b/c it's not a package nor default on linux
    PCAP_PATH = Path.home() / "infer_ids" / "data" / "infected.pcap"