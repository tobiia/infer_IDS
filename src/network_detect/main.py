from setup import zeek
from pathlib import Path
from config import Config

def main():
    # file dialog to get pcap
    pcap_path = Path(Config.PCAP_PATH).resolve()
    zeek.process_pcap(pcap_path)


if __name__ == "__main__":
    main()