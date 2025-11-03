from setup import zeek, features, windows
from pathlib import Path
from config import Config
from pprint import pprint

def main():
    # file dialog to get pcap
    #pcap_path = Path(Config.PCAP_PATH).resolve()
    #run_id = zeek.process_pcap(pcap_path)
    run_id = "220126_100532"
    flows, dns_events_by_host = features.parse_run(run_id)
    pprint("------------------------------ FLOWS -----------------------------")
    pprint(flows["CFDem7iuzfUF0fXve"])
    pprint("------------------------------ EVENTS -----------------------------")
    #pprint(dns_events_by_host["10.0.0.182"])
    pprint("------------------------------ WINDOWS -----------------------------")
    windows_dict = windows.create_windows(flows)
    pprint(windows_dict[0])


if __name__ == "__main__":
    main()