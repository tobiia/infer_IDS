from setup import zeek, features
from pathlib import Path
from config import Config
import pprint

def main():
    # file dialog to get pcap
    #pcap_path = Path(Config.PCAP_PATH).resolve()
    #run_id = zeek.process_pcap(pcap_path)
    run_id = "220126_100532"
    flows, dns_events_by_host = features.parse_run(run_id)
    print("------------------------------ FLOWS -----------------------------")
    print(flows["CFDem7iuzfUF0fXve"])
    print("------------------------------ EVENTS -----------------------------")
    #print(dns_events_by_host)


if __name__ == "__main__":
    main()