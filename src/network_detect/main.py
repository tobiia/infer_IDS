from setup.zeek import process_pcap
from parse.parse_log import ParseLogs
from pathlib import Path
from config import Config
from pprint import pprint

def main():
    # file dialog to get pcap
    pcap_path = Path(Config.PCAP_PATH).resolve()
    #run_id = process_pcap(pcap_path)
    run_id = "280126_030631"
    parser = ParseLogs()
    dns_connections, ssl_connections = parser.parse_logs(run_id)
    dns_rows = parser.to_dataframe(dns_connections)
    ssl_rows = parser.to_dataframe(ssl_connections)
    pprint("------------------------------ FLOWS -----------------------------")
    pprint(dns_rows.head(1))
    pprint(ssl_rows.head(1))



    pprint("------------------------------ EVENTS -----------------------------")
    #pprint(dns_events_by_host["10.0.0.182"])
    pprint("------------------------------ WINDOWS -----------------------------")
    #windows_dict = windows.create_windows(flows)


if __name__ == "__main__":
    main()