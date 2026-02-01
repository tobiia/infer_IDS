import json
from pathlib import Path
from typing import Dict, Tuple
import pandas as pd

from utils import iter_log
from .base_connection import Connection
from .dns_connection import DNSConnection
from .tls_connection import TLSConnection

class ParseLogs:
    def __init__(self):
        self.connections: Dict[str, Connection] = {}
        self.dns_connections: Dict[str, Connection] = {}
        self.tls_connections: Dict[str, Connection] = {}

    def parse_logs(self, log_direct: Path) -> Tuple[Dict[str, Connection], Dict[str, Connection]]:
        try:
            self.connections.clear()
            self.dns_connections.clear()
            self.tls_connections.clear()
            
            conn_path = log_direct / "conn.log"
            self._add_conn_info(conn_path)

            # append DNS info
            dns_path = log_direct / "dns.log"
            if dns_path.exists():
                self._add_dns_info(dns_path)
            
            # append tls info
            tls_path = log_direct / "ssl.log"
            if tls_path.exists():
                self._add_tls_info(tls_path)
            
            return self.dns_connections, self.tls_connections
        except Exception as e:
            print(f"Error parsing pcap: {e}")
            raise e
    
    def parse_dns_logs(self, log_direct: Path) -> Dict[str, Connection]:
        self.connections.clear()
        self.dns_connections.clear()

        conn_path = log_direct / "conn.log"
        self._add_conn_info(conn_path)

        #FIXME - replace with error
        dns_path = log_direct / "dns.log"
        if dns_path.exists():
            self._add_dns_info(dns_path)

        return self.dns_connections

    def parse_tls_logs(self, log_direct: Path) -> Dict[str, Connection]:
        self.connections.clear()
        self.tls_connections.clear()
        
        conn_path = log_direct / "conn.log"
        self._add_conn_info(conn_path)

        tls_path = log_direct / "ssl.log"
        if tls_path.exists():
            self._add_tls_info(tls_path)
        
        return self.tls_connections
    
    def _add_conn_info(self, conn_path: Path) -> None:
        for record in iter_log(conn_path):
            conn = Connection.from_zeek_record(record)
            if conn:
                self.connections[conn.uid] = conn
    
    def _add_dns_info(self, dns_path: Path) -> None:
        for record in iter_log(dns_path):
            conn_uid = record.get("uid", "")
            if conn_uid and conn_uid in self.connections.keys():
                conn = self.connections[conn_uid]
                dns_conn = DNSConnection.from_dns_record(record, conn)
                if dns_conn:
                    self.dns_connections[dns_conn.uuid] = dns_conn
    
    def _add_tls_info(self, tls_path: Path) -> None:
        for record in iter_log(tls_path):
            conn_uid = record.get("uid", "")
            if conn_uid and conn_uid in self.connections.keys():
                conn = self.connections[conn_uid]
                tls_conn = TLSConnection.parse_tls_record(record, conn)
                if tls_conn:
                    self.tls_connections[tls_conn.uuid] = tls_conn
    
    def to_dataframe(self, conn_dict: Dict[str, Connection]) -> pd.DataFrame:
        rows = []
        
        for connection in conn_dict.values():
            row = {
                "uuid": connection.uuid,
                "uid": connection.uid,
                "ts": connection.ts,
                "ts_iso": connection.ts_iso,
                "duration": connection.duration,
                "proto": connection.proto,
                "orig_h": connection.orig_h,
                "resp_h": connection.resp_h,
                "orig_p": connection.orig_p,
                "resp_p": connection.resp_p,
                "orig_bytes": connection.orig_bytes,
                "resp_bytes": connection.resp_bytes,
                "orig_pkts": connection.orig_pkts,
                "resp_pkts": connection.resp_pkts,
                "missed_bytes": connection.missed_bytes,
                "service": connection.service,
                "has_dns": connection.has_dns,
                "has_tls": connection.has_tls,
                "label": connection.label,
                
                "flow_bytes_per_sec": connection.flow_bytes_per_sec,
                "pkts_per_sec": connection.pkts_per_sec,
                "pkt_ratio": connection.pkt_ratio,
                "approx_fwd_pkt_len_mean": connection.approx_fwd_pkt_len_mean,
                "approx_bwd_pkt_len_mean": connection.approx_bwd_pkt_len_mean,
            }
            
            # dns feats if available -- not incl list features
            if isinstance(connection, DNSConnection):
                row.update({
                    "uuid": connection.uuid,
                    "query": connection.query,
                    "qclass": connection.qclass,
                    "qtype": connection.qtype,
                    "rcode": connection.rcode,
                    "rejected": connection.rejected,
                    "answers": json.dumps(connection.answers),
                    "ttls": json.dumps(connection.ttls),
                    
                    "q_len": connection.q_len,
                    "q_tld": connection.q_tld,
                    "q_max_subd_len": connection.q_max_subd_len,
                    "q_min_subd_len": connection.q_min_subd_len,
                    "q_entropy": connection.q_entropy,
                    "q_num_levels": connection.q_num_levels,
                    "q_dig_ratio": connection.q_dig_ratio,
                    "q_consec_conso_ratio": connection.q_consec_conso_ratio,
                    "q_alternate_ratio": connection.q_alternate_ratio,
                    "q_conse_digits_ratio": connection.q_conse_digits_ratio,

                    "num_ans": connection.num_ans,
                    "ans_len_mean": connection.ans_len_mean,
                    "ans_entropy_mean": connection.ans_entropy_mean,
                    "ttl_mean": connection.ttl_mean,
                })
            
            # tls feats not incl list
            if isinstance(connection, TLSConnection):
                row.update({
                    "uuid": connection.uuid,
                    "version": connection.version,
                    "cipher": connection.cipher,
                    "server_name": connection.server_name,
                    "resumed": connection.resumed,
                    "established": connection.established,
                    "ssl_history": connection.ssl_history,
                    "ja4": connection.ja4,
                    "ja4s": connection.ja4s,
                    "cert_chain_fps": json.dumps(connection.cert_chain_fps),
                    "client_ciphers": json.dumps(connection.client_ciphers),
                    "ssl_client_exts": json.dumps(connection.ssl_client_exts),
                    "ssl_server_exts": json.dumps(connection.ssl_server_exts),
                    
                    "num_cli_exts": connection.num_cli_exts,
                    "num_srv_exts": connection.num_srv_exts,
                    "num_certs": connection.num_certs,
                    
                    "weak_cipher": connection.weak_cipher,
                })
            
            rows.append(row)

        return pd.DataFrame(rows)