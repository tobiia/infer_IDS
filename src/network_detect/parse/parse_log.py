import json
from pathlib import Path
from typing import Dict, Iterator, Tuple
import pandas as pd

from config import Config
from .connect import Connection
from .dns_connection import DNSConnection
from .ssl_connection import SSLConnection

class ParseLogs:
    def __init__(self):
        self.connections: Dict[str, Connection] = {}
        self.dns_connections: Dict[str, Connection] = {}
        self.ssl_connections: Dict[str, Connection] = {}
    
    def iter_json(self, path: Path) -> Iterator[dict]:
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    yield json.loads(line)
        except FileNotFoundError:
            return
    
    def parse_logs(self, run_id: str) -> Tuple[Dict[str, Connection], Dict[str, Connection]]:

        run_path = Path(Config.RUNS_DIR) / run_id
        
        self.connections.clear()
        
        conn_path = run_path / "conn.log"
        self._parse_conn_log(conn_path)
        
        # append DNS info
        dns_path = run_path / "dns.log"
        if dns_path.exists():
            self._add_dns_info(dns_path)
        
        # append SSL info
        ssl_path = run_path / "ssl.log"
        if ssl_path.exists():
            self._add_ssl_info(ssl_path)
        
        # Store in database
        #self._store_in_database() TODO
        
        return self.dns_connections, self.ssl_connections
    
    def _parse_conn_log(self, conn_path: Path) -> None:
        for record in self.iter_json(conn_path):
            conn = Connection.parse_conn_record(record)
            if conn:
                self.connections[conn.uid] = conn
    
    def _add_dns_info(self, dns_path: Path) -> None:
        for record in self.iter_json(dns_path):
            conn_uid = record.get("uid", "")
            if conn_uid and conn_uid in self.connections.keys():
                conn = self.connections[conn_uid]
                dns_conn = DNSConnection.parse_dns_record(record, conn)
                if dns_conn:
                    self.dns_connections[dns_conn.uuid] = dns_conn
    
    def _add_ssl_info(self, ssl_path: Path) -> None:
        for record in self.iter_json(ssl_path):
            conn_uid = record.get("uid", "")
            if conn_uid and conn_uid in self.connections.keys():
                conn = self.connections[conn_uid]
                ssl_conn = SSLConnection.parse_ssl_record(record, conn)
                if ssl_conn:
                    self.ssl_connections[ssl_conn.uuid] = ssl_conn
    
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
                    "dns_query": connection.query,
                    "dns_qclass": connection.qclass,
                    "dns_qtype": connection.qtype,
                    "dns_rcode": connection.rcode,
                    "dns_rejected": connection.rejected,
                    
                    "dns_q_len": connection.q_len,
                    "dns_q_tld": connection.q_tld,
                    "dns_q_max_subd_len": connection.q_max_subd_len,
                    "dns_q_min_subd_len": connection.q_min_subd_len,
                    "dns_q_entropy": connection.q_entropy,
                    "dns_q_num_levels": connection.q_num_levels,
                    "dns_q_dig_ratio": connection.q_dig_ratio,
                    "dns_q_consec_conso_ratio": connection.q_consec_conso_ratio,
                    "dns_q_alternate_ratio": connection.q_alternate_ratio,
                    "dns_q_conse_digits_ratio": connection.q_conse_digits_ratio,

                    "dns_ans_len_mean": connection.ans_len_mean,
                    "dns_ans_entropy_mean": connection.ans_entropy_mean,
                    "dns_ttl_mean": connection.ttl_mean,
                })
            
            # ssl feats not incl list
            if isinstance(connection, SSLConnection):
                row.update({
                    "uuid": connection.uuid,
                    "ssl_version": connection.version,
                    "ssl_cipher": connection.cipher,
                    "ssl_server_name": connection.server_name,
                    "ssl_resumed": connection.resumed,
                    "ssl_established": connection.established,
                    "ssl_history": connection.ssl_history,
                    "ssl_ja4": connection.ja4,
                    "ssl_ja4s": connection.ja4s,
                    
                    "ssl_num_cli_exts": connection.num_cli_exts,
                    "ssl_num_srv_exts": connection.num_srv_exts,
                    "ssl_num_certs": connection.num_certs,
                    
                    "ssl_weak_cipher": connection.weak_cipher,
                })
            
            rows.append(row)
        df = pd.DataFrame(rows)
        uuid_col = df.pop("uuid")
        df.insert(0, "column_to_move", uuid_col)
        return pd.DataFrame(rows)