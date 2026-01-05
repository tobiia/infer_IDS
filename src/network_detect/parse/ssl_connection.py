from dataclasses import dataclass, field
from typing import List
from uuid import uuid4
from .connect import Connection
from utils import weak_cipher

@dataclass
class SSLConnection(Connection):
    version: str = ""
    cipher: str = ""
    server_name: str = ""
    resumed: int = 0
    established: int = 0
    ssl_history: str = ""
    ja4: str = ""
    ja4s: str = ""
    cert_chain_fps: List[str] = field(default_factory=list)
    
    # weak = RC4, 3DES / DES / RC2 / IDEA, TLS_RSA
    client_ciphers: List[str] = field(default_factory=list)
    ssl_client_exts: List[str] = field(default_factory=list)
    ssl_server_exts: List[str] = field(default_factory=list)
    
    # counts
    num_cli_exts: int = 0
    num_srv_exts: int = 0
    num_certs: int = 0

    # boolean
    weak_cipher: int = 0
    
    def _calculate_ssl_features(self) -> None:

        self.weak_cipher = weak_cipher(self.cipher)
        self.num_cli_exts = len(self.ssl_client_exts)
        self.num_srv_exts = len(self.ssl_server_exts)
        self.num_certs = len(self.cert_chain_fps)

    @classmethod
    def _from_con(cls, conn: Connection, record: dict):

        ssl_conn = cls(
            uuid = str(uuid4()),
            uid=conn.uid,
            ts=conn.ts,
            ts_iso=conn.ts_iso,
            duration=conn.duration,
            proto = conn.proto,
            orig_h = conn.orig_h,
            resp_h = conn.resp_h,
            orig_p = conn.orig_p,
            resp_p = conn.resp_p,
            orig_pkts = conn.orig_pkts,
            resp_pkts = conn.resp_pkts,
            orig_bytes = conn.orig_bytes,
            resp_bytes = conn.resp_bytes,
            missed_bytes = conn.missed_bytes,
            service = conn.service,
            has_dns = 0,
            has_tls = 1,

            # ssl-specific fields
            version = record.get("version", ""),
            cipher = record.get("cipher", ""),
            server_name = record.get("server_name", ""),
            resumed = bool(record.get("resumed", 0)),
            established = bool(record.get("established", 0)),
            ssl_history = record.get("ssl_history", ""),
            cert_chain_fps = record.get("cert_chain_fps", []),
            client_ciphers = record.get("client_ciphers", []),
            ssl_client_exts = record.get("ssl_client_exts", []),
            ssl_server_exts = record.get("ssl_server_exts", []),
            ja4 = record.get("ja4", ""),
            ja4s = record.get("ja4s", ""),
        )

        # REVIEW derived fields not in __init__ --> change later
        ssl_conn.total_bytes = conn.total_bytes
        ssl_conn.total_pkts = conn.total_pkts
        ssl_conn.approx_fwd_pkt_len_mean = conn.approx_fwd_pkt_len_mean
        ssl_conn.flow_bytes_per_sec = conn.flow_bytes_per_sec
        ssl_conn.pkts_per_sec = conn.pkts_per_sec
        ssl_conn.pkt_ratio = conn.pkt_ratio
        ssl_conn.approx_bwd_pkt_len_mean = conn.approx_bwd_pkt_len_mean

        return ssl_conn
    
    @staticmethod
    def parse_ssl_record(rec: dict, conn: Connection):
        try:
            ssl_conn = SSLConnection._from_con(conn, rec)
            ssl_conn._calculate_ssl_features()
            return ssl_conn
        except Exception as e:
            print(f"Error parsing SSL: {e}")
            return None