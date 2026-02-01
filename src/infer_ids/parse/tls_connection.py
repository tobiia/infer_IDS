from dataclasses import dataclass, field
from pprint import pprint
from uuid import uuid4
from .base_connection import Connection
from utils import weak_cipher

@dataclass
class TLSConnection(Connection):
    version: int = 12
    cipher: str = ""
    server_name: str = ""
    resumed: int = 0
    established: int = 0
    ssl_history: str = ""
    ja4: str = ""
    ja4s: str = ""
    cert_chain_fps: list[str] = field(default_factory=list)
    
    # weak = RC4, 3DES / DES / RC2 / IDEA, TLS_RSA
    client_ciphers: list[str] = field(default_factory=list)
    ssl_client_exts: list[str] = field(default_factory=list)
    ssl_server_exts: list[str] = field(default_factory=list)
    
    # counts
    num_cli_exts: int = 0
    num_srv_exts: int = 0
    num_certs: int = 0

    # boolean
    weak_cipher: int = 0
    
    def _calculate_tls_features(self) -> None:

        self.weak_cipher = weak_cipher(self.cipher)
        self.num_cli_exts = len(self.ssl_client_exts)
        self.num_srv_exts = len(self.ssl_server_exts)
        self.num_certs = len(self.cert_chain_fps)

    @classmethod
    def _from_conn(cls, conn: Connection, record: dict):

        tls_conn = cls()
        label = record.get("label", conn.label)
        label = label.lower() if label else None

        tls_conn.uuid = str(uuid4())
        tls_conn.uid = conn.uid
        tls_conn.ts = conn.ts
        tls_conn.ts_iso = conn.ts_iso
        tls_conn.duration = conn.duration
        tls_conn.proto = conn.proto
        tls_conn.orig_h = record.get("id_orig_h", conn.orig_h)
        tls_conn.resp_h = record.get("id_resp_h", conn.resp_h)
        tls_conn.orig_p = record.get("id_orig_p", conn.orig_p)
        tls_conn.resp_p = record.get("id_resp_p", conn.resp_p)
        tls_conn.orig_pkts = conn.orig_pkts
        tls_conn.resp_pkts = conn.resp_pkts
        tls_conn.orig_bytes = conn.orig_bytes
        tls_conn.resp_bytes = conn.resp_bytes
        tls_conn.missed_bytes = conn.missed_bytes
        tls_conn.service = "ssl"
        tls_conn.has_dns = 0
        tls_conn.has_tls = 1
        tls_conn.label = label

        # tls-specific fields
        tls_conn.version = int(record.get("version", "TLSv12")[4:])
        tls_conn.cipher = record.get("cipher", "")
        tls_conn.server_name = record.get("server_name", "")
        tls_conn.resumed = 1 if record.get("resumed", False) else 0
        tls_conn.established = 1 if record.get("established", False) else 0
        tls_conn.ssl_history = record.get("ssl_history", "")
        tls_conn.cert_chain_fps = record.get("cert_chain_fps", [])
        tls_conn.client_ciphers = record.get("client_ciphers", [])
        tls_conn.ssl_client_exts = record.get("ssl_client_exts", [])
        tls_conn.ssl_server_exts = record.get("ssl_server_exts", [])
        tls_conn.ja4 = record.get("ja4", "")
        tls_conn.ja4s = record.get("ja4s", "")

        # REVIEW derived fields not in __init__ --> change later
        tls_conn._calculate_derived_features()

        return tls_conn
    
    @classmethod
    def parse_tls_record(cls, record: dict, conn: Connection):
        try:
            tls_conn = cls._from_conn(conn, record)
            tls_conn._calculate_tls_features()
            return tls_conn
        except Exception as e:
            print(f"Error parsing ssl.log: {e}")
            print(f"Record data: ", end=" ")
            pprint(record)
            return None