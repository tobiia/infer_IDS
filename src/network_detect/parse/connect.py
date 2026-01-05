from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

@dataclass
class Connection:
    uuid: str = ""
    uid: str = ""
    ts: float = 0
    ts_iso: str = ""
    duration: float = 0.0
    proto: str = ""
    orig_h: str = ""
    resp_h: str = ""
    orig_p: int = 0
    resp_p: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_bytes: int = 0
    resp_bytes: int = 0
    missed_bytes: int = 0
    service: str = ""
    has_dns: int = 0
    has_tls: int = 0
    
    # derived features
    total_bytes: int = 0
    total_pkts: int = 0
    approx_fwd_pkt_len_mean: float = 0.0
    approx_bwd_pkt_len_mean: float = 0.0
    flow_bytes_per_sec: float = 0.0
    pkts_per_sec: float = 0.0
    pkt_ratio: float = 0.0
    
    @property
    def four_tuple(self) -> tuple:
        return (self.orig_h, self.resp_h, self.orig_p, self.resp_p)
    
    def _calculate_derived_features(self) -> None:

        self.total_bytes = self.orig_bytes + self.resp_bytes
        self.total_pkts = self.orig_pkts + self.resp_pkts

        self.flow_bytes_per_sec = self.total_bytes / self.duration if self.duration > 0 else 0
        self.pkts_per_sec = self.total_pkts / self.duration if self.duration > 0 else 0
    
        self.pkt_ratio = self.orig_pkts / (self.resp_pkts + 1)
        
        self.approx_fwd_pkt_len_mean = self.orig_bytes / self.orig_pkts if self.orig_pkts > 0 else 0

        self.approx_bwd_pkt_len_mean = self.resp_bytes / self.resp_pkts if self.resp_pkts > 0 else 0

    @staticmethod
    def parse_conn_record(record: dict):
        try:
            ts = float(record.get("ts", 0))
            ts_iso = datetime.fromtimestamp(ts).isoformat()
            
            conn = Connection(
                uuid = "",
                uid = record.get("uid", ""),
                ts = ts,
                ts_iso = ts_iso,
                duration = record.get("duration", 0.0),
                proto = record.get("proto", ""),
                orig_h = record.get("id.orig_h", ""),
                resp_h = record.get("id.resp_h", ""),
                orig_p = record.get("id.orig_p", 0),
                resp_p = record.get("id.resp_p", 0),
                orig_pkts = record.get("orig_pkts", 0),
                resp_pkts = record.get("resp_pkts", 0),
                orig_bytes = record.get("orig_bytes", 0),
                resp_bytes = record.get("resp_bytes", 0),
                missed_bytes = record.get("missed_bytes", 0),
                service = record.get("service", ""),
                has_dns = 0,
                has_tls = 0,
            )
            
            conn._calculate_derived_features()
            
            return conn
            
        except (KeyError, ValueError, TypeError) as e:
            print(f"Error parsing conn record: {e}")
            return None