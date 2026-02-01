from dataclasses import dataclass, field
from datetime import datetime
from pprint import pprint
from typing import Optional

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
    label: Optional[str] = field(default=None)
    
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

    # must be a class method b/c dataclasses only generate _init_ after class is fully def
    # so staticmethod won't work since it'll need that
    @classmethod
    def from_zeek_record(cls, record: dict):
        try:
            ts = float(record.get("ts", 0))
            ts_iso = datetime.fromtimestamp(ts).isoformat()
            label = record.get("label", None)
            label = label.lower() if label else None

            # have to create empty instance to deal with dataclass __init__ issue
            conn = cls()
            conn.uuid = record.get("uid", "")
            conn.uid = record.get("uid", "")
            conn.ts = ts
            conn.ts_iso = ts_iso
            conn.duration = float(record.get("duration", 0.0))
            conn.proto = record.get("proto", "").lower()
            conn.orig_h = record.get("id_orig_h", "")
            conn.resp_h = record.get("id_resp_h", "")
            conn.orig_p = int(record.get("id_orig_p", 0))
            conn.resp_p = int(record.get("id_resp_p", 0))
            conn.orig_pkts = int(record.get("orig_pkts", 0))
            conn.resp_pkts = int(record.get("resp_pkts", 0))
            conn.orig_bytes = int(record.get("orig_bytes", 0))
            conn.resp_bytes = int(record.get("resp_bytes", 0))
            conn.missed_bytes = int(record.get("missed_bytes", 0))
            conn.service = record.get("service", "").lower()
            conn.has_dns = 0
            conn.has_tls = 0
            conn.label = label

            conn._calculate_derived_features()
            
            return conn
            
        except Exception as e:
            print(f"Error parsing conn.log: {e}")
            print(f"Record data: ", end=" ")
            pprint(record)
            return None