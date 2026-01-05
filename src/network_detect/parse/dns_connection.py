from dataclasses import dataclass, field
from typing import List
from uuid import uuid4
from .connect import Connection
from utils import shannon_entropy, tld, subdomain_labels, consecutive_consonant_ratio, letter_digit_alternation_ratio, consecutive_digits_ratio

@dataclass
class DNSConnection(Connection):
    query: str = ""
    qclass: int = 1     # default: in
    qtype: int = 1      # A
    rcode: int = 0      # NOERROR
    answers: List[str] = field(default_factory=list)
    ttls: List[float] = field(default_factory=list)
    rejected: int = 0
    
    # query features
    q_len: int = 0
    q_tld: str = ""
    q_max_subd_len: int = 0
    q_min_subd_len: int = 0
    q_entropy: float = 0.0
    q_num_levels: int = 0       # dots in query
    q_dig_ratio: float = 0.0
    q_consec_conso_ratio: float = 0.0
    q_alternate_ratio: float = 0.0
    q_conse_digits_ratio: float = 0.0
    
    # answer features
    ans_len_mean: float = 0.0
    ans_entropy_mean: float = 0.0
    ttl_mean: float = 0.0
    
    def _calculate_dns_features(self) -> None:
        # query
        if self.query:
            self.q_len = len(self.query)
        
        if self.q_len > 0:
            self.q_tld = tld(self.query)
            self.q_num_levels = self.query.count('.')

            subdomain_list = subdomain_labels(self.query)
            if subdomain_list:

                sub_lens = [len(sub) for sub in subdomain_list]
                self.q_max_subd_len = max(sub_lens)
                self.q_min_subd_len = min(sub_lens)
                
                subdomains_str = "".join(subdomain_list)

                if any(c.isalpha() for c in subdomains_str):
                    self.q_dig_ratio = sum(1 for c in subdomains_str if c.isdigit()) / sum(1 for c in subdomains_str if c.isalpha())
                
                self.q_entropy = shannon_entropy(subdomains_str)
                self.q_consec_conso_ratio = consecutive_consonant_ratio(subdomains_str)
                self.q_alternate_ratio = letter_digit_alternation_ratio(subdomains_str)
                self.q_conse_digits_ratio = consecutive_digits_ratio(subdomains_str)
        
        # snswer features
        if self.answers:
            self.ans_len_mean = sum(len(ans) for ans in self.answers) / len(self.answers)

            entropies = [shannon_entropy(answers) for answers in self.answers]
            self.ans_entropy_mean = sum(x for x in entropies) / len(entropies)
        if self.ttls:
            self.ttl_mean = sum(self.ttls) / len(self.ttls)

    @classmethod
    def _from_conn(cls, conn: Connection, record: dict):
        dns_conn = cls(
            uuid = str(uuid4()),
            uid = conn.uid,
            ts = conn.ts,
            ts_iso = conn.ts_iso,
            duration = conn.duration,
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
            has_dns = 1,
            has_tls = 0,

            # dns-specific fields
            query = record.get("query", ""),
            qclass = record.get("qclass", 1),
            qtype = record.get("qtype", 1),
            rcode = record.get("rcode", 0),
            answers = record.get("answers", []),
            ttls = record.get("TTLs", []),
            rejected = bool(record.get("query", 0)),
        )

        # REVIEW derived fields not in __init__ --> change later
        dns_conn.total_bytes = conn.total_bytes
        dns_conn.total_pkts = conn.total_pkts
        dns_conn.approx_fwd_pkt_len_mean = conn.approx_fwd_pkt_len_mean
        dns_conn.flow_bytes_per_sec = conn.flow_bytes_per_sec
        dns_conn.pkts_per_sec = conn.pkts_per_sec
        dns_conn.pkt_ratio = conn.pkt_ratio
        dns_conn.approx_bwd_pkt_len_mean = conn.approx_bwd_pkt_len_mean

        return dns_conn
    
    @staticmethod
    def parse_dns_record(rec: dict, conn: Connection):
        try:
            dns_conn = DNSConnection._from_conn(conn, rec)
            dns_conn._calculate_dns_features()
            return dns_conn
        except Exception as e:
            print(f"Error parsing DNS: {e}")
            return None