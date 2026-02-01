from dataclasses import dataclass, field
from uuid import uuid4
from .base_connection import Connection
from utils import shannon_entropy, tld, subdomain_labels, consecutive_consonant_ratio, letter_digit_alternation_ratio, consecutive_digits_ratio
from pprint import pprint

@dataclass
class DNSConnection(Connection):
    query: str = ""
    qclass: int = 1     # default: in
    qtype: int = 1      # A
    rcode: int = 0      # NOERROR
    answers: list[str] = field(default_factory=list)
    ttls: list[float] = field(default_factory=list)
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
    num_ans: int = 0
    ans_len_mean: float = 0.0
    ans_entropy_mean: float = 0.0
    ttl_mean: float = 0.0
    
    def _calculate_dns_features(self) -> None:# query
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
            self.num_ans = len(self.answers)
            self.ans_len_mean = sum(len(answer) for answer in self.answers) / self.num_ans
            entropies = [shannon_entropy(answer) for answer in self.answers]
            self.ans_entropy_mean = sum(x for x in entropies) / len(entropies)

        if self.ttls:
            self.ttl_mean = sum(self.ttls) / len(self.ttls)

    @classmethod
    def _from_conn(cls, conn: Connection, record: dict):

        dns_conn = cls()
        label = record.get("label", conn.label)
        label = label.lower() if label else None

        dns_conn.uuid = str(uuid4())
        dns_conn.uid = conn.uid
        dns_conn.ts = conn.ts
        dns_conn.ts_iso = conn.ts_iso
        dns_conn.duration = conn.duration
        dns_conn.proto = conn.proto
        dns_conn.orig_h = record.get("id_orig_h", conn.orig_h)
        dns_conn.resp_h = record.get("id_resp_h", conn.resp_h)
        dns_conn.orig_p = record.get("id_orig_p", conn.orig_p)
        dns_conn.resp_p = record.get("id_resp_p", conn.resp_p)
        dns_conn.orig_pkts = conn.orig_pkts
        dns_conn.resp_pkts = conn.resp_pkts
        dns_conn.orig_bytes = conn.orig_bytes
        dns_conn.resp_bytes = conn.resp_bytes
        dns_conn.missed_bytes = conn.missed_bytes
        dns_conn.service = "dns"
        dns_conn.has_dns = 1
        dns_conn.has_tls = 0
        dns_conn.label = label

        # dns-specific fields
        dns_conn.query = record.get("query", "")
        dns_conn.qclass = int(record.get("qclass", 1))
        dns_conn.qtype = int(record.get("qtype", 1))
        dns_conn.rcode = int(record.get("rcode", 0))
        dns_conn.answers = record.get("answers", [])
        dns_conn.ttls = record.get("TTLs", [])
        dns_conn.rejected = 1 if record.get("rejected", False) else 0

        dns_conn._calculate_derived_features()

        return dns_conn
    
    @classmethod
    def from_dns_record(cls, record: dict, conn: Connection):
        try:
            dns_conn = cls._from_conn(conn, record)
            dns_conn._calculate_dns_features()
            return dns_conn
        except Exception as e:
            print(f"Error parsing dns.log: {e}")
            print(f"Record data: ", end=" ")
            pprint(record)
            return None