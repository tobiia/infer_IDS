# parse the log files to get the features

import os
from pathlib import Path
from config import Config
import json
import ipaddress

def iter_json(path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def shannon_entropy(s):
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in counts.values())

def tld_from_domain(domain):
    if not domain or "." not in domain:
        return ""
    return domain.rsplit(".", 1)[-1].lower()

def split_labels(domain):
    if not domain:
        return []
    d = domain.strip(".").lower()
    if not d:
        return []
    return [p for p in d.split(".") if p]

def is_ip(s):
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def new_flow(uid):
    return {
        "uid": uid,

        # base conn
        "ts": None,
        "duration": 0.0,
        "proto": "",
        "id.orig_h": "",
        "id.resp_h": "",
        "id.orig_p": None,
        "id.resp_p": None,
        "orig_pkts": 0,
        "resp_pkts": 0,
        "orig_bytes": 0,
        "resp_bytes": 0,

        # dns.log aggregates
        "dns_count": 0,
        "dns_qtype_counts": {},
        "dns_rcode_counts": {},
        "dns_unique_domains": set(),
        "dns_unique_tlds": set(),
        "dns_unique_ips": set(),
        "dns_entropy_sum": 0.0,
        "dns_entropy_max": 0.0,
        "dns_len_sum": 0,
        "dns_len_max": 0,
        "dns_num_pct_sum": 0.0,
        "dns_num_pct_max": 0.0,
        "dns_has_subdomain_count": 0,


        # ssl.log
        "tls_version": "",
        "tls_cipher": "",
        "tls_server_name": "",
        "tls_sni_present": 0,
        "tls_sni_len": 0,
        "tls_sni_tld": "",
        "tls_resumed": 0,
        "tls_cipher_family": "",
        "tls_weak_cipher_flag": 0,
        "tls_ja3": "",
        "tls_ja4": "",

        # window features (filled later)
        "win_dns_query_rate": 0.0,
        "win_dns_fail_rate": 0.0,
        "win_dns_ptr_rate": 0.0,
        "win_dns_txt_rate": 0.0,
        "win_dns_unique_domains": 0,
        "win_dns_unique_tlds": 0,
    }

def update(run_id):
    flows = {}
    # conn
    connPath = Config.RUNS_DIR / run_id / "conn.log"
    for record in iter_json(connPath):
        uid = record.get("uid")
        if not uid:
            continue
        flows[uid] = new_flow(uid)
        update_from_conn(flows[uid], record)


def update_from_conn(flow, rec):
    flow["proto"] = rec.get("proto") or ""
    flow["ts"] = rec.get("ts")
    flow["duration"] = float(rec.get("duration") or 0.0) # handles None or ""
    flow["orig_pkts"] = int(rec.get("orig_pkts") or 0)
    flow["resp_pkts"] = int(rec.get("resp_pkts") or 0)
    flow["orig_bytes"] = int(rec.get("orig_bytes") or 0)
    flow["resp_bytes"] = int(rec.get("resp_bytes") or 0)
    flow["id.orig_h"] = rec.get("id.orig_h") or ""
    flow["id.resp_h"] = rec.get("id.resp_h") or ""
    flow["id.orig_p"] = rec.get("id.orig_p") or ""
    flow["id.resp_p"] = rec.get("id.resp_p") or ""

def update_dns(flow, rec, dns_events_by_host):
    # f = flow uid, rec = specific record in log
    flow["dns_count"] = int(flow.get("dns_count") or 0) + 1

    ts = rec.get("ts")
    host = rec.get("id.orig_h") or flow.get("id.orig_h") or ""
    query = (rec.get("query") or "").strip().lower()
    qtype = (rec.get("qtype_name") or "").upper()
    rcode = (rec.get("rcode_name") or "").upper()
    # ttl or rtt?

    # counts
    qt = flow.setdefault("dns_qtype_counts", {})
    if qtype:
        qt[qtype] = qt.get(qtype, 0) + 1

    rc = flow.setdefault("dns_rcode_counts", {})
    if rcode:
        rc[rcode] = rc.get(rcode, 0) + 1

    # uniques + lexical stats across queries (per UID)
    if query:
        flow.setdefault("dns_unique_domains", set()).add(query)
        tld = tld_from_domain(query)
        if tld:
            flow.setdefault("dns_unique_tlds", set()).add(tld)

        labels = split_labels(query)
        has_sub = 1 if len(labels) > 2 else 0
        flow["dns_has_subdomain_count"] = int(flow.get("dns_has_subdomain_count") or 0) + has_sub

        qlen = len(query)
        digits = sum(ch.isdigit() for ch in query)
        num_pct = digits / max(qlen, 1)
        ent = shannon_entropy(query)

        flow["dns_len_sum"] = int(flow.get("dns_len_sum") or 0) + qlen
        flow["dns_len_max"] = max(int(flow.get("dns_len_max") or 0), qlen)

        flow["dns_num_pct_sum"] = float(flow.get("dns_num_pct_sum") or 0.0) + num_pct
        flow["dns_num_pct_max"] = max(float(flow.get("dns_num_pct_max") or 0.0), num_pct)

        flow["dns_entropy_sum"] = float(flow.get("dns_entropy_sum") or 0.0) + ent
        flow["dns_entropy_max"] = max(float(flow.get("dns_entropy_max") or 0.0), ent)

    # unique ips
    answers = rec.get("answers") or []
    ipset = flow.setdefault("dns_unique_ips", set())
    for a in answers:
        s = a.strip()
        if is_ip(s):
            ipset.add(s)

    # host-based events --> might not be necessary for windows
    if host and ts is not None:
        dns_events_by_host[host].append({
            "ts": float(ts),
            "rcode": rcode,
            "qtype": qtype,
            "query": query,
            "tld": tld_from_domain(query) if query else "",
        })


def update_tls(flow, rec):
    flow["tls_version"] = rec.get("version") or ""
    flow["tls_cipher"] = rec.get("cipher") or ""
    sni = (rec.get("server_name") or "").strip().lower()
    flow["tls_server_name"] = sni
    flow["tls_sni_present"] = 1 if sni else 0
    flow["tls_sni_len"] = len(sni) if sni else 0
    flow["tls_sni_tld"] = tld_from_domain(sni) if sni else ""
    flow["tls_resumed"] = 1 if rec.get("resumed") else 0
