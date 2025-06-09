# parse the log files to get the features

import os
import sys
import shutil
import subprocess
from pathlib import Path
from config import Config
import json

def iter_json(path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

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

        # dns.log
        "dns_query": "",
        "dns_has_subdomain": 0,
        "dns_tld": "",
        "dns_domain_len": 0,
        "dns_subdomain_len": 0,
        "dns_num_pct": 0.0,
        "dns_entropy": 0.0,
        "dns_num_dots": 0,
        "dns_num_hyphens": 0,
        "dns_num_digits": 0,
        "dns_qtype_counts": {},
        "dns_count": 0,
        "dns_rcode_counts": {},

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

        # http.log
        "http_host": "",
        "http_uri": "",
        "http_user_agent": "",
        "http_method": "",
        "http_status_code": None,
        "http_response_body_len": 0,
        "http_resp_mime_types": [],
        "http_uri_len": 0,
        "http_query_len": 0,
        "http_param_count": 0,
        "http_exe_mime_flag": 0,
        "http_script_mime_flag": 0,

        # window features (filled later)
        "win_dns_query_rate": 0.0,
        "win_dns_fail_rate": 0.0,
        "win_dns_ptr_rate": 0.0,
        "win_dns_txt_rate": 0.0,
        "win_dns_unique_domains": 0,
        "win_dns_unique_tlds": 0,

        "win_http_error_rate": 0.0,
        "win_http_request_rate": 0.0,
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
        update_from_conn(flows["uid"], record)


def update_from_conn(f, rec: dict):
    f["proto"] = rec.get("proto") or ""
    f["ts"] = rec.get("ts")
    f["duration"] = float(rec.get("duration") or 0.0) # handles None or ""
    f["orig_pkts"] = int(rec.get("orig_pkts") or 0)
    f["resp_pkts"] = int(rec.get("resp_pkts") or 0)
    f["orig_bytes"] = int(rec.get("orig_bytes") or 0)
    f["resp_bytes"] = int(rec.get("resp_bytes") or 0)
    f["id.orig_h"] = rec.get("id.orig_h") or ""
    f["id.resp_h"] = rec.get("id.resp_h") or ""
    f["id.orig_p"] = rec.get("id.orig_p") or ""
    f["id.resp_p"] = rec.get("id.resp_p") or ""

def update_lof(flows_dict):
    # need to iterate over each.log to get the basic __ features
    # then calculate the extra features
    # add all features to new_flow
    pass