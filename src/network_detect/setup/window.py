# file for creating the event windows
# + several DNS features over time

from bisect import bisect_left, bisect_right


FAIL_RCODES = {"NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"}


def event_time_idx(events_by_host):
    # idx_events_by_host = dict[host: list of events associated]
    index = {}
    for host, events in events_by_host.items():
        events_sorted = sorted(events, key=lambda e: e["ts"])
        ts_list = [e["ts"] for e in events_sorted]
        index[host] = (ts_list, events_sorted)
    return index

def dns_window_feat(flow, host_index, window_s = 300):
    host = flow.get("id.orig_h") or ""
    ts = flow.get("ts")
    if not host or ts is None:
        return

    if host not in host_index:
        return

    ts_list, evs = host_index[host]

    t1 = float(ts)
    t0 = t1 - float(window_s)

    # bisect to get indices for [t0, t1]
    lo = bisect_left(ts_list, t0)
    hi = bisect_right(ts_list, t1)
    win = evs[lo:hi]

    n = len(win)
    if n == 0:
        return

    flow["win_dns_query_rate"] = n / max(window_s, 1e-9)

    fail = sum(1 for e in win if e.get("rcode") in FAIL_RCODES)
    flow["win_dns_fail_rate"] = fail / n

    ptr = sum(1 for e in win if e.get("qtype") == "PTR")
    txt = sum(1 for e in win if e.get("qtype") == "TXT")
    flow["win_dns_ptr_rate"] = ptr / n
    flow["win_dns_txt_rate"] = txt / n

    domains = {e["query"] for e in win if e.get("query")}
    tlds = {e["tld"] for e in win if e.get("tld")}
    flow["win_dns_unique_domains"] = len(domains)
    flow["win_dns_unique_tlds"] = len(tlds)

def create_windows(flows):
    rows = []

    # flows = dict where keys are uid, values are a dict of the features
    for uid, features in flows.items():

        # everything needs to be atomic
        # must convert sets to int
        domains_set = features.get("dns_unique_domains") or set()
        tlds_set = features.get("dns_unique_tlds") or set()
        ips_set = features.get("dns_unique_ips") or set()

        features["dns_unique_domains_count"] = len(domains_set)
        features["dns_unique_tlds_count"] = len(tlds_set)
        features["dns_unique_ips_count"] = len(ips_set)

        # delete the sets if they exist
        if "dns_unique_domains" in features:
            del features["dns_unique_domains"]
        if "dns_unique_tlds" in features:
            del features["dns_unique_tlds"]
        if "dns_unique_ips" in features:
            del features["dns_unique_ips"]

        dns_n = int(features.get("dns_count") or 0)
        # only do the following if this flow had associated dns messages
        if dns_n > 0:
            features["dns_entropy_mean"] = float(features.get("dns_entropy_sum") or 0.0) / dns_n
            features["dns_len_mean"] = float(features.get("dns_len_sum") or 0) / dns_n
            features["dns_num_pct_mean"] = float(features.get("dns_num_pct_sum") or 0.0) / dns_n
        else:
            # might be better to put null instead of 0
            features["dns_entropy_mean"] = 0.0
            features["dns_len_mean"] = 0.0
            features["dns_num_pct_mean"] = 0.0
            features["dns_subdomain_rate"] = 0.0

        rows.append(features)

    return rows