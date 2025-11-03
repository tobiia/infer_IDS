# file for creating the event windows
# + several DNS features over time

from bisect import bisect_left, bisect_right


FAIL_RCODES = {"NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"}

def create_windows(flows: dict[str, dict]):
    rows = []

    # flows = dict where keys are uid, values are a dict of the features
    for uid, features in flows.items():

        # everything needs to be atomic
        # must convert sets to int
        dns_n = int(features.get("dns_count") or 0)
        # only do the following if this flow had associated dns messages
        if dns_n > 0:
            domains_set = features.get("dns_unique_domains") or set()
            tlds_set = features.get("dns_unique_tlds") or set()
            ips_set = features.get("dns_unique_ips") or set()

            features["dns_unique_domains_count"] = len(domains_set)
            features["dns_unique_tlds_count"] = len(tlds_set)
            features["dns_unique_ips_count"] = len(ips_set)

            features["dns_entropy_mean"] = float(features.get("dns_entropy_sum") or 0.0) / dns_n
            features["dns_len_mean"] = float(features.get("dns_len_sum") or 0) / dns_n
            features["dns_num_pct_mean"] = float(features.get("dns_num_pct_sum") or 0.0) / dns_n

            if features.get("dns_entropy_sum"): del features["dns_entropy_sum"]
            if features.get("dns_len_sum"): del features["dns_len_sum"]
            if features.get("dns_num_pct_sum"): del features["dns_num_pct_sum"]
            if features.get("dns_has_subdomain_count"): del features["dns_has_subdomain_count"]
        else:
            features["dns_entropy_mean"] = None
            features["dns_entropy_max"] = None
            features["dns_len_mean"] = None
            features["dns_len_max"] = None
            features["dns_num_pct_mean"] = None
            features["dns_num_pct_max"] = None
            features["dns_subdomain_rate"] = None
            features["dns_unique_domains_count"] = None
            features["dns_unique_tlds_count"] = None
            features["dns_unique_ips_count"] = None

        # REVIEW delete not part of schema
        del features["dns_unique_domains"]
        del features["dns_unique_tlds"]
        del features["dns_unique_ips"]

        rows.append(features)

    return rows