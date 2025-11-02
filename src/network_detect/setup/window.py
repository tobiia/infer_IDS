# file for creating the event windows
# + several DNS features over time


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