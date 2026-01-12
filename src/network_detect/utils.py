from pathlib import Path
from typing import Dict
import re
from setup.zeek_parser import ParseZeekLogs

def iter_log(filepath: Path):
    parser = ParseZeekLogs(
        str(filepath),
        safe_headers=True,
        output_format=None
    )
    
    for record in parser:
        if record is not None and isinstance(record, Dict):
            yield dict(record)
        else:
            raise ValueError("log iterator encountered a non-Dict object")

def shannon_entropy(s: str):
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c/n) * log2(c/n) for c in counts.values())

def tld(domain: str):
    if not domain or "." not in domain:
        return ""
    return domain.rsplit(".", 1)[-1].lower()

def subdomain_labels(domain: str):
    # not including tld
    if not domain:
        return []
    d = domain.strip(".").lower()
    if not d:
        return []
    parts = [p for p in d.split(".") if p]
    return parts[:-1]

def consecutive_digits_ratio(domain: str):
    s = re.sub(r'[^a-z0-9]', '', domain.lower())
    if not s:
        return 0.0

    consecutive_digit_chars = 0
    for match in re.finditer(r'\d{2,}', s):
        consecutive_digit_chars += len(match.group())

    return consecutive_digit_chars / len(s)

def letter_digit_alternation_ratio(domain: str):
    s = re.sub(r'[^a-z0-9]', '', domain.lower())
    if len(s) < 2:
        return 0.0

    transitions = 0
    for i in range(len(s) - 1):
        if (s[i].isalpha() and s[i+1].isdigit()) or \
           (s[i].isdigit() and s[i+1].isalpha()):
            transitions += 1

    return transitions / (len(s) - 1)

def consecutive_consonant_ratio(domain: str):
    s = re.sub(r'[^a-z]', '', domain.lower())
    if not s:
        return 0.0

    consonants = "bcdfghjklmnpqrstvwxyz"
    consecutive_cons_chars = 0
    run_len = 0

    for ch in s:
        if ch in consonants:
            run_len += 1
        else:
            if run_len >= 2:
                consecutive_cons_chars += run_len
            run_len = 0

    if run_len >= 2:
        consecutive_cons_chars += run_len

    return consecutive_cons_chars / len(s)

def weak_cipher(cipher: str):
    if not cipher:
        return 0
    c = cipher.upper()
    return 1 if ("RC4" in c or "3DES" in c or "MD5" in c) else 0