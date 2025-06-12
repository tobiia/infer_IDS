@load base/frameworks/logging
redef LogAscii::use_json = T;

# load log types
@load base/misc/version
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
# below extends SSL::Info
@load policy/protocols/ssl/ssl-log-ext

# load packages for fingerprinting
@load ja3/ja3
@load ja3/ja3s
@load ja4