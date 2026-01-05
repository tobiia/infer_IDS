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
@load base/protocols/ssl/files.zeek

# load packages for fingerprinting
@load ja4