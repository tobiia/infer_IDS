@load base/frameworks/logging # necessary for logging

# only generate the below streams
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load policy/protocols/ssl/ssl-log-ext

# json output
redef LogAscii::use_json = T;