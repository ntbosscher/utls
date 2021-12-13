
Generating testing key/cert
```
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout localhost.key -out localhost.crt -config openssl.conf -extensions v3_req
```