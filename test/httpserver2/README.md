#### HTTP/2 simple server

```
# run (libssl)
./test-httpserver2 -r -k --trace &
# run (trial)
./test-httpserver2 -r -k --trace -T &

# chrome or edge
#   https://localhost:9000/
#   https://[::1]:9000/
# curl
#   curl https://localhost:9000/ -v -s -k -http2
#   curl https://[::1]:9000/ -v -s -k -http2

# stop
rm .run
```

- [x] tasks
  - [x] network_server
  - [x] HTTP/2
  - [x] libssl
  - [x] trial
  - [x] ALPN
