#### test

- [sslkeylog](sslkeylog)
- ubuntu20.pcap
  - test environment
    - ubuntu 20.04.6 LTS
    - openssl
      - 1.1.1f openssl s_server
      - 3.0.0  netclient
    - Revision 778
  - test step
    - $ sudo tcpdump -i lo tcp port 9000 -v -w ubuntu20.pcap
    - $ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile sslkeylog
    - $ ./test-netclient -v -d -P tls13 -T
    - $ ./test-netclient -v -d -P tls12 -T
  - files
    - [server](ubuntu20_server.md)
    - [client](ubuntu20_client_tls13.md)
    - [client](ubuntu20_client_tls12.md)


## What this capture documents

The `ubuntu20.pcap` scenario records a loopback TLS test against OpenSSL `s_server` and associates the capture with the server-side trace plus TLS 1.2 and TLS 1.3 client notes. The stated environment and revision are historical reproduction details, not a claim that the same command sequence is a current cross-version test recipe.

The `sslkeylog` material is relevant to decrypting TLS application records in packet-analysis tools. Keep private keys and key-log files out of public captures when they could expose real traffic. This directory records a specific experiment; it is not the repository's general sanitizer or Valgrind test path.
