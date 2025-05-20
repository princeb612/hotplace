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
    - $ ./test-netclient -v -d -P tls13 -i
    - $ ./test-netclient -v -d -P tls12 -i
  - files
    - [server](README_ubuntu20_server.md)
    - [client](README_ubuntu20_client.md)
