#### test

- understanding state machine
- debugging in progress
  - MINGW64 only
  - linux not tested yet

| server     | client    | TLS 1.3 | TLS 1.2 |
| --         | --        | --      |  --     |
| tlsserver  | netclient | PASS    |  PASS   |
| tlsserver2 | netclient | PASS    |  PASS   |
| s_server   | netclient | PASS    |  PASS   |
| tlsserver2 | s_client  | FAIL    |  FAIL   |
