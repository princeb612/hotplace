#### TLS 1.3

* 1-RTT
  * C->S
    * client_hello
  * S->C
    * server_hello
    * encrypted_extensions
    * certificate
    * certificate_verify
    * finished
  * C->S
    * finished
  * S->C
    * new_session_ticket
  * C->S
    * application data
  * S->C
    * application data
  * C->S
    * close_notify
  * S->C
    * close_notify
* 0-RTT
  * C->S
    * client_hello
      * pre_shared_key
  * S->C
    * server_hello
    * encrypted_extensions
    * finished

