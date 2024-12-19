### understanding TLS

* TLS
  * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
  * RFC 8446 Example Handshake Traces for TLS 1.3
  * https://dtls.xargs.org/
  * wireshark.exe


#### RFC 8446 Figure 1: Message Flow for Full TLS Handshake
````
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.

               Figure 1: Message Flow for Full TLS Handshake
````

#### RFC 8446 Figure 2: Message Flow for a Full Handshake with Mismatched Parameters
````
        Client                                               Server

        ClientHello
        + key_share             -------->
                                                  HelloRetryRequest
                                <--------               + key_share
        ClientHello
        + key_share             -------->
                                                        ServerHello
                                                        + key_share
                                              {EncryptedExtensions}
                                              {CertificateRequest*}
                                                     {Certificate*}
                                               {CertificateVerify*}
                                                         {Finished}
                                <--------       [Application Data*]
        {Certificate*}
        {CertificateVerify*}
        {Finished}              -------->
        [Application Data]      <------->        [Application Data]

             Figure 2: Message Flow for a Full Handshake with
                           Mismatched Parameters
````

#### RFC 8446 Figure 3: Message Flow for Resumption and PSK
````

          Client                                               Server

   Initial Handshake:
          ClientHello
          + key_share               -------->
                                                          ServerHello
                                                          + key_share
                                                {EncryptedExtensions}
                                                {CertificateRequest*}
                                                       {Certificate*}
                                                 {CertificateVerify*}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Certificate*}
          {CertificateVerify*}
          {Finished}                -------->
                                    <--------      [NewSessionTicket]
          [Application Data]        <------->      [Application Data]


   Subsequent Handshake:
          ClientHello
          + key_share*
          + pre_shared_key          -------->
                                                          ServerHello
                                                     + pre_shared_key
                                                         + key_share*
                                                {EncryptedExtensions}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Finished}                -------->
          [Application Data]        <------->      [Application Data]

               Figure 3: Message Flow for Resumption and PSK
````

#### RFC 8446 Figure 4: Message Flow for a 0-RTT Handshake
````
         Client                                               Server

         ClientHello
         + early_data
         + key_share*
         + psk_key_exchange_modes
         + pre_shared_key
         (Application Data*)     -------->
                                                         ServerHello
                                                    + pre_shared_key
                                                        + key_share*
                                               {EncryptedExtensions}
                                                       + early_data*
                                                          {Finished}
                                 <--------       [Application Data*]
         (EndOfEarlyData)
         {Finished}              -------->
         [Application Data]      <------->        [Application Data]

               +  Indicates noteworthy extensions sent in the
                  previously noted message.

               *  Indicates optional or situation-dependent
                  messages/extensions that are not always sent.

               () Indicates messages protected using keys
                  derived from a client_early_traffic_secret.

               {} Indicates messages protected using keys
                  derived from a [sender]_handshake_traffic_secret.

               [] Indicates messages protected using keys
                  derived from [sender]_application_traffic_secret_N.

               Figure 4: Message Flow for a 0-RTT Handshake

````
#### RFC 9147 Figure 2: DTLS 1.3 Record Formats
````
       struct {
           ContentType type;
           ProtocolVersion legacy_record_version;
           uint16 epoch = 0
           uint48 sequence_number;
           uint16 length;
           opaque fragment[DTLSPlaintext.length];
       } DTLSPlaintext;

       struct {
            opaque content[DTLSPlaintext.length];
            ContentType type;
            uint8 zeros[length_of_padding];
       } DTLSInnerPlaintext;

       struct {
           opaque unified_hdr[variable];
           opaque encrypted_record[length];
       } DTLSCiphertext;

                     Figure 2: DTLS 1.3 Record Formats
````
#### RFC 9147 Figure 3: DTLS 1.3 Unified Header
````
       0 1 2 3 4 5 6 7
       +-+-+-+-+-+-+-+-+
       |0|0|1|C|S|L|E E|
       +-+-+-+-+-+-+-+-+
       | Connection ID |   Legend:
       | (if any,      |
       /  length as    /   C   - Connection ID (CID) present
       |  negotiated)  |   S   - Sequence number length
       +-+-+-+-+-+-+-+-+   L   - Length present
       |  8 or 16 bit  |   E   - Epoch
       |Sequence Number|
       +-+-+-+-+-+-+-+-+
       | 16 bit Length |
       | (if present)  |
       +-+-+-+-+-+-+-+-+

                     Figure 3: DTLS 1.3 Unified Header
````
#### RFC 9147 Figure 4: DTLS 1.3 Header Examples
````
    0 1 2 3 4 5 6 7       0 1 2 3 4 5 6 7       0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+
   | Content Type  |     |0|0|1|1|1|1|E E|     |0|0|1|0|0|0|E E|
   +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+
   |   16 bit      |     |               |     |8 bit Seq. No. |
   |   Version     |     / Connection ID /     +-+-+-+-+-+-+-+-+
   +-+-+-+-+-+-+-+-+     |               |     |               |
   |   16 bit      |     +-+-+-+-+-+-+-+-+     |   Encrypted   |
   |    Epoch      |     |    16 bit     |     /   Record      /
   +-+-+-+-+-+-+-+-+     |Sequence Number|     |               |
   |               |     +-+-+-+-+-+-+-+-+     +-+-+-+-+-+-+-+-+
   |               |     |   16 bit      |
   |   48 bit      |     |   Length      |       DTLSCiphertext
   |Sequence Number|     +-+-+-+-+-+-+-+-+         Structure
   |               |     |               |         (minimal)
   |               |     |  Encrypted    |
   +-+-+-+-+-+-+-+-+     /  Record       /
   |    16 bit     |     |               |
   |    Length     |     +-+-+-+-+-+-+-+-+
   +-+-+-+-+-+-+-+-+
   |               |      DTLSCiphertext
   |               |        Structure
   /   Fragment    /          (full)
   |               |
   +-+-+-+-+-+-+-+-+

    DTLSPlaintext
      Structure

                     Figure 4: DTLS 1.3 Header Examples
````
