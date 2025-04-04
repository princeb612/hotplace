/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 *  https://dtls.xargs.org/
 */

#include "sample.hpp"

void test_dtls12() {
    _test_case.begin("DTLS 1.2");
    // dtlsserver
    // openssl s_client -connect localhost:9000 -state -debug -dtls1_2

    return_t ret = errorcode_t::success;
    tls_session session;

    crypto_keychain keychain;
    openssl_digest dgst;
    openssl_kdf kdf;
    basic_stream bs;
    size_t pos = 0;
    binary_t bin_clienthello_record;
    binary_t bin_serverhello_record;
    tls_advisor* advisor = tls_advisor::get_instance();

    // self-signed certificate, private key
    {
        crypto_keychain keychain;
        auto key = session.get_tls_protection().get_keyexchange();
        keychain.load_file(&key, key_certfile, "rsa.crt", KID_TLS_SERVER_CERTIFICATE_PUBLIC);
        keychain.load_file(&key, key_pemfile, "rsa.key", KID_TLS_SERVER_CERTIFICATE_PRIVATE);
    }
    // client_hello (fragment)
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 00 00 c3 01 00 00"
            "bd 00 00 00 00 00 00 00 b7 fe fd 6d 15 62 78 04"
            "d2 bb d6 0b aa 05 f2 c6 68 06 7a ac 89 35 37 d4"
            "07 46 43 26 8d a7 03 e4 84 fb 4d 00 00 00 36 c0"
            "2c c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f 00"
            "9e c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0"
            "14 00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d 00"
            "3c 00 35 00 2f 01 00 00 5d ff 01 00 01 00 00 0b"
            "00 04 03 00 01 02 00 0a 00 0c 00 0a 00 1d 00 17"
            "00 1e 00 19 00 18 00 23 00 00 00 16 00 00 00 17"
            "00 00 00 0d 00 30 00 2e 04 03 05 03 06 03 08 07"
            "08 08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04"
            "08 05 08 06 04 01 05 01 06 01 03 03 03 01 03 02";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello (fragment)", &session, bin_record, from_client);
    }
    // client_hello (reassembled)
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 01 00 12 01 00 00"
            "bd 00 00 00 00 b7 00 00 06 04 02 05 02 06 02";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello (reassembled)", &session, bin_record, from_client);
    }
    // hello verify request
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 00 00 23 03 00 00"
            "17 00 00 00 00 00 00 00 17 fe ff 14 9c 97 bf b8"
            "5b 6a 73 10 45 43 86 9e 69 c4 2d 7e 9f 62 61 08";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("hello_verify_request", &session, bin_record, from_server);
    }
    // client_hello (fragment)
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 02 00 c3 01 00 00"
            "d1 00 01 00 00 00 00 00 b7 fe fd 6d 15 62 78 04"
            "d2 bb d6 0b aa 05 f2 c6 68 06 7a ac 89 35 37 d4"
            "07 46 43 26 8d a7 03 e4 84 fb 4d 00 14 9c 97 bf"
            "b8 5b 6a 73 10 45 43 86 9e 69 c4 2d 7e 9f 62 61"
            "08 00 36 c0 2c c0 30 00 9f cc a9 cc a8 cc aa c0"
            "2b c0 2f 00 9e c0 24 c0 28 00 6b c0 23 c0 27 00"
            "67 c0 0a c0 14 00 39 c0 09 c0 13 00 33 00 9d 00"
            "9c 00 3d 00 3c 00 35 00 2f 01 00 00 5d ff 01 00"
            "01 00 00 0b 00 04 03 00 01 02 00 0a 00 0c 00 0a"
            "00 1d 00 17 00 1e 00 19 00 18 00 23 00 00 00 16"
            "00 00 00 17 00 00 00 0d 00 30 00 2e 04 03 05 03"
            "06 03 08 07 08 08 08 1a 08 1b 08 1c 08 09 08 0a";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello (fragment)", &session, bin_record, from_client);
    }
    // client_hello (reassembled)
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 03 00 26 01 00 00"
            "d1 00 01 00 00 b7 00 00 1a 08 0b 08 04 08 05 08"
            "06 04 01 05 01 06 01 03 03 03 01 03 02 04 02 05"
            "02 06 02";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_hello (reassembled)", &session, bin_record, from_client);
    }
    // server_hello, certificate (fragment)
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 01 00 4d 02 00 00"
            "41 00 01 00 00 00 00 00 41 fe fd 09 4f 1e cb b2"
            "49 7b 95 a0 b5 61 14 c6 fe f7 7e 68 43 1e 11 c2"
            "78 24 70 1e b1 d2 03 dc 33 11 74 00 c0 27 00 00"
            "19 ff 01 00 01 00 00 0b 00 04 03 00 01 02 00 23"
            "00 00 00 16 00 00 00 17 00 00 16 fe fd 00 00 00"
            "00 00 00 00 02 00 69 0b 00 03 66 00 02 00 00 00"
            "00 00 5d 00 03 63 00 03 60 30 82 03 5c 30 82 02"
            "44 a0 03 02 01 02 02 14 63 a6 71 10 79 d6 a6 48"
            "59 da 67 a9 04 e8 e3 5f e2 03 a3 26 30 0d 06 09"
            "2a 86 48 86 f7 0d 01 01 0b 05 00 30 59 31 0b 30"
            "09 06 03 55 04 06 13 02 4b 52 31 0b 30 09 06 03"
            "55 04 08 0c 02 47 47 31 0b 30 09 06 03 55 04 07";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello, certificate (fragment)", &session, bin_record, from_server);
    }
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 03 00 c3 0b 00 03"
            "66 00 02 00 00 5d 00 00 b7 0c 02 59 49 31 0d 30"
            "0b 06 03 55 04 0a 0c 04 54 65 73 74 31 0d 30 0b"
            "06 03 55 04 0b 0c 04 54 65 73 74 31 12 30 10 06"
            "03 55 04 03 0c 09 54 65 73 74 20 52 6f 6f 74 30"
            "1e 17 0d 32 34 30 38 32 39 30 36 32 37 31 37 5a"
            "17 0d 32 35 30 38 32 39 30 36 32 37 31 37 5a 30"
            "54 31 0b 30 09 06 03 55 04 06 13 02 4b 52 31 0b"
            "30 09 06 03 55 04 08 0c 02 47 47 31 0b 30 09 06"
            "03 55 04 07 0c 02 59 49 31 0d 30 0b 06 03 55 04"
            "0a 0c 04 54 65 73 74 31 0d 30 0b 06 03 55 04 0b"
            "0c 04 54 65 73 74 31 0d 30 0b 06 03 55 04 03 0c"
            "04 54 65 73 74 30 82 01 22 30 0d 06 09 2a 86 48";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("certificate (fragment)", &session, bin_record, from_server);
    }
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 04 00 c3 0b 00 03"
            "66 00 02 00 01 14 00 00 b7 86 f7 0d 01 01 01 05"
            "00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 ad"
            "9a 29 67 5f f3 a4 79 b4 c6 e6 32 73 d8 d7 ed 88"
            "94 15 83 e4 31 00 04 6c b5 8c ac 87 ab 74 44 13"
            "76 ca 0b 74 29 40 9e 97 2a 01 d7 8b 46 26 6e 19"
            "35 4d c0 d3 b5 ea 0e 93 3a 06 e8 e5 85 b5 27 05"
            "63 db 28 b8 92 da 5a 14 39 0f da 68 6d 6f 0a fb"
            "52 dc 08 0f 54 d3 e4 a2 28 9d a0 71 50 82 e0 db"
            "ca d1 94 dd 42 98 3a 09 33 a8 d9 ef fb d2 35 43"
            "b1 22 a2 be 41 6d ba 91 dc 0b 31 4e 88 f9 4d 9c"
            "61 2d ec b2 13 0a c2 91 8e a2 d6 e9 40 b9 32 b9"
            "80 8f b3 18 a3 33 13 23 d5 d0 7e d9 d0 7f 93 e0";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("certificate (fragment)", &session, bin_record, from_server);
    }
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 05 00 c3 0b 00 03"
            "66 00 02 00 01 cb 00 00 b7 2d 4d 90 c5 58 24 56"
            "d5 c9 10 13 4a b2 99 23 7d 34 b9 8e 97 19 69 6f"
            "ce c6 3f d6 17 a7 d2 43 e0 36 cb 51 7b 2f 18 8b"
            "c2 33 f8 57 cf d1 61 0b 7c ed 37 35 e3 13 7a 24"
            "2e 77 08 c2 e3 d9 e6 17 d3 a5 c6 34 5a da 86 a7"
            "f8 02 36 1d 66 63 cf e9 c0 3d 82 fb 39 a2 8d 92"
            "01 4a 83 cf e2 76 3d 87 02 03 01 00 01 a3 21 30"
            "1f 30 1d 06 03 55 1d 11 04 16 30 14 82 12 74 65"
            "73 74 2e 70 72 69 6e 63 65 62 36 31 32 2e 70 65"
            "30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03"
            "82 01 01 00 00 a5 f5 54 18 ab ad 36 38 c8 fc 0b"
            "66 60 dd 9f 75 9d 86 5b 79 2f ee 57 f1 79 1c 15";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("certificate (fragment)", &session, bin_record, from_server);
    }
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 06 00 c3 0b 00 03"
            "66 00 02 00 02 82 00 00 b7 a1 34 23 d0 1c a9 58"
            "51 a4 d0 08 f5 d8 f7 49 e9 c5 b5 65 91 51 2d 6d"
            "e4 3b 0e 77 02 1f 45 8e 34 e5 bb eb f6 9d df 4a"
            "40 60 21 b3 8e 16 33 3f f4 b6 90 d3 3c 34 ce e6"
            "d9 47 07 a7 57 14 0c f9 78 0b 36 72 a9 88 07 07"
            "93 b4 d7 fe 29 5e e8 41 37 20 a5 03 c7 97 cb 82"
            "ca db 14 e5 8b 96 1f a9 e9 20 3d 6b 25 ae f4 89"
            "4c 60 8d e9 14 33 47 4b 88 54 a2 47 19 81 c8 7b"
            "0e 32 52 2b 91 88 ad 0f 6d 73 30 8c 00 af d5 fc"
            "46 46 af 3a c2 17 89 ec c8 83 ae da e6 69 63 e0"
            "9c 84 22 c5 7a de e8 23 6b 53 9d 6f 94 d2 7f 5c"
            "be 1d 0c de 0e 07 0d 52 a5 43 8c e8 05 ef c0 ff";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("certificate (fragment)", &session, bin_record, from_server);
    }
    // certificate (reassembled), server_key_exchange (fragment)
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 07 00 39 0b 00 03"
            "66 00 02 00 03 39 00 00 2d f0 73 fa dc 5a 51 4c"
            "24 09 65 45 7d ab 52 8b 7e 5d f0 fb de a7 3d 43"
            "c5 af 76 e3 6e f9 a1 dc 78 a2 bd 54 41 04 99 e5"
            "56 32 ba 02 fd 72 16 fe fd 00 00 00 00 00 00 00"
            "08 00 7d 0c 00 01 28 00 03 00 00 00 00 00 71 03"
            "00 1d 20 34 0d c9 22 f7 ee a7 2b a1 13 ca 5a dc"
            "09 53 d5 05 69 a6 80 31 dc 5b fc 4d d2 06 70 68"
            "34 e1 26 08 04 01 00 67 2a 94 51 63 88 0d 13 a5"
            "14 33 30 96 db ba 6c 01 d7 b0 70 25 e2 60 3d 50"
            "aa 84 5c 32 fb 4f da 69 88 b8 70 96 78 a8 f6 ea"
            "a2 fc 61 06 45 11 94 e6 6c 4f 25 23 fd 16 36 24"
            "75 ca d2 43 01 80 27 63 56 a8 d9 13 01 4d 25 2c";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("certificate (reassembled), server_key_exchange (fragment)", &session, bin_record, from_server);
    }
    // server_key_exchange (reassembled)
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 09 00 c3 0c 00 01"
            "28 00 03 00 00 71 00 00 b7 f2 3e 92 12 0a 35 87"
            "85 40 56 b5 29 73 06 1d 2d 90 42 ab 12 52 a2 91"
            "ca 03 92 87 1b df e9 f7 7c be 32 f3 ac cf 33 3b"
            "84 56 a7 f0 06 07 c2 4f 54 c4 15 e6 dd 0f df 2d"
            "e0 de 7b 91 62 fb ae 38 84 32 d7 c9 f3 ba 72 3b"
            "ca e9 30 d3 b2 13 21 e4 02 02 bd 21 0c 46 18 a6"
            "f8 76 ec ad 81 24 44 7f a3 e8 7d 83 0c 90 7b 80"
            "25 b6 04 5a 11 c9 2b ed 17 c2 c8 ed 96 4c 79 06"
            "fb cb 8e d5 a5 1e 6e 3a 12 1b bd a4 10 cd f0 7d"
            "fa 32 78 86 86 df db 11 9f 70 d2 b0 1d 9d c9 c1"
            "e5 99 8b 00 3a 22 9e 32 61 de 05 69 fb fa cd 65"
            "a8 74 8b b8 e3 23 26 d5 f8 dc df cb ed 41 89 d2";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_key_exchange (reassembled)", &session, bin_record, from_server);
    }
    // server_hello_done
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 0a 00 0c 0e 00 00"
            "00 00 04 00 00 00 00 00 00";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("server_hello_done", &session, bin_record, from_server);
    }
#if 0
    // client_key_exchange, change_cipher_spec, encrypted_handshake message
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 04 00 2d 10 00 00"
            "21 00 02 00 00 00 00 00 21 20 72 b7 34 6a 14 e0"
            "d7 20 8a e7 99 63 92 c0 8f c1 f1 1a 9c 60 48 9a"
            "41 44 09 b7 bb 3f 93 59 d7 5e 14 fe fd 00 00 00"
            "00 00 00 00 05 00 01 01 16 fe fd 00 01 00 00 00"
            "00 00 00 00 50 58 2f 88 eb cc 17 af 37 40 3f 1a"
            "f0 0f c0 04 d6 17 17 05 41 c6 ca 59 3a 46 aa bd"
            "47 25 96 ea 1b 99 57 32 00 b4 39 bc 9f 2e f2 bd"
            "2e 4d c5 7c 9e 9b aa ae 1d 7c 1f 4e f9 f6 05 98"
            "18 c1 a6 f2 f5 a8 f4 22 f3 88 e0 05 13 79 72 2d"
            "a5 b2 38 84 cb";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_key_exchange, change_cipher_spec, encrypted_handshake message", &session, bin_record, from_client);
    }
    // new_session_ticket
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 0b 00 c2 04 00 00"
            "b6 00 05 00 00 00 00 00 b6 00 00 1c 20 00 b0 77"
            "15 7d 9f 0b 34 65 1b 65 82 9d d1 cf 3d 23 9b 47"
            "c7 5b 89 d0 1b c2 ef d3 a7 23 e8 40 5e bd 60 36"
            "e0 5a 61 b3 68 bf 58 69 58 e9 6a dc ad 8e 1c 80"
            "c0 66 5c f2 68 59 9c a0 bf 68 23 e9 37 eb 15 d8"
            "da cb e5 6d ef ba a9 f0 fd ab bc 32 fb e7 ff 29"
            "4d 08 e5 9d 7a f9 01 cd 71 1f 7d 76 cd 3d 6a ac"
            "64 b2 c1 09 9c 97 6b 3a 91 98 c0 00 d3 c0 6d c0"
            "c5 b9 2c a2 ff 97 de 1d 37 b2 b9 39 e1 4a 7c 88"
            "49 3e 88 9c 97 2a 3a bd 61 e9 a5 40 e9 87 29 66"
            "02 c6 d9 ed bb 5a ad d9 5a 59 51 2d ca 8d ac 9e"
            "50 13 43 08 d8 e5 bf c8 b9 4f fb e8 a3 98 c7";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("new_session_ticket", &session, bin_record, from_server);
    }
    // change_cipher_spec, encrypted_handshake message
    {
        const char* record =
            "14 fe fd 00 00 00 00 00 00 00 0c 00 01 01 16 fe"
            "fd 00 01 00 00 00 00 00 00 00 50 24 28 4f f3 13"
            "22 6a c4 98 d9 14 66 28 e9 82 07 d9 61 00 7e 0e"
            "a0 ee 63 99 71 e9 29 6e 8d 2e 04 12 77 9c c2 4c"
            "6d 95 ce 58 bd 8c cb 0d 1b 4f da 1b a7 80 52 e6"
            "60 a2 c6 3e 05 32 df 0a 68 7f b5 5d 66 16 53 ec"
            "d2 73 3e 72 12 fd 79 e1 f3 d7 71";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("change_cipher_spec, encrypted_handshake message", &session, bin_record, from_server);
    }
    // application data
    {
        const char* record =
            "17 fe fd 00 01 00 00 00 00 00 01 00 40 1e a9 65"
            "81 47 fc e3 95 e4 71 a6 bf 0c 85 61 df 2c 79 f4"
            "70 2f 7b 15 45 e9 08 72 28 ed dc 1d bb 88 7d e4"
            "a4 e5 af 8a 1e 4b 4e 16 9e 6f 16 cf 8c 64 a5 01"
            "f7 8f d6 6f 19 e9 34 9c 1b 51 61 43 f1";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("application data (hello)", &session, bin_record, from_client);
    }
#endif
}
