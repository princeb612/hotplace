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
    auto& protection = session.get_tls_protection();

    {
        crypto_keychain keychain;
        auto key = session.get_tls_protection().get_keyexchange();
        keychain.load_file(&key, key_certfile, "server.crt", KID_TLS_SERVER_CERTIFICATE_PUBLIC);
        keychain.load_file(&key, key_pemfile, "server.key", KID_TLS_SERVER_CERTIFICATE_PRIVATE);

        constexpr char constexpr_master_secret[] = "93be6304758c8b4f0e106df7bbbb7a4edc23ed6188d44ed4d567b6e375400a74471fda4ad6748c84bda37a19399bd4a4";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));
    }

    // client_hello (fragment)
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 00 00 c3 01 00 00"
            "bd 00 00 00 00 00 00 00 b7 fe fd 9f c7 e2 53 87"
            "0b 87 fa a8 21 b7 76 16 c4 c3 6f 60 6f 82 ed 8c"
            "d7 86 d7 0a f2 d4 23 6e 99 2e 07 00 00 00 36 c0"
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
            "17 00 00 00 00 00 00 00 17 fe ff 14 d8 32 1d 16"
            "e2 72 e5 3c bc 26 77 2d ff 69 a2 56 ed cd cc 0a";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("hello_verify_request", &session, bin_record, from_server);
    }
    // client_hello (fragment)
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 02 00 c3 01 00 00"
            "d1 00 01 00 00 00 00 00 b7 fe fd 9f c7 e2 53 87"
            "0b 87 fa a8 21 b7 76 16 c4 c3 6f 60 6f 82 ed 8c"
            "d7 86 d7 0a f2 d4 23 6e 99 2e 07 00 14 d8 32 1d"
            "16 e2 72 e5 3c bc 26 77 2d ff 69 a2 56 ed cd cc"
            "0a 00 36 c0 2c c0 30 00 9f cc a9 cc a8 cc aa c0"
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
            "41 00 01 00 00 00 00 00 41 fe fd f0 21 fa a3 69"
            "c3 88 f4 80 2c 34 4d 67 cb 23 d9 6e 79 b6 85 68"
            "d2 ad ee 45 b0 0c cc 36 a7 7f 8a 00 c0 27 00 00"
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
            "00 1d 20 a4 a9 ba 02 fb 67 3f 13 6f bf af d8 43"
            "b9 c8 7a 23 20 d8 5e 20 de a7 d1 bc 41 59 76 68"
            "c9 e5 6a 08 04 01 00 81 f4 db ab 15 fc ab 02 6b"
            "85 ef 8d 5b 5d 17 a8 d7 e8 88 a2 fa 5a 8f 2e a9"
            "53 cc 65 89 9e 9b 35 45 63 15 92 99 92 6f 3d 06"
            "ce c0 0b 05 c0 d7 b1 73 c2 61 1c 65 8b f1 e0 bf"
            "68 e6 22 c4 c3 5f ff 90 70 3e 95 cc 0b e3 e6 ef";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("certificate (reassembled), server_key_exchange (fragment)", &session, bin_record, from_server);
    }
    // server_key_exchange (reassembled)
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 09 00 c3 0c 00 01"
            "28 00 03 00 00 71 00 00 b7 81 36 3e 53 1e c2 40"
            "e5 2a 99 11 79 bd 23 62 29 df d4 ba 03 7f e4 5c"
            "6b 89 4f c0 0e f5 12 68 5f bf c4 54 f1 9f 91 db"
            "0d 58 75 f9 29 bf 8f b1 90 a2 84 0d 4a 6c 04 ad"
            "ea 1c 35 c6 b1 8f c4 49 e4 31 d9 dc 36 9a 81 ae"
            "db 28 cf 33 1b bf c8 23 b7 c7 11 c8 cf f6 69 69"
            "3c 21 0c 1b 58 73 25 39 76 dc 33 be 71 9e 28 cb"
            "df 28 e8 ca df ac 64 d6 c2 09 68 cd 9f d9 0f 8a"
            "f7 99 dd f8 93 01 19 68 7b e8 89 f5 c5 e7 0b 27"
            "18 8b 62 17 5d 7b 13 c2 4a 64 9c 38 46 56 c3 11"
            "3b 41 4b a5 26 20 df e0 a8 6d f9 72 31 fe 95 da"
            "a9 f3 a6 a1 54 e3 74 e1 7b 00 54 b7 eb 8e cc 5e";
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
    // client_key_exchange, change_cipher_spec, finished
    // finished - decryption failed
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 04 00 2d 10 00 00"
            "21 00 02 00 00 00 00 00 21 20 50 42 a8 d6 b5 bb"
            "fe 9a 7a d0 69 fc 48 e4 59 d5 c2 be f4 c5 f2 15"
            "3f 31 df 94 de 89 03 2e f9 57 14 fe fd 00 00 00"
            "00 00 00 00 05 00 01 01 16 fe fd 00 01 00 00 00"
            "00 00 00 00 50 41 e2 f4 6b 71 97 6e a4 73 76 92"
            "a1 a5 d7 d0 da 07 06 ef 1b 20 34 9a 04 83 f7 ae"
            "c6 8c 3a c6 6e 12 a3 d9 32 f3 07 a3 ef 74 cb e6"
            "6c 29 4e c9 c2 a0 12 4e e2 5c 98 69 c2 68 3b 10"
            "93 e2 cd ca 56 4a d7 d7 71 39 66 41 13 ec e4 96"
            "73 20 46 d5 6a";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("client_key_exchange, change_cipher_spec, finished", &session, bin_record, from_client);
    }
    // new_session_ticket
    {
        const char* record = ""
        ;
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("new_session_ticket", &session, bin_record, from_server);
    }
    // change_cipher_spec, encrypted_handshake message
    {
        const char* record = ""
        ;
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("change_cipher_spec, encrypted_handshake message", &session, bin_record, from_server);
    }
    // application data
    {
        const char* record = ""
        ;
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("application data (hello)", &session, bin_record, from_client);
    }
#endif
}
