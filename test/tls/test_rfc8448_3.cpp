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
 *  RFC 8446
 *  RFC 5246
 *  -- RFC 8996 --
 *  RFC 4346
 *  RFC 2246
 */

#include "sample.hpp"

void test_rfc8448_3() {
    _test_case.begin("RFC 8448 3.  Simple 1-RTT Handshake");
    return_t ret = errorcode_t::success;
    basic_stream bs;
    size_t pos = 0;
    crypto_keychain keychain;

    // read client_epk.pub @client_hello
    // {client}  create an ephemeral x25519 key pair:
    // # ECDH(server_epk.priv, client_epk.pub) --> shared_secret
    {
        constexpr char constexpr_client[] = "client";
        const char* x =
            "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d"
            "ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c";
        const char* y = nullptr;
        const char* d =
            "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78"
            "4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05";
        crypto_key key;
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, y, d, keydesc(constexpr_client));

        rfc8448_session.get_tls_protection().get_keyexchange().add((EVP_PKEY*)key.any(), constexpr_client, true);
        rfc8448_session2.get_tls_protection().get_keyexchange().add((EVP_PKEY*)key.any(), constexpr_client, true);

        _logger->writeln(constexpr_client);
        dump_key(key.find(constexpr_client), &bs);
        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }

    // #1 client_hello
    // {client}  construct a ClientHello handshake message:
    // # hash (ClientHello + ServerHello) --> hello_hash
    {
        // {client}  send handshake record:
        const char* record =
            "16 03 01 00 c4 01 00 00 c0 03 03 cb"
            "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
            "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
            "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
            "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
            "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
            "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
            "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
            "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
            "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#1A client_hello", &rfc8448_session, bin_record, role_client);
        dump_record("#1B client_hello", &rfc8448_session2, bin_record, role_client);
    }

    // send server_epk.pub @server_hello
    // {server}  create an ephemeral x25519 key pair:
    // # ECDH(server_epk.priv, client_epk.pub) --> shared_secret
    {
        constexpr char constexpr_server[] = "server";
        const char* x = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
        const char* y = "";
        const char* d = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";

        crypto_key key;
        crypto_keychain keychain;
        keychain.add_ec_b16(&key, ec_x25519, x, y, d, keydesc(constexpr_server));

        // from key to rfc8448_session, rfc8448_session2
        rfc8448_session.get_tls_protection().get_keyexchange().add((EVP_PKEY*)key.any(), constexpr_server, true);
        rfc8448_session2.get_tls_protection().get_keyexchange().add((EVP_PKEY*)key.any(), constexpr_server, true);

        dump_key(key.find(constexpr_server), &bs);
        _logger->writeln(bs);
        bs.clear();
    }

    // #2 server_hello
    // {server}  construct a ServerHello handshake message:
    // {server}  send handshake record:
    // # hash (ClientHello + ServerHello) --> hello_hash
    {
        const char* record =
            "16 03 03 00 5a 02 00 00 56 03 03 a6"
            "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
            "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
            "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
            "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#2A server_hello", &rfc8448_session, bin_record);
        dump_record("#2B server_hello", &rfc8448_session2, bin_record);

        // > handshake type 2 (server_hello)
        //  > cipher suite 0x1301 TLS_AES_128_GCM_SHA256
        _test_case.assert(0x1301 == rfc8448_session.get_tls_protection().get_cipher_suite(), __FUNCTION__, "cipher suite");

        test_transcript_hash(&rfc8448_session, base16_decode_rfc("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
    }

    // hello_hash, shared_secret, early_secret, ...
    auto cipher_suite = rfc8448_session.get_tls_protection().get_cipher_suite();

    {
        // # hash (ClientHello + ServerHello) --> hello_hash
        binary_t hello_hash;
        test_keycalc(&rfc8448_session, tls_secret_hello_hash, hello_hash, "hello_hash", "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        // # ECDH(priv, pub) --> shared_secret
        binary_t shared_secret;
        test_keycalc(&rfc8448_session, tls_secret_shared_secret, shared_secret, "shared_secret",
                     "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        // compute ...
        // for more details ... see tls_protection::calc
        // hello_hash               860c06ed..
        // shared_secret            8bd4054f..
        // early_secret             33ad0a1c.. salt(1)=00,ikm(32)=00..
        // empty_hash               e3b0c442.. hash(0)=empty
        // secret_handshake_derived 6f2615a1.. hkdf_expand_label, prk(32)=early, info(49)=HkdfLabel("derived"), hash/context=empty_hash
        // secret_handshake         1dc826e9.. hmac_kdf_extract, salt(32)=secret_handshake_derived, ikm(32)=shared_secret
        // secret_handshake_client  b3eddb12.. hkdf_expand_label prk(32)=secret_handshake info(54)=HkdfLabel("c hs traffic"), hash/context=hello_hash
        // secret_handshake_server  b67b7d69.. hkdf_expand_label prk(32)=secret_handshake info(54)=HkdfLabel("s hs traffic"), hash/context=hello_hash

        // secret_master_derived    43de77e0.. hkdf_expand_label prk(32)=secret_handshake info(49)=HkdfLabel("derived"), hash/context=empty_hash
        // secret_master            18df0684.. hmac_kdf_extract, salt(32)=secret_master_derived, ikm(32)=00..

        // ..
        // client_key       dbfaa693.. hkdf_expand_label prk(32)=secret_handshake_client info=HkdfLabel("key"), hash/context=empty
        // client_iv        5bd3c71b.. hkdf_expand_label prk(32)=secret_handshake_client info=HkdfLabel("iv"), hash/context=empty

        // {server}  extract secret "early":
        binary_t early_secret;
        test_keycalc(&rfc8448_session, tls_secret_early_secret, early_secret, "early_secret",
                     "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        // {server}  derive secret for handshake "tls13 derived":
        binary_t secret_handshake_derived;
        test_keycalc(&rfc8448_session, tls_secret_handshake_derived, secret_handshake_derived, "secret_handshake_derived",
                     "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        // {server}  extract secret "handshake":
        binary_t secret_handshake;
        test_keycalc(&rfc8448_session, tls_secret_handshake, secret_handshake, "secret_handshake",
                     "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        // {server}  derive secret "tls13 c hs traffic":
        binary_t secret_handshake_client;
        test_keycalc(&rfc8448_session, tls_secret_handshake_client, secret_handshake_client, "secret_handshake_client",
                     "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        // {server}  derive secret "tls13 s hs traffic":
        binary_t secret_handshake_server;
        test_keycalc(&rfc8448_session, tls_secret_handshake_server, secret_handshake_server, "secret_handshake_server",
                     "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

        binary_t secret_handshake_server_key;
        binary_t secret_handshake_server_iv;
        test_keycalc(&rfc8448_session, tls_secret_handshake_server_key, secret_handshake_server_key, "secret_handshake_server_key",
                     "3fce516009c21727d0f2e4e86ee403bc");
        test_keycalc(&rfc8448_session, tls_secret_handshake_server_iv, secret_handshake_server_iv, "secret_handshake_server_iv", "5d313eb2671276ee13000b30");

        binary_t secret_handshake_client_key;
        binary_t secret_handshake_client_iv;
        test_keycalc(&rfc8448_session, tls_secret_handshake_client_key, secret_handshake_client_key, "secret_handshake_client_key",
                     "dbfaa693d1762c5b666af5d950258d01");
        test_keycalc(&rfc8448_session, tls_secret_handshake_client_iv, secret_handshake_client_iv, "secret_handshake_client_iv", "5bd3c71b836e0b76bb73265f");
    }
    // #3A1 encrypted_extensions
    // {server}  construct an EncryptedExtensions handshake message:
    {
        const char* handshake =
            "08 00 00 24 00 22 00 0a 00 14 00"
            "12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c"
            "00 02 40 01 00 00 00 00";
        binary_t bin_handshake = base16_decode_rfc(handshake);
        dump_handshake("#3A1 encrypted_extensions", &rfc8448_session, bin_handshake);

        test_transcript_hash(&rfc8448_session, base16_decode_rfc("28477e0227567481e5ee83016a3e447840200586cf01526781898a964a45caf9"));
    }
    // #3A2 certificate
    // {server}  construct a Certificate handshake message:
    {
        const char* handshake =
            "0b 00 01 b9 00 00 01 b5 00 01 b0 30 82"
            "01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48"
            "86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03"
            "72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17"
            "0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06"
            "03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7"
            "0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f"
            "82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26"
            "d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c"
            "1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52"
            "4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74"
            "80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93"
            "ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03"
            "01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06"
            "03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01"
            "01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a"
            "72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea"
            "e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01"
            "51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be"
            "c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b"
            "1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8"
            "96 12 29 ac 91 87 b4 2b 4d e1 00 00";
        binary_t bin_handshake = base16_decode_rfc(handshake);
        dump_handshake("#3A2 certificate", &rfc8448_session, bin_handshake);

        test_transcript_hash(&rfc8448_session, base16_decode_rfc("764d6632b3c35c3f3205e3499ac3edbaabb88295fba751461d3678e2e5ea0687"));
    }
    // #3A3 certificate_verify
    // {server}  construct a CertificateVerify handshake message:
    {
        const char* handshake =
            "0f 00 00 84 08 04 00 80 5a 74 7c"
            "5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a"
            "b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07"
            "86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b"
            "be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44"
            "5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a"
            "3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3";
        binary_t bin_handshake = base16_decode_rfc(handshake);
        dump_handshake("#3A3 certificate_verify", &rfc8448_session, bin_handshake);

        test_transcript_hash(&rfc8448_session, base16_decode_rfc("edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed"));
    }
    // #3A4 finished
    // {server}  construct a Finished handshake message:
    {
        const char* handshake =
            "14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb"
            "dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07"
            "18";
        binary_t bin_handshake = base16_decode_rfc(handshake);
        dump_handshake("#3A4 server finished", &rfc8448_session, bin_handshake);

        test_transcript_hash(&rfc8448_session, base16_decode_rfc("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"));
    }
    // #3B = #3A1 + #3A2 + #3A3 + #3A4
    {
        const char* record =
            "17 03 03 02 a2 d1 ff 33 4a 56 f5 bf"
            "f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df"
            "78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45"
            "cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3"
            "89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b"
            "d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9"
            "b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf"
            "51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d"
            "2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55"
            "cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f"
            "d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6"
            "86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac"
            "66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea"
            "52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e"
            "a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6"
            "54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb"
            "31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59"
            "62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e"
            "92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af"
            "36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37"
            "8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c"
            "f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88"
            "2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80"
            "f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69"
            "18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99"
            "2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11"
            "c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51"
            "56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42"
            "f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f"
            "60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd"
            "d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af"
            "93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da"
            "bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b";

        // {server}  derive read traffic keys for handshake data:
        // PRK          (32) secret_handshake_client       b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21
        // key info     (13) hkdflabel("key")              001009746c733133206b657900
        // key expanded (16) secret_handshake_client_key   dbfaa693d1762c5b666af5d950258d01
        // iv info      (12) hkdflabel("iv")               000c08746c73313320697600
        // iv expanded  (12) secret_handshake_client_iv    5bd3c71b836e0b76bb73265f
        //
        //  > key 3fce516009c21727d0f2e4e86ee403bc
        //  > iv 5d313eb2671276ee13000b30
        //  > record no 0
        //  > nonce 5d313eb2671276ee13000b30
        //  > aad 17030302a2
        //  > tag bf0253fe5175be898e750edc53370d2b

        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#3B (#3A1..#3A4)", &rfc8448_session2, bin_record);

        test_transcript_hash(&rfc8448_session2, base16_decode_rfc("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"));
    }

    // after server finished
    {
        binary_t secret_application_derived;
        test_keycalc(&rfc8448_session, tls_secret_application_derived, secret_application_derived, "secret_application_derived",
                     "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4");
        binary_t secret_application;
        test_keycalc(&rfc8448_session, tls_secret_application, secret_application, "secret_application",
                     "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
        // {server}  derive secret "tls13 c ap traffic":
        binary_t secret_application_client;
        test_keycalc(&rfc8448_session, tls_secret_application_client, secret_application_client, "secret_application_client",
                     "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        binary_t secret_application_client_key;
        test_keycalc(&rfc8448_session, tls_secret_application_client_key, secret_application_client_key, "secret_application_client_key",
                     "17422dda596ed5d9acd890e3c63f5051");
        // {client}  derive write traffic keys for application data:
        binary_t secret_application_client_iv;
        test_keycalc(&rfc8448_session, tls_secret_application_client_iv, secret_application_client_iv, "secret_application_client_iv",
                     "5b78923dee08579033e523d9");
        // {server}  derive secret "tls13 s ap traffic":
        binary_t secret_application_server;
        test_keycalc(&rfc8448_session, tls_secret_application_server, secret_application_server, "secret_application_server",
                     "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");
        binary_t secret_application_server_key;
        test_keycalc(&rfc8448_session, tls_secret_application_server_key, secret_application_server_key, "secret_application_server_key",
                     "9f02283b6c9c07efc26bb9f2ac92e356");
        // {server}  derive write traffic keys for application data:
        binary_t secret_application_server_iv;
        test_keycalc(&rfc8448_session, tls_secret_application_server_iv, secret_application_server_iv, "secret_application_server_iv",
                     "cf782b88dd83549aadf1e984");
        // {server}  derive secret "tls13 exp master":
        binary_t secret_exporter_master;
        test_keycalc(&rfc8448_session, tls_secret_exporter_master, secret_exporter_master, "secret_exporter_master",
                     "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50");
    }
    // #4 client finished
    // {client}  construct a Finished handshake message:
    // {client}  send handshake record:
    {
        const char* record =
            "17 03 03 00 35 75 ec 4d c2 38 cc e6"
            "0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44"
            "d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7"
            "26 c4 05 46";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#4 client finished", &rfc8448_session, bin_record, role_client);
        dump_record("#4 client finished", &rfc8448_session2, bin_record, role_client);
    }
    // after client finished
    {
        // {client}  derive secret "tls13 res master":
        // PRK (32)      secret_application                  18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919
        // hash (32)     hash(client_hello..client finished) 209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d
        // info (52)     hkdflabel("res master")
        // expanded (32)
        binary_t secret_resumption_master;
        test_keycalc(&rfc8448_session, tls_secret_resumption_master, secret_resumption_master, "secret_resumption_master",
                     "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c");
        // {server} generate resumption secret "tls13 resumption":
        // PRK (32)      secret_resumption_master 7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c
        // hash (2)      0000
        // info (22)     hkdflabel("resumption")
        // expanded (32)
        binary_t secret_resumption;
        test_keycalc(&rfc8448_session, tls_secret_resumption, secret_resumption, "secret_resumption",
                     "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    }
    // #5
    // {server}  construct a NewSessionTicket handshake message:
    {
        const char* record =
            "17 03 03 00 de 3a 6b 8f 90 41 4a 97"
            "d6 95 9c 34 87 68 0d e5 13 4a 2b 24 0e 6c ff ac 11 6e 95 d4 1d"
            "6a f8 f6 b5 80 dc f3 d1 1d 63 c7 58 db 28 9a 01 59 40 25 2f 55"
            "71 3e 06 1d c1 3e 07 88 91 a3 8e fb cf 57 53 ad 8e f1 70 ad 3c"
            "73 53 d1 6d 9d a7 73 b9 ca 7f 2b 9f a1 b6 c0 d4 a3 d0 3f 75 e0"
            "9c 30 ba 1e 62 97 2a c4 6f 75 f7 b9 81 be 63 43 9b 29 99 ce 13"
            "06 46 15 13 98 91 d5 e4 c5 b4 06 f1 6e 3f c1 81 a7 7c a4 75 84"
            "00 25 db 2f 0a 77 f8 1b 5a b0 5b 94 c0 13 46 75 5f 69 23 2c 86"
            "51 9d 86 cb ee ac 87 aa c3 47 d1 43 f9 60 5d 64 f6 50 db 4d 02"
            "3e 70 e9 52 ca 49 fe 51 37 12 1c 74 bc 26 97 68 7e 24 87 46 d6"
            "df 35 30 05 f3 bc e1 86 96 12 9c 81 53 55 6b 3b 6c 67 79 b3 7b"
            "f1 59 85 68 4f";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#5 new_session_ticket", &rfc8448_session, bin_record);
        dump_record("#5 new_session_ticket", &rfc8448_session2, bin_record);
    }
    // #6
    // {client}  send application_data record:
    {
        const char* record =
            "17 03 03 00 43 a2 3f 70 54 b6 2c 94"
            "d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b"
            "98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62"
            "92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#6 application data", &rfc8448_session, bin_record, role_client);
        dump_record("#6 application data", &rfc8448_session2, bin_record, role_client);
    }
    // #7
    // {server}  send application_data record:
    {
        const char* record =
            "17 03 03 00 43 2e 93 7e 11 ef 4a c7"
            "40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36 e3"
            "0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5"
            "f0 a2 1c 00 47 c2 ab f3 32 54 0d d0 32 e1 67 c2 95 5d";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#7 application data", &rfc8448_session, bin_record);
        dump_record("#7 application data", &rfc8448_session2, bin_record);
    }
    // #8
    // {client}  send alert record:
    {
        const char* record =
            "17 03 03 00 13 c9 87 27 60 65 56 66"
            "b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#8 alert", &rfc8448_session, bin_record, role_client);
        dump_record("#8 alert", &rfc8448_session2, bin_record, role_client);
    }
    // #9
    // {server}  send alert record:
    {
        const char* record =
            "17 03 03 00 13 b5 8f d6 71 66 eb f5"
            "99 d2 47 20 cf be 7e fa 7a 88 64 a9";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#9 alert", &rfc8448_session, bin_record);
        dump_record("#9 alert", &rfc8448_session2, bin_record);
    }
}
