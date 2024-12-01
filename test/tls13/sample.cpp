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

// studying ...

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void debug_handler(trace_category_t category, uint32 event, stream_t* s) {
    std::string ct;
    std::string ev;
    basic_stream bs;
    auto advisor = trace_advisor::get_instance();
    advisor->get_names(category, event, ct, ev);
    bs.printf("[%s][%s]%.*s", ct.c_str(), ev.c_str(), (unsigned int)s->size(), s->data());
    _logger->writeln(bs);
}

return_t dump_record(const char* text, tls_session* session, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == text || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        basic_stream bs;
        size_t pos = 0;
        ret = tls_dump_record(&bs, session, &bin[0], bin.size(), pos);

        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "%s - dump record", text);

        // https://williamlieurance.com/tls-handshake-parser/
        // _logger->writeln("copy and paste https://williamlieurance.com/tls-handshake-parser/");
        // _logger->writeln(base16_encode(bin));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dump_handshake(const char* text, tls_session* session, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == text || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        basic_stream bs;
        size_t pos = 0;
        ret = tls_dump_handshake(&bs, session, &bin[0], bin.size(), pos);

        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "%s - dump handshake", text);
    }
    __finally2 {
        // do nothing
    }
    return ret;
};

tls_session rfc8448_server_session;
tls_session rfc8448_client_session;

void test_rfc8448_2() {
    _test_case.begin("RFC 8448 2.  Private Keys");
    basic_stream bs;
    crypto_keychain keychain;
    tls_protection& protection = rfc8448_server_session.get_tls_protection();

    {
        const char* n =
            "b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c"
            "0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab"
            "bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87"
            "a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f"
            "da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0"
            "3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e"
            "3f";
        const char* e = "01 00 01";
        const char* d =
            "04 de a7 05 d4 3a 6e a7 20 9d d8 07 21 11 a8 3c 81"
            "e3 22 a5 92 78 b3 34 80 64 1e af 7c 0a 69 85 b8 e3 1c 44 f6 de 62"
            "e1 b4 c2 30 9f 61 26 e7 7b 7c 41 e9 23 31 4b bf a3 88 13 05 dc 12"
            "17 f1 6c 81 9c e5 38 e9 22 f3 69 82 8d 0e 57 19 5d 8c 84 88 46 02"
            "07 b2 fa a7 26 bc f7 08 bb d7 db 7f 67 9f 89 34 92 fc 2a 62 2e 08"
            "97 0a ac 44 1c e4 e0 c3 08 8d f2 5a e6 79 23 3d f8 a3 bd a2 ff 99"
            "41";

        crypto_key& cert = protection.get_cert();
        keychain.add_rsa(&cert, nid_rsa, base16_decode_rfc(n), base16_decode_rfc(e), base16_decode_rfc(d), keydesc("server RSA certificate"));
        dump_key(cert.find("server RSA certificate"), &bs);
        _logger->writeln(bs);
    }
}

void test_rfc8448_3() {
    _test_case.begin("RFC 8448 3.  Simple 1-RTT Handshake");
    return_t ret = errorcode_t::success;
    basic_stream bs;
    size_t pos = 0;
    crypto_keychain keychain;
    tls_protection& protection = rfc8448_server_session.get_tls_protection();

    // read client_epk.pub @client_hello
    // {client}  create an ephemeral x25519 key pair:
    // # ECDH(server_epk.priv, client_epk.pub) --> shared_secret
    {
        constexpr char constexpr_client_epk[] = "client epk";
        const char* x =
            "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d"
            "ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c";
        const char* y = "";
        const char* d =
            "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78"
            "4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05";
        crypto_key key;
        keychain.add_ec_b16(&key, "X25519", x, y, d, keydesc(constexpr_client_epk));

        _logger->writeln(constexpr_client_epk);
        dump_key(key.find(constexpr_client_epk), &bs);
        _logger->writeln(bs);
        bs.clear();
    }

    // {client}  construct a ClientHello handshake message:
    // # hash (ClientHello + ServerHello) --> hello_hash
    {
        // {client}  send handshake record:
        const char* clienthello_record =
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

        binary_t bin_clienthello_record = base16_decode_rfc(clienthello_record);

        dump_record("client_hello", &rfc8448_server_session, bin_clienthello_record);
    }

    // send server_epk.pub @server_hello
    // {server}  create an ephemeral x25519 key pair:
    // # ECDH(server_epk.priv, client_epk.pub) --> shared_secret
    {
        constexpr char constexpr_server_epk[] = "server epk";
        const char* x = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
        const char* y = "";
        const char* d = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";
        crypto_key key;
        crypto_key& rfc8448_keys = protection.get_key();
        keychain.add_ec_b16(&rfc8448_keys, "X25519", x, y, d, keydesc(constexpr_server_epk));

        dump_key(rfc8448_keys.find(constexpr_server_epk), &bs);
        _logger->writeln(bs);
        bs.clear();
    }

    // {server}  construct a ServerHello handshake message:
    // {server}  send handshake record:
    // # hash (ClientHello + ServerHello) --> hello_hash
    {
        const char* serverhello_record =
            "16 03 03 00 5a 02 00 00 56 03 03 a6"
            "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
            "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
            "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
            "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";
        binary_t bin_serverhello_record = base16_decode_rfc(serverhello_record);
        dump_record("server_hello", &rfc8448_server_session, bin_serverhello_record);

        // > handshake type 2 (server_hello)
        //  > cipher suite 0x1301 TLS_AES_128_GCM_SHA256
        _test_case.assert(0x1301 == protection.get_cipher_suite(), __FUNCTION__, "cipher suite");
    }

    auto lambda_test = [&](tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect) -> void {
        protection.get_item(tls_secret, secret);
        _logger->writeln("> %s : %s", text, base16_encode(secret).c_str());
        _test_case.assert(secret == base16_decode(expect), __FUNCTION__, text);
    };

    // hello_hash, shared_secret, early_secret, ...
    auto cipher_suite = protection.get_cipher_suite();
    protection.calc(&rfc8448_server_session);

    {
        // # hash (ClientHello + ServerHello) --> hello_hash
        binary_t hello_hash;
        lambda_test(tls_secret_hello_hash, hello_hash, "hello_hash", "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        // # ECDH(priv, pub) --> shared_secret
        binary_t shared_secret;
        lambda_test(tls_secret_shared_secret, shared_secret, "shared_secret", "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
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
        lambda_test(tls_secret_early_secret, early_secret, "early_secret", "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        // {server}  derive secret for handshake "tls13 derived":
        binary_t secret_handshake_derived;
        lambda_test(tls_secret_handshake_derived, secret_handshake_derived, "secret_handshake_derived",
                    "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        // {server}  extract secret "handshake":
        binary_t secret_handshake;
        lambda_test(tls_secret_handshake, secret_handshake, "secret_handshake", "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        // {server}  derive secret "tls13 c hs traffic":
        binary_t secret_handshake_client;
        lambda_test(tls_secret_handshake_client, secret_handshake_client, "secret_handshake_client",
                    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        // {server}  derive secret "tls13 s hs traffic":
        binary_t secret_handshake_server;
        lambda_test(tls_secret_handshake_server, secret_handshake_server, "secret_handshake_server",
                    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        // {server}  derive secret for master "tls13 derived":
        binary_t secret_master_derived;
        lambda_test(tls_secret_master_derived, secret_master_derived, "secret_master_derived",
                    "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4");
        // {server}  extract secret "master":
        binary_t secret_master;
        lambda_test(tls_secret_master, secret_master, "secret_master", "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
        // {server}  derive write traffic keys for handshake data:
        binary_t secret_handshake_server_key;
        binary_t secret_handshake_server_iv;

        lambda_test(tls_secret_handshake_server_key, secret_handshake_server_key, "secret_handshake_server_key", "3fce516009c21727d0f2e4e86ee403bc");
        lambda_test(tls_secret_handshake_server_iv, secret_handshake_server_iv, "secret_handshake_server_iv", "5d313eb2671276ee13000b30");
    }
    // {server}  construct an EncryptedExtensions handshake message:
    {
        const char* encrypted_extensions_handshake =
            "08 00 00 24 00 22 00 0a 00 14 00"
            "12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c"
            "00 02 40 01 00 00 00 00";
        binary_t bin_encrypted_extensions = base16_decode_rfc(encrypted_extensions_handshake);
        dump_handshake("encrypted_extensions_handshake", &rfc8448_server_session, bin_encrypted_extensions);
    }
    // {server}  construct a Certificate handshake message:
    {
        const char* certificate_handshake =
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
        binary_t bin_certificate = base16_decode_rfc(certificate_handshake);
        dump_handshake("certificate_handshake", &rfc8448_server_session, bin_certificate);
    }
    // {server}  construct a CertificateVerify handshake message:
    {
        const char* certificate_verify_handshake =
            "0f 00 00 84 08 04 00 80 5a 74 7c"
            "5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a"
            "b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07"
            "86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b"
            "be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44"
            "5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a"
            "3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3";
        binary_t bin_certificate_vertify = base16_decode_rfc(certificate_verify_handshake);
        dump_handshake("certificate_verify_handshake", &rfc8448_server_session, bin_certificate_vertify);
    }
    // {server}  construct a Finished handshake message:
    {
        const char* finished_handshake =
            "14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb"
            "dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07"
            "18";
        binary_t bin_finished = base16_decode_rfc(finished_handshake);
        dump_handshake("finished_handshake", &rfc8448_server_session, bin_finished);
    }
    // {server}  send handshake record:
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
    }
}

void test_rfc8448_4() {
    _test_case.begin("RFC 8448 4.  Resumed 0-RTT Handshake");
    //
}

void test_rfc8448_5() {
    _test_case.begin("RFC 8448 5.  HelloRetryRequest");
    //
}

void test_rfc8448_6() {
    _test_case.begin("RFC 8448 6.  Client Authentication");
    //
}

void test_rfc8448_7() {
    _test_case.begin("RFC 8448 7.  Compatibility Mode");
    //
}

void test_tls13_xargs_org() {
    _test_case.begin("https://tls13.xargs.org/");

    return_t ret = errorcode_t::success;
    tls_session server_session;
    // tls_session client_session;

    crypto_keychain keychain;
    openssl_digest dgst;
    openssl_kdf kdf;
    basic_stream bs;
    size_t pos = 0;
    binary_t bin_clienthello_record;
    binary_t bin_serverhello_record;
    tls_advisor* advisor = tls_advisor::get_instance();

    {
        const char* servercert =
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDITCCAgmgAwIBAgIIFVqSrcIEj5AwDQYJKoZIhvcNAQELBQAwIjELMAkGA1UE\n"
            "BhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0EwHhcNMTgxMDA1MDEzODE3WhcNMTkx\n"
            "MDA1MDEzODE3WjArMQswCQYDVQQGEwJVUzEcMBoGA1UEAxMTZXhhbXBsZS51bGZo\n"
            "ZWltLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSANga650dr\n"
            "CJQE7Ke2kQQ/95K8Ge77fXTXqA0AHntLOkrmD+jAcfxz5wJMDbz0vdEdOWu6cEZK\n"
            "E+lK+D3z4QlZVHvJVftBLaN2UhHh89x3bKpTN27KOuy+w6q3OzHVbLZSnICYvMng\n"
            "KBjiC/f4oDr9FwRQns55vZ858epp7EeXLoMPtcqV3pWh5gQi1e6+UnlUoee/iob2\n"
            "Rm0NnxaVGkz3oEaSWVwTUvJUnlr7Tr/XejeVAUTkwCaHTGU+QH19IwdEAfSE/9CP\n"
            "eh+gUhDR9PDVznlwKTLiyr5wH9+ta0u3EQH0S61mahETD+Lugp5NAp3JHN1nFtu5\n"
            "BhiG7cG6lCECAwEAAaNSMFAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\n"
            "AQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBSJT95bzGniUs8+owDfsZe4HeHB\n"
            "RjANBgkqhkiG9w0BAQsFAAOCAQEAWRZFppouN3nk9t0nGrocC/1s11WZtefDblM+\n"
            "/zZZCEMkyeelBAedOeDUKYf/4+vdCcHPHZFEVYcLVx3Rm98dJPi7mhH+gP1ZK6A5\n"
            "jN4R4mUeYYzlmPqW5Tcu7z0kiv3hdGPrv6u45NGrUCpU7ABk6S94GWYNPyfPIJ5m\n"
            "f85a4uSsmcfJOBj4slEHIt/tl/MuPpNJ1MZsnqY5bXREYqBrQsbVumiOrDoBe938\n"
            "jiz8rSfLadPM3KKAQURl0640jODzSrL7nGGDcTErGRBBZBwjfxGl1lyETwQEhJk4\n"
            "cSuVntaFvFxd1kXtGZCUc0ApJty0DjRpoVlB6OLMqEu2CEY2oA==\n"
            "-----END CERTIFICATE-----";

        crypto_key& cert = server_session.get_tls_protection().get_cert();
        keychain.load_cert(&cert, servercert, 0);

        dump_key(cert.any(), &bs);
        _logger->writeln(bs);
        bs.clear();
    }

    /**
     * https://tls13.xargs.org/#client-key-exchange-generation
     */
    {
        crypto_key key;
        // Client Key Exchange Generation
        const char* x = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        const char* y = "";
        const char* d = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        keychain.add_ec_b16(&key, "X25519", x, y, d, keydesc("client key"));
        basic_stream bs;
        dump_key(key.find("client key"), &bs);
        _logger->writeln(bs);

        // store key_share public_key in tls_session and ecdh key agreement
        //
        // > handshake type 1 (client_hello)
        //   > extension - 0033 key_share
        //    > extension len 38
        //    > group 0x001d (x25519)
        //    > public key len 32
        //      00000000 : 35 80 72 D6 36 58 80 D1 AE EA 32 9A DF 91 21 38 | 5.r.6X....2...!8
        //      00000010 : 38 51 ED 21 A2 8E 3B 75 E9 65 D0 D2 CD 16 62 54 | 8Q.!..;u.e....bT
        //      358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
    }
    // https://tls13.xargs.org/#client-hello
    {
        const char* clienthello_record =
            "16 03 01 00 F8 01 00 00 F4 03 03 00 01 02 03 04"
            "05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14"
            "15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 E0 E1 E2 E3"
            "E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3"
            "F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 00 08 13 02"
            "13 03 13 01 00 FF 01 00 00 A3 00 00 00 18 00 16"
            "00 00 13 65 78 61 6D 70 6C 65 2E 75 6C 66 68 65"
            "69 6D 2E 6E 65 74 00 0B 00 04 03 00 01 02 00 0A"
            "00 16 00 14 00 1D 00 17 00 1E 00 19 00 18 01 00"
            "01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00"
            "00 17 00 00 00 0D 00 1E 00 1C 04 03 05 03 06 03"
            "08 07 08 08 08 09 08 0A 08 0B 08 04 08 05 08 06"
            "04 01 05 01 06 01 00 2B 00 03 02 03 04 00 2D 00"
            "02 01 01 00 33 00 26 00 24 00 1D 00 20 35 80 72"
            "D6 36 58 80 D1 AE EA 32 9A DF 91 21 38 38 51 ED"
            "21 A2 8E 3B 75 E9 65 D0 D2 CD 16 62 54 -- -- --";
        bin_clienthello_record = base16_decode_rfc(clienthello_record);
        dump_record("client_hello", &server_session, bin_clienthello_record);
    }
    // https://tls13.xargs.org/#server-key-exchange-generation
    binary_t shared_secret;
    {
        const char* x = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
        const char* y = "";
        const char* d = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        crypto_key& server_keys = server_session.get_tls_protection().get_key();
        keychain.add_ec_b16(&server_keys, "X25519", x, y, d, keydesc("server key"));

        dump_key(server_keys.find("server key"), &bs);
        _logger->writeln(bs);
        bs.clear();
    }
    // https://tls13.xargs.org/#server-hello
    {
        const char* serverhello_record =
            "16 03 03 00 7A 02 00 00 76 03 03 70 71 72 73 74"
            "75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 81 82 83 84"
            "85 86 87 88 89 8A 8B 8C 8D 8E 8F 20 E0 E1 E2 E3"
            "E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3"
            "F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 13 02 00 00"
            "2E 00 2B 00 02 03 04 00 33 00 24 00 1D 00 20 9F"
            "D7 AD 6D CF F4 29 8D D3 F9 6D 5B 1B 2A F9 10 A0"
            "53 5B 14 88 D7 F8 FA BB 34 9A 98 28 80 B6 15 --";
        bin_serverhello_record = base16_decode_rfc(serverhello_record);
        dump_record("server_hello", &server_session, bin_serverhello_record);
    }

    // > handshake type 2 (server_hello)
    //  > cipher suite 0x1302 TLS_AES_256_GCM_SHA384
    uint16 cipher_suite = server_session.get_tls_protection().get_cipher_suite();
    _test_case.assert(0x1302 == cipher_suite, __FUNCTION__, "cipher suite");

    // https://quic.xargs.org/#server-handshake-server_keys-calc
    {
        server_session.get_tls_protection().calc(&server_session);

        auto lambda_test = [&](tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect) -> void {
            server_session.get_tls_protection().get_item(tls_secret, secret);
            _logger->writeln("> %s : %s", text, base16_encode(secret).c_str());
            _test_case.assert(secret == base16_decode(expect), __FUNCTION__, text);
        };

        binary_t hello_hash;
        lambda_test(tls_secret_hello_hash, hello_hash, "hello_hash",
                    "e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd");

        binary_t shared_secret;
        lambda_test(tls_secret_shared_secret, shared_secret, "shared_secret", "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624");

        binary_t early_secret;
        lambda_test(tls_secret_early_secret, early_secret, "early_secret",
                    "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5");
        binary_t empty_hash;
        lambda_test(tls_secret_empty_hash, empty_hash, "empty_hash",
                    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        binary_t secret_handshake_derived;
        lambda_test(tls_secret_handshake_derived, secret_handshake_derived, "secret_handshake_derived",
                    "1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b");
        binary_t secret_handshake;
        lambda_test(tls_secret_handshake, secret_handshake, "secret_handshake",
                    "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299");
        binary_t secret_handshake_client;
        lambda_test(tls_secret_handshake_client, secret_handshake_client, "secret_handshake_client",
                    "db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0");
        binary_t secret_handshake_server;
        lambda_test(tls_secret_handshake_server, secret_handshake_server, "secret_handshake_server",
                    "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622");
        binary_t client_handshake_key;
        lambda_test(tls_secret_handshake_client_key, client_handshake_key, "client_handshake_key",
                    "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69");
        binary_t client_handshake_iv;
        lambda_test(tls_secret_handshake_client_iv, client_handshake_iv, "client_handshake_iv", "4256d2e0e88babdd05eb2f27");
        binary_t server_handshake_key;
        lambda_test(tls_secret_handshake_server_key, server_handshake_key, "server_handshake_key",
                    "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f");
        binary_t server_handshake_iv;
        lambda_test(tls_secret_handshake_server_iv, server_handshake_iv, "server_handshake_iv", "9563bc8b590f671f488d2da3");
    }
    // https://tls13.xargs.org/#server-change-cipher-spec
    {
        const char* change_cipher_spec = "14 03 03 00 01 01";
        binary_t bin_change_cipher_spec = base16_decode_rfc(change_cipher_spec);
        dump_record("change cipher spec", &server_session, bin_change_cipher_spec);
    }

    // https://tls13.xargs.org/#wrapped-record
    {
        const char* record =
            "17 03 03 00 17 6B E0 2F 9D A7 C2 DC 9D DE F5 6F"
            "24 68 B9 0A DF A2 51 01 AB 03 44 AE -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record (encrypted_extensions)", &server_session, bin_record);

        // TODO
        // https://tls13.xargs.org/#server-encrypted-extensions/annotated

        // > decrypted
        //   00000000 : 08 00 00 02 00 00 16 -- -- -- -- -- -- -- -- -- | .......
    }
    // https://tls13.xargs.org/#wrapped-record-2
    {
        const char* record =
            "17 03 03 03 43 BA F0 0A 9B E5 0F 3F 23 07 E7 26"
            "ED CB DA CB E4 B1 86 16 44 9D 46 C6 20 7A F6 E9"
            "95 3E E5 D2 41 1B A6 5D 31 FE AF 4F 78 76 4F 2D"
            "69 39 87 18 6C C0 13 29 C1 87 A5 E4 60 8E 8D 27"
            "B3 18 E9 8D D9 47 69 F7 73 9C E6 76 83 92 CA CA"
            "8D CC 59 7D 77 EC 0D 12 72 23 37 85 F6 E6 9D 6F"
            "43 EF FA 8E 79 05 ED FD C4 03 7E EE 59 33 E9 90"
            "A7 97 2F 20 69 13 A3 1E 8D 04 93 13 66 D3 D8 BC"
            "D6 A4 A4 D6 47 DD 4B D8 0B 0F F8 63 CE 35 54 83"
            "3D 74 4C F0 E0 B9 C0 7C AE 72 6D D2 3F 99 53 DF"
            "1F 1C E3 AC EB 3B 72 30 87 1E 92 31 0C FB 2B 09"
            "84 86 F4 35 38 F8 E8 2D 84 04 E5 C6 C2 5F 66 A6"
            "2E BE 3C 5F 26 23 26 40 E2 0A 76 91 75 EF 83 48"
            "3C D8 1E 6C B1 6E 78 DF AD 4C 1B 71 4B 04 B4 5F"
            "6A C8 D1 06 5A D1 8C 13 45 1C 90 55 C4 7D A3 00"
            "F9 35 36 EA 56 F5 31 98 6D 64 92 77 53 93 C4 CC"
            "B0 95 46 70 92 A0 EC 0B 43 ED 7A 06 87 CB 47 0C"
            "E3 50 91 7B 0A C3 0C 6E 5C 24 72 5A 78 C4 5F 9F"
            "5F 29 B6 62 68 67 F6 F7 9C E0 54 27 35 47 B3 6D"
            "F0 30 BD 24 AF 10 D6 32 DB A5 4F C4 E8 90 BD 05"
            "86 92 8C 02 06 CA 2E 28 E4 4E 22 7A 2D 50 63 19"
            "59 35 DF 38 DA 89 36 09 2E EF 01 E8 4C AD 2E 49"
            "D6 2E 47 0A 6C 77 45 F6 25 EC 39 E4 FC 23 32 9C"
            "79 D1 17 28 76 80 7C 36 D7 36 BA 42 BB 69 B0 04"
            "FF 55 F9 38 50 DC 33 C1 F9 8A BB 92 85 83 24 C7"
            "6F F1 EB 08 5D B3 C1 FC 50 F7 4E C0 44 42 E6 22"
            "97 3E A7 07 43 41 87 94 C3 88 14 0B B4 92 D6 29"
            "4A 05 40 E5 A5 9C FA E6 0B A0 F1 48 99 FC A7 13"
            "33 31 5E A0 83 A6 8E 1D 7C 1E 4C DC 2F 56 BC D6"
            "11 96 81 A4 AD BC 1B BF 42 AF D8 06 C3 CB D4 2A"
            "07 6F 54 5D EE 4E 11 8D 0B 39 67 54 BE 2B 04 2A"
            "68 5D D4 72 7E 89 C0 38 6A 94 D3 CD 6E CB 98 20"
            "E9 D4 9A FE ED 66 C4 7E 6F C2 43 EA BE BB CB 0B"
            "02 45 38 77 F5 AC 5D BF BD F8 DB 10 52 A3 C9 94"
            "B2 24 CD 9A AA F5 6B 02 6B B9 EF A2 E0 13 02 B3"
            "64 01 AB 64 94 E7 01 8D 6E 5B 57 3B D3 8B CE F0"
            "23 B1 FC 92 94 6B BC A0 20 9C A5 FA 92 6B 49 70"
            "B1 00 91 03 64 5C B1 FC FE 55 23 11 FF 73 05 58"
            "98 43 70 03 8F D2 CC E2 A9 1F C7 4D 6F 3E 3E A9"
            "F8 43 EE D3 56 F6 F8 2D 35 D0 3B C2 4B 81 B5 8C"
            "EB 1A 43 EC 94 37 E6 F1 E5 0E B6 F5 55 E3 21 FD"
            "67 C8 33 2E B1 B8 32 AA 8D 79 5A 27 D4 79 C6 E2"
            "7D 5A 61 03 46 83 89 19 03 F6 64 21 D0 94 E1 B0"
            "0A 9A 13 8D 86 1E 6F 78 A2 0A D3 E1 58 00 54 D2"
            "E3 05 25 3C 71 3A 02 FE 1E 28 DE EE 73 36 24 6F"
            "6A E3 43 31 80 6B 46 B4 7B 83 3C 39 B9 D3 1C D3"
            "00 C2 A6 ED 83 13 99 77 6D 07 F5 70 EA F0 05 9A"
            "2C 68 A5 F3 AE 16 B6 17 40 4A F7 B7 23 1A 4D 94"
            "27 58 FC 02 0B 3F 23 EE 8C 15 E3 60 44 CF D6 7C"
            "D6 40 99 3B 16 20 75 97 FB F3 85 EA 7A 4D 99 E8"
            "D4 56 FF 83 D4 1F 7B 8B 4F 06 9B 02 8A 2A 63 A9"
            "19 A7 0E 3A 10 E3 08 41 58 FA A5 BA FA 30 18 6C"
            "6B 2F 23 8E B5 30 C7 3E -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-2 (certificate)", &server_session, bin_record);
    }
    // https://tls13.xargs.org/certificate.html#server-certificate-detail/annotated
    // TODO
    {
        const char* cert =
            "30 82 03 21 30 82 02 09 A0 03 02 01 02 02 08 15"
            "5A 92 AD C2 04 8F 90 30 0D 06 09 2A 86 48 86 F7"
            "0D 01 01 0B 05 00 30 22 31 0B 30 09 06 03 55 04"
            "06 13 02 55 53 31 13 30 11 06 03 55 04 0A 13 0A"
            "45 78 61 6D 70 6C 65 20 43 41 30 1E 17 0D 31 38"
            "31 30 30 35 30 31 33 38 31 37 5A 17 0D 31 39 31"
            "30 30 35 30 31 33 38 31 37 5A 30 2B 31 0B 30 09"
            "06 03 55 04 06 13 02 55 53 31 1C 30 1A 06 03 55"
            "04 03 13 13 65 78 61 6D 70 6C 65 2E 75 6C 66 68"
            "65 69 6D 2E 6E 65 74 30 82 01 22 30 0D 06 09 2A"
            "86 48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 30"
            "82 01 0A 02 82 01 01 00 C4 80 36 06 BA E7 47 6B"
            "08 94 04 EC A7 B6 91 04 3F F7 92 BC 19 EE FB 7D"
            "74 D7 A8 0D 00 1E 7B 4B 3A 4A E6 0F E8 C0 71 FC"
            "73 E7 02 4C 0D BC F4 BD D1 1D 39 6B BA 70 46 4A"
            "13 E9 4A F8 3D F3 E1 09 59 54 7B C9 55 FB 41 2D"
            "A3 76 52 11 E1 F3 DC 77 6C AA 53 37 6E CA 3A EC"
            "BE C3 AA B7 3B 31 D5 6C B6 52 9C 80 98 BC C9 E0"
            "28 18 E2 0B F7 F8 A0 3A FD 17 04 50 9E CE 79 BD"
            "9F 39 F1 EA 69 EC 47 97 2E 83 0F B5 CA 95 DE 95"
            "A1 E6 04 22 D5 EE BE 52 79 54 A1 E7 BF 8A 86 F6"
            "46 6D 0D 9F 16 95 1A 4C F7 A0 46 92 59 5C 13 52"
            "F2 54 9E 5A FB 4E BF D7 7A 37 95 01 44 E4 C0 26"
            "87 4C 65 3E 40 7D 7D 23 07 44 01 F4 84 FF D0 8F"
            "7A 1F A0 52 10 D1 F4 F0 D5 CE 79 70 29 32 E2 CA"
            "BE 70 1F DF AD 6B 4B B7 11 01 F4 4B AD 66 6A 11"
            "13 0F E2 EE 82 9E 4D 02 9D C9 1C DD 67 16 DB B9"
            "06 18 86 ED C1 BA 94 21 02 03 01 00 01 A3 52 30"
            "50 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 05"
            "A0 30 1D 06 03 55 1D 25 04 16 30 14 06 08 2B 06"
            "01 05 05 07 03 02 06 08 2B 06 01 05 05 07 03 01"
            "30 1F 06 03 55 1D 23 04 18 30 16 80 14 89 4F DE"
            "5B CC 69 E2 52 CF 3E A3 00 DF B1 97 B8 1D E1 C1"
            "46 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00"
            "03 82 01 01 00 59 16 45 A6 9A 2E 37 79 E4 F6 DD"
            "27 1A BA 1C 0B FD 6C D7 55 99 B5 E7 C3 6E 53 3E"
            "FF 36 59 08 43 24 C9 E7 A5 04 07 9D 39 E0 D4 29"
            "87 FF E3 EB DD 09 C1 CF 1D 91 44 55 87 0B 57 1D"
            "D1 9B DF 1D 24 F8 BB 9A 11 FE 80 FD 59 2B A0 39"
            "8C DE 11 E2 65 1E 61 8C E5 98 FA 96 E5 37 2E EF"
            "3D 24 8A FD E1 74 63 EB BF AB B8 E4 D1 AB 50 2A"
            "54 EC 00 64 E9 2F 78 19 66 0D 3F 27 CF 20 9E 66"
            "7F CE 5A E2 E4 AC 99 C7 C9 38 18 F8 B2 51 07 22"
            "DF ED 97 F3 2E 3E 93 49 D4 C6 6C 9E A6 39 6D 74"
            "44 62 A0 6B 42 C6 D5 BA 68 8E AC 3A 01 7B DD FC"
            "8E 2C FC AD 27 CB 69 D3 CC DC A2 80 41 44 65 D3"
            "AE 34 8C E0 F3 4A B2 FB 9C 61 83 71 31 2B 19 10"
            "41 64 1C 23 7F 11 A5 D6 5C 84 4F 04 04 84 99 38"
            "71 2B 95 9E D6 85 BC 5C 5D D6 45 ED 19 90 94 73"
            "40 29 26 DC B4 0E 34 69 A1 59 41 E8 E2 CC A8 4B"
            "B6 08 46 36 A0 -- -- -- -- -- -- -- -- -- -- --";

        // # openssl x509 -in server.crt -text
        // Certificate:
        //     Data:
        //         Version: 3 (0x2)
        //         Serial Number:
        //             15:5a:92:ad:c2:04:8f:90
        //         Signature Algorithm: sha256WithRSAEncryption
        //         Issuer: C=US, O=Example CA
        //         Validity
        //             Not Before: Oct  5 01:38:17 2018 GMT
        //             Not After : Oct  5 01:38:17 2019 GMT
        //         Subject: C=US, CN=example.ulfheim.net
        //         Subject Public Key Info:
        //             Public Key Algorithm: rsaEncryption
        //                 Public-Key: (2048 bit)
        //                 Modulus:
        //                     00:c4:80:36:06:ba:e7:47:6b:08:94:04:ec:a7:b6:
        //                     91:04:3f:f7:92:bc:19:ee:fb:7d:74:d7:a8:0d:00:
        //                     1e:7b:4b:3a:4a:e6:0f:e8:c0:71:fc:73:e7:02:4c:
        //                     0d:bc:f4:bd:d1:1d:39:6b:ba:70:46:4a:13:e9:4a:
        //                     f8:3d:f3:e1:09:59:54:7b:c9:55:fb:41:2d:a3:76:
        //                     52:11:e1:f3:dc:77:6c:aa:53:37:6e:ca:3a:ec:be:
        //                     c3:aa:b7:3b:31:d5:6c:b6:52:9c:80:98:bc:c9:e0:
        //                     28:18:e2:0b:f7:f8:a0:3a:fd:17:04:50:9e:ce:79:
        //                     bd:9f:39:f1:ea:69:ec:47:97:2e:83:0f:b5:ca:95:
        //                     de:95:a1:e6:04:22:d5:ee:be:52:79:54:a1:e7:bf:
        //                     8a:86:f6:46:6d:0d:9f:16:95:1a:4c:f7:a0:46:92:
        //                     59:5c:13:52:f2:54:9e:5a:fb:4e:bf:d7:7a:37:95:
        //                     01:44:e4:c0:26:87:4c:65:3e:40:7d:7d:23:07:44:
        //                     01:f4:84:ff:d0:8f:7a:1f:a0:52:10:d1:f4:f0:d5:
        //                     ce:79:70:29:32:e2:ca:be:70:1f:df:ad:6b:4b:b7:
        //                     11:01:f4:4b:ad:66:6a:11:13:0f:e2:ee:82:9e:4d:
        //                     02:9d:c9:1c:dd:67:16:db:b9:06:18:86:ed:c1:ba:
        //                     94:21
        //                 Exponent: 65537 (0x10001)
        //         X509v3 extensions:
        //             X509v3 Key Usage: critical
        //                 Digital Signature, Key Encipherment
        //             X509v3 Extended Key Usage:
        //                 TLS Web Client Authentication, TLS Web Server Authentication
        //             X509v3 Authority Key Identifier:
        //                 89:4F:DE:5B:CC:69:E2:52:CF:3E:A3:00:DF:B1:97:B8:1D:E1:C1:46
        //     Signature Algorithm: sha256WithRSAEncryption
        //     Signature Value:
        //         59:16:45:a6:9a:2e:37:79:e4:f6:dd:27:1a:ba:1c:0b:fd:6c:
        //         d7:55:99:b5:e7:c3:6e:53:3e:ff:36:59:08:43:24:c9:e7:a5:
        //         04:07:9d:39:e0:d4:29:87:ff:e3:eb:dd:09:c1:cf:1d:91:44:
        //         55:87:0b:57:1d:d1:9b:df:1d:24:f8:bb:9a:11:fe:80:fd:59:
        //         2b:a0:39:8c:de:11:e2:65:1e:61:8c:e5:98:fa:96:e5:37:2e:
        //         ef:3d:24:8a:fd:e1:74:63:eb:bf:ab:b8:e4:d1:ab:50:2a:54:
        //         ec:00:64:e9:2f:78:19:66:0d:3f:27:cf:20:9e:66:7f:ce:5a:
        //         e2:e4:ac:99:c7:c9:38:18:f8:b2:51:07:22:df:ed:97:f3:2e:
        //         3e:93:49:d4:c6:6c:9e:a6:39:6d:74:44:62:a0:6b:42:c6:d5:
        //         ba:68:8e:ac:3a:01:7b:dd:fc:8e:2c:fc:ad:27:cb:69:d3:cc:
        //         dc:a2:80:41:44:65:d3:ae:34:8c:e0:f3:4a:b2:fb:9c:61:83:
        //         71:31:2b:19:10:41:64:1c:23:7f:11:a5:d6:5c:84:4f:04:04:
        //         84:99:38:71:2b:95:9e:d6:85:bc:5c:5d:d6:45:ed:19:90:94:
        //         73:40:29:26:dc:b4:0e:34:69:a1:59:41:e8:e2:cc:a8:4b:b6:
        //         08:46:36:a0
        // -----BEGIN CERTIFICATE-----
        // MIIDITCCAgmgAwIBAgIIFVqSrcIEj5AwDQYJKoZIhvcNAQELBQAwIjELMAkGA1UE
        // BhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0EwHhcNMTgxMDA1MDEzODE3WhcNMTkx
        // MDA1MDEzODE3WjArMQswCQYDVQQGEwJVUzEcMBoGA1UEAxMTZXhhbXBsZS51bGZo
        // ZWltLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSANga650dr
        // CJQE7Ke2kQQ/95K8Ge77fXTXqA0AHntLOkrmD+jAcfxz5wJMDbz0vdEdOWu6cEZK
        // E+lK+D3z4QlZVHvJVftBLaN2UhHh89x3bKpTN27KOuy+w6q3OzHVbLZSnICYvMng
        // KBjiC/f4oDr9FwRQns55vZ858epp7EeXLoMPtcqV3pWh5gQi1e6+UnlUoee/iob2
        // Rm0NnxaVGkz3oEaSWVwTUvJUnlr7Tr/XejeVAUTkwCaHTGU+QH19IwdEAfSE/9CP
        // eh+gUhDR9PDVznlwKTLiyr5wH9+ta0u3EQH0S61mahETD+Lugp5NAp3JHN1nFtu5
        // BhiG7cG6lCECAwEAAaNSMFAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG
        // AQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBSJT95bzGniUs8+owDfsZe4HeHB
        // RjANBgkqhkiG9w0BAQsFAAOCAQEAWRZFppouN3nk9t0nGrocC/1s11WZtefDblM+
        // /zZZCEMkyeelBAedOeDUKYf/4+vdCcHPHZFEVYcLVx3Rm98dJPi7mhH+gP1ZK6A5
        // jN4R4mUeYYzlmPqW5Tcu7z0kiv3hdGPrv6u45NGrUCpU7ABk6S94GWYNPyfPIJ5m
        // f85a4uSsmcfJOBj4slEHIt/tl/MuPpNJ1MZsnqY5bXREYqBrQsbVumiOrDoBe938
        // jiz8rSfLadPM3KKAQURl0640jODzSrL7nGGDcTErGRBBZBwjfxGl1lyETwQEhJk4
        // cSuVntaFvFxd1kXtGZCUc0ApJty0DjRpoVlB6OLMqEu2CEY2oA==
        // -----END CERTIFICATE-----
    }
    // https://tls13.xargs.org/#wrapped-record-3
    // https://tls13.xargs.org/#server-certificate-verify
    {
        const char* record =
            "17 03 03 01 19 73 71 9F CE 07 EC 2F 6D 3B BA 02"
            "92 A0 D4 0B 27 70 C0 6A 27 17 99 A5 33 14 F6 F7"
            "7F C9 5C 5F E7 B9 A4 32 9F D9 54 8C 67 0E BE EA"
            "2F 2D 5C 35 1D D9 35 6E F2 DC D5 2E B1 37 BD 3A"
            "67 65 22 F8 CD 0F B7 56 07 89 AD 7B 0E 3C AB A2"
            "E3 7E 6B 41 99 C6 79 3B 33 46 ED 46 CF 74 0A 9F"
            "A1 FE C4 14 DC 71 5C 41 5C 60 E5 75 70 3C E6 A3"
            "4B 70 B5 19 1A A6 A6 1A 18 FA FF 21 6C 68 7A D8"
            "D1 7E 12 A7 E9 99 15 A6 11 BF C1 A2 BE FC 15 E6"
            "E9 4D 78 46 42 E6 82 FD 17 38 2A 34 8C 30 10 56"
            "B9 40 C9 84 72 00 40 8B EC 56 C8 1E A3 D7 21 7A"
            "B8 E8 5A 88 71 53 95 89 9C 90 58 7F 72 E8 DD D7"
            "4B 26 D8 ED C1 C7 C8 37 D9 F2 EB BC 26 09 62 21"
            "90 38 B0 56 54 A6 3A 0B 12 99 9B 4A 83 06 A3 DD"
            "CC 0E 17 C5 3B A8 F9 C8 03 63 F7 84 13 54 D2 91"
            "B4 AC E0 C0 F3 30 C0 FC D5 AA 9D EE F9 69 AE 8A"
            "B2 D9 8D A8 8E BB 6E A8 0A 3A 11 F0 0E A2 96 A3"
            "23 23 67 FF 07 5E 1C 66 DD 9C BE DC 47 13 -- --";
        binary_t bin_record = base16_decode_rfc(record);
        // > handshake type 15 (certificate_verify)
        //  > signature algorithm 0x0804 rsa_pss_rsae_sha256
        //  > len 0x0100(256)
        dump_record("wrapped-record-3 (certificate_verify)", &server_session, bin_record);
    }
    // https://tls13.xargs.org/#wrapped-record-4
    // https://tls13.xargs.org/#server-handshake-finished
    {
        const char* record =
            "17 03 03 00 45 10 61 DE 27 E5 1C 2C 9F 34 29 11"
            "80 6F 28 2B 71 0C 10 63 2C A5 00 67 55 88 0D BF"
            "70 06 00 2D 0E 84 FE D9 AD F2 7A 43 B5 19 23 03"
            "E4 DF 5C 28 5D 58 E3 C7 62 24 07 84 40 C0 74 23"
            "74 74 4A EC F2 8C F3 18 2F D0 -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("wrapped-record-4 (finished)", &server_session, bin_record);
    }
    // https://tls13.xargs.org/#server-application-keys-calc
    {
        // auto hash = server_session.get_tls_protection().get_transcript_hash();
        // if (hash) {
        //     binary_t handshake_hash;
        //     hash->digest(handshake_hash);
        //     _logger->hdump("> handshake_hash", handshake_hash);
        // }
    }  //
    {
        const char* record =
            "17 03 03 00 45 9f f9 b0 63 17 51 77 32 2a 46 dd 98 96 f3 c3 bb 82 0a b5 17 43 eb c2 5f da dd 53 45 4b 73 de b5 4c c7 24 8d 41 1a 18 bc cf 65 7a "
            "96 08 24 e9 a1 93 64 83 7c 35 0a 69 a8 8d 4b f6 35 c8 5e b8 74 ae bc 9d fd e8";
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    if (option.verbose) {
        set_trace_debug(debug_handler);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    openssl_startup();

    // RFC 8448 Example Handshake Traces for TLS 1.3
    test_rfc8448_2();
    test_rfc8448_3();
    test_rfc8448_4();
    test_rfc8448_5();
    test_rfc8448_6();
    test_rfc8448_7();

    // https://tls13.xargs.org/
    test_tls13_xargs_org();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
