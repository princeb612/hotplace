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
};

crypto_key keys;
crypto_keychain keychain;

void test_rfc8448_2() {
    _test_case.begin("RFC 8448 2.  Private Keys");
    basic_stream bs;
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
        keychain.add_rsa(&keys, "server RSA certificate", "RSA", base16_decode_rfc(n), base16_decode_rfc(e), base16_decode_rfc(d));
        dump_key(keys.find("server RSA certificate"), &bs);
        _logger->writeln(bs);
    }
}

void test_rfc8448_3() {
    _test_case.begin("RFC 8448 3.  Simple 1-RTT Handshake");
    return_t ret = errorcode_t::success;
    basic_stream bs;
    size_t pos = 0;

    const char* x =
        "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d"
        "ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c";
    const char* y = "";
    const char* d =
        "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78"
        "4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05";
    keychain.add_ec(&keys, "client epk", "EdDSA", "X25519", base16_decode_rfc(x), base16_decode_rfc(y), base16_decode_rfc(d));
    dump_key(keys.find("client epk"), &bs);
    _logger->writeln(bs);
    bs.clear();

    const char* client_hello =
        "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63"
        "ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83"
        "02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b"
        "00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00"
        "12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23"
        "00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2"
        "3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a"
        "af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03"
        "02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06"
        "02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";
    const char* client_handshake =
        "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba"
        "1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02"
        "4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00"
        "09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12"
        "00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00"
        "00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d"
        "8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af"
        "2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02"
        "03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02"
        "02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";
    // [
    //   {
    //     "ClientHello": {
    //       "version": "Tls12",
    //       "random_data": "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef628324dece7",
    //       "session_id": "",
    //       "cipherlist": [
    //         "0x1301(TLS_AES_128_GCM_SHA256)",
    //         "0x1303(TLS_CHACHA20_POLY1305_SHA256)",
    //         "0x1302(TLS_AES_256_GCM_SHA384)"
    //       ],
    //       "compressionlist": [
    //         "Null"
    //       ],
    //       "extensions": [
    //         "TlsExtension::SNI([\"type=HostName,name=server\"])",
    //         "TlsExtension::RenegotiationInfo(data=[])",
    //         "TlsExtension::EllipticCurves([\"EcdhX25519\", \"Secp256r1\", \"Secp384r1\", \"Secp521r1\", \"Ffdhe2048\", \"Ffdhe3072\",
    //              \"Ffdhe4096\", \"Ffdhe6144\", \"Ffdhe8192\"])",
    //         "TlsExtension::SessionTicket(data=[])",
    //         "TlsExtension::KeyShare(
    //              data=[00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c])",
    //         "TlsExtension::SupportedVersions(v=[\"Tls13\"])",
    //         "TlsExtension::SignatureAlgorithms([\"ecdsa_secp256r1_sha256\", \"ecdsa_secp384r1_sha384\", \"ecdsa_secp521r1_sha512\", \"ecdsa_sha1\",
    //             \"rsa_pss_rsae_sha256\", \"rsa_pss_rsae_sha384\", \"rsa_pss_rsae_sha512\", \"rsa_pkcs1_sha256\", \"rsa_pkcs1_sha384\", \"rsa_pkcs1_sha512\",
    //             \"rsa_pkcs1_sha1\", \"HashSign(Sha256,Dsa)\", \"HashSign(Sha384,Dsa)\", \"HashSign(Sha512,Dsa)\", \"HashSign(Sha1,Dsa)\"])",
    //         "TlsExtension::PskExchangeModes([1])",
    //         "TlsExtension::RecordSizeLimit(data=16385)"
    //       ]
    //     }
    //   }
    // ]
    const char* client_record =
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

    binary_t bin_client_hello = base16_decode_rfc(client_hello);
    binary_t bin_client_handshake = base16_decode_rfc(client_handshake);
    binary_t bin_client_record = base16_decode_rfc(client_record);

    auto lambda_dump_record = [&](const char* text, const binary_t& bin) -> return_t {
        _logger->hdump(format("> %s", text), bin);

        return_t ret = errorcode_t::success;
        pos = 0;
        ret = tls_dump_record(&bs, &bin[0], bin.size(), pos);
        _logger->writeln(bs);
        bs.clear();

        // https://williamlieurance.com/tls-handshake-parser/
        _logger->writeln("copy and paste https://williamlieurance.com/tls-handshake-parser/");
        _logger->writeln(base16_encode(bin));

        return ret;
    };

    // bin_client_hello == bin_client_handshake
    ret = lambda_dump_record("client record", bin_client_record);
    _test_case.test(ret, __FUNCTION__, "dump handshake record");
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

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
