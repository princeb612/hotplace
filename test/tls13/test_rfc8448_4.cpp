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

// This handshake resumes from the handshake in Section 3.
void test_rfc8448_4() {
    _test_case.begin("RFC 8448 4.  Resumed 0-RTT Handshake");
    return_t ret = errorcode_t::success;
    basic_stream bs;
    size_t pos = 0;
    crypto_keychain keychain;

    // {client}  create an ephemeral x25519 key pair:
    {
        constexpr char constexpr_client_epk[] = "client epk";
        const char* d =
            "bf f9 11 88 28 38 46 dd 6a 21 34 ef 71"
            "80 ca 2b 0b 14 fb 10 dc e7 07 b5 09 8c 0d dd c8 13 b2 df";
        const char* x =
            "e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34"
            "6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b";
        crypto_key key;
        ret = keychain.add_ec_b16rfc(&key, ec_x25519, x, nullptr, d, keydesc(constexpr_client_epk));

        _logger->writeln(constexpr_client_epk);
        dump_key(key.find(constexpr_client_epk), &bs);
        _logger->writeln(bs);
        bs.clear();

        _test_case.test(ret, __FUNCTION__, "ephemeral x25519 key pair");
    }
    // {client}  send handshake record:
    {
        const char* record =
            "16 03 01 02 00 01 00 01 fc 03 03 1b"
            "c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49"
            "d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00"
            "01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
            "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
            "01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d"
            "96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1"
            "8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
            "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
            "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01"
            "00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59"
            "ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb"
            "33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc"
            "55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3"
            "6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66"
            "4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29"
            "51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72"
            "14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6"
            "21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93"
            "4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca"
            "3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f"
            "9d";
        binary_t bin_record = base16_decode_rfc(record);
        dump_record("#1A client_hello", &rfc8448_session, bin_record, role_client);
    }
    {
        binary_t resumption_early;
        test_keycalc(&rfc8448_session, tls_secret_resumption_early, resumption_early, "resumption_early",
                     "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
    }
    {
        const char* record =
            "17 03 03 00 17 ab 1d f4 20 e7 5c 45"
            "7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0";
        // binary_t bin_record = base16_decode_rfc(record);
        // dump_record("#1A client_hello", &rfc8448_session, bin_record, role_client);
    }
}
