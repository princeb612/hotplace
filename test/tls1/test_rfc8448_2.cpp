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

void test_rfc8448_2() {
    _test_case.begin("RFC 8448 2.  Private Keys");
    basic_stream bs;
    crypto_keychain keychain;

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

        crypto_key key;
        keychain.add_rsa_b16rfc(&key, nid_rsa, n, e, d, keydesc("server RSA certificate"));
        dump_key(key.find("server RSA certificate"), &bs);
        _logger->writeln(bs);
    }
}
