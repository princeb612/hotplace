/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_der() {
    _test_case.begin("DER");
    return_t ret = success;
    // RFC 8448
    // 3.  Simple 1-RTT Handshake
    // server certificate
    const char* cert =
        "30 82 01 AC 30 82 01 15 A0 03 02 01 02 02 01 02"
        "30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00 30"
        "0E 31 0C 30 0A 06 03 55 04 03 13 03 72 73 61 30"
        "1E 17 0D 31 36 30 37 33 30 30 31 32 33 35 39 5A"
        "17 0D 32 36 30 37 33 30 30 31 32 33 35 39 5A 30"
        "0E 31 0C 30 0A 06 03 55 04 03 13 03 72 73 61 30"
        "81 9F 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05"
        "00 03 81 8D 00 30 81 89 02 81 81 00 B4 BB 49 8F"
        "82 79 30 3D 98 08 36 39 9B 36 C6 98 8C 0C 68 DE"
        "55 E1 BD B8 26 D3 90 1A 24 61 EA FD 2D E4 9A 91"
        "D0 15 AB BC 9A 95 13 7A CE 6C 1A F1 9E AA 6A F9"
        "8C 7C ED 43 12 09 98 E1 87 A8 0E E0 CC B0 52 4B"
        "1B 01 8C 3E 0B 63 26 4D 44 9A 6D 38 E2 2A 5F DA"
        "43 08 46 74 80 30 53 0E F0 46 1C 8C A9 D9 EF BF"
        "AE 8E A6 D1 D0 3E 2B D1 93 EF F0 AB 9A 80 02 C4"
        "74 28 A6 D3 5A 8D 88 D7 9F 7F 1E 3F 02 03 01 00"
        "01 A3 1A 30 18 30 09 06 03 55 1D 13 04 02 30 00"
        "30 0B 06 03 55 1D 0F 04 04 03 02 05 A0 30 0D 06"
        "09 2A 86 48 86 F7 0D 01 01 0B 05 00 03 81 81 00"
        "85 AA D2 A0 E5 B9 27 6B 90 8C 65 F7 3A 72 67 17"
        "06 18 A5 4C 5F 8A 7B 33 7D 2D F7 A5 94 36 54 17"
        "F2 EA E8 F8 A5 8C 8F 81 72 F9 31 9C F3 6B 7F D6"
        "C5 5B 80 F2 1A 03 01 51 56 72 60 96 FD 33 5E 5E"
        "67 F2 DB F1 02 70 2E 60 8C CA E6 BE C1 FC 63 A4"
        "2A 99 BE 5C 3E B7 10 7C 3C 54 E9 B9 EB 2B D5 20"
        "3B 1C 3B 84 E0 A8 B2 F7 59 40 9B A3 EA C9 D9 1D"
        "40 2D CC 0C C8 F8 96 12 29 AC 91 87 B4 2B 4D E1";
    binary_t bin_sample = std::move(base16_decode_rfc(cert));

    const char* kid = "der";
    basic_stream bs;
    crypto_key key;
    crypto_keychain keychain;
    ret = keychain.load_der(&key, &bin_sample[0], bin_sample.size(), keydesc(kid));
    _logger->hdump("DER", bin_sample, 16, 3);
    _test_case.test(ret, __FUNCTION__, "RFC 8448 3. server certificate");

    auto x509 = key.find_x509(kid);
    _logger->write(bs);
    _test_case.assert(x509, __FUNCTION__, "dump");

    binary_t bin_der;
    ret = keychain.write_der(x509, bin_der);

    _logger->hdump("DER", bin_der, 16, 3);
    _test_case.assert(bin_der == bin_sample, __FUNCTION__, "write DER");
}
