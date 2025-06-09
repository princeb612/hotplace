/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @remarks
 *      RFC 7541 HPACK: Header Compression for HTTP/2
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_h2_header_frame_fragment() {
    _test_case.begin("HTTP/2 Header Compression");
    const OPTION& option = _cmdline->value();

    // [test vector] chrome generated header

    struct testvector {
        const char* key;
        const char* value;
    };

    hpack_dynamic_table session;
    binary_t bin;
    size_t pos = 0;
    std::string name;
    std::string value;

    const char* sample1 =
        "82 41 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 87 84 40 "
        "87 41 48 B1 27 5A D1 FF B8 FE 6F 4F 61 E9 35 B4 "
        "FF 3F 7D E0 FE 42 26 BF 9F A5 3F 9C 47 3C D4 15 "
        "4B D3 D8 7A 4B FC FD F7 83 F9 08 9A FE 7E 94 FE "
        "74 9D 2B 42 BD DB 07 54 9F CF DF 78 3F 97 DF FE "
        "7F 40 8B 41 48 B1 27 5A D1 AD 49 E3 35 05 02 3F "
        "30 40 8D 41 48 B1 27 5A D1 AD 5D 03 4C A7 B2 9F "
        "88 FE 79 1A A9 0F E1 1F CF 40 92 B6 B9 AC 1C 85 "
        "58 D5 20 A4 B6 C2 AD 61 7B 5A 54 25 1F 01 31 7A "
        "D5 D0 7F 66 A2 81 B0 DA E0 53 FA E4 6A A4 3F 84 "
        "29 A7 7A 81 02 E0 FB 53 91 AA 71 AF B5 3C B8 D7 "
        "F6 A4 35 D7 41 79 16 3C C6 4B 0D B2 EA EC B8 A7 "
        "F5 9B 1E FD 19 FE 94 A0 DD 4A A6 22 93 A9 FF B5 "
        "2F 4F 61 E9 2B 01 13 4B 81 70 2E 05 37 0E 51 D8 "
        "66 1B 65 D5 D9 73 53 E5 49 7C A5 89 D3 4D 1F 43 "
        "AE BA 0C 41 A4 C7 A9 8F 33 A6 9A 3F DF 9A 68 FA "
        "1D 75 D0 62 0D 26 3D 4C 79 A6 8F BE D0 01 77 FE "
        "8D 48 E6 2B 03 EE 69 7E 8D 48 E6 2B 1E 0B 1D 7F "
        "46 A4 73 15 81 D7 54 DF 5F 2C 7C FD F6 80 0B BD "
        "F4 3A EB A0 C4 1A 4C 7A 98 41 A6 A8 B2 2C 5F 24 "
        "9C 75 4C 5F BE F0 46 CF DF 68 00 BB BF 40 8A 41 "
        "48 B4 A5 49 27 59 06 49 7F 83 A8 F5 17 40 8A 41 "
        "48 B4 A5 49 27 5A 93 C8 5F 86 A8 7D CD 30 D2 5F "
        "40 8A 41 48 B4 A5 49 27 5A D4 16 CF 02 3F 31 40 "
        "8A 41 48 B4 A5 49 27 5A 42 A1 3F 86 90 E4 B6 92 "
        "D4 9F 50 92 9B D9 AB FA 52 42 CB 40 D2 5F A5 23 "
        "B3 E9 4F 68 4C 9F 51 9C EA 75 B3 6D FA EA 7F BE "
        "D0 01 77 FE 8B 52 DC 37 7D F6 80 0B BD F4 5A BE "
        "FB 40 05 DD 40 86 AE C3 1E C3 27 D7 85 B6 00 7D "
        "28 6F -- -- -- -- -- -- -- -- -- -- -- -- -- -- ";

    if (option.verbose) {
        _logger->writeln("decode HEADER");
    }

    pos = 0;
    bin = std::move(base16_decode_rfc(sample1));
    skey_value kv1;
    while (pos < bin.size()) {
        encoder->decode_header(&session, &bin[0], bin.size(), pos, name, value);
        kv1.set(name, value);
        if (option.verbose) {
            _logger->writeln("> %s: %s", name.c_str(), value.c_str());
            fflush(stdout);
        }
    }
    session.commit();
    testvector _tv1[] = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "localhost:9000"},
        {":path", "/"},
    };
    for (auto item : _tv1) {
        _test_case.assert(kv1[item.key] == item.value, __FUNCTION__, "decode %s: %s", item.key, kv1[item.key].c_str());
    }

    const char* sample2 =
        "82 CB 87 04 89 62 51 F7 31 0F 52 E6 21 FF CA C9 "
        "C6 C8 53 B1 35 23 98 AC 0F B9 A5 FA 35 23 98 AC "
        "78 2C 75 FD 1A 91 CC 56 07 5D 53 7D 1A 91 CC 56 "
        "11 DE 6F F7 E6 9A 3E 8D 48 E6 2B 1F 3F 5F 2C 7C "
        "FD F6 80 0B BD 7F 06 88 40 E9 2A C7 B0 D3 1A AF "
        "7F 06 85 A8 EB 10 F6 23 7F 05 84 35 23 98 BF 73 "
        "90 9D 29 AD 17 18 62 83 90 74 4E 74 26 E3 E0 00 "
        "18 C5 C4 7F 04 85 B6 00 FD 28 6F -- -- -- -- -- ";

    if (option.verbose) {
        _logger->writeln("decode HEADER");
    }

    pos = 0;
    bin = std::move(base16_decode_rfc(sample2));
    skey_value kv2;
    while (pos < bin.size()) {
        encoder->decode_header(&session, &bin[0], bin.size(), pos, name, value);
        kv2.set(name, value);
        if (option.verbose) {
            _logger->writeln("> %s: %s", name.c_str(), value.c_str());
            fflush(stdout);
        }
        session.commit();
    }
    testvector _tv2[] = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "localhost:9000"},
        {":path", "/favicon.ico"},
    };
    for (auto item : _tv2) {
        _test_case.assert(kv2[item.key] == item.value, __FUNCTION__, "decode %s: %s", item.key, kv2[item.key].c_str());
    }
}
