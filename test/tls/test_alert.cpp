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
 */

#include "sample.hpp"

void test_alert() {
    _test_case.begin("alert");

    tls_session session;

    // test scenario - flow violation
    // test/tls/tls12/tls12etm.pcapng

    // client hello
    {
        const char* record =
            "16 03 01 00 c0 01 00 00 bc 03 03 96 89 88 b1 0e"
            "d8 d7 2b e8 7f ae a5 64 a0 d8 15 a4 62 f1 41 ca"
            "80 19 ad c5 33 ae c9 89 15 2b ff 00 00 36 c0 2c"
            "c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f 00 9e"
            "c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0 14"
            "00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d 00 3c"
            "00 35 00 2f 01 00 00 5d ff 01 00 01 00 00 0b 00"
            "04 03 00 01 02 00 0a 00 0c 00 0a 00 1d 00 17 00"
            "1e 00 19 00 18 00 23 00 00 00 16 00 00 00 17 00"
            "00 00 0d 00 30 00 2e 04 03 05 03 06 03 08 07 08"
            "08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04 08"
            "05 08 06 04 01 05 01 06 01 03 03 03 01 03 02 04"
            "02 05 02 06 02";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("client_hello", &session, from_client, bin_record);
    }
    // server hello
    {
        const char* record =
            "16 03 03 00 45 02 00 00 41 03 03 65 8b 66 a2 af"
            "4e 1b 13 dd 8b 50 51 78 90 21 13 a5 bf b0 21 ee"
            "8b 24 30 cf ab 97 20 b1 37 6d 63 00 c0 27 00 00"
            "19 ff 01 00 01 00 00 0b 00 04 03 00 01 02 00 23"
            "00 00 00 16 00 00 00 17 00 00";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("server_hello", &session, from_server, bin_record);
    }
    // no certificate handshake
    // server key exchange
    {
        const char* record =
            "16 03 03 01 2c 0c 00 01 28 03 00 1d 20 8e 93 3b"
            "4c a7 02 61 06 89 0b e2 d0 3e 0e 05 64 a7 37 9e"
            "b8 b9 0b 5b 3d 68 2c 55 f4 a5 ef 46 67 08 04 01"
            "00 50 ec 45 47 75 24 3b 9c af e9 2f 3a af 50 bb"
            "aa 85 f0 67 5c b6 cd 12 e6 7d 01 1a 3f a5 f4 0a"
            "38 a2 4b 7d 90 b1 3f 7e 41 3b c6 d2 e0 c6 97 39"
            "6f 22 aa 2b ee 09 d6 83 b9 ab 77 c0 a4 63 e8 cb"
            "f2 0a 67 1d 72 71 b8 7a a9 36 b4 90 ad 6d 22 25"
            "01 ee 52 3b ce b9 56 8b f6 46 38 cf d9 dc d5 30"
            "8e 3c aa e8 05 d7 05 c4 bb 25 33 43 8f a7 5c 72"
            "a6 c1 c1 f9 3d 89 a8 9c b2 15 86 82 11 0e 1f 9c"
            "00 12 6f cd 64 01 57 08 fa 5a 85 f6 5a be 58 e4"
            "18 20 79 d8 13 6a cf 9a 3a 81 b7 ba 08 e4 4c ed"
            "e6 53 f9 f9 a5 7d 25 27 b7 84 a2 73 86 83 fe 28"
            "d5 50 c4 ad c6 c2 10 24 f7 89 ec b1 18 a7 75 84"
            "ef d5 52 08 dc 6d 74 0e 99 a7 2e 0b cf af 85 3b"
            "c7 15 a3 52 29 26 19 d0 cf fc 29 f2 1d d8 59 b1"
            "5d 4a 54 2b 9e 1e dd 52 fe d8 74 a2 78 ca f5 1b"
            "c8 3a c1 06 16 ad 35 4a 84 be 16 2b c6 10 a8 b2"
            "f7";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        auto ret = dump_record("server_key_exchange", &session, from_server, bin_record, false);
        _test_case.test(errorcode_t::error_handshake == ret, __FUNCTION__, "unexpected message");
    }

    {
        std::set<uint8> fatal_alerts;
        // unexpected message
        auto lambda = [&](uint8 level, uint8 desc) -> void {
            if (tls_alertlevel_fatal == level) {
                fatal_alerts.insert(desc);
            }
            _logger->writeln("level %i desc %i", level, desc);
        };
        session.get_alert(from_server, lambda);

        auto iter = fatal_alerts.find(tls_alertdesc_unexpected_message);
        bool test = (fatal_alerts.end() != iter);
        _test_case.assert(test, __FUNCTION__, "unexpected message");
    }
}
