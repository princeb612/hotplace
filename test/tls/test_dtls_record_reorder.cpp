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

void test_dtls_record_reoder() {
    _test_case.begin("DTLS record reorder");
    tls_session session(session_dtls);
    auto& reorder = session.get_dtls_record_reorder();

    return_t ret = errorcode_t::success;
    uint16 epoch = 0;
    uint64 seq = 0;
    binary_t packet;

    // S->C, epoch 0 seq 0 - hello_verify_request
    {
        const char* record =
            "16 fe ff 00 00 00 00 00 00 00 00 00 23 03 00 00"
            "17 00 00 00 00 00 00 00 17 fe ff 14 d8 32 1d 16"
            "e2 72 e5 3c bc 26 77 2d ff 69 a2 56 ed cd cc 0a";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());

        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (0 == seq), __FUNCTION__, "expect epoch 0 seq 0");
    }
    // S->C, epoch 0 seq 3 - certificate (fragment)
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
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());

        ret = reorder.consume(epoch, seq, packet);
        _test_case.assert(errorcode_t::not_ready == ret, __FUNCTION__, "expect not_ready");
    }
    // S->C, epoch 0 seq 1 - server_hello
    // S->C, epoch 0 seq 2 - certificate (fragment)
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
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());

        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (1 == seq), __FUNCTION__, "expect epoch 0 seq 1");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (2 == seq), __FUNCTION__, "expect epoch 0 seq 2");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (3 == seq), __FUNCTION__, "expect epoch 0 seq 3");
        ret = reorder.consume(epoch, seq, packet);
        _test_case.assert(errorcode_t::not_ready == ret, __FUNCTION__, "expect not_ready");
    }
    // S->C, epoch 0 seq 5 - certificate (fragment)
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
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());
    }
    // S->C, epoch 0 seq 4 - certificate (fragment)
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
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());

        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (4 == seq), __FUNCTION__, "expect epoch 0 seq 4");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (5 == seq), __FUNCTION__, "expect epoch 0 seq 5");
    }
    // S->C, epoch 0 seq 7 - certificate (reassembled)
    // S->C, epoch 0 seq 8 - server_key_exchange (fragment)
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
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());
    }
    // S->C, epoch 0 seq 6 - certificate (fragment)
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
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());

        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (6 == seq), __FUNCTION__, "expect epoch 0 seq 6");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (7 == seq), __FUNCTION__, "expect epoch 0 seq 7");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (8 == seq), __FUNCTION__, "expect epoch 0 seq 8");
    }
    // epoch 0 seq 10 - server_hello_done
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 0a 00 0c 0e 00 00"
            "00 00 04 00 00 00 00 00 00";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());
    }
    // S->C, epoch 0 seq 9 - server_key_exchange (reassembled)
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
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());
    }
    // S->C, epoch 1 seq 1 - encrypted alert
    {
        const char* record =
            "15 fe fd 00 01 00 00 00 00 00 01 00 40 1c 80 74"
            "c8 39 a7 19 3d 4e 1d 31 82 f0 5c f9 ca c3 1d 8b"
            "0f 0c 8c 3a 1a be 77 ee 4b e7 96 8d bf fb 32 ed"
            "06 d6 56 2d b9 e5 d9 62 23 fc c2 c0 cf 39 aa bd"
            "3e 38 e8 ab 29 14 61 64 11 28 45 a9 59";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());
    }
    // S->C, epoch 0 seq 12 - change_cipher_spec
    // S->C, epoch 1 seq 0 - encrypted_handshake message
    {
        const char* record =
            "14 fe fd 00 00 00 00 00 00 00 0c 00 01 01 16 fe"
            "fd 00 01 00 00 00 00 00 00 00 50 43 7b 0b 20 0b"
            "70 d3 a0 5e a6 31 8d af dc 14 5f ca 16 e2 05 03"
            "40 2a a2 0d 11 74 68 17 a5 60 f0 94 5b b7 a2 30"
            "e0 7e 05 a1 80 ba f8 1d 01 a0 62 ec 7c b4 95 da"
            "c3 99 95 90 59 4c f5 83 e3 cf 53 c8 16 6c 2d 8f"
            "70 4e 30 15 d9 f7 43 d7 3a 65 94";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());
    }
    // S->C, epoch 0 seq 11 - new_session_ticket
    {
        const char* record =
            "16 fe fd 00 00 00 00 00 00 00 0b 00 c2 04 00 00"
            "b6 00 05 00 00 00 00 00 b6 00 00 1c 20 00 b0 81"
            "91 12 df b7 f9 8c 99 db 44 56 fa 53 74 da 51 bb"
            "30 e2 f5 f2 f0 81 66 13 76 33 40 22 0b 0b f0 c5"
            "20 81 2b 62 f9 fa cc ac aa e8 08 a2 c2 c6 3e 70"
            "51 fc 62 e1 cb 88 8e d2 7c e3 d8 d1 ae f4 3f 01"
            "21 f4 37 a8 22 34 4d 66 7c d6 aa 16 70 28 f1 ca"
            "8e 66 71 8a fe 80 22 26 66 33 57 28 6d bd c5 04"
            "c1 66 02 d7 ac 0d 38 97 db f3 a3 77 73 4f 10 46"
            "ef f1 b9 9a e7 3b 84 fb 35 6a 44 d7 fd 94 7c b2"
            "78 1c b3 ff 90 be ad 1b 0b 5d 9e 95 db 51 35 e9"
            "3f 42 7f af a8 10 94 64 8f 2d e4 0d 30 ba c4 14"
            "a2 f2 63 3b 0d a5 6f b4 9f 52 81 e0 3b dd ac";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        reorder.produce(&bin_record[0], bin_record.size());
    }
    {
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (9 == seq), __FUNCTION__, "expect epoch 0 seq 9");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (10 == seq), __FUNCTION__, "expect epoch 0 seq 10");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (11 == seq), __FUNCTION__, "expect epoch 0 seq 11");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((0 == epoch) && (12 == seq), __FUNCTION__, "expect epoch 0 seq 12");
        reorder.consume(epoch, seq, packet);
        _test_case.assert((1 == epoch) && (0 == seq), __FUNCTION__, "expect epoch 1 seq 0");
    }
}
