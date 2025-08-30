/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *          RFC 9204 QPACK: Field Compression for HTTP/3
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

// test/quic/http3/http3.pcapng

struct testvector_qpack {
    int dir;
    uint32 type;
    const char* desc;
    const char* stream;
} testvector_qpack_stream[] = {
    {
        from_client,
        qpack_quic_stream_encoder,
        "#23 QPACK encoder stream",
        // QPACK encoder stream; 2 opcodes (2 total)
        //     QPACK encoder opcode: Set DTable Cap=4096
        //         Capacity: 4096
        //     QPACK encoder INSERT_INDEXED ref_len=1 ref=0 val_len=15
        //         Name Reference: c0
        //         Value: "www.google.com"
        //     QPACK encoder INSERT_INDEXED ref_len=2 ref=95 val_len=9
        //         Name Reference: ff20
        //         Value (Huffman): 25b650c3cb842b83
        //         Value: "curl/8.11.0"
        //     [QPACK encoder instruction count increment: 2]
        //     [QPACK encoder instruction count: 2]
        "3f e1 1f c0 0e 77 77 77 2e 67 6f 6f 67 6c 65 2e"
        "63 6f 6d ff 20 88 25 b6 50 c3 cb 84 2b 83",
    },
    {
        from_client,
        qpack_quic_stream_header,  // Frame Payload only
        "#24 HEADERS",
        // Header: :method: GET
        // Header: :scheme: https
        // Header: :authority: www.google.com
        // Header: :path: /
        // Header: user-agent: curl/8.11.0
        // Header: accept: */*
        // [Full request URI: https://www.google.com/]
        "03 81 d1 d7 10 c1 11 dd",
    },
    {
        from_server,
        qpack_quic_stream_encoder,
        "#38 DTable cap=0",
        // QPACK encoder stream; 0 opcodes (0 total)
        //     QPACK encoder opcode: Set DTable Cap=0
        //     [QPACK encoder instruction count increment: 0]
        //     [QPACK encoder instruction count: 0]
        "20",
    },
    {
        from_server,
        qpack_quic_stream_header,
        "#38 HEADERS",
        // Header: :status: 200 OK
        // Header: date: Thu, 19 Jun 2025 04:53:07 GMT
        // Header: expires: -1
        // Header: cache-control: private, max-age=0
        // Header: content-type: text/html; charset=ISO-8859-1
        //  […]Header: content-security-policy-report-only: ...
        // Header: accept-ch: Sec-CH-Prefers-Color-Scheme
        // Header: p3p: CP="This is not a P3P policy! See g.co/p3phelp for more info."
        // Header: server: gws
        // Header: x-xss-protection: 0
        // Header: x-frame-options: SAMEORIGIN
        // Header: set-cookie: ...
        //  […]Header: set-cookie: ...
        // Header: alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
        // Header: accept-ranges: none
        // Header: vary: Accept-Encoding
        "00 00 d9 56 97 df 3d bf 4a 05 f5 32 db 52 82 00"
        "9b 50 0d 5c 6d 9b 80 75 4c 5a 37 ff 2d 2f 9a cd"
        "61 51 02 2d 31 5f 15 8d ae c3 77 1a 4b f4 a5 23"
        "f2 b0 e6 2c 00 5f 1d 96 49 7c a5 89 d3 4d 1f 6a"
        "12 71 d8 82 a6 0c 9b b5 2c f3 cd be b0 7f 2f 12"
        "21 ea 49 6a 4a c8 29 2d b0 c9 f4 b5 67 a0 c4 f4"
        "b5 85 ac f6 25 63 d5 47 af ff 1e 3c 7d 0a 44 ac"
        "8b 08 a7 fa a8 f5 17 fd 7d c6 34 15 6b 6c 32 9f"
        "e9 05 a2 5f f5 f6 82 58 6a d2 b2 2c 22 9f ea a3"
        "d4 42 ad 9f 2e fe 8c f8 a4 b8 c7 e5 f2 d8 b7 e9"
        "6f d7 0f 19 bf d2 9f e9 09 b0 c4 4a d2 7a a8 74"
        "98 9f e9 4f f5 61 6b 3d 89 59 03 a6 ba 0b fe 94"
        "ff 56 d4 81 ca 55 8b dc 74 7f a5 3f d5 b5 20 72"
        "95 63 55 41 aa 2f fa 52 74 a6 b4 5c 52 74 a6 bb"
        "9f 76 16 b3 d8 95 ad b0 ca 4e 94 d6 8b 8c 30 44"
        "56 bf 83 26 79 8e 79 a8 2a e4 3d 2c 11 15 b1 37"
        "84 30 74 ce 5b 16 9e bf 2e 19 08 5a d2 b1 27 94"
        "dc 52 2d 7b 1a da ec 2c a5 b1 0b 5e 3d 07 b1 6d"
        "c4 9c b4 97 23 70 33 70 af bd ae 0f e7 7c e6 42"
        "86 42 95 1d 2a 0d 4d 6c eb 52 b3 d0 62 7a fe 14"
        "dc 52 a9 32 e4 3b 15 b3 5c e5 a2 b5 25 3d 8a 52"
        "7b 0a a1 aa 94 eb ff 3f 5f 4d 03 67 77 73 5f 2f"
        "01 30 5f 52 89 dd 0e 8c 1a b6 e4 c5 93 4f 5e fc"
        "87 05 e8 21 e3 3c 5c 45 d2 ba 03 d0 79 35 eb e9"
        "e2 c6 b0 47 83 4c d5 5f 67 77 e6 70 ed b7 88 59"
        "e6 50 6a e5 7e 4b db 33 bb 2e cc eb 7a 6f 18 32"
        "11 ff 1f 6a 17 cd 66 b0 a8 83 7d a5 fa 50 2e 2d"
        "7c a4 58 40 13 6a 01 ab 8d b3 70 0e a9 8b 46 ff"
        "b5 2b 1a 67 81 8f b5 24 3d 23 35 50 2f 31 cf 35"
        "05 5c 87 a7 ed 4d c5 25 b6 17 ed 4c 69 4d 7a aa"
        "a3 d7 da 9b 87 49 77 19 25 82 81 f9 5e ff 6a d3"
        "92 fc 0d 89 a8 27 c1 e7 4d 29 17 ee 0a 29 24 b8"
        "b4 b5 8b 2e 0e 87 67 97 3a bc ec c8 5c ff b9 51"
        "e3 ae b8 ec 91 36 f3 e5 df 9e 1c d7 d1 56 92 9a"
        "f8 1b 90 ba b3 f2 e3 fa 5a 1b e9 db 6b 26 db 57"
        "e6 5e 4d cd 24 73 6b e5 77 9d 7a bc 7e bf 4f ad"
        "90 de c2 49 3d 3c 0b ff 94 3f cb 9a 22 a2 7d 76"
        "6f bb 96 98 f0 6e 8e 83 b3 fa 8c 75 85 e1 cb 39"
        "3f 4a 9d 43 fc f0 4c 4e 69 48 ba 65 ec 0a 75 85"
        "ec f2 7a 33 e0 06 9b b1 73 85 a7 b1 82 fa de 34"
        "65 8b 2f ec bc 72 c7 d1 ae 17 a9 e1 9d 6c f7 7a"
        "1d cd 37 df bb e3 cf 1d 9a 36 cd 96 47 f8 7d a8"
        "5f 35 9a c2 a2 0c 36 1b e9 40 be b5 f2 91 61 00"
        "4d a8 06 ae 36 cd c0 3a a6 2d 1b fe d4 ac 69 9e"
        "06 3e d4 90 f4 8c d5 40 bc c7 3c d4 15 72 1e 9f"
        "b5 31 a5 35 ea aa 8f 5f 5f 44 a4 9d 98 3f 9b 8d"
        "34 cf f3 f6 a5 23 80 4d be 20 00 1f 53 b2 b0 9f"
        "83 f9 b8 d3 4c ff 3f 6a 52 38 04 db e2 00 01 5f"
        "11 83 a8 f5 17 5f 2c 8b 84 84 2d 69 5b 05 44 3c"
        "86 aa 6f",
    },
};

void test_qpack_stream() {
    _test_case.begin("HTTP/3 QPACK STREAM");

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_dynamic_table qpack_dyntable;
    for (auto item : testvector_qpack_stream) {
        auto bin = base16_decode_rfc(item.stream);
        size_t pos = 0;
        std::list<http_compression_decode_t> kv;
        ret = enc.decode(&qpack_dyntable, &bin[0], bin.size(), pos, kv, item.type);
        _test_case.test(ret, __FUNCTION__, "%s", item.desc);
    }
}
