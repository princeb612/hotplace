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

// test/tls/http/http2.pcapng
// wireshark
// decode 'Header Block Fragment'

void test_h2_header_frame() {
    _test_case.begin("HTTP/2 Header Compression");
    const OPTION& option = _cmdline->value();

    // [test vector] chrome generated header

    struct testvector {
        const char* key;
        const char* value;
    };

    auto lambda_decode = [&](hpack_dynamic_table* sess, skey_value& kv, const binary_t bin) -> void {
        size_t pos = 0;
        std::string name;
        std::string value;
        while (pos < bin.size()) {
            encoder->decode_header(sess, &bin[0], bin.size(), pos, name, value);
            kv.set(name, value);
            _logger->writeln("> %s: %s", name.c_str(), value.c_str());
            sess->commit();
        }
    };

    auto lambda_test = [&](const char* text, hpack_dynamic_table* sess, const char* stream, testvector* tv, size_t size_tv) -> void {
        _logger->writeln(text);

        binary_t bin;
        bin = std::move(base16_decode_rfc(stream));

        skey_value kv;
        lambda_decode(sess, kv, bin);

        sess->dump("dynamic table", dump_hpack_session_routine);

        for (auto i = 0; i < size_tv; i++) {
            auto& item = tv[i];
            const auto& key = kv[item.key];
            _test_case.assert(key == item.value, __FUNCTION__, "%s (%s: %s)", text, item.key, key.c_str());
        }
    };

    hpack_dynamic_table hpack_dyntable;

    // HEADERS[1]: GET /
    // HyperText Transfer Protocol 2
    //     Stream: HEADERS, Stream ID: 1, Length 471, GET /
    //         Length: 471
    //         Type: HEADERS (1)
    //         Flags: 0x25, Priority, End Headers, End Stream
    //         0... .... .... .... .... .... .... .... = Reserved: 0x0
    //         .000 0000 0000 0000 0000 0000 0000 0001 = Stream Identifier: 1
    //         [Pad Length: 0]
    //         1... .... .... .... .... .... .... .... = Exclusive: True
    //         .000 0000 0000 0000 0000 0000 0000 0000 = Stream Dependency: 0
    //         Weight: 255
    //         [Weight real: 256]
    //         Header Block Fragment […]: ...
    //         [Header Length: 775]
    //         [Header Count: 17]
    //         Header: :method: GET
    //         Header: :authority: localhost:9000
    //         Header: :scheme: https
    //         Header: :path: /
    //         Header: sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
    //         Header: sec-ch-ua-mobile: ?0
    //         Header: sec-ch-ua-platform: "Windows"
    //         Header: upgrade-insecure-requests: 1
    //         Header: user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
    //         Header: accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;
    //                         v=b3;q=0.7
    //         Header: sec-fetch-site: none
    //         Header: sec-fetch-mode: navigate
    //         Header: sec-fetch-user: ?1
    //         Header: sec-fetch-dest: document
    //         Header: accept-encoding: gzip, deflate, br, zstd
    //         Header: accept-language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
    //         Header: priority: u=0, i

    const char* sample1 =
        "82 41 8a a0 e4 1d 13 9d 09 b8 f8 00 0f 87 84 40"
        "87 41 48 b1 27 5a d1 ff b8 fe 71 1c f3 50 55 2f"
        "4f 61 e9 2f f3 f7 de 0f e4 2c bb fc fd 29 fc de"
        "9e c3 d2 6b 69 fe 7e fb c1 fc 85 97 7f 9f a5 3f"
        "9d 27 4b 10 ff 77 6c 1d 52 7f 3f 7d e0 fe 44 d7"
        "f3 40 8b 41 48 b1 27 5a d1 ad 49 e3 35 05 02 3f"
        "30 40 8d 41 48 b1 27 5a d1 ad 5d 03 4c a7 b2 9f"
        "88 fe 79 1a a9 0f e1 1f cf 40 92 b6 b9 ac 1c 85"
        "58 d5 20 a4 b6 c2 ad 61 7b 5a 54 25 1f 01 31 7a"
        "d5 d0 7f 66 a2 81 b0 da e0 53 fa e4 6a a4 3f 84"
        "29 a7 7a 81 02 e0 fb 53 91 aa 71 af b5 3c b8 d7"
        "f6 a4 35 d7 41 79 16 3c c6 4b 0d b2 ea ec b8 a7"
        "f5 9b 1e fd 19 fe 94 a0 dd 4a a6 22 93 a9 ff b5"
        "2f 4f 61 e9 2b 01 65 d5 c0 b8 17 02 9b 87 28 ec"
        "33 0d b2 ea ec b9 53 e5 49 7c a5 89 d3 4d 1f 43"
        "ae ba 0c 41 a4 c7 a9 8f 33 a6 9a 3f df 9a 68 fa"
        "1d 75 d0 62 0d 26 3d 4c 79 a6 8f be d0 01 77 fe"
        "8d 48 e6 2b 03 ee 69 7e 8d 48 e6 2b 1e 0b 1d 7f"
        "46 a4 73 15 81 d7 54 df 5f 2c 7c fd f6 80 0b bd"
        "f4 3a eb a0 c4 1a 4c 7a 98 41 a6 a8 b2 2c 5f 24"
        "9c 75 4c 5f be f0 46 cf df 68 00 bb bf 40 8a 41"
        "48 b4 a5 49 27 59 06 49 7f 83 a8 f5 17 40 8a 41"
        "48 b4 a5 49 27 5a 93 c8 5f 86 a8 7d cd 30 d2 5f"
        "40 8a 41 48 b4 a5 49 27 5a d4 16 cf 02 3f 31 40"
        "8a 41 48 b4 a5 49 27 5a 42 a1 3f 86 90 e4 b6 92"
        "d4 9f 50 92 9b d9 ab fa 52 42 cb 40 d2 5f a5 23"
        "b3 e9 4f 68 4c 9f 51 9c ea 75 b3 6d fa ea 7f be"
        "d0 01 77 fe 8b 52 dc 37 7d f6 80 0b bd f4 5a be"
        "fb 40 05 dd 40 86 ae c3 1e c3 27 d7 85 b6 00 7d"
        "28 6f";

    testvector tv1[] = {
        {":method", "GET"},
        {":authority", "localhost:9000"},
        {":scheme", "https"},
        {":path", "/"},
        {"sec-ch-ua", R"("Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24")"},
        {"sec-ch-ua-mobile", "?0"},
        {"sec-ch-ua-platform", R"("Windows")"},
        {"upgrade-insecure-requests", "1"},
        {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "none"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-user", "?1"},
        {"sec-fetch-dest", "document"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"accept-language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"},
        {"priority", "u=0, i"},
    };

    lambda_test("GET /", &hpack_dyntable, sample1, tv1, RTL_NUMBER_OF(tv1));

    // HEADERS[3]: GET /favicon.ico
    // HyperText Transfer Protocol 2
    //     Stream: HEADERS, Stream ID: 3, Length 128, GET /favicon.ico
    //         Length: 128
    //         Type: HEADERS (1)
    //         Flags: 0x25, Priority, End Headers, End Stream
    //         0... .... .... .... .... .... .... .... = Reserved: 0x0
    //         .000 0000 0000 0000 0000 0000 0000 0011 = Stream Identifier: 3
    //         [Pad Length: 0]
    //         1... .... .... .... .... .... .... .... = Exclusive: True
    //         .000 0000 0000 0000 0000 0000 0000 0000 = Stream Dependency: 0
    //         Weight: 219
    //         [Weight real: 220]
    //         Header Block Fragment […]: ...
    //         [Header Length: 698]
    //         [Header Count: 16]
    //         Header: :method: GET
    //         Header: :authority: localhost:9000
    //         Header: :scheme: https
    //         Header: :path: /favicon.ico
    //         Header: sec-ch-ua-platform: "Windows"
    //         Header: user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
    //         Header: sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
    //         Header: sec-ch-ua-mobile: ?0
    //         Header: accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
    //         Header: sec-fetch-site: same-origin
    //         Header: sec-fetch-mode: no-cors
    //         Header: sec-fetch-dest: image
    //         Header: referer: https://localhost:9000/
    //         Header: accept-encoding: gzip, deflate, br, zstd
    //         Header: accept-language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
    //         Header: priority: u=1, i

    const char* sample2 =
        "82 cb 87 04 89 62 51 f7 31 0f 52 e6 21 ff c8 c6"
        "ca c9 53 b1 35 23 98 ac 0f b9 a5 fa 35 23 98 ac"
        "78 2c 75 fd 1a 91 cc 56 07 5d 53 7d 1a 91 cc 56"
        "11 de 6f f7 e6 9a 3e 8d 48 e6 2b 1f 3f 5f 2c 7c"
        "fd f6 80 0b bd 7f 06 88 40 e9 2a c7 b0 d3 1a af"
        "7f 06 85 a8 eb 10 f6 23 7f 05 84 35 23 98 bf 73"
        "90 9d 29 ad 17 18 62 83 90 74 4e 74 26 e3 e0 00"
        "18 c5 c4 7f 04 85 b6 00 fd 28 6f";

    testvector tv2[] = {
        {":method", "GET"},
        {":authority", "localhost:9000"},
        {":scheme", "https"},
        {":path", "/favicon.ico"},
        {"sec-ch-ua-platform", R"("Windows")"},
        {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"},
        {"sec-ch-ua", R"("Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24")"},
        {"sec-ch-ua-mobile", "?0"},
        {"accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
        {"sec-fetch-site", "same-origin"},
        {"sec-fetch-mode", "no-cors"},
        {"sec-fetch-dest", "image"},
        {"referer", "https://localhost:9000/"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"accept-language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"},
        {"priority", "u=1, i"},
    };

    lambda_test("GET /favicon.ico", &hpack_dyntable, sample2, tv2, RTL_NUMBER_OF(tv2));

    // HyperText Transfer Protocol 2
    //     Stream: HEADERS, Stream ID: 1, Length 502, GET /api/html
    //         Length: 502
    //         Type: HEADERS (1)
    //         Flags: 0x25, Priority, End Headers, End Stream
    //         0... .... .... .... .... .... .... .... = Reserved: 0x0
    //         .000 0000 0000 0000 0000 0000 0000 0001 = Stream Identifier: 1
    //         [Pad Length: 0]
    //         1... .... .... .... .... .... .... .... = Exclusive: True
    //         .000 0000 0000 0000 0000 0000 0000 0000 = Stream Dependency: 0
    //         Weight: 255
    //         [Weight real: 256]
    //         Header Block Fragment […]: ...
    //         [Header Length: 828]
    //         [Header Count: 18]
    //         Header: :method: GET
    //         Header: :authority: localhost:9000
    //         Header: :scheme: https
    //         Header: :path: /api/html
    //         Header: sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
    //         Header: sec-ch-ua-mobile: ?0
    //         Header: sec-ch-ua-platform: "Windows"
    //         Header: upgrade-insecure-requests: 1
    //         Header: user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
    //         Header: accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;
    //                         v=b3;q=0.7
    //         Header: sec-fetch-site: same-origin
    //         Header: sec-fetch-mode: navigate
    //         Header: sec-fetch-user: ?1
    //         Header: sec-fetch-dest: document
    //         Header: referer: https://localhost:9000/
    //         Header: accept-encoding: gzip, deflate, br, zstd
    //         Header: accept-language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
    //         Header: priority: u=0, i

    const char* sample3 =
        "82 41 8a a0 e4 1d 13 9d 09 b8 f8 00 0f 87 04 87"
        "60 75 99 89 d3 4d 1f 40 87 41 48 b1 27 5a d1 ff"
        "b8 fe 71 1c f3 50 55 2f 4f 61 e9 2f f3 f7 de 0f"
        "e4 2c bb fc fd 29 fc de 9e c3 d2 6b 69 fe 7e fb"
        "c1 fc 85 97 7f 9f a5 3f 9d 27 4b 10 ff 77 6c 1d"
        "52 7f 3f 7d e0 fe 44 d7 f3 40 8b 41 48 b1 27 5a"
        "d1 ad 49 e3 35 05 02 3f 30 40 8d 41 48 b1 27 5a"
        "d1 ad 5d 03 4c a7 b2 9f 88 fe 79 1a a9 0f e1 1f"
        "cf 40 92 b6 b9 ac 1c 85 58 d5 20 a4 b6 c2 ad 61"
        "7b 5a 54 25 1f 01 31 7a d5 d0 7f 66 a2 81 b0 da"
        "e0 53 fa e4 6a a4 3f 84 29 a7 7a 81 02 e0 fb 53"
        "91 aa 71 af b5 3c b8 d7 f6 a4 35 d7 41 79 16 3c"
        "c6 4b 0d b2 ea ec b8 a7 f5 9b 1e fd 19 fe 94 a0"
        "dd 4a a6 22 93 a9 ff b5 2f 4f 61 e9 2b 01 65 d5"
        "c0 b8 17 02 9b 87 28 ec 33 0d b2 ea ec b9 53 e5"
        "49 7c a5 89 d3 4d 1f 43 ae ba 0c 41 a4 c7 a9 8f"
        "33 a6 9a 3f df 9a 68 fa 1d 75 d0 62 0d 26 3d 4c"
        "79 a6 8f be d0 01 77 fe 8d 48 e6 2b 03 ee 69 7e"
        "8d 48 e6 2b 1e 0b 1d 7f 46 a4 73 15 81 d7 54 df"
        "5f 2c 7c fd f6 80 0b bd f4 3a eb a0 c4 1a 4c 7a"
        "98 41 a6 a8 b2 2c 5f 24 9c 75 4c 5f be f0 46 cf"
        "df 68 00 bb bf 40 8a 41 48 b4 a5 49 27 59 06 49"
        "7f 88 40 e9 2a c7 b0 d3 1a af 40 8a 41 48 b4 a5"
        "49 27 5a 93 c8 5f 86 a8 7d cd 30 d2 5f 40 8a 41"
        "48 b4 a5 49 27 5a d4 16 cf 02 3f 31 40 8a 41 48"
        "b4 a5 49 27 5a 42 a1 3f 86 90 e4 b6 92 d4 9f 73"
        "90 9d 29 ad 17 18 62 83 90 74 4e 74 26 e3 e0 00"
        "18 50 92 9b d9 ab fa 52 42 cb 40 d2 5f a5 23 b3"
        "e9 4f 68 4c 9f 51 9c ea 75 b3 6d fa ea 7f be d0"
        "01 77 fe 8b 52 dc 37 7d f6 80 0b bd f4 5a be fb"
        "40 05 dd 40 86 ae c3 1e c3 27 d7 85 b6 00 7d 28"
        "6f";

    testvector tv3[] = {
        {":method", "GET"},
        {":authority", "localhost:9000"},
        {":scheme", "https"},
        {":path", "/api/html"},
        {"sec-ch-ua", R"("Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24")"},
        {"sec-ch-ua-mobile", "?0"},
        {"sec-ch-ua-platform", R"("Windows")"},
        {"upgrade-insecure-requests", "1"},
        {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "same-origin"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-user", "?1"},
        {"sec-fetch-dest", "document"},
        {"referer", "https://localhost:9000/"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"accept-language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7"},
        {"priority", "u=0, i"},
    };

    lambda_test("GET /api/html", &hpack_dyntable, sample3, tv3, RTL_NUMBER_OF(tv3));
}
