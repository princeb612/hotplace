/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *  see HTTP/2 Frame
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {}
} OPTION;

t_shared_instance<t_cmdline_t<OPTION> > cmdline;

//  test_payload_dump
//  test_payload_parse
//
//  type        size    endian      name        group
//  uint8       1       N/A         "padlen"    "pad"
//  binary_t    *       N/A         "data"      N/A
//  uint32      4       true        "value"     N/A
//  binary_t    *       N/A         "pad"       "pad"

void test_payload_dump() {
    const OPTION& option = cmdline->value();
    _test_case.begin("payload");

    {
        payload pl;
        binary_t data = strtobin("data");
        binary_t pad = strtobin("pad");
        uint8 padlen = 3;  // "pad"
        basic_stream bs;
        binary_t bin_padded;
        binary_t bin_notpadded;

        pl << new payload_member(padlen, "padlen", "pad") << new payload_member(data, "data") << new payload_member((uint32)0x1000, true, "value")
           << new payload_member(pad, "pad", "pad");

        pl.set_group("pad", true);  // enable "pad" group
        pl.dump(bin_padded);
        if (option.verbose) {
            _logger->dump(bin_padded);
        }
        _test_case.assert(bin_padded == base16_decode_rfc("03 64 61 74 61 00 00 10 00 70 61 64"), __FUNCTION__,
                          "payload padded");  // 3 || "data" || 0x00001000 || "pad"

        pl.set_group("pad", false);  // disable "pad" group
        pl.dump(bin_notpadded);
        if (option.verbose) {
            _logger->dump(bin_notpadded);
        }
        _test_case.assert(bin_notpadded == base16_decode_rfc("64 61 74 61 00 00 10 00"), __FUNCTION__, "payload not padded");  // "data" || 0x00001000
    }
}

void test_payload_parse() {
    const OPTION& option = cmdline->value();
    _test_case.begin("payload");

    {
        payload pl;
        binary_t data;
        binary_t pad;
        pl << new payload_member((uint8)0, "padlen", "pad") << new payload_member(data, "data") << new payload_member((uint32)0, true, "value")
           << new payload_member(pad, "pad", "pad");
        binary_t decoded = base16_decode("036461746100001000706164");
        pl.set_reference_value("pad", "padlen");
        pl.read(decoded);
        binary_t bin_dump;
        pl.dump(bin_dump);
        _test_case.assert(bin_dump == decoded, __FUNCTION__, "read/parse");

        binary_t data2;
        pl.select("data")->get_variant().dump(data2, true);
        _test_case.assert(data2 == strtobin("data"), __FUNCTION__, "read binary");
    }
}

//  test_payload_uint24
//
//  type        size    endian      name        group
//  uint8       1       N/A         "padlen"    N/A
//  uint32_24_t 3       N/A         "data"      N/A
//  uint32      4       true        "value"     N/A
//  binary_t    *       N/A         "pad"       N/A

void test_payload_uint24() {
    const OPTION& option = cmdline->value();
    _test_case.begin("payload");

    binary_t pad = strtobin("pad");
    binary_t bin_payload;
    binary_t expect = base16_decode("0310000010000000706164");

    {
        payload pl;
        uint8 padlen = 3;  // "pad"
        basic_stream bs;
        uint32_24_t i32_24(0x100000);  // 32/24 [0 .. 0x00ffffff]
        uint32 i32 = 0x10000000;       // 32/32 [0 .. 0xffffffff]

        pl << new payload_member(padlen, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member(i32, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.dump(bin_payload);
        if (option.verbose) {
            _logger->dump(bin_payload);
        }
        _test_case.assert(expect == bin_payload, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }

    {
        payload pl;
        uint32_24_t i32_24;
        pl << new payload_member((uint8)0, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member((uint32)0, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.read(expect);

        uint8 padlen = t_to_int<uint8>(pl.select("padlen"));
        uint32_24_t i24 = t_to_int<uint32>(pl.select("int32_24"));
        uint32 i32 = t_to_int<uint32>(pl.select("int32_32"));

        if (option.verbose) {
            uint32 i24_value = i24.get();
            _logger->writeln("padlen %u uint32_24 %u (0x%08x) uint32_32 %u (0x%08x)", padlen, i24_value, i24_value, i32, i32);
        }

        _test_case.assert(0x100000 == i24.get(), __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)

        binary_t bin_dump;
        pl.dump(bin_dump);
        _test_case.assert(expect == bin_dump, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }
}

void do_test_http2_frame(http2_frame* frame, const char* text, const char* expect) {
    basic_stream bs;
    binary_t bin_frame;

    frame->write(bin_frame);
    _logger->dump(bin_frame);

    frame->dump(&bs);
    _logger->write(bs);

    _test_case.assert(bin_frame == base16_decode_rfc(expect), __FUNCTION__, text);
}

void test_http2_frame() {
    const OPTION& option = cmdline->value();
    _test_case.begin("HTTP/2 Frame");

    basic_stream bs;

    // SETTINGS

    http2_frame_settings frame_settings;
    frame_settings.add(h2_settings_enable_push, 0).add(h2_settings_max_concurrent_streams, 100).add(h2_settings_initial_window_size, 0xa00000);

    const char* expect_settings =
        "00 00 12 04 00 00 00 00 00 00 02 00 00 00 00 00"
        "03 00 00 00 64 00 04 00 A0 00 00 -- -- -- -- --";

    do_test_http2_frame(&frame_settings, "SETTINGS Frame", expect_settings);

    // HEADERS

    hpack hp;
    hpack_encoder encoder;
    hpack_session session;  // dynamic table
    hp.get_binary().clear();
    hp.set_encoder(&encoder)
        .set_session(&session)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .encode_header(":method", "GET")
        .encode_header(":scheme", "https")
        .encode_header(":path", "/index.html")
        .encode_header(":authority", "www.example.com");

    http2_frame_headers frame_headers;
    frame_headers.set_flags(0).set_stream_id(1);
    frame_headers.get_fragment() = hp.get_binary();
    frame_headers.set_hpack_encoder(&encoder).set_hpack_session(&session);  // dump

    const char* expect_headers =
        "00 00 11 01 00 00 00 00 01 82 87 85 41 8C F1 E3 "
        "C2 E5 F2 3A 6B A0 AB 90 F4 FF";

    do_test_http2_frame(&frame_headers, "HEADERS Frame", expect_headers);

    // CONTINUATION

    hp.get_binary().clear();
    hp.encode_header("custom-key", "custom-value");

    http2_frame_continuation frame_continuation;
    frame_continuation.set_flags(h2_flag_end_headers).set_stream_id(1);
    frame_continuation.get_fragment() = hp.get_binary();
    frame_continuation.set_hpack_encoder(&encoder).set_hpack_session(&session);  // dump

    const char* expect_continuation =
        "00 00 14 09 04 00 00 00 01 40 88 25 A8 49 E9 5B "
        "A9 7D 7F 89 25 A8 49 E9 5B B8 E8 B4 BF -- -- -- ";

    do_test_http2_frame(&frame_continuation, "CONTINUATION Frame", expect_continuation);

    // DATA

    http2_frame_data frame_data;
    frame_data.set_flags(h2_flag_end_stream).set_stream_id(1);
    frame_data.get_data() = strtobin("hello world");

    const char* expect_data =
        "00 00 0B 00 01 00 00 00 01 68 65 6C 6C 6F 20 77"
        "6F 72 6C 64 -- -- -- -- -- -- -- -- -- -- -- --";

    do_test_http2_frame(&frame_data, "DATA Frame", expect_data);

    // GOAWAY

    http2_frame_headers frame_goaway;
    frame_goaway.set_stream_id(1);
    frame_goaway.get_fragment() = strtobin("protocol error cause of .... blah blah ...");

    const char* expect_goaway =
        "00 00 2A 01 00 00 00 00 01 70 72 6F 74 6F 63 6F "
        "6C 20 65 72 72 6F 72 20 63 61 75 73 65 20 6F 66 "
        "20 2E 2E 2E 2E 20 62 6C 61 68 20 62 6C 61 68 20 "
        "2E 2E 2E -- -- -- -- -- -- -- -- -- -- -- -- -- ";

    do_test_http2_frame(&frame_goaway, "GOAWAY Frame", expect_goaway);
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif
    cmdline.make_share(new t_cmdline_t<OPTION>);

    *cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [&](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();

    cmdline->parse(argc, argv);
    const OPTION& option = cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    test_payload_dump();
    test_payload_parse();
    test_payload_uint24();
    test_http2_frame();

    _logger->flush();

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
