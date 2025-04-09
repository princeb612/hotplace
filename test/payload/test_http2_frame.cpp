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

#include "sample.hpp"

void do_test_http2_frame(http2_frame* frame1, http2_frame* frame2, const char* text, const char* expect) {
    basic_stream bs;
    binary_t bin_f1;
    binary_t bin_f2;
    binary_t bin_expect = std::move(base16_decode_rfc(expect));

    // write a composed http2_frame context into binary
    frame1->write(bin_f1);
    _logger->hdump("frame", bin_f1, 16, 3);

    // human-readable
    frame1->dump(&bs);
    _logger->write(bs);

    // comparison
    _test_case.assert(bin_f1 == bin_expect, __FUNCTION__, "%s #compose", text);

    // read from bytestream
    frame2->read((http2_frame_header_t*)&bin_expect[0], bin_expect.size());
    frame2->write(bin_f2);

    _logger->hdump("dump", bin_f2, 16, 3);

    // comparison
    _test_case.assert(bin_f1 == bin_f2, __FUNCTION__, "%s #read", text);
}

void test_http2_frame() {
    const OPTION& option = _cmdline->value();
    _test_case.begin("HTTP/2 Frame");

    basic_stream bs;

    // SETTINGS

    http2_frame_settings frame_settings;
    frame_settings.add(h2_settings_enable_push, 0).add(h2_settings_max_concurrent_streams, 100).add(h2_settings_initial_window_size, 0xa00000);

    // test
    {
        const char* expect_settings =
            "00 00 12 04 00 00 00 00 00 00 02 00 00 00 00 00"
            "03 00 00 00 64 00 04 00 A0 00 00 -- -- -- -- --";

        http2_frame_settings frame;
        do_test_http2_frame(&frame_settings, &frame, "SETTINGS Frame", expect_settings);
    }

    // HEADERS

    hpack_stream hp;
    hpack_dynamic_table session;  // dynamic table
    hp.get_binary().clear();
    hp.set_session(&session)
        .set_encode_flags(hpack_indexing | hpack_huffman)
        .encode_header(":method", "GET")
        .encode_header(":scheme", "https")
        .encode_header(":path", "/index.html")
        .encode_header(":authority", "www.example.com");

    http2_frame_headers frame_headers;
    frame_headers.set_flags(0).set_stream_id(1);
    frame_headers.set_fragment(hp.get_binary());
    frame_headers.set_hpack_session(&session);  // dump

    // test
    {
        const char* expect_headers =
            "00 00 11 01 00 00 00 00 01 82 87 85 41 8C F1 E3 "
            "C2 E5 F2 3A 6B A0 AB 90 F4 FF";

        http2_frame_headers frame;
        do_test_http2_frame(&frame_headers, &frame, "HEADERS Frame", expect_headers);
    }

    // CONTINUATION

    hp.get_binary().clear();
    hp.encode_header("custom-key", "custom-value");

    http2_frame_continuation frame_continuation;
    frame_continuation.set_flags(h2_flag_end_headers).set_stream_id(1);
    frame_continuation.set_fragment(hp.get_binary());
    frame_continuation.set_hpack_session(&session);  // dump

    // test
    {
        const char* expect_continuation =
            "00 00 14 09 04 00 00 00 01 40 88 25 A8 49 E9 5B "
            "A9 7D 7F 89 25 A8 49 E9 5B B8 E8 B4 BF -- -- -- ";

        http2_frame_continuation frame;
        do_test_http2_frame(&frame_continuation, &frame, "CONTINUATION Frame", expect_continuation);
    }

    // DATA

    http2_frame_data frame_data;
    frame_data.set_flags(h2_flag_end_stream).set_stream_id(1);
    frame_data.set_data(str2bin("hello world"));

    // test
    {
        const char* expect_data =
            "00 00 0B 00 01 00 00 00 01 68 65 6C 6C 6F 20 77"
            "6F 72 6C 64 -- -- -- -- -- -- -- -- -- -- -- --";

        http2_frame_data frame;
        do_test_http2_frame(&frame_data, &frame, "DATA Frame", expect_data);
    }

    // GOAWAY

    http2_frame_headers frame_goaway;
    frame_goaway.set_stream_id(1);
    frame_goaway.set_fragment(str2bin("protocol error cause of .... blah blah ..."));

    // test
    {
        const char* expect_goaway =
            "00 00 2A 01 00 00 00 00 01 70 72 6F 74 6F 63 6F "
            "6C 20 65 72 72 6F 72 20 63 61 75 73 65 20 6F 66 "
            "20 2E 2E 2E 2E 20 62 6C 61 68 20 62 6C 61 68 20 "
            "2E 2E 2E -- -- -- -- -- -- -- -- -- -- -- -- -- ";

        http2_frame_headers frame;
        do_test_http2_frame(&frame_goaway, &frame, "GOAWAY Frame", expect_goaway);
    }

    // ALTSVC

    http2_frame_alt_svc frame_alt_svc;
    frame_alt_svc.set_stream_id(1);  // ignore stream id
    frame_alt_svc.set_origin(str2bin("origin"));
    frame_alt_svc.set_altsvc(str2bin("altsvc"));

    // test
    {
        const char* expect_altsvc =
            "00 00 0E 0A 00 00 00 00 00 00 06 6F 72 69 67 69"
            "6E 61 6C 74 73 76 63 -- -- -- -- -- -- -- -- --";

        http2_frame_alt_svc frame;
        do_test_http2_frame(&frame_alt_svc, &frame, "ALTSVC Frame", expect_altsvc);
    }
}
