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
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {}
} OPTION;

t_shared_instance<t_cmdline_t<OPTION> > cmdline;

//  test_payload_write
//  test_payload_read
//
//  type        size    endian      name        group
//  uint8       1       N/A         "padlen"    "pad"
//  binary_t    *       N/A         "data"      N/A
//  uint32      4       true        "value"     N/A
//  binary_t    *       N/A         "pad"       "pad"

void test_payload_write() {
    const OPTION& option = cmdline->value();
    _test_case.begin("payload");

    payload pl;
    binary_t data = str2bin("data");
    binary_t pad = str2bin("pad");
    uint8 padlen = 3;  // "pad"
    basic_stream bs;
    binary_t bin_padded;
    binary_t bin_notpadded;

    pl << new payload_member(padlen, "padlen", "pad") << new payload_member(data, "data") << new payload_member((uint32)0x1000, true, "value")
       << new payload_member(pad, "pad", "pad");

    // enable "pad" group
    {
        pl.set_group("pad", true);
        pl.write(bin_padded);

        // test
        binary_t data;
        binary_t pad;
        auto padlen = t_to_int<uint8>(pl.select("padlen"));
        auto value = t_to_int<uint32>(pl.select("value"));
        pl.select("data")->get_variant().to_binary(data);
        pl.select("pad")->get_variant().to_binary(pad);
        _test_case.assert(3 == padlen, __FUNCTION__, "write #padlen");
        _test_case.assert(data == str2bin("data"), __FUNCTION__, "write #value");
        _test_case.assert(0x1000 == value, __FUNCTION__, "write #data");
        _test_case.assert(pad == str2bin("pad"), __FUNCTION__, "write #pad");
        _logger->hdump("padded", bin_padded, 16, 3);
        _test_case.assert(bin_padded == base16_decode_rfc("03 64 61 74 61 00 00 10 00 70 61 64"), __FUNCTION__,
                          R"(enable "pad" group)");  // 3 || "data" || 0x00001000 || "pad"
    }

    // disable "pad" group
    {
        pl.set_group("pad", false);
        pl.write(bin_notpadded);

        // test
        _logger->hdump("not padded", bin_notpadded, 16, 3);
        _test_case.assert(bin_notpadded == base16_decode_rfc("64 61 74 61 00 00 10 00"), __FUNCTION__, R"(disable "pad" group)");  // "data" || 0x00001000
    }
}

void test_payload_read() {
    const OPTION& option = cmdline->value();
    _test_case.begin("payload");

    payload pl;
    binary_t bin_dump;
    binary_t decoded = base16_decode("036461746100001000706164");

    pl << new payload_member((uint8)0, "padlen", "pad") << new payload_member(binary_t(), "data") << new payload_member((uint32)0, true, "value")
       << new payload_member(binary_t(), "pad", "pad");
    pl.set_reference_value("pad", "padlen");  // length of "pad" is value of "padlen"

    // read
    {
        // pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:?)
        //  input  : 036461746100001000706164
        //         : pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:?)
        //  learn  :
        //         : pl.select("padlen")
        //         : pl << padlen(uint8:1) << data(unknown:?) << value(uint32:4) << pad(referenceof.padlen:3)
        //  infer  :
        //         : 12 - 1 - 4 - 3 = 12 - 8 = 4
        //         : pl << padlen(uint8:1) << data(unknown:4) << value(uint32:4) << pad(referenceof.padlen:3)
        //         : 03 64617461 00001000 706164
        //  result : padlen->3, data->"data", value->0x00001000, pad->"pad"
        pl.read(decoded);

        binary_t data;
        binary_t pad;
        auto padlen = t_to_int<uint8>(pl.select("padlen"));
        auto value = t_to_int<uint32>(pl.select("value"));
        pl.select("data")->get_variant().to_binary(data);
        pl.select("pad")->get_variant().to_binary(pad);
        _test_case.assert(3 == padlen, __FUNCTION__, "read #padlen");
        _test_case.assert(data == str2bin("data"), __FUNCTION__, "read #value");
        _test_case.assert(0x1000 == value, __FUNCTION__, "read #data");
        _test_case.assert(pad == str2bin("pad"), __FUNCTION__, "read #pad");
    }
    // write
    {
        pl.write(bin_dump);

        _logger->hdump("decoded", decoded, 16, 3);
        _logger->hdump("dump", bin_dump, 16, 3);
        _test_case.assert(bin_dump == decoded, __FUNCTION__, "read (contains one member of arbitrary size)");
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

    binary_t pad = str2bin("pad");
    binary_t bin_payload;
    binary_t expect = base16_decode("0310000010000000706164");

    // write
    {
        payload pl;
        uint8 padlen = 3;  // "pad"
        basic_stream bs;
        uint32_24_t i32_24(0x100000);  // 32/24 [0 .. 0x00ffffff]
        uint32 i32 = 0x10000000;       // 32/32 [0 .. 0xffffffff]

        pl << new payload_member(padlen, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member(i32, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.write(bin_payload);

        // test
        _logger->hdump("uint24", bin_payload, 16, 3);
        _test_case.assert(expect == bin_payload, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }

    // read
    {
        payload pl;
        uint32_24_t i32_24;
        pl << new payload_member((uint8)0, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member((uint32)0, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.read(expect);

        // test
        uint8 padlen = t_to_int<uint8>(pl.select("padlen"));
        uint32_24_t i24 = t_to_int<uint32>(pl.select("int32_24"));
        uint32 i32 = t_to_int<uint32>(pl.select("int32_32"));
        uint32 i24_value = i24.get();
        _logger->writeln("padlen %u uint32_24 %u (0x%08x) uint32_32 %u (0x%08x)", padlen, i24_value, i24_value, i32, i32);
        _test_case.assert(3 == padlen, __FUNCTION__, "read #padlen");
        _test_case.assert(0x100000 == i24.get(), __FUNCTION__, "read #i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)

        binary_t bin_dump;
        pl.write(bin_dump);
        _test_case.assert(expect == bin_dump, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }
}

void do_test_http2_frame(http2_frame* frame1, http2_frame* frame2, const char* text, const char* expect) {
    basic_stream bs;
    binary_t bin_f1;
    binary_t bin_f2;
    binary_t bin_expect = base16_decode_rfc(expect);

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
    const OPTION& option = cmdline->value();
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

void test_quic_packet() {
    _test_case.begin("QUIC Packet");
    auto lambda = [&](quic_packet_t type) -> void {
        // dummy
        quic_packet packet(type);
        binary_t bin;
        packet.set_version(0x01020304);
        packet.set_dcid(str2bin("destination connection id"));
        packet.set_scid(str2bin("source connection id"));
        packet.write(bin);
        basic_stream bs;
        packet.dump(&bs);
        _logger->hdump("packet", bin, 16, 3);
        _logger->writeln(bs);

        bs.clear();

        _logger->writeln("reparse");
        binary_t bin2;
        size_t pos = 0;
        quic_packet packet2;
        packet2.read(&bin[0], bin.size(), pos);
        packet2.write(bin2);
        packet2.dump(&bs);
        _logger->hdump("dump", bin, 16, 3);
        _logger->writeln(bs);

        _test_case.assert(bin == bin2, __FUNCTION__, "quic packet");
    };

    lambda(quic_packet_type_version_negotiation);
    lambda(quic_packet_type_initial);
    lambda(quic_packet_type_0_rtt);
    lambda(quic_packet_type_handshake);
    lambda(quic_packet_type_retry);
    lambda(quic_packet_type_1_rtt);
}

void test_quic_integer() {
    _test_case.begin("proof of concept payload_encoded");
    const char* expect =
        "3B 52 46 43 20 39 30 30 30 20 51 55 49 43 3A 20"  // ;RFC 9000 QUIC:
        "41 20 55 44 50 2D 42 61 73 65 64 20 4D 75 6C 74"  // A UDP-Based Mult
        "69 70 6C 65 78 65 64 20 61 6E 64 20 53 65 63 75"  // iplexed and Secu
        "72 65 20 54 72 61 6E 73 70 6F 72 74 25 31 36 2E"  // re Transport%16.
        "20 20 56 61 72 69 61 62 6C 65 2D 4C 65 6E 67 74"  //   Variable-Lengt
        "68 20 49 6E 74 65 67 65 72 20 45 6E 63 6F 64 69"  // h Integer Encodi
        "6E 67 -- -- -- -- -- -- -- -- -- -- -- -- -- --"  // ng
        ;
    binary_t bin_expect = base16_decode_rfc(expect);

    // step.1 a variable length integer + set_reference_value
    {
        payload pl1;
        binary_t bin1;
        pl1 << new payload_member(new quic_encoded(59), "len1") << new payload_member("RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport", "var1")
            << new payload_member(new quic_encoded(37), "len2") << new payload_member("16.  Variable-Length Integer Encoding", "var2");
        pl1.write(bin1);
        _logger->hdump("dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect, __FUNCTION__, "QUIC variable length integer #write");

        payload pl2;
        binary_t bin2;
        pl2 << new payload_member(new quic_encoded(uint64(0)), "len1") << new payload_member(binary_t(), "var1")
            << new payload_member(new quic_encoded(uint64(0)), "len2") << new payload_member(binary_t(), "var2");
        pl2.set_reference_value("var1", "len1");  // length of "var1" is value of "len1"
        pl2.set_reference_value("var2", "len2");  // length of "var2" is value of "len2"
        pl2.read(bin1);
        pl2.write(bin2);
        _logger->hdump("dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect, __FUNCTION__, "QUIC variable length integer #read");
        size_t len1 = pl2.select("len1")->get_payload_encoded()->value();
        _test_case.assert(59 == len1, __FUNCTION__, "QUIC variable length integer #get_length %zi", len1);
        size_t len2 = pl2.select("len2")->get_payload_encoded()->value();
        _test_case.assert(37 == len2, __FUNCTION__, "QUIC variable length integer #get_length %zi", len2);
    }

    // step.1 encode a variable length integer + data
    {
        payload pl1;
        binary_t bin1;
        pl1 << new payload_member(new quic_encoded("RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport"), "var1")
            << new payload_member(new quic_encoded("16.  Variable-Length Integer Encoding"), "var2");
        pl1.write(bin1);
        _logger->hdump("dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect, __FUNCTION__, "QUIC variable length integer #write");

        // step.2 decode a variable length integer + data
        payload pl2;
        binary_t bin2;
        pl2 << new payload_member(new quic_encoded, "var1") << new payload_member(new quic_encoded, "var2");
        pl2.read(bin1);
        pl2.write(bin2);
        _logger->hdump("dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect, __FUNCTION__, "QUIC variable length integer #read");
    }

    // step.4 zero-length
    {
        const char* expect_zero_length = "00";
        binary_t bin_expect_zero_length = base16_decode_rfc(expect_zero_length);
        payload pl1;
        binary_t bin1;
        pl1 << new payload_member(new quic_encoded(""));
        pl1.write(bin1);
        _logger->hdump("dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect_zero_length, __FUNCTION__, "zero-length #write");

        payload pl2;
        binary_t bin2;
        pl2 << new payload_member(new quic_encoded(binary_t()));
        pl2.read(bin1);
        pl2.write(bin2);
        _logger->hdump("dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect_zero_length, __FUNCTION__, "zero-length #read");
    }

    // integer
    auto test_lambda = [&](uint64 value, const char* expect) -> void {
        binary_t bin_expect = base16_decode_rfc(expect);
        payload pl1;
        binary_t bin1;

        pl1 << new payload_member(new quic_encoded(value));
        pl1.write(bin1);

        _logger->hdump("> dump", bin1, 16, 3);
        _test_case.assert(bin1 == bin_expect, __FUNCTION__, "QUIC variable length integer #write %I64i -> %s", value, base16_encode(bin1).c_str());

        payload pl2;
        binary_t bin2;

        pl2 << new payload_member(new quic_encoded(uint64(0)));
        pl2.read(bin1);
        pl2.write(bin2);

        _logger->hdump("> dump", bin2, 16, 3);
        _test_case.assert(bin2 == bin_expect, __FUNCTION__, "QUIC variable length integer #read %I64i -> %s", value, base16_encode(bin2).c_str());
    };

    // RFC 9000 A.1
    test_lambda(151288809941952652, "0xc2197c5eff14e88c");
    test_lambda(494878333, "0x9d7f3e7d");
    test_lambda(15293, "0x7bbd");

    test_lambda(0x00, "0x00");
    test_lambda(0x3f, "0x3f");
    test_lambda(0x40, "0x4040");
    test_lambda(0x3fff, "0x7fff");
    test_lambda(0x4000, "0x80004000");
    test_lambda(0x3fffffff, "0xbfffffff");
    test_lambda(0x40000000, "0xc000000040000000");
    test_lambda(0x3fffffffffffffff, "0xffffffffffffffff");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif
    cmdline.make_share(new t_cmdline_t<OPTION>);

    *cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
             << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
             << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();

    cmdline->parse(argc, argv);
    const OPTION& option = cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    test_payload_write();
    test_payload_read();
    test_payload_uint24();
    test_http2_frame();
    test_quic_packet();
    test_quic_integer();

    _logger->flush();

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
