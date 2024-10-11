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
 * TODO
 *  - understand RIC and Base (B.4)
 *  - decoder not implemented yet
 */

#include <stdio.h>

#include <iostream>
#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_expect(binary_t& bin, const char* expect, bool flush, const char* text) {
    _logger->dump(bin);
    _test_case.assert(base16_decode_rfc(expect) == bin, __FUNCTION__, text);
    if (flush) {
        bin.clear();
    }
}

void tet_rfc9204_b1() {
    /**
     * Data                | Interpretation
     *                              | Encoder's Dynamic Table
     *
     * Stream: 0
     * 0000                | Required Insert Count = 0, Base = 0
     * 510b 2f69 6e64 6578 | Literal Field Line with Name Reference
     * 2e68 746d 6c        |  Static Table, Index=1
     *                     |  (:path=/index.html)
     *
     *                               Abs Ref Name        Value
     *                               ^-- acknowledged --^
     *                               Size=0
     */

    qpack_encoder enc;
    qpack_session session;
    binary_t bin;

    enc.encode(&session, bin, ":path", "/index.html");  // wo qpack_indexing
    enc.sync(&session, bin);                            // field section prefix

    const char* expect2 = "0000 510b 2f69 6e64 6578 2e68 746d 6c";
    test_expect(bin, expect2, true, "B.1.  Literal Field Line with Name Reference #1");
}

void tet_rfc9204_b2() {
    qpack_encoder enc;
    qpack_session session;
    binary_t bin;
    uint32 flags = 0;

    /**
     *   Stream: Encoder
     *   3fbd01              | Set Dynamic Table Capacity=220
     *   c00f 7777 772e 6578 | Insert With Name Reference
     *   616d 706c 652e 636f | Static Table, Index=0
     *   6d                  |  (:authority=www.example.com)
     *   c10c 2f73 616d 706c | Insert With Name Reference
     *   652f 7061 7468      |  Static Table, Index=1
     *                       |  (:path=/sample/path)
     *
     *                                 Abs Ref Name        Value
     *                                 ^-- acknowledged --^
     *                                  0   0  :authority  www.example.com
     *                                  1   0  :path       /sample/path
     *                                 Size=106
     */
    enc.set_dynamic_table_size(bin, 220);
    const char* expect1 = "3fbd01";
    test_expect(bin, expect1, true, "B.2.  Dynamic Table #1");

    flags = qpack_indexing | qpack_intermediary;
    enc.encode(&session, bin, ":authority", "www.example.com", flags);  // abs 0
    enc.encode(&session, bin, ":path", "/sample/path", flags);          // abs 1
    const char* expect2 = "c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468";
    test_expect(bin, expect2, true, "B.2.  Dynamic Table #2");

    /**
     *   Stream: 4
     *   0381                | Required Insert Count = 2, Base = 0
     *   10                  | Indexed Field Line With Post-Base Index
     *                       |  Absolute Index = Base(0) + Index(0) = 0
     *                       |  (:authority=www.example.com)
     *   11                  | Indexed Field Line With Post-Base Index
     *                       |  Absolute Index = Base(0) + Index(1) = 1
     *                       |  (:path=/sample/path)
     *
     *                                 Abs Ref Name        Value
     *                                 ^-- acknowledged --^
     *                                  0   1  :authority  www.example.com
     *                                  1   1  :path       /sample/path
     *                                 Size=106
     *
     */

    flags = qpack_postbase_index;
    enc.encode(&session, bin, ":authority", "www.example.com", flags);  // ref++
    enc.encode(&session, bin, ":path", "/sample/path", flags);          // ref++
    enc.sync(&session, bin);

    const char* expect3 = "0381 10 11";
    test_expect(bin, expect3, true, "B.2.  Dynamic Table #3");

    /**
     *   Stream: Decoder
     *   84                  | Section Acknowledgment (stream=4)
     *
     *                                 Abs Ref Name        Value
     *                                  0   0  :authority  www.example.com
     *                                  1   0  :path       /sample/path
     *                                 ^-- acknowledged --^
     *                                 Size=106
     */

    uint32 streamid = 4;
    enc.ack(bin, streamid);

    const char* expect5 = "84";
    test_expect(bin, expect5, true, "B.2.  Dynamic Table #5");
}

void tet_rfc9204_b3() {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_session session;
    uint32 flags = 0;
    binary_t bin;

    flags = qpack_indexing | qpack_intermediary;
    enc.encode(&session, bin, ":authority", "www.example.com", flags);  // abs 0
    enc.encode(&session, bin, ":path", "/sample/path", flags);          // abs 1
    enc.sync(&session, bin);
    _logger->dump(bin);
    bin.clear();  // next step
    /**
     *   Stream: Encoder
     *   4a63 7573 746f 6d2d | Insert With Literal Name
     *   6b65 790c 6375 7374 |  (custom-key=custom-value)
     *   6f6d 2d76 616c 7565 |
     *
     *                                 Abs Ref Name        Value
     *                                  0   0  :authority  www.example.com
     *                                  1   0  :path       /sample/path
     *                                 ^-- acknowledged --^
     *                                  2   0  custom-key  custom-value
     *                                 Size=160
     */
    ret = enc.encode(&session, bin, "custom-key", "custom-value", flags);  // abs 2
    const char* expect1 = "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565";
    test_expect(bin, expect1, true, "B.3.  Speculative Insert #1");
    /**
     *   Stream: Decoder
     *   01                  | Insert Count Increment (1)
     *
     *                                 Abs Ref Name        Value
     *                                  0   0  :authority  www.example.com
     *                                  1   0  :path       /sample/path
     *                                  2   0  custom-key  custom-value
     *                                 ^-- acknowledged --^
     *                                 Size=160
     */
    if (errorcode_t::success == ret) {
        enc.increment(bin, 1);  // stream id 1
    }

    test_expect(bin, "01", true, "B.3.  Speculative Insert #2");
}

void tet_rfc9204_b4() {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_session session;
    uint32 flags = 0;
    binary_t bin;

    flags = qpack_indexing | qpack_intermediary;
    enc.encode(&session, bin, ":authority", "www.example.com", flags);  // abs 0
    enc.encode(&session, bin, ":path", "/sample/path", flags);          // abs 1
    enc.encode(&session, bin, "custom-key", "custom-value", flags);     // abs 2
    _logger->hdump("B.4.  Duplicate Instruction, Stream Cancellation #1", bin);
    bin.clear();  // next step
    /**
     *   Stream: Encoder
     *   02                  | Duplicate (Relative Index = 2)
     *                       |  Absolute Index =
     *                       |   Insert Count(3) - Index(2) - 1 = 0
     *
     *                                 Abs Ref Name        Value
     *                                  0   0  :authority  www.example.com
     *                                  1   0  :path       /sample/path
     *                                  2   0  custom-key  custom-value
     *                                 ^-- acknowledged --^
     *                                  3   0  :authority  www.example.com
     *                                 Size=217
     */
    ret = enc.encode(&session, bin, ":authority", "www.example.com", flags);  // ref++
    // check already_exist
    _test_case.assert(errorcode_t::already_exist == ret, __FUNCTION__, "B.4.  Duplicate Instruction, Stream Cancellation #2.1");
    // check duplicate
    test_expect(bin, "02", true, "B.4.  Duplicate Instruction, Stream Cancellation #2.2");

    /**
     *   Stream: 8
     *   0500                | Required Insert Count = 4, Base = 4
     *   80                  | Indexed Field Line, Dynamic Table
     *                       |  Absolute Index = Base(4) - Index(0) - 1 = 3
     *                       |  (:authority=www.example.com)
     *   c1                  | Indexed Field Line, Static Table Index = 1
     *                       |  (:path=/)
     *   81                  | Indexed Field Line, Dynamic Table
     *                       |  Absolute Index = Base(4) - Index(1) - 1 = 2
     *                       |  (custom-key=custom-value)
     *
     *                                 Abs Ref Name        Value
     *                                  0   0  :authority  www.example.com
     *                                  1   0  :path       /sample/path
     *                                  2   1  custom-key  custom-value
     *                                 ^-- acknowledged --^
     *                                  3   1  :authority  www.example.com
     *                                 Size=217
     */

    // studying
    // 0500

    flags = 0;
    enc.encode(&session, bin, ":authority", "www.example.com", flags);
    enc.encode(&session, bin, ":path", "/", flags);
    enc.encode(&session, bin, "custom-key", "custom-value", flags);

    const char* expect3 = "80 c1 81";
    test_expect(bin, expect3, true, "B.4.  Duplicate Instruction, Stream Cancellation #3");
    /**
     *   Stream: Decoder
     *   48                  | Stream Cancellation (Stream=8)
     *
     *                                 Abs Ref Name        Value
     *                                  0   0  :authority  www.example.com
     *                                  1   0  :path       /sample/path
     *                                  2   0  custom-key  custom-value
     *                                 ^-- acknowledged --^
     *                                  3   0  :authority  www.example.com
     *                                 Size=217
     */

    // studying
    //

    uint32 streamid = 8;
    enc.cancel(bin, streamid);
    const char* expect4 = "48";
    test_expect(bin, expect4, true, "B.4.  Duplicate Instruction, Stream Cancellation #4");
}

void tet_rfc9204_b5() {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_session session;
    uint32 flags = 0;
    binary_t bin;

    /**
     *   Stream: Encoder
     *   810d 6375 7374 6f6d | Insert With Name Reference
     *   2d76 616c 7565 32   |  Dynamic Table, Relative Index = 1
     *                       |  Absolute Index =
     *                       |   Insert Count(4) - Index(1) - 1 = 2
     *                       |  (custom-key=custom-value2)
     *
     *                                 Abs Ref Name        Value
     *                                  1   0  :path       /sample/path
     *                                  2   0  custom-key  custom-value
     *                                 ^-- acknowledged --^
     *                                  3   0  :authority  www.example.com
     *                                  4   0  custom-key  custom-value2
     *                                 Size=215
     */
    flags = qpack_indexing;
    enc.encode(&session, bin, ":authority", "www.example.com", flags);  // abs 0
    enc.encode(&session, bin, ":path", "/sample/path", flags);          // abs 1
    enc.encode(&session, bin, "custom-key", "custom-value", flags);     // abs 2
    enc.sync(&session, bin);
    bin.clear();  // next step

    enc.encode(&session, bin, ":authority", "www.example.com", flags);  // abs 3
    enc.encode(&session, bin, "custom-key", "custom-value2", flags);    // abs 4

    // 81(1000 0001) indexed, dynamic table, 1
    // 0d(0000 1011)

    const char* expect = "810d 6375 7374 6f6d 2d76 616c 7565 32";
    test_expect(bin, expect, true, "B.5.  Dynamic Table Insert, Eviction #1");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    _test_case.begin("RFC 9204 Appendix B");

    // studying
    tet_rfc9204_b1();
    tet_rfc9204_b2();
    tet_rfc9204_b3();
    tet_rfc9204_b4();
    tet_rfc9204_b5();

    _logger->flush();

    _test_case.report(5);
    return _test_case.result();
}
