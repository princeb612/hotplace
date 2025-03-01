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

unsigned int count_evict_encoder = 0;
unsigned int count_evict_decoder = 0;

void test_expect(binary_t& bin, const char* expect, const char* text, ...) {
    _logger->dump(bin);

    va_list ap;
    va_start(ap, text);
    _test_case.assert(base16_decode_rfc(expect) == bin, __FUNCTION__, text, ap);
    va_end(ap);
}

void test_dump(binary_t& bin, const char* text, ...) {
    if (text) {
        basic_stream bs;
        va_list ap;
        va_start(ap, text);
        bs.printf(text, ap);
        _logger->hdump(bs.c_str(), bin);
        va_end(ap);
    } else {
        _logger->dump(bin);
    }
}

void debug_qpack_encoder(trace_category_t, uint32 event) {
    if (net_event_header_compression_evict == event) {
        count_evict_encoder++;
    }
};

void debug_qpack_decoder(trace_category_t, uint32 event) {
    if (net_event_header_compression_evict == event) {
        count_evict_decoder++;
    }
};

void test_rfc9204_b() {
    _test_case.begin("RFC 9204 Appendix B");

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_dynamic_table session_encoder;
    qpack_dynamic_table session_decoder;
    binary_t bin;
    uint32 flags_encoder = 0;
    uint32 flags_decoder = 0;
    size_t pos = 0;
    std::string name;
    std::string value;

    session_encoder.set_debug_hook(debug_qpack_encoder);
    session_decoder.set_debug_hook(debug_qpack_decoder);
    count_evict_encoder = 0;

    // B.1.  Literal Field Line with Name Reference
    {
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
        flags_encoder = 0;
        // field section
        enc.encode(&session_encoder, bin, ":path", "/index.html", flags_encoder);
        // not inserted yet, RIC = 0
        enc.sync(&session_encoder, bin, flags_encoder);

        // debug
        {
            constexpr char text1[] = "B.1.  Literal Field Line with Name Reference";
            const char* expect1 = "0000 510b 2f69 6e64 6578 2e68 746d 6c";
            // 00000000 : 00 00 51 0B 2F 69 6E 64 65 78 2E 68 74 6D 6C -- | ..Q./index.html
            test_expect(bin, expect1, "%s #field section", text1);
            _test_case.assert(0 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text1);

            pos = 0;
            ret = enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, qpack_quic_stream_header);  // field section prefix
            session_decoder.commit();
            _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "%s #field section prefix", text1);
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, qpack_quic_stream_header);  // field line
            session_decoder.commit();
            _test_case.assert((":path" == name) && ("/index.html" == value), __FUNCTION__, "%s #decode", text1);
            _test_case.assert(0 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text1);
        }
        bin.clear();
    }
    // B.2.  Dynamic Table
    {
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
        enc.set_capacity(&session_encoder, bin, 220);

        flags_encoder = qpack_intermediary;
        // insert field line
        enc.insert(&session_encoder, bin, ":authority", "www.example.com", flags_encoder);  // abs 0
        enc.insert(&session_encoder, bin, ":path", "/sample/path", flags_encoder);          // abs 1

        constexpr char text2[] = "B.2.  Dynamic Table";
        // debug
        {
            _test_case.assert(2 == session_encoder.get_entries(), __FUNCTION__, "%s #entries", text2);
            _test_case.assert(106 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text2);
            _test_case.assert(220 == session_encoder.get_capacity(), __FUNCTION__, "%s #capacity", text2);

            const char* expect1 = "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468";
            // 00000000 : 3F BD 01 C0 0F 77 77 77 2E 65 78 61 6D 70 6C 65 | ?....www.example
            // 00000010 : 2E 63 6F 6D C1 0C 2F 73 61 6D 70 6C 65 2F 70 61 | .com../sample/pa
            // 00000020 : 74 68 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | th
            test_expect(bin, expect1, "%s #insert", text2);
        }
        // debug QPACK encoder stream
        {
            flags_decoder = qpack_quic_stream_encoder;
            pos = 0;
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert(220 == session_decoder.get_capacity(), __FUNCTION__, "%s #capacity", text2);

            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert(1 == session_decoder.get_entries(), __FUNCTION__, "%s #entries", text2);
            _test_case.assert((":authority" == name) && ("www.example.com" == value), __FUNCTION__, "%s #decode", text2);

            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert(2 == session_decoder.get_entries(), __FUNCTION__, "%s #entries", text2);

            _test_case.assert((":path" == name) && ("/sample/path" == value), __FUNCTION__, "%s #decode", text2);
        }
        bin.clear();

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

        // field section
        flags_encoder = qpack_postbase_index;
        enc.encode(&session_encoder, bin, ":authority", "www.example.com", flags_encoder);
        enc.encode(&session_encoder, bin, ":path", "/sample/path", flags_encoder);
        enc.sync(&session_encoder, bin, flags_encoder);

        // debug
        {
            const char* expect2 = "0381 10 11";
            test_expect(bin, expect2, "%s #field section", text2);
            _test_case.assert(106 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text2);
        }
        {
            flags_decoder = qpack_quic_stream_header;
            pos = 0;
            ret = enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);  // field section prefix
            session_decoder.commit();
            _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "%s #field section prefix", text2);
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);  // :authority
            session_decoder.commit();
            _test_case.assert((":authority" == name) && ("www.example.com" == value), __FUNCTION__, "%s #decode", text2);
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);  // :path
            session_decoder.commit();
            _test_case.assert((":path" == name) && ("/sample/path" == value), __FUNCTION__, "%s #decode", text2);

            _test_case.assert(session_encoder.get_entries() == session_decoder.get_entries(), __FUNCTION__, "%s #entries", text2);
        }
        bin.clear();

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

        // debug
        {
            const char* expect3 = "84";
            test_expect(bin, expect3, "%s #ack", text2);
            _test_case.assert(106 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text2);
        }
        bin.clear();
    }
    // B.3.  Speculative Insert
    {
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
        flags_encoder = qpack_intermediary;
        ret = enc.insert(&session_encoder, bin, "custom-key", "custom-value", flags_encoder);  // abs 2

        constexpr char text3[] = "B.3.  Speculative Insert";
        // debug
        {
            const char* expect1 = "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565";
            // 00000000 : 4A 63 75 73 74 6F 6D 2D 6B 65 79 0C 63 75 73 74 | Jcustom-key.cust
            // 00000010 : 6F 6D 2D 76 61 6C 75 65 -- -- -- -- -- -- -- -- | om-value
            test_expect(bin, expect1, "%s #encode", text3);
            _test_case.assert(3 == session_encoder.get_entries(), __FUNCTION__, "%s #entries", text3);
            _test_case.assert(160 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text3);
        }
        // debug QPACK encoder stream
        {
            flags_decoder = qpack_quic_stream_encoder;
            pos = 0;
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert(("custom-key" == name) && ("custom-value" == value), __FUNCTION__, "%s #decode", text3);
            _test_case.assert(3 == session_decoder.get_entries(), __FUNCTION__, "%s #entries", text3);
            _test_case.assert(160 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text3);
        }
        bin.clear();

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

        test_expect(bin, "01", "%s #increment", text3);
        bin.clear();
    }
    // B.4.  Duplicate Instruction, Stream Cancellation
    {
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

        // insert field line
        flags_encoder = qpack_intermediary;
        ret = enc.insert(&session_encoder, bin, ":authority", "www.example.com", flags_encoder);

        constexpr char text4[] = "B.4.  Duplicate Instruction, Stream Cancellation";
        // debug
        {
            _test_case.assert(errorcode_t::already_exist == ret, __FUNCTION__, "%s #duplicate", text4);
            _test_case.assert(4 == session_encoder.get_entries(), __FUNCTION__, "%s #entries", text4);  // is duplicated
            test_expect(bin, "02", "%s #duplicate", text4);
        }
        // debug QPACK stream encoder
        {
            flags_decoder = qpack_quic_stream_encoder;
            pos = 0;
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert((":authority" == name) && ("www.example.com" == value), __FUNCTION__, "%s #decode", text4);
            _test_case.assert(4 == session_decoder.get_entries(), __FUNCTION__, "%s #entries", text4);
            _test_case.assert(217 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text4);
        }
        bin.clear();

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

        flags_encoder = 0;
        enc.encode(&session_encoder, bin, ":authority", "www.example.com", flags_encoder);
        enc.encode(&session_encoder, bin, ":path", "/", flags_encoder);
        enc.encode(&session_encoder, bin, "custom-key", "custom-value", flags_encoder);
        enc.sync(&session_encoder, bin, flags_encoder);

        // debug
        {
            _test_case.assert(4 == session_encoder.get_entries(), __FUNCTION__, "%s #entries", text4);

            const char* expect3 = "0500 80 c1 81";
            test_expect(bin, expect3, "%s #field section", text4);
            _test_case.assert(217 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text4);
        }
        {
            flags_decoder = qpack_quic_stream_header;
            pos = 0;
            ret = enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);  // field section prefix
            session_decoder.commit();
            _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "%s #field section prefix", text4);
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert((":authority" == name) && ("www.example.com" == value), __FUNCTION__, "%s #decode", text4);
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert((":path" == name) && ("/" == value), __FUNCTION__, "%s #decode", text4);
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert(("custom-key" == name) && ("custom-value" == value), __FUNCTION__, "%s #decode", text4);
            _test_case.assert(4 == session_decoder.get_entries(), __FUNCTION__, "%s #entries", text4);
        }
        bin.clear();

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

        uint32 streamid = 8;
        enc.cancel(bin, streamid);
        const char* expect4 = "48";
        test_expect(bin, expect4, "%s #cancel", text4);
        _test_case.assert(217 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text4);
        bin.clear();
    }
    // B.5.  Dynamic Table Insert, Eviction
    {
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
        constexpr char text5[] = "B.5.  Dynamic Table Insert, Eviction";
        { _test_case.assert(0 == count_evict_encoder, __FUNCTION__, "%s #eviction - before", text5); }

        flags_encoder = qpack_name_reference;
        enc.insert(&session_encoder, bin, "custom-key", "custom-value2", flags_encoder);  // abs 4, evict entry 0

        // debug
        {
            _test_case.assert(1 == count_evict_encoder, __FUNCTION__, "%s #eviction - after", text5);
            _test_case.assert(4 == session_encoder.get_entries(), __FUNCTION__, "%s #entries", text5);
            _test_case.assert(215 == session_encoder.get_tablesize(), __FUNCTION__, "%s #table size", text5);

            const char* expect = "810d 6375 7374 6f6d 2d76 616c 7565 32";
            //   00000000 : 81 0D 63 75 73 74 6F 6D 2D 76 61 6C 75 65 32 -- | ..custom-value2
            test_expect(bin, expect, "%s #insert", text5);
        }
        // debug QPACK stream encoder
        {
            flags_decoder = qpack_quic_stream_encoder;
            pos = 0;
            enc.decode(&session_decoder, &bin[0], bin.size(), pos, name, value, flags_decoder);
            session_decoder.commit();
            _test_case.assert(("custom-key" == name) && ("custom-value2" == value), __FUNCTION__, "%s #decode", text5);
            _test_case.assert(1 == count_evict_decoder, __FUNCTION__, "%s #eviction", text5);
            _test_case.assert(4 == session_decoder.get_entries(), __FUNCTION__, "%s #entries", text5);
            _test_case.assert(215 == session_decoder.get_tablesize(), __FUNCTION__, "%s #table size", text5);
        }
        bin.clear();
    }
}
