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

void test_expect(binary_t& bin, const char* expect, const char* func, const char* text, ...) {
    _logger->dump(bin);

    va_list ap;
    va_start(ap, text);
    _test_case.assert(base16_decode_rfc(expect) == bin, func, text, ap);
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

unsigned int count_evict_client = 0;
unsigned int count_evict_server = 0;

void debug_qpack_client(trace_category_t, uint32 event) {
    if (trace_event_header_compression_evict == event) {
        count_evict_client++;
    }
};

void debug_qpack_server(trace_category_t, uint32 event) {
    if (trace_event_header_compression_evict == event) {
        count_evict_server++;
    }
};

void test_rfc9204_b1() {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    qpack_dynamic_table dyntable;
    binary_t bin;
    uint32 flags = qpack_quic_stream_header;

    constexpr char text1[] = "B.1.  Literal Field Line with Name Reference";
    _logger->colorln(text1);

    // B.1.  Literal Field Line with Name Reference

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
    {
        // Literal Field Line with Name Reference
        // Static Table, Index=1 (:path=/)
        enc.encode(&dyntable, bin, ":path", "/index.html", flags);
        // Required Insert Count = 0, Base = 0
        enc.pack(&dyntable, bin, flags);

        const char* expect1 = "0000 510b 2f69 6e64 6578 2e68 746d 6c";
        test_expect(bin, expect1, __FUNCTION__, "%s #field section", text1);
        _test_case.assert(0 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text1);
    }

    {
        size_t pos = 0;
        http_compression_decode_t item;

#if 0
        ret = enc.decode(&dyntable, &bin[0], bin.size(), pos, item, flags | qpack_field_section_prefix);
#else
        ret = enc.unpack(&dyntable, &bin[0], bin.size(), pos, item);
#endif
        _test_case.assert((0 == item.ric) && (0 == item.base), __FUNCTION__, "%s #field section prefix", text1);

        std::string name;
        std::string value;
        enc.decode(&dyntable, &bin[0], bin.size(), pos, item, flags);  // field line
        _test_case.assert((":path" == item.name) && ("/index.html" == item.value), __FUNCTION__, "%s #decode", text1);

        dyntable.dump("RFC 9204 B.1.", dump_qpack_session_routine);
        _test_case.assert(0 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text1);
    }
}

void test_rfc9204_b2_encoder_stream(const char* text2, binary_t& bin, qpack_dynamic_table& dyntable) {
    bin.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

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
    {
        // Set Dynamic Table Capacity=220
        enc.set_capacity(&dyntable, bin, 220);

        flags = qpack_intermediary;

        // Insert With Name Reference
        // Static Table, Index=0 :authority
        enc.insert(&dyntable, bin, ":authority", "www.example.com", flags);
        // Insert With Name Reference
        // Static Table, Index=1 :path=/
        enc.insert(&dyntable, bin, ":path", "/sample/path", flags);
    }

    {
        dyntable.dump("RFC 9204 B.2. Stream: Encoder", dump_qpack_session_routine);

        const char* expect1 = "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468";
        // 00000000 : 3F BD 01 C0 0F 77 77 77 2E 65 78 61 6D 70 6C 65 | ?....www.example
        // 00000010 : 2E 63 6F 6D C1 0C 2F 73 61 6D 70 6C 65 2F 70 61 | .com../sample/pa
        // 00000020 : 74 68 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | th
        test_expect(bin, expect1, __FUNCTION__, "%s #insert", text2);
        _test_case.assert(220 == dyntable.get_capacity(), __FUNCTION__, "%s #capacity %zi", text2, dyntable.get_capacity());
        _test_case.assert(106 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size %zi", text2, dyntable.get_tablesize());
    }
}

void test_rfc9204_b2_header_stream(const char* text2, binary_t& bin, qpack_dynamic_table& dyntable) {
    bin.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

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

    {
        flags = qpack_postbase_index;
        enc.encode(&dyntable, bin, ":authority", "www.example.com", flags);
        enc.encode(&dyntable, bin, ":path", "/sample/path", flags);
        enc.pack(&dyntable, bin, flags);  // field section prefix
    }

    {
        dyntable.dump("RFC 9204 B.2. Stream: 4", dump_qpack_session_routine);

        const char* expect2 = "0381 10 11";
        test_expect(bin, expect2, __FUNCTION__, "%s #field section", text2);
        _test_case.assert(106 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size %zi", text2, dyntable.get_tablesize());

        flags = qpack_quic_stream_header;
        pos = 0;
#if 0
        ret = enc.decode(&dyntable, &bin[0], bin.size(), pos, item, flags | qpack_field_section_prefix);
#else
        ret = enc.unpack(&dyntable, &bin[0], bin.size(), pos, item);
#endif
        _test_case.assert((2 == item.ric) && (0 == item.base), __FUNCTION__, "%s #field section prefix", text2);

        enc.decode(&dyntable, &bin[0], bin.size(), pos, item, flags);  // :authority
        _test_case.assert((":authority" == item.name) && ("www.example.com" == item.value), __FUNCTION__, "%s #decode", text2);

        enc.decode(&dyntable, &bin[0], bin.size(), pos, item, flags);  // :path
        _test_case.assert((":path" == item.name) && ("/sample/path" == item.value), __FUNCTION__, "%s #decode", text2);
    }
}

void test_rfc9204_b2(const char* text2, const binary_t& encoderstream, const binary_t& headerstream, binary_t& decoderstream, qpack_dynamic_table& dyntable) {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

    // encoder stream
    {
        flags = qpack_quic_stream_encoder;
        pos = 0;

        enc.decode(&dyntable, &encoderstream[0], encoderstream.size(), pos, item, flags);  // capacity
        _test_case.assert(220 == dyntable.get_capacity(), __FUNCTION__, "%s #capacity %zi", text2, dyntable.get_capacity());

        enc.decode(&dyntable, &encoderstream[0], encoderstream.size(), pos, item, flags);
        _test_case.assert((":authority" == item.name) && ("www.example.com" == item.value), __FUNCTION__, "%s #decode", text2);

        enc.decode(&dyntable, &encoderstream[0], encoderstream.size(), pos, item, flags);
        _test_case.assert((":path" == item.name) && ("/sample/path" == item.value), __FUNCTION__, "%s #decode", text2);

        _test_case.assert(220 == dyntable.get_capacity(), __FUNCTION__, "%s #capacity %zi", text2, dyntable.get_capacity());

        dyntable.dump("RFC 9204 B.2. Stream: Decoder #before", dump_qpack_session_routine);
    }

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

    {
        uint32 streamid = 4;  // RFC 9204 B.2.  Dynamic Table
        enc.ack(&dyntable, decoderstream, streamid);
    }

    {
        dyntable.dump("RFC 9204 B.2. Stream: Decoder #after", dump_qpack_session_routine);

        const char* expect3 = "84";
        test_expect(decoderstream, expect3, __FUNCTION__, "%s #ack", text2);
    }
}

void test_rfc9204_b2_decoder_stream(const char* text2, binary_t& bin, qpack_dynamic_table& dyntable) {
    bin.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

    dyntable.dump("RFC 9204 B.2. Stream: Decoder #before", dump_qpack_session_routine);

    {
        flags = qpack_quic_stream_decoder;
        pos = 0;
        ret = enc.decode(&dyntable, bin.empty() ? nullptr : &bin[0], bin.size(), pos, item, flags);

        dyntable.dump("RFC 9204 B.2. Stream: Decoder #after", dump_qpack_session_routine);

        _test_case.assert(106 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size %zi", text2, dyntable.get_tablesize());
    }
}

void test_rfc9204_b3_encoder_stream(const char* text3, binary_t& bin, qpack_dynamic_table& dyntable) {
    bin.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

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

    {
        flags = qpack_intermediary;
        ret = enc.insert(&dyntable, bin, "custom-key", "custom-value", flags);  // abs 2
    }

    {
        dyntable.dump("RFC 9204 B.3. Stream: Encoder", dump_qpack_session_routine);

        const char* expect1 = "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565";
        // 00000000 : 4A 63 75 73 74 6F 6D 2D 6B 65 79 0C 63 75 73 74 | Jcustom-key.cust
        // 00000010 : 6F 6D 2D 76 61 6C 75 65 -- -- -- -- -- -- -- -- | om-value
        test_expect(bin, expect1, __FUNCTION__, "%s #encode", text3);
        _test_case.assert(160 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size %zi", text3, dyntable.get_tablesize());
    }
}

void test_rfc9204_b3(const char* text3, const binary_t& encoderstream, binary_t& decoderstream, qpack_dynamic_table& dyntable) {
    decoderstream.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

    {
        flags = qpack_quic_stream_encoder;
        pos = 0;
        enc.decode(&dyntable, &encoderstream[0], encoderstream.size(), pos, item, flags);

        _test_case.assert(("custom-key" == item.name) && ("custom-value" == item.value), __FUNCTION__, "%s #decode", text3);

        dyntable.dump("RFC 9204 B.3. Stream: Decoder #before", dump_qpack_session_routine);
    }

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
    enc.increment(&dyntable, decoderstream, 1);

    {
        dyntable.dump("RFC 9204 B.3. Stream: Decoder #after", dump_qpack_session_routine);

        test_expect(decoderstream, "01", __FUNCTION__, "%s #increment", text3);
    }
}

void test_rfc9204_b3_decoder_stream(const char* text3, const binary_t& bin, qpack_dynamic_table& dyntable) {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

    dyntable.dump("RFC 9204 B.3. Stream: Decoder #efore", dump_qpack_session_routine);

    {
        flags = qpack_quic_stream_decoder;
        pos = 0;
        enc.decode(&dyntable, &bin[0], bin.size(), pos, item, flags);
    }

    dyntable.dump("RFC 9204 B.3. Stream: Decoder #after", dump_qpack_session_routine);
}

void test_rfc9204_b4_encoder_stream(const char* text4, binary_t& bin, qpack_dynamic_table& dyntable) {
    bin.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

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

    {
        // insert field line
        flags = qpack_intermediary;
        ret = enc.insert(&dyntable, bin, ":authority", "www.example.com", flags);
    }
    {
        _test_case.assert(errorcode_t::already_exist == ret, __FUNCTION__, "%s #duplicate", text4);

        dyntable.dump("RFC 9204 B.4. Stream: Encoder", dump_qpack_session_routine);

        test_expect(bin, "02", __FUNCTION__, "%s #duplicate", text4);
    }
}

void test_rfc9204_b4_header_stream(const char* text4, binary_t& bin, qpack_dynamic_table& dyntable) {
    bin.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

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

    {
        flags = 0;
        enc.encode(&dyntable, bin, ":authority", "www.example.com", flags);
        enc.encode(&dyntable, bin, ":path", "/", flags);
        enc.encode(&dyntable, bin, "custom-key", "custom-value", flags);
        enc.pack(&dyntable, bin, flags);
    }

    {
        dyntable.dump("RFC 9204 B.4. Stream: 8", dump_qpack_session_routine);

        const char* expect3 = "0500 80 c1 81";
        test_expect(bin, expect3, __FUNCTION__, "%s #field section", text4);
        _test_case.assert(217 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text4);
    }
}

void test_rfc9204_b4(const char* text4, const binary_t& encoderstream, const binary_t& headerstream, binary_t& decoderstream, qpack_dynamic_table& dyntable) {
    decoderstream.clear();

    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

    dyntable.dump("RFC 9204 B.4. #Before the encoder stream packet arrives", dump_qpack_session_routine);

    int encoder_stream_state = 0;  // RFC 9204. B.4. before the encoder stream packet arrives
    if (encoder_stream_state) {
        flags = qpack_quic_stream_encoder;
        pos = 0;
        enc.decode(&dyntable, &encoderstream[0], encoderstream.size(), pos, item, flags);

        _test_case.assert((":authority" == item.name) && ("www.example.com" == item.value), __FUNCTION__, "%s #decode", text4);
        _test_case.assert(217 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text4);
    }

    {
        flags = qpack_quic_stream_header;
        pos = 0;
#if 0
        ret = enc.decode(&dyntable, &headerstream[0], headerstream.size(), pos, item, flags | qpack_field_section_prefix);
#else
        ret = enc.unpack(&dyntable, &headerstream[0], headerstream.size(), pos, item);
#endif

        if (errorcode_t::success == ret) {
            _test_case.assert((4 == item.ric) && (4 == item.base), __FUNCTION__, "%s #field section prefix", text4);

            enc.decode(&dyntable, &headerstream[0], headerstream.size(), pos, item, flags);
            _test_case.assert((":authority" == item.name) && ("www.example.com" == item.value), __FUNCTION__, "%s #decode", text4);

            enc.decode(&dyntable, &headerstream[0], headerstream.size(), pos, item, flags);
            _test_case.assert((":path" == item.name) && ("/" == item.value), __FUNCTION__, "%s #decode", text4);

            enc.decode(&dyntable, &headerstream[0], headerstream.size(), pos, item, flags);
            _test_case.assert(("custom-key" == item.name) && ("custom-value" == item.value), __FUNCTION__, "%s #decode", text4);
        } else if (errorcode_t::not_ready == ret) {
            // delayed state

            uint32 streamid = 8;
            enc.cancel(&dyntable, decoderstream, streamid);

            {
                const char* expect4 = "48";
                test_expect(decoderstream, expect4, __FUNCTION__, "%s #cancel", text4);
            }
        }
    }
}

void test_rfc9204_b4_decoder_stream(const char* text4, const binary_t& bin, qpack_dynamic_table& dyntable) {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

    flags = qpack_quic_stream_decoder;
    pos = 0;
    ret = enc.decode(&dyntable, &bin[0], bin.size(), pos, item, flags);

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

    dyntable.dump("RFC 9204 B.4. Stream: Decoder", dump_qpack_session_routine);

    _test_case.assert(217 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text4);
}

void test_rfc9204_b5(const char* text5, qpack_dynamic_table& dyntable) {
    return_t ret = errorcode_t::success;
    qpack_encoder enc;
    uint32 flags = 0;
    size_t pos = 0;
    http_compression_decode_t item;

    binary_t bin;

    // B.5.  Dynamic Table Insert, Eviction

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
    {
        dyntable.dump("RFC 9204 B.5. Stream: Encoder #before", dump_qpack_session_routine);

        _test_case.assert(0 == count_evict_client, __FUNCTION__, "%s #eviction - before", text5);
    }

    {
        flags = qpack_name_reference;
        enc.insert(&dyntable, bin, "custom-key", "custom-value2", flags);  // abs 4, evict entry 0
    }

    {
        dyntable.dump("RFC 9204 B.5. Stream: Encoder #after", dump_qpack_session_routine);

        const char* expect = "810d 6375 7374 6f6d 2d76 616c 7565 32";
        //   00000000 : 81 0D 63 75 73 74 6F 6D 2D 76 61 6C 75 65 32 -- | ..custom-value2
        test_expect(bin, expect, __FUNCTION__, "%s #insert", text5);

        _test_case.assert(1 == count_evict_client, __FUNCTION__, "%s #eviction - after", text5);
        _test_case.assert(215 == dyntable.get_tablesize(), __FUNCTION__, "%s #table size", text5);
    }
}

void test_rfc9204_b() {
    _test_case.begin("RFC 9204 Appendix B");

    test_rfc9204_b1();

    qpack_dynamic_table clienttable;
    qpack_dynamic_table servertable;
    clienttable.set_debug_hook(debug_qpack_client);
    servertable.set_debug_hook(debug_qpack_server);
    qpack_encoder enc;
    binary_t encoderstream;
    binary_t headerstream;
    binary_t decoderstream;

    // (client) send QPACK STREAM QPACK Decoder Stream (client-initiated uni-directional)
    // (client) send QPACK STREAM QPACK Encoder Stream (client-initiated uni-directional)

    // B.2.  Dynamic Table
    // The encoder sets the dynamic table capacity, inserts a header with a dynamic name reference,
    // then sends a potentially blocking, encoded field section referencing this new entry.
    // The decoder acknowledges processing the encoded field section, which implicitly acknowledges
    // all dynamic table insertions up to the Required Insert Count.

    constexpr char text2[] = "B.2.  Dynamic Table";
    _logger->colorln(text2);

    // (client) send QPACK STREAM QPACK Encoder Stream .. set capacity, insert operations
    test_rfc9204_b2_encoder_stream(text2, encoderstream, clienttable);
    // (client) send QPACK STREAM Header Stream (4 client-initiated bi-directional)
    test_rfc9204_b2_header_stream(text2, headerstream, clienttable);
    // (server) read QPACK STREAM QPACK Encoder Stream .. set capacity, insert operations
    // (server) ack QPACK STREAM Header Stream
    // (server) send QPACK STREAM QPACK Decoder Stream
    test_rfc9204_b2(text2, encoderstream, headerstream, decoderstream, servertable);
    // (client) read decoder stream
    test_rfc9204_b2_decoder_stream(text2, decoderstream, clienttable);

    // B.3.  Speculative Insert

    // The encoder inserts a header into the dynamic table with a literal name.
    // The decoder acknowledges receipt of the entry.
    // The encoder does not send any encoded field sections.

    constexpr char text3[] = "B.3.  Speculative Insert";
    _logger->colorln(text3);

    // (client) send encoder stream
    test_rfc9204_b3_encoder_stream(text3, encoderstream, clienttable);
    // (client) do not send header stream
    // (server) increment
    // (server) send decoder stream
    test_rfc9204_b3(text3, encoderstream, decoderstream, servertable);
    // (client) read decoder stream
    test_rfc9204_b3_decoder_stream(text2, decoderstream, clienttable);

    // B.4.  Duplicate Instruction, Stream Cancellation

    // The encoder duplicates an existing entry in the dynamic table,
    //  then sends an encoded field section referencing the dynamic table entries including the duplicated entry.
    // The packet containing the encoder stream data is delayed.
    // Before the packet arrives, the decoder cancels the stream and notifies the encoder that the encoded field
    //  section was not processed.

    constexpr char text4[] = "B.4.  Duplicate Instruction, Stream Cancellation";
    _logger->colorln(text4);

    test_rfc9204_b4_encoder_stream(text4, encoderstream, clienttable);
    test_rfc9204_b4_header_stream(text4, headerstream, clienttable);
    test_rfc9204_b4(text4, encoderstream, headerstream, decoderstream, servertable);
    test_rfc9204_b4_decoder_stream(text4, decoderstream, clienttable);

    constexpr char text5[] = "B.5.  Dynamic Table Insert, Eviction";
    _logger->colorln(text5);

    test_rfc9204_b5(text5, clienttable);
}
