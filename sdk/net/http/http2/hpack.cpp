/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/http2/hpack.hpp>

namespace hotplace {
namespace net {

hpack::hpack() : _safe_mask(false) {
    _hc.imports(_h2hcodes);  // RFC 7541 Appendix B. Huffman Code
}

hpack& hpack::encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value) {
    if ((1 <= prefix) && (prefix <= 8)) {
        // RFC 7541 5.1.  Integer Representation
        // RFC 7541 C.1.  Integer Representation Examples
        // RFC 7541 Figure 3: Integer Value Encoded after the Prefix (Shown for N = 5)
        //
        //     0   1   2   3   4   5   6   7
        //   +---+---+---+---+---+---+---+---+
        //   | ? | ? | ? | 1   1   1   1   1 |
        //   +---+---+---+-------------------+
        //   | 1 |    Value-(2^N-1) LSB      |
        //   +---+---------------------------+
        //                  ...
        //   +---+---------------------------+
        //   | 0 |    Value-(2^N-1) MSB      |
        //   +---+---------------------------+

        uint8 n = (1 << prefix) - 1;

        // safety mask
        if (_safe_mask && mask) {
            uint8 temp = 0;
            for (int t = 0; t < prefix; t++) {
                temp |= (1 << t);
            }
            mask &= ~temp;
        }

        uint8 i = 0;
        if (value < n) {
            target.insert(target.end(), value | mask);
        } else {
            target.insert(target.end(), n | mask);
            value -= n;
            // 128 (0x80)
            //   1 value
            //   1 value
            //   0 value
            while (value >= 0x80) {
                i = (value % 0x80) | 0x80;
                target.insert(target.end(), i);
                value /= 0x80;
            }
            target.insert(target.end(), value);
        }
    }
    return *this;
}

hpack& hpack::encode_string(binary_t& target, uint32 flags, const char* value) {
    __try2 {
        if (nullptr == value) {
            __leave2;
        }
        encode_string(target, flags, value, strlen(value));
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

hpack& hpack::encode_string(binary_t& target, uint32 flags, const char* value, size_t size) {
    __try2 {
        if (nullptr == value) {
            __leave2;
        }

        // RFC 7541 Figure 4: String Literal Representation
        //
        //     0   1   2   3   4   5   6   7
        //   +---+---+---+---+---+---+---+---+
        //   | H |    String Length (7+)     |
        //   +---+---------------------------+
        //   |  String Data (Length octets)  |
        //   +-------------------------------+

        if (hpack_huffman & flags) {
            size_t size_expected = 0;
            _hc.expect(value, size, size_expected);
            encode_int(target, 0x80, 7, size_expected);
            _hc.encode(target, value, size);
        } else {
            encode_int(target, 0x00, 7, size);
            target.insert(target.end(), value, value + size);
        }
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

hpack& hpack::encode_string(binary_t& target, uint32 flags, std::string const& value) { return encode_string(target, flags, value.c_str(), value.size()); }

hpack& hpack::encode_index(binary_t& target, uint8 index) {
    // RFC 7541 Figure 5: Indexed Header Field
    //
    //     0   1   2   3   4   5   6   7
    //   +---+---+---+---+---+---+---+---+
    //   | 1 |        Index (7+)         |
    //   +---+---------------------------+

    encode_int(target, 0x80, 7, index);
    return *this;
}

hpack& hpack::encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value) {
    __try2 {
        if (nullptr == value) {
            __leave2;
        }
        encode_indexed_name(target, flags, index, value, strlen(value));
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

hpack& hpack::encode_indexed_name(binary_t& target, uint32 flags, uint8 index, const char* value, size_t size) {
    __try2 {
        if (nullptr == value) {
            __leave2;
        }

        if (hpack_indexing & flags) {
            // RFC 7541 Figure 6: Literal Header Field with Incremental Indexing -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 1 |      Index (6+)       |
            //   +---+---+-----------------------+
            encode_int(target, 0x40, 6, index);
        } else if (hpack_wo_indexing & flags) {
            // RFC 7541 Figure 8: Literal Header Field without Indexing -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 0 |  Index (4+)   |
            //   +---+---+-----------------------+
            encode_int(target, 0x00, 4, index);
        } else if (hpack_never_indexed & flags) {
            // RFC 7541 Figure 10: Literal Header Field Never Indexed -- Indexed Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 1 |  Index (4+)   |
            //   +---+---+-----------------------+
            encode_int(target, 0x10, 4, index);
        } else {
            __leave2;
        }

        //   +-------------------------------+
        //   | H |     Value Length (7+)     |
        //   +---+---------------------------+
        //   | Value String (Length octets)  |
        //   +-------------------------------+
        encode_string(target, flags, value, size);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

hpack& hpack::encode_indexed_name(binary_t& target, uint32 flags, uint8 index, std::string const& value) {
    return encode_indexed_name(target, flags, index, value.c_str(), value.size());
}

hpack& hpack::encode_name_value(binary_t& target, uint32 flags, const char* name, const char* value) {
    __try2 {
        if (nullptr == name || nullptr == value) {
            __leave2;
        }

        if (hpack_indexing & flags) {
            // RFC 7541 Figure 7: Literal Header Field with Incremental Indexing -- New Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 1 |           0           |
            //   +---+---+-----------------------+
            target.insert(target.end(), 0x40);
        } else if (hpack_wo_indexing & flags) {
            // RFC 7541 Figure 9: Literal Header Field without Indexing -- New Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 0 |       0       |
            //   +---+---+-----------------------+
            target.insert(target.end(), 0);
        } else if (hpack_never_indexed & flags) {
            // RFC 7541 Figure 11: Literal Header Field Never Indexed -- New Name
            //
            //     0   1   2   3   4   5   6   7
            //   +---+---+---+---+---+---+---+---+
            //   | 0 | 0 | 0 | 1 |       0       |
            //   +---+---+-----------------------+
            target.insert(target.end(), 0x10);
        } else {
            __leave2;
        }

        //   +---+---------------------------+
        //   | H |     Name Length (7+)      |
        //   +---+---------------------------+
        //   |  Name String (Length octets)  |
        //   +---+---------------------------+
        //   | H |     Value Length (7+)     |
        //   +---+---------------------------+
        //   | Value String (Length octets)  |
        //   +-------------------------------+
        encode_string(target, flags, name);
        encode_string(target, flags, value);
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

hpack& hpack::encode_name_value(binary_t& target, uint32 flags, std::string const& name, std::string const& value) {
    return encode_name_value(target, flags, name.c_str(), value.c_str());
}

hpack& hpack::encode_dyntablesize(binary_t& target, uint8 maxsize) {
    // RFC 7541 Figure 12: Maximum Dynamic Table Size Change
    encode_int(target, 0x20, 5, maxsize);
    return *this;
}

return_t hpack::decode_int(byte_t* p, size_t& pos, uint8 prefix, size_t& value) {
    // 5.1.  Integer Representation
    // C.1.  Integer Representation Examples
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == p) {
            ret = errorcode_t::success;
            __leave2;
        }

        value = 0;
        if ((1 <= prefix) && (prefix <= 8)) {
            uint8 n = (1 << prefix) - 1;
            uint8 b = p[pos++];
            if (b < n) {
                value = b;
            } else {
                size_t m = 0;
                size_t i = b;
                do {
                    b = p[pos++];
                    i += (b & 0x7f) << m;
                    m += 7;
                } while (0x80 == (b & 0x80));
                value = i;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

match_result_t hpack::find_table(std::string const& name, std::string const& value, size_t& index) {
    match_result_t state = not_matched;
    index = 0;

    {
        size_t idx = 0;
        for (dynamic_table_t::iterator iter = _dynamic_table.begin(); iter != _dynamic_table.end(); iter++, idx++) {
            if ((name == iter->first) && (value == iter->second.value)) {
                state = all_matched;
                index = _static_table.size() + 1 + idx;
                break;
            }
        }
    }
    if (not_matched == state) {
        static_table_t::iterator iter;
        static_table_t::iterator liter;
        static_table_t::iterator uiter;

        liter = _static_table.lower_bound(name);
        uiter = _static_table.upper_bound(name);

        for (iter = liter; iter != uiter; iter++) {
            if (iter == liter) {
                index = iter->second.index;  // :path: /sample/path
                state = key_matched;
            }
            if (value == iter->second.value) {
                index = iter->second.index;
                state = all_matched;
                break;
            }
        }
    }
    return state;
}

return_t hpack::insert_table(std::string const& name, std::string const& value) {
    //  RFC 7541 Figure 1: Index Address Space
    //
    //   <----------  Index Address Space ---------->
    //   <-- Static  Table -->  <-- Dynamic Table -->
    //   +---+-----------+---+  +---+-----------+---+
    //   | 1 |    ...    | s |  |s+1|    ...    |s+k|
    //   +---+-----------+---+  +---+-----------+---+
    //                          ^                   |
    //                          |                   V
    //                   Insertion Point      Dropping Point
    //
    //               Figure 1: Index Address Space
    return_t ret = errorcode_t::success;
    _dynamic_table.push_front(std::make_pair(name, http2_table_t(value, 0)));
    return ret;
}

hpack& hpack::encode_header(binary_t& target, std::string const& name, std::string const& value, uint32 flags) {
    // RFC 7541 Appendix A.  Static Table Definition
    if (_static_table.empty()) {
#define ENTRY(index, header_name, header_value) \
    { index, header_name, header_value }
        struct static_table_entry {
            uint32 index;
            const char* name;
            const char* value;
        } entries[] = {
            ENTRY(1, ":authority", nullptr),
            ENTRY(2, ":method", "GET"),
            ENTRY(3, ":method", "POST"),
            ENTRY(4, ":path", "/"),
            ENTRY(5, ":path", "/index.html"),
            ENTRY(6, ":scheme", "http"),
            ENTRY(7, ":scheme", "https"),
            ENTRY(8, ":status", "200"),
            ENTRY(9, ":status", "204"),
            ENTRY(10, ":status", "206"),
            ENTRY(11, ":status", "304"),
            ENTRY(12, ":status", "400"),
            ENTRY(13, ":status", "404"),
            ENTRY(14, ":status", "500"),
            ENTRY(15, "accept-charset", nullptr),
            ENTRY(16, "accept-encoding", "gzip,deflate"),
            ENTRY(17, "accept-language", nullptr),
            ENTRY(18, "accept-ranges", nullptr),
            ENTRY(19, "accept", nullptr),
            ENTRY(20, "access-control-allow-origin", nullptr),
            ENTRY(21, "age", nullptr),
            ENTRY(22, "allow", nullptr),
            ENTRY(23, "authorization", nullptr),
            ENTRY(24, "cache-control", nullptr),
            ENTRY(25, "content-disposition", nullptr),
            ENTRY(26, "content-encoding", nullptr),
            ENTRY(27, "content-language", nullptr),
            ENTRY(28, "content-length", nullptr),
            ENTRY(29, "content-location", nullptr),
            ENTRY(30, "content-range", nullptr),
            ENTRY(31, "content-type", nullptr),
            ENTRY(32, "cookie", nullptr),
            ENTRY(33, "date", nullptr),
            ENTRY(34, "etag", nullptr),
            ENTRY(35, "expect", nullptr),
            ENTRY(36, "expires", nullptr),
            ENTRY(37, "from", nullptr),
            ENTRY(38, "host", nullptr),
            ENTRY(39, "if-match", nullptr),
            ENTRY(40, "if-modified-since", nullptr),
            ENTRY(41, "if-none-match", nullptr),
            ENTRY(42, "if-range", nullptr),
            ENTRY(43, "if-unmodified-since", nullptr),
            ENTRY(44, "last-modified", nullptr),
            ENTRY(45, "link", nullptr),
            ENTRY(46, "location", nullptr),
            ENTRY(47, "max-forwards", nullptr),
            ENTRY(48, "proxy-authenticate", nullptr),
            ENTRY(49, "proxy-authorization", nullptr),
            ENTRY(50, "range", nullptr),
            ENTRY(51, "referer", nullptr),
            ENTRY(52, "refresh", nullptr),
            ENTRY(53, "retry-after", nullptr),
            ENTRY(54, "server", nullptr),
            ENTRY(55, "set-cookie", nullptr),
            ENTRY(56, "strict-transport-security", nullptr),
            ENTRY(57, "transfer-encoding", nullptr),
            ENTRY(58, "user-agent", nullptr),
            ENTRY(59, "vary", nullptr),
            ENTRY(60, "via", nullptr),
            ENTRY(61, "www-authenticate", nullptr),
        };

        for (size_t i = 0; i < RTL_NUMBER_OF(entries); i++) {
            static_table_entry* item = entries + i;
            _static_table.insert(std::make_pair(item->name, http2_table_t(item->value, item->index)));
        }
    }

    match_result_t state = not_matched;
    size_t index = 0;

    state = find_table(name, value, index);
    switch (state) {
        case all_matched:
            encode_index(target, index);
            break;
        case key_matched:
            encode_indexed_name(target, flags, index, value);
            if (hpack_indexing & flags) {
                insert_table(name, value);
            }
            break;
        default:
            encode_name_value(target, flags, name, value);
            if (hpack_indexing & flags) {
                insert_table(name, value);
            }
            break;
    }
    return *this;
}

hpack& hpack::safe_mask(bool enable) {
    _safe_mask = enable;
    return *this;
}

}  // namespace net
}  // namespace hotplace
