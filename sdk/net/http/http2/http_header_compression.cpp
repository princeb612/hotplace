/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/http_header_compression.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_header_compression::http_header_compression() : _safe_mask(false) {
    // RFC 7541 Appendix B. Huffman Code
    _huffcode.imports(_h2hcodes);
}

return_t http_header_compression::encode(http_header_compression_session* session, binary_t& target, const std::string& name, const std::string& value,
                                         uint32 flags) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http_header_compression::decode(http_header_compression_session* session, const byte_t* source, size_t size, size_t& pos, std::string& name,
                                         std::string& value, uint32 flags) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http_header_compression::sync(http_header_compression_session* session, binary_t& target, uint32 flags) { return errorcode_t::success; }

return_t http_header_compression::encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value) {
    return_t ret = errorcode_t::success;
    if ((1 <= prefix) && (prefix <= 8)) {
        /**
         * RFC 7541 5.1.  Integer Representation
         * RFC 7541 C.1.  Integer Representation Examples
         * RFC 7541 Figure 3: Integer Value Encoded after the Prefix (Shown for N = 5)
         *
         *     0   1   2   3   4   5   6   7
         *   +---+---+---+---+---+---+---+---+
         *   | ? | ? | ? | 1   1   1   1   1 |
         *   +---+---+---+-------------------+
         *   | 1 |    Value-(2^N-1) LSB      |
         *   +---+---------------------------+
         *                  ...
         *   +---+---------------------------+
         *   | 0 |    Value-(2^N-1) MSB      |
         *   +---+---------------------------+
         *
         * RFC 9204 4.1.1.  Prefixed Integers
         */

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
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t http_header_compression::decode_int(const byte_t* p, size_t& pos, uint8 mask, uint8 prefix, size_t& value) {
    /**
     * RFC 7541 5.1.  Integer Representation
     * RFC 7541 C.1.  Integer Representation Examples
     * RFC 9204 4.1.1.  Prefixed Integers
     */
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == p) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        value = 0;
        if ((1 <= prefix) && (prefix <= 8)) {
            uint8 n = (1 << prefix) - 1;
            uint8 b = p[pos++];

            if (_safe_mask) {
                uint8 temp = 0;
                for (int t = 0; t < prefix; t++) {
                    temp |= (1 << t);
                }
                mask &= ~temp;
            }
            b &= ~mask;

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

return_t http_header_compression::encode_string(binary_t& target, uint32 flags, const char* value, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 7541 5.2.  String Literal Representation
         * RFC 7541 Figure 4: String Literal Representation
         *
         *     0   1   2   3   4   5   6   7
         *   +---+---+---+---+---+---+---+---+
         *   | H |    String Length (7+)     |
         *   +---+---------------------------+
         *   |  String Data (Length octets)  |
         *   +-------------------------------+
         *
         * RFC 9204 4.1.2.  String Literals
         */

        if (hpack_huffman & flags) {
            size_t size_expected = 0;
            _huffcode.expect(value, size, size_expected);
            encode_int(target, 0x80, 7, size_expected);
            _huffcode.encode(target, value, size);
        } else {
            encode_int(target, 0x00, 7, size);
            target.insert(target.end(), value, value + size);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header_compression::encode_string(binary_t& target, uint32 flags, const std::string& value) {
    return encode_string(target, flags, value.c_str(), value.size());
}

return_t http_header_compression::decode_string(const byte_t* p, size_t& pos, uint8 flags, std::string& value) {
    return_t ret = errorcode_t::success;
    __try2 {
        value.clear();
        if (nullptr == p) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        byte_t b = p[pos];

        size_t len = 0;
        if (0x80 & b) {
            // huffman
            decode_int(p, pos, 0x80, 7, len);
            basic_stream bs;
            _huffcode.decode(&bs, p + pos, len);
            value = bs.c_str();
        } else {
            // string
            decode_int(p, pos, 0x80, 7, len);
            value.assign((char*)p + pos, len);
        }
        pos += len;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header_compression::decode_name_reference(const byte_t* p, size_t& pos, uint8 flags, uint8 mask, uint8 prefix, std::string& name) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == p) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t namelen = 0;
        decode_int(p, pos, mask, prefix, namelen);
        if (qpack_huffman & flags) {
            basic_stream bs;
            _huffcode.decode(&bs, p + pos, namelen);
            name = bs.c_str();
        } else {
            name.assign((char*)p + pos, namelen);
        }
        pos += namelen;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header_compression::set_capacity(http_header_compression_session* session, binary_t& target, uint8 maxsize) {
    /**
     * RFC 7541 Figure 12: Maximum Dynamic Table Size Change
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 |   Max size (5+)   |
     * +---+---------------------------+
     *
     * RFC 9204 Figure 5: Set Dynamic Table Capacity
     *   0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * | 0 | 0 | 1 |   Capacity (5+)   |
     * +---+---+---+-------------------+
     */

    if (session) {
        /**
         * RFC 7541 4.2.  Maximum Table Size
         * RFC 7541 6.3.  Dynamic Table Size Update
         * RFC 9204 5.  Configuration
         *
         * SETTINGS_HEADER_TABLE_SIZE
         * SETTINGS_QPACK_MAX_TABLE_CAPACITY
         */
        session->set_capacity(maxsize);
    }

    return encode_int(target, 0x20, 5, maxsize);
}

return_t http_header_compression::sizeof_entry(const std::string& name, const std::string& value, size_t& size) {
    return_t ret = errorcode_t::success;
    size = name.size() + value.size() + 32;
    return ret;
}

void http_header_compression::safe_mask(bool enable) { _safe_mask = enable; }

match_result_t http_header_compression::match(http_header_compression_session* session, uint32 flags, const std::string& name, const std::string& value,
                                              size_t& index) {
    match_result_t state = match_result_t::not_matched;
    index = 0;

    __try2 {
        if (nullptr == session) {
            __leave2;
        }

        // skip if qpack_static flag set
        if (qpack_static & ~flags) {
            // dynamic table
            state = session->match(name, value, index, flags);
        }

        // if not matched or qpack_static flag set
        if (match_result_t::not_matched == state) {
            // static table
            static_table_t::iterator iter;
            static_table_t::iterator liter;
            static_table_t::iterator uiter;

            liter = _static_table.lower_bound(name);
            uiter = _static_table.upper_bound(name);

            for (iter = liter; iter != uiter; iter++) {
                if (iter == liter) {
                    index = iter->second.second;  // :path: /sample/path
                    state = match_result_t::key_matched;
                }
                if (value == iter->second.first) {
                    index = iter->second.second;
                    state = match_result_t::all_matched;
                    break;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return state;
}

return_t http_header_compression::select(http_header_compression_session* session, uint32 flags, size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;
    __try2 {
        name.clear();
        value.clear();

        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // skip if qpack_static flag set
        if (qpack_static & ~flags) {
            // dynamic table
            if (header_compression_hpack == session->type()) {
                if (index > _static_table.size()) {
                    ret = session->select(index, flags, name, value);
                }
            } else {
                ret = session->select(index, flags, name, value);
            }
        }

        // post-base index in dynamic table
        if (qpack_postbase_index & flags) {
            __leave2;
        }

        // if not found or qpack_static flag set
        if (errorcode_t::success != ret) {
            // static table
            static_table_index_t::iterator iter = _static_table_index.find(index);
            if (_static_table_index.end() == iter) {
                ret = errorcode_t::not_found;
                __leave2;
            } else {
                name = iter->second.first;
                if ((hpack_layout_index | hpack_layout_name_value) & flags) {
                    value = iter->second.second;
                    ret = errorcode_t::success;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
