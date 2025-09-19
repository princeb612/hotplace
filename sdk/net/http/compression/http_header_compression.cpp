/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/http/compression/http_dynamic_table.hpp>
#include <hotplace/sdk/net/http/compression/http_header_compression.hpp>
#include <hotplace/sdk/net/http/compression/http_huffman_coding.hpp>
#include <hotplace/sdk/net/http/compression/http_static_table.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_header_compression::http_header_compression() : _safe_mask(false) {}

return_t http_header_compression::encode(http_dynamic_table* dyntable, binary_t& target, const std::string& name, const std::string& value, uint32 flags) {
    return errorcode_t::success;
}

return_t http_header_compression::decode(http_dynamic_table* dyntable, const byte_t* source, size_t size, size_t& pos, std::string& name, std::string& value,
                                         uint32 flags) {
    return errorcode_t::success;
}

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
    __finally2 {}
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
        auto huffcode = http_huffman_coding::get_instance();
        if (hpack_huffman & flags) {
            size_t size_expected = 0;
            huffcode->expect(value, size, size_expected);
            encode_int(target, 0x80, 7, size_expected);
            huffcode->encode(target, value, size);
        } else {
            encode_int(target, 0x00, 7, size);
            target.insert(target.end(), value, value + size);
        }
    }
    __finally2 {}
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
            auto huffcode = http_huffman_coding::get_instance();
            huffcode->decode(&bs, p + pos, len);
            value = bs.c_str();
        } else {
            // string
            decode_int(p, pos, 0x80, 7, len);
            value.assign((char*)p + pos, len);
        }
        pos += len;
    }
    __finally2 {}
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
            auto huffcode = http_huffman_coding::get_instance();
            huffcode->decode(&bs, p + pos, namelen);
            name = bs.c_str();
        } else {
            name.assign((char*)p + pos, namelen);
        }
        pos += namelen;
    }
    __finally2 {}
    return ret;
}

return_t http_header_compression::sizeof_entry(const std::string& name, const std::string& value, size_t& size) {
    return_t ret = errorcode_t::success;
    size = name.size() + value.size() + 32;
    return ret;
}

void http_header_compression::safe_mask(bool enable) { _safe_mask = enable; }

match_result_t http_header_compression::matchall(http_static_table* statable, http_dynamic_table* dyntable, uint32 flags, const std::string& name,
                                                 const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;
    index = 0;

    __try2 {
        if (nullptr == statable || nullptr == dyntable) {
            __leave2;
        }

        // skip if qpack_static flag set
        if (qpack_static & ~flags) {
            // dynamic table
            state = dyntable->match(flags, name, value, index);
        }

        // if not matched or qpack_static flag set
        if (match_result_t::not_matched == state) {
            state = statable->match(flags, name, value, index);
        }
    }
    __finally2 {}
    return state;
}

return_t http_header_compression::selectall(http_static_table* statable, http_dynamic_table* dyntable, uint32 flags, size_t index, std::string& name,
                                            std::string& value) {
    return_t ret = errorcode_t::not_found;
    name.clear();
    value.clear();
    __try2 {
        if (nullptr == statable || nullptr == dyntable) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // skip if qpack_static flag set
        if (qpack_static & ~flags) {
            // dynamic table
            if (header_compression_hpack == dyntable->get_type()) {
                if (index > statable->size()) {
                    ret = dyntable->select(flags, index, name, value);
                }
            } else {
                ret = dyntable->select(flags, index, name, value);
            }
        }

        // post-base index in dynamic table
        if (qpack_postbase_index & flags) {
            __leave2;
        }

        // if not found or qpack_static flag set
        if (errorcode_t::success != ret) {
            ret = statable->select(flags, index, name, value);
        }
    }
    __finally2 {}
    return ret;
}

return_t http_header_compression::set_capacity(http_dynamic_table* dyntable, binary_t& target, uint8 maxsize) { return errorcode_t::success; }

return_t http_header_compression::duplicate(http_dynamic_table* dyntable, binary_t& target, size_t index) { return errorcode_t::success; }

return_t http_header_compression::ack(http_dynamic_table* dyntable, binary_t& target, uint32 streamid) { return errorcode_t::success; }

return_t http_header_compression::cancel(http_dynamic_table* dyntable, binary_t& target, uint32 streamid) { return errorcode_t::success; }

return_t http_header_compression::increment(http_dynamic_table* dyntable, binary_t& target, size_t inc) { return errorcode_t::success; }

return_t http_header_compression::pack(http_dynamic_table* dyntable, binary_t& target, uint32 flags) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
