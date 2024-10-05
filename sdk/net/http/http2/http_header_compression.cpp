/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_header_compression::http_header_compression() : _safe_mask(false) {}

return_t http_header_compression::hc_encode_int(binary_t& target, uint8 mask, uint8 prefix, size_t value) {
    return_t ret = errorcode_t::success;
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
    } else {
        ret = errorcode_t::invalid_parameter;
    }
    return ret;
}

return_t http_header_compression::hc_decode_int(const byte_t* p, size_t& pos, uint8 mask, uint8 prefix, size_t& value) {
    // 5.1.  Integer Representation
    // C.1.  Integer Representation Examples
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

return_t http_header_compression::hc_encode_string(const huffman_coding& hc, binary_t& target, uint32 flags, const char* value, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 7541 5.2.  String Literal Representation
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
            hc.expect(value, size, size_expected);
            hc_encode_int(target, 0x80, 7, size_expected);
            hc.encode(target, value, size);
        } else {
            hc_encode_int(target, 0x00, 7, size);
            target.insert(target.end(), value, value + size);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header_compression::hc_decode_string(const huffman_coding& hc, const byte_t* p, size_t& pos, uint8 flags, std::string& value) {
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
            hc_decode_int(p, pos, 0x80, 7, len);
            basic_stream bs;
            hc.decode(&bs, p + pos, len);
            value = bs.c_str();
        } else {
            // string
            hc_decode_int(p, pos, 0x80, 7, len);
            value.assign((char*)p + pos, len);
        }
        pos += len;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header_compression::set_dynamic_table_size(binary_t& target, uint8 maxsize) {
    // RFC 7541 Figure 12: Maximum Dynamic Table Size Change
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // | 0 | 0 | 1 |   Max size (5+)   |
    // +---+---------------------------+
    //
    // RFC 9204 Figure 5: Set Dynamic Table Capacity
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // | 0 | 0 | 1 |   Capacity (5+)   |
    // +---+---+---+-------------------+

    return hc_encode_int(target, 0x20, 5, maxsize);
}

void http_header_compression::safe_mask(bool enable) { _safe_mask = enable; }

}  // namespace net
}  // namespace hotplace
