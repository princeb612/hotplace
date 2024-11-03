/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <math.h>

#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

return_t quic_read_vle_int(const byte_t* stream, size_t size, size_t& pos, uint64& value) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || 0 == size || (pos > size)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        value = 0;
        byte_t v = stream[pos];
        auto prefix = v >> 6;
        auto length = 1 << prefix;

        if (pos + length > size) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        pos++;

        v &= 0x3f;
        value = v;
        for (auto i = 0; i < length - 1; i++) {
            value = (value << 8) + stream[pos++];
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_write_vle_int(uint64 value, binary_t& bin) {
    return_t ret = errorcode_t::success;
    byte_t prefix = 0;
    __try2 {
        if (value > 0x3fffffffffffffff) {
            // Packet numbers are integers in the range 0 to 2^62-1 (Section 12.3).
            ret = errorcode_t::bad_data;
            __leave2;
        } else if (value > 0x3fffffff) {
            prefix = 3;
        } else if (value > 0x3fff) {
            prefix = 2;
        } else if (value > 0x3f) {
            prefix = 1;
        }

        byte_t v = prefix << 6;
        byte_t length = 1 << prefix;
        auto i = hton64(value);
        byte_t* begin = (byte_t*)&i + sizeof(uint64) - length;

        begin[0] |= v;
        bin.insert(bin.end(), begin, begin + length);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_length_vle_int(uint64 value, uint8& length) {
    return_t ret = errorcode_t::success;
    __try2 {
        length = 0;
        byte_t prefix = 0;
        if (value > 0x3fffffffffffffff) {
            // Packet numbers are integers in the range 0 to 2^62-1 (Section 12.3).
            ret = errorcode_t::bad_data;
            __leave2;
        } else if (value > 0x3fffffff) {
            prefix = 3;
        } else if (value > 0x3fff) {
            prefix = 2;
        } else if (value > 0x3f) {
            prefix = 1;
        }
        length = 1 << prefix;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t encode_packet_number(uint64 full_pn, uint64 largest_acked, uint64& represent, uint8& nbits) {
    return_t ret = errorcode_t::success;
    uint64 num_unacked = 0;
    __try2 {
        represent = 0;
        nbits = 0;

        if (0 == largest_acked) {
            num_unacked = full_pn + 1;
        } else {
            num_unacked = full_pn - largest_acked;
        }

        uint64 min_bits = (log(num_unacked) / log(2)) + 1;
        uint8 num_bytes = ceil(min_bits / 8);

        // represent at leat twice
        represent = num_unacked << 1;
        nbits = (log(represent) / log(2)) + 1;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t decode_packet_number(uint64 largest_pn, uint64 truncated_pn, uint8 pn_nbits, uint64& value) {
    return_t ret = errorcode_t::success;
    __try2 {
        value = 0;
        auto expected_pn = largest_pn + 1;
        auto pn_win = 1 << pn_nbits;
        auto pn_hwin = pn_win / 2;
        auto pn_mask = pn_win - 1;
        auto candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
        if ((candidate_pn <= expected_pn - pn_hwin) && (candidate_pn < 0x400000000000000 - pn_win)) {
            value = candidate_pn + pn_win;
        } else if ((candidate_pn > expected_pn + pn_hwin) && (candidate_pn >= pn_win)) {
            value = candidate_pn - pn_win;
        } else {
            value = candidate_pn;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
