/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEACK__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMEACK__

#include <sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

// RFC 9000 13.2.6.  ACK Frames and Packet Protection
// RFC 9000 19.3.  ACK Frames

struct ack_range_t {
    uint32 gap;
    uint32 ack_range_length;

    ack_range_t() : gap(0), ack_range_length(0) {}
    ack_range_t(uint32 g, uint32 l) : gap(g), ack_range_length(l) {}
    bool operator==(const ack_range_t& rhs) const { return (gap == rhs.gap) && (ack_range_length == rhs.ack_range_length); }
};
/**
 * @example
 *          ack_t ack;
 *          t_ovl_points<uint32> part;
 *          // ACK(21, FAR:0, [0]G:1,R:4, [1]G:0,R:5)
 *          part.add(7, 12).add(14, 18).add(21);
 *          ack << part;
 *
 *          // (gdb) p part
 *          // $1 = {_arr = std::vector of length 3, capacity 4 = {{s = 7, e = 12}, {s = 14, e = 18}, {s = 21, e = 21}}}
 *
 *          // (gdb) p ack
 *          // $2 = {largest_ack = 21, first_ack_range = 0,
 *          //      ack_ranges = std::vector of length 2, capacity 2 = {{gap = 1, ack_range_length = 4}, {gap = 0, ack_range_length = 5}}}
 */
struct ack_t {
    uint32 largest_ack;
    uint32 first_ack_range;
    std::vector<ack_range_t> ack_ranges;

    ack_t() : largest_ack(0), first_ack_range(0) {}
    ack_t(uint32 l, uint32 f) : largest_ack(l), first_ack_range(f) {}
    void clear() {
        largest_ack = 0;
        first_ack_range = 0;
        ack_ranges.clear();
    }
    bool operator==(const ack_t& rhs) const {
        return ((largest_ack == rhs.largest_ack) && (first_ack_range == rhs.first_ack_range) && (ack_ranges == rhs.ack_ranges));
    }

    friend ack_t& operator<<(ack_t& ack, t_ovl_points<uint32>& part) {
        ack.clear();

        auto res = part.merge();
        auto size = res.size();
        if (0 == size) {
        } else if (1 <= size) {
            uint32 smallest = 0;
            {
                const auto& ent = res[size - 1];
                ack.largest_ack = ent.e;
                ack.first_ack_range = ent.e - ent.s;
                smallest = ent.s;
            }
            if (size > 1) {
                for (auto i = size - 1; i > 0; i--) {
                    const auto& ent = res[i - 1];
                    ack.ack_ranges.push_back(ack_range_t(smallest - ent.e - 2, ent.e - ent.s));
                    smallest = ent.s;
                }
            }
        }

        return ack;
    }
    friend t_ovl_points<uint32>& operator>>(const ack_t& ack, t_ovl_points<uint32>& part) {
        part.clear();
        auto smallest = ack.largest_ack - ack.first_ack_range;
        part.add(smallest, ack.largest_ack);
        for (const auto& ent : ack.ack_ranges) {
            auto largest = smallest - ent.gap - 2;
            smallest = largest - ent.ack_range_length;
            part.add(smallest, largest);
        }
        part.merge();

        return part;
    }
};

class quic_frame_ack : public quic_frame {
   public:
    quic_frame_ack(quic_packet* packet, uint8 type = quic_frame_type_ack);

    quic_frame_ack& set_protection_level(protection_space_t space);
    protection_space_t get_protection_space();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    protection_space_t _space;
};

}  // namespace net
}  // namespace hotplace

#endif
