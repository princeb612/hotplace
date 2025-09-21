/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * reference
 *  https://github.com/martinduke/quic-test-vector
 *  https://quic.xargs.org/
 *
 * studying...
 *
 * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
 * RFC 9001 Using TLS to Secure QUIC
 *
 * OpenSSL 3.2 and later features support for the QUIC transport protocol.
 * Currently, only client connectivity is supported.
 * This man page describes the usage of QUIC client functionality for both existing and new applications.
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMES__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMES__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/quic/types.hpp>
#include <hotplace/sdk/net/tls/tls_container.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

class quic_frames {
   public:
    /**
     * @constructor
     */
    quic_frames();
    /**
     * @constructor
     */
    quic_frames(tls_session* session);

    return_t read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    return_t read(tls_direction_t dir, const binary_t& bin);
    return_t write(tls_direction_t dir, binary_t& bin);

    /**
     * t_tls_distinct_container
     */
    return_t add(quic_frame* frame, bool upref = false);
    quic_frames& add(quic_frame_t type, tls_session* session, std::function<return_t(quic_frame*)> func = nullptr, bool upref = false);
    quic_frames& add_h3(quic_frame_t type, tls_session* session, std::function<return_t(quic_frame*)> func = nullptr, bool upref = false);
    quic_frames& operator<<(quic_frame* frame);
    return_t for_each(std::function<return_t(quic_frame*)> func);
    quic_frame* get(uint8 type, bool upref = false);
    quic_frame* getat(size_t index, bool upref = false);
    quic_frame* operator[](size_t index);
    bool empty();
    size_t size();
    void clear();

    tls_session* get_session();
    void set_session(tls_session* session);
    /**
     * return true if there is any frame other than ACK, PADDING
     */
    bool is_significant();

    t_tls_distinct_container<quic_frame*, uint64>& get_container();

   protected:
   private:
    t_tls_distinct_container<quic_frame*, uint64> _frames;  // quic_frame_t
    tls_session* _session;
};

}  // namespace net
}  // namespace hotplace

#endif
