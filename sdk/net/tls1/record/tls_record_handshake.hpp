/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_RECORD_HANDSHAKE__
#define __HOTPLACE_SDK_NET_TLS1_RECORD_HANDSHAKE__

#include <sdk/net/tls1/handshake/tls_handshakes.hpp>
#include <sdk/net/tls1/record/tls_record.hpp>

namespace hotplace {
namespace net {

class tls_record_handshake : public tls_record {
   public:
    tls_record_handshake(tls_session* session);

    tls_handshakes& get_handshakes();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

    tls_handshakes _handshakes;
};

}  // namespace net
}  // namespace hotplace

#endif
