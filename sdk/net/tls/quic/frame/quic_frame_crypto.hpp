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

#ifndef __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMECRYPTO__
#define __HOTPLACE_SDK_NET_TLS_QUIC_FRAME_QUICFRAMECRYPTO__

#include <sdk/net/tls/quic/frame/quic_frame.hpp>

namespace hotplace {
namespace net {

struct external_crypto_data {
    const byte_t* stream;
    size_t size;
    size_t pos;

    external_crypto_data() : stream(nullptr), size(0), pos(0) {}
    external_crypto_data(const byte_t* s, size_t z, size_t p) : stream(s), size(z), pos(p) {}
    void set(const byte_t* s, size_t z, size_t p) {
        stream = s;
        size = z;
        pos = p;
    }
    void setpos(size_t p) { pos = p; }
};

// RFC 9000 19.6.  CRYPTO Frames
class quic_frame_crypto : public quic_frame {
   public:
    quic_frame_crypto(quic_packet* packet);

    return_t refer(external_crypto_data* data);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual return_t do_write_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, binary_t& bin);

   private:
    external_crypto_data* _extcd;
};

}  // namespace net
}  // namespace hotplace

#endif
