/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_DTLSHANDSHAKEFRAGMENTED__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_DTLSHANDSHAKEFRAGMENTED__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class dtls_handshake_fragmented : public tls_handshake {
    friend class dtls_record_publisher;

   public:
    virtual ~dtls_handshake_fragmented();

    virtual return_t write(tls_direction_t dir, binary_t& bin);

    void set_fragment(const binary_t& frag);
    void set_fragment(binary_t&& frag);

    return_t prepare_fragment(const byte_t* stream, uint32 size, uint16 seq, uint32 fragment_offset, uint32 fragment_length);

   protected:
    dtls_handshake_fragmented(tls_hs_type_t type, tls_session* session);

   private:
    binary_t _fragmented;
};

}  // namespace net
}  // namespace hotplace

#endif
