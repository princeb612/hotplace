/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_HANDSHAKES__
#define __HOTPLACE_SDK_NET_TLS1_HANDSHAKES__

#include <sdk/net/tls1/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshakes {
   public:
    tls_handshakes();
    ~tls_handshakes();

    return_t read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    return_t read(tls_session* session, tls_direction_t dir, const binary_t& bin, stream_t* debugstream = nullptr);
    return_t write(tls_session* session, tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    return_t add(tls_handshake* handshake, bool upref = false);
    tls_handshakes& operator<<(tls_handshake* handshake);
    void for_each(std::function<void(tls_handshake*)> func);
    tls_handshake* get(uint8 type, bool upref = false);
    tls_handshake* getat(size_t index, bool upref = false);
    size_t size();
    void clear();

   protected:
    critical_section _lock;
    std::map<uint8, tls_handshake*> _dictionary;  // tls_hs_type_t
    std::vector<tls_handshake*> _handshakes;      // ordered
};

}  // namespace net
}  // namespace hotplace

#endif
