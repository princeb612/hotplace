/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKES__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKES__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

class tls_handshakes {
   public:
    tls_handshakes();
    ~tls_handshakes();

    return_t read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    return_t read(tls_session* session, tls_direction_t dir, const binary_t& bin);

    return_t write(tls_session* session, tls_direction_t dir, binary_t& bin);

    return_t add(tls_handshake* handshake, bool upref = false);
    tls_handshakes& operator<<(tls_handshake* handshake);

    /**
     * do { } while (success == returnof_func);
     */
    return_t for_each(std::function<return_t(tls_handshake*)> func);

    tls_handshake* get(uint8 type, bool upref = false);
    tls_handshake* getat(size_t index, bool upref = false);

    size_t size();

    void clear();

    void set_dtls_seq(uint16 seq);
    uint16 get_dtls_seq();

   protected:
   private:
    uint16 _dtls_seq;
    critical_section _lock;
    std::map<uint8, tls_handshake*> _dictionary;  // tls_hs_type_t
    std::vector<tls_handshake*> _handshakes;      // ordered
};

}  // namespace net
}  // namespace hotplace

#endif
