/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECLIENTKEYEXCHANGE__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECLIENTKEYEXCHANGE__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 5246 7.4.7.  Client Key Exchange Message
 * struct {
 *     select (KeyExchangeAlgorithm) {
 *         case rsa:
 *             EncryptedPreMasterSecret;
 *         case dhe_dss:
 *         case dhe_rsa:
 *         case dh_dss:
 *         case dh_rsa:
 *         case dh_anon:
 *             ClientDiffieHellmanPublic;
 *     } exchange_keys;
 * } ClientKeyExchange;
 */
class tls_handshake_client_key_exchange : public tls_handshake {
   public:
    tls_handshake_client_key_exchange(tls_session* session);

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
