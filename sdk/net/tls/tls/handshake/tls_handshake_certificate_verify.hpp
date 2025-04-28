/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECERTIFICATEVERIFY__
#define __HOTPLACE_SDK_NET_TLS_TLS_HANDSHAKE_TLSHANDSHAKECERTIFICATEVERIFY__

#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>

namespace hotplace {
namespace net {

/**
 * @remarks
 *          RFC 5246 7.4.8.  Certificate Verify
 * @example
 *          tls_record_application_data record(session);
 *          auto handshake = new tls_handshake_certificate_verify(session);
 *
 *          record.get_handshakes().add(handshake);
 *          record.write(dir, bin);
 */
class tls_handshake_certificate_verify : public tls_handshake {
   public:
    tls_handshake_certificate_verify(tls_session* session);

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

    return_t sign_certverify(const EVP_PKEY* pkey, tls_direction_t dir, uint16& scheme, binary_t& signature);
    return_t verify_certverify(const EVP_PKEY* pkey, tls_direction_t dir, uint16 scheme, binary_t& signature);
};

}  // namespace net
}  // namespace hotplace

#endif
