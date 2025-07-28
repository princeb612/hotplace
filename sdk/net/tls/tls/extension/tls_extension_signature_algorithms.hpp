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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSIGNATUREALGORITHMS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSIGNATUREALGORITHMS__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * RFC 5246 7.4.1.4.1.  Signature Algorithms
 */
class tls_extension_signature_algorithms : public tls_extension {
   public:
    tls_extension_signature_algorithms(tls_handshake* handshake);
    virtual ~tls_extension_signature_algorithms();

    tls_extension_signature_algorithms& add(uint16 code);
    tls_extension_signature_algorithms& add(const std::string& name);

    void clear();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    std::list<uint16> _algorithms;
};

}  // namespace net
}  // namespace hotplace

#endif
