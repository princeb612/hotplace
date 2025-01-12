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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_SIGNATURE_ALGORITHMS__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_SIGNATURE_ALGORITHMS__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   signature_algorithms (0x000d)
 */
class tls_extension_signature_algorithms : public tls_extension {
   public:
    tls_extension_signature_algorithms(tls_session* session);

    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    tls_extension_signature_algorithms& add_algorithm(uint16 alg);
    const binary_t& get_algorithms();

   protected:
   private:
    binary_t _algorithms;
};

}  // namespace net
}  // namespace hotplace

#endif
