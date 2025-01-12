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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_COMPRESS_CERTIFICATE__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_COMPRESS_CERTIFICATE__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   compress_certificate (0x001b)
 */
class tls_extension_compress_certificate : public tls_extension {
   public:
    tls_extension_compress_certificate(tls_session* session);

    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    tls_extension_compress_certificate& add_algorithm(uint16 alg);
    const binary_t& get_algorithms();

   protected:
   private:
    binary_t _algorithms;
};

}  // namespace net
}  // namespace hotplace

#endif
