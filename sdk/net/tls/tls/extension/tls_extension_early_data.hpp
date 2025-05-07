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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONEARLYDATA__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONEARLYDATA__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   RFC 8446 4.2.10.  Early Data Indication
 */
class tls_extension_early_data : public tls_extension {
   public:
    tls_extension_early_data(tls_session* session, tls_hs_type_t hs);

    tls_hs_type_t get_handshake_type();

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(binary_t& bin);

   private:
    tls_hs_type_t _hs;
};

}  // namespace net
}  // namespace hotplace

#endif
