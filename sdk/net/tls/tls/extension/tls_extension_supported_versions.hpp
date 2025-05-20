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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSUPPORTEDVERSIONS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSUPPORTEDVERSIONS__

#include <sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   supported_versions (0x002b)
 */
class tls_extension_supported_versions : public tls_extension {
   protected:
    tls_extension_supported_versions(tls_session* session);
};

class tls_extension_client_supported_versions : public tls_extension_supported_versions {
   public:
    tls_extension_client_supported_versions(tls_session* session);

    tls_extension_client_supported_versions& add(uint16 code);
    const std::list<uint16>& get_versions();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    std::list<uint16> _versions;
};

class tls_extension_server_supported_versions : public tls_extension_supported_versions {
   public:
    tls_extension_server_supported_versions(tls_session* session);

    uint16 get_version();
    tls_extension_server_supported_versions& set(uint16 code);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
