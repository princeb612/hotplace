/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_supported_versions.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSUPPORTEDVERSIONS__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSUPPORTEDVERSIONS__

#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   supported_versions (0x002b)
 */
class tls_extension_supported_versions : public tls_extension {
   protected:
    tls_extension_supported_versions(tls_handshake* handshake);
    virtual ~tls_extension_supported_versions();
};

class tls_extension_client_supported_versions : public tls_extension_supported_versions {
   public:
    tls_extension_client_supported_versions(tls_handshake* handshake);
    virtual ~tls_extension_client_supported_versions();

    tls_extension_client_supported_versions& add(tls_version_t code);
    const std::list<tls_version_t>& get_versions();

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    std::list<tls_version_t> _versions;
};

class tls_extension_server_supported_versions : public tls_extension_supported_versions {
   public:
    tls_extension_server_supported_versions(tls_handshake* handshake);
    virtual ~tls_extension_server_supported_versions();

    tls_version_t get_version();
    tls_extension_server_supported_versions& set(tls_version_t code);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
