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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_SUPPORTED_VERSIONS__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_SUPPORTED_VERSIONS__

#include <sdk/net/tls1/extension/tls_extension.hpp>

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
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(binary_t& bin, stream_t* debugstream = nullptr);

   private:
    std::list<uint16> _versions;
};

class tls_extension_server_supported_versions : public tls_extension_supported_versions {
   public:
    tls_extension_server_supported_versions(tls_session* session);

    uint16 get_version();
    tls_extension_server_supported_versions& set(uint16 code);

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(binary_t& bin, stream_t* debugstream = nullptr);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
