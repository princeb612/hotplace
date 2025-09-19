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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSTATUSREQUEST__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONSTATUSREQUEST__

#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   status_request (0x0005)
 */
class tls_extension_status_request : public tls_extension {
   public:
    tls_extension_status_request(tls_handshake* handshake);
    virtual ~tls_extension_status_request();

    uint8 get_cert_status_type();
    void set_responderid_info(const binary_t& info);
    const binary_t& get_responderid_info();
    void set_request_ext_info(const binary_t& info);
    const binary_t& get_request_ext_info();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint8 _cert_status_type;
    binary_t _responderid_info;
    binary_t _request_ext_info;
};

}  // namespace net
}  // namespace hotplace

#endif
