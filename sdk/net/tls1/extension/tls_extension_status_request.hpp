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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_STATUS_REQUEST__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_STATUS_REQUEST__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   status_request (0x0005)
 */
class tls_extension_status_request : public tls_extension {
   public:
    tls_extension_status_request(tls_session* session);

    virtual return_t read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

    uint8 get_cert_status_type();
    void set_responderid_info(const binary_t& info);
    const binary_t& get_responderid_info();
    void set_request_ext_info(const binary_t& info);
    const binary_t& get_request_ext_info();

   protected:
   private:
    uint8 _cert_status_type;
    binary_t _responderid_info;
    binary_t _request_ext_info;
};

}  // namespace net
}  // namespace hotplace

#endif
