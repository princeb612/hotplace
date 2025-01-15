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

#ifndef __HOTPLACE_SDK_NET_TLS1_EXTENSION_KEY_SHARE__
#define __HOTPLACE_SDK_NET_TLS1_EXTENSION_KEY_SHARE__

#include <sdk/net/tls1/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   tls1_ext_key_share (0x0033)
 */
class tls_extension_key_share : public tls_extension {
   public:
    virtual return_t add(uint16 group);
    virtual return_t add(const std::string& group);

   protected:
    tls_extension_key_share(tls_session* session);
    virtual std::string get_kid();

    return_t add(uint16 group, tls_direction_t dir);
    return_t add(const std::string& group, tls_direction_t dir);
    return_t add_pubkey(uint16 group, const binary_t& pubkey, const keydesc& desc);
};

class tls_extension_client_key_share : public tls_extension_key_share {
   public:
    tls_extension_client_key_share(tls_session* session);

    virtual return_t add(uint16 group);
    virtual return_t add(const std::string& group);

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(binary_t& bin, stream_t* debugstream = nullptr);
    virtual std::string get_kid();

   private:
};

class tls_extension_server_key_share : public tls_extension_key_share {
   public:
    tls_extension_server_key_share(tls_session* session);

    virtual return_t add(uint16 group);
    virtual return_t add(const std::string& group);

   protected:
    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t do_write_body(binary_t& bin, stream_t* debugstream = nullptr);
    virtual std::string get_kid();

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
