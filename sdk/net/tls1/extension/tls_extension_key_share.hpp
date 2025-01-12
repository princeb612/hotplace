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
   protected:
    tls_extension_key_share(tls_session* session);
    return_t add_pubkey(uint16 group, const binary_t& pubkey, const keydesc& desc);
};

class tls_extension_client_key_share : public tls_extension_key_share {
   public:
    tls_extension_client_key_share(tls_session* session);

    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

   protected:
   private:
    uint16 _key_share_len;
    std::list<uint16> _keys;
    std::map<uint16, binary_t> _keyshares;
};

class tls_extension_server_key_share : public tls_extension_key_share {
   public:
    tls_extension_server_key_share(tls_session* session);

    virtual return_t do_read_body(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(binary_t& bin, stream_t* debugstream = nullptr);

   protected:
   private:
    uint16 _group;
    binary_t _pubkey;
};

}  // namespace net
}  // namespace hotplace

#endif
