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

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONKEYSHARE__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_TLSEXTENSIONKEYSHARE__

#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief   tls_ext_key_share (0x0033)
 */
class tls_extension_key_share : public tls_extension {
   public:
    virtual ~tls_extension_key_share();

    virtual return_t add(uint16 group);
    virtual return_t add(const std::string& group);
    virtual void clear();

   protected:
    tls_extension_key_share(tls_handshake* handshake);
    virtual std::string get_kid();

    return_t add(uint16 group, tls_direction_t dir);
    return_t add(const std::string& group, tls_direction_t dir);
    return_t add_pubkey(uint16 group, const binary_t& pubkey, const keydesc& desc);
};

class tls_extension_client_key_share : public tls_extension_key_share {
   public:
    tls_extension_client_key_share(tls_handshake* handshake);
    virtual ~tls_extension_client_key_share();

    virtual return_t add(uint16 group);
    virtual return_t add(const std::string& group);
    virtual void clear();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual std::string get_kid();

   private:
};

class tls_extension_server_key_share : public tls_extension_key_share {
   public:
    tls_extension_server_key_share(tls_handshake* handshake);
    virtual ~tls_extension_server_key_share();

    /**
     * RFC 8446 2.  Protocol Overview
     * If (EC)DHE key establishment is in use, then the ServerHello contains a "key_share" extension with the server's ephemeral Diffie-Hellman share;
     * the server's share MUST be in the same group as one of the client's shares.
     */
    return_t add_keyshare();
    virtual void clear();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual std::string get_kid();

    virtual return_t add(uint16 group);
    virtual return_t add(const std::string& group);

   private:
};

}  // namespace net
}  // namespace hotplace

#endif
