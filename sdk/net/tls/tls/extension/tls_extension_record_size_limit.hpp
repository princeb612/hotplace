/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_record_size_limit.hpp
 * @author OpenAI
 * @desc   RFC 8449 Record Size Limit Extension
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_RECORDSIZELIMIT__
#define __HOTPLACE_SDK_NET_TLS_TLS_EXTENSION_RECORDSIZELIMIT__

#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>

namespace hotplace {
namespace net {

/**
 * @brief RFC 8449 Record Size Limit Extension (0x001c)
 *
 * The advertised value limits protected records received by this endpoint.
 */
class HOTPLACE_NET_API tls_extension_record_size_limit : public tls_extension {
   public:
    explicit tls_extension_record_size_limit(tls_handshake* handshake);
    virtual ~tls_extension_record_size_limit();

    uint16 get_record_size_limit() const;
    void set_record_size_limit(uint16 value);

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

   private:
    uint16 _record_size_limit;
};

}  // namespace net
}  // namespace hotplace

#endif
