/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_RECORD_CHANGE_CIPHER_SPEC__
#define __HOTPLACE_SDK_NET_TLS1_RECORD_CHANGE_CIPHER_SPEC__

#include <sdk/net/tls1/record/tls_record.hpp>

namespace hotplace {
namespace net {

class tls_record_change_cipher_spec : public tls_record {
   public:
    tls_record_change_cipher_spec(tls_session* session);

    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);
};

}  // namespace net
}  // namespace hotplace

#endif
