/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_RECORD_DTLS13_CIPHERTEXT__
#define __HOTPLACE_SDK_NET_TLS1_RECORD_DTLS13_CIPHERTEXT__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/net/tls1/record/tls_record.hpp>

namespace hotplace {
namespace net {

class dtls13_ciphertext : public tls_record {
   public:
    dtls13_ciphertext(uint8 type, tls_session* session);

    virtual return_t read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);

   protected:
    virtual return_t write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    uint16 _sequence;
    uint8 _sequence_len;
    size_t _offset_encdata;
};

}  // namespace net
}  // namespace hotplace

#endif
