/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDUNKNOWN__
#define __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDUNKNOWN__

#include <sdk/net/tls/tls/record/tls_record.hpp>

namespace hotplace {
namespace net {

class tls_record_unknown : public tls_record {
   public:
    tls_record_unknown(uint8 type, tls_session* session);
    virtual ~tls_record_unknown();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
};

}  // namespace net
}  // namespace hotplace

#endif
