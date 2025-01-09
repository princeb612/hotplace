/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_RECORD_APPLICATION_DATA__
#define __HOTPLACE_SDK_NET_TLS1_RECORD_APPLICATION_DATA__

#include <sdk/net/tls1/record/tls_record.hpp>

namespace hotplace {
namespace net {

class tls_record_application_data : public tls_record {
   public:
    tls_record_application_data(tls_session* session);
    virtual return_t read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    virtual return_t write(tls_direction_t dir, binary_t& bin, stream_t* debugstream = nullptr);

    void addref();
    void release();

   protected:
    t_shared_reference<tls_record_application_data> _shared;
    // std::list<tls_extension*> _extensions;
};

}  // namespace net
}  // namespace hotplace

#endif
