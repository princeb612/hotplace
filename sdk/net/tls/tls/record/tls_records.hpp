/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDS__
#define __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDS__

#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls_container.hpp>

namespace hotplace {
namespace net {

class tls_records {
   public:
    tls_records();

    return_t read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    return_t read(tls_session* session, tls_direction_t dir, const binary_t& bin);
    return_t write(tls_session* session, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func);

    return_t add(tls_record* record, bool upref = false);
    tls_records& add(tls_content_type_t type, tls_session* session, std::function<return_t(tls_record*)> func = nullptr, bool upref = false);
    tls_records& operator<<(tls_record* record);
    return_t for_each(std::function<return_t(tls_record*)> func);
    tls_record* getat(size_t index, bool upref = false);
    bool empty();
    size_t size();
    void clear();

   protected:
   private:
    t_tls_container<tls_record*, uint8> _records;  // tls_content_type_t
};

}  // namespace net
}  // namespace hotplace

#endif
