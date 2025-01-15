/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS1_RECORDS__
#define __HOTPLACE_SDK_NET_TLS1_RECORDS__

#include <sdk/net/tls1/record/tls_record.hpp>

namespace hotplace {
namespace net {

class tls_records {
   public:
    tls_records();
    ~tls_records();

    return_t read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream = nullptr);
    return_t read(tls_session* session, tls_direction_t dir, const binary_t& bin, stream_t* debugstream = nullptr);
    return_t add(tls_record* record, bool upref = false);
    tls_records& operator<<(tls_record* record);
    void for_each(std::function<void(tls_record*)> func);
    tls_record* getat(size_t index, bool upref = false) const;
    size_t size();
    void clear();

   protected:
    critical_section _lock;
    std::vector<tls_record*> _records;
};

}  // namespace net
}  // namespace hotplace

#endif
